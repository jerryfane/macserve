// Package workerclient connects a credential-free native worker to its controller.
package workerclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/peercred"
	"github.com/jerryfane/macserve/internal/protocol"
	"github.com/jerryfane/macserve/internal/worker"
)

type Executor interface {
	Recover(context.Context) error
	Execute(context.Context, model.Job, worker.Source, io.Reader, worker.Sink) (worker.Result, error)
	ArtifactPath(string, string) (string, error)
	RemoveExport(string) error
}

type Client struct {
	config Config
	engine Executor
	http   *http.Client
	root   *os.Root
	epoch  string
}

var ErrPeerIdentity = errors.New("controller Unix peer UID mismatch")

type HTTPError struct{ Status int }

func (e *HTTPError) Error() string { return fmt.Sprintf("controller HTTP status %d", e.Status) }

func New(config Config, engine Executor) (*Client, error) {
	config, err := normalize(config)
	if err != nil {
		return nil, err
	}
	if engine == nil {
		return nil, errors.New("worker executor required")
	}
	root, err := os.OpenRoot(config.Root)
	if err != nil {
		return nil, err
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		root.Close()
		return nil, err
	}
	transport := &http.Transport{
		Proxy:                 nil,
		MaxConnsPerHost:       8,
		MaxIdleConnsPerHost:   4,
		ResponseHeaderTimeout: time.Duration(config.RequestTimeoutSeconds) * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, "unix", config.Socket)
			if err != nil {
				return nil, err
			}
			uid, err := peercred.UID(conn)
			if err != nil || uid != config.ControllerUID {
				conn.Close()
				return nil, ErrPeerIdentity
			}
			return conn, nil
		},
	}
	return &Client{config: config, engine: engine, root: root, epoch: hex.EncodeToString(nonce[:]), http: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("worker redirects are forbidden") }}}, nil
}

func (c *Client) Close() error { c.http.CloseIdleConnections(); return c.root.Close() }

func (c *Client) request(ctx context.Context, method, path, epoch, lease string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, "http://controller"+protocol.Prefix+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set(protocol.EpochHeader, epoch)
	if lease != "" {
		req.Header.Set(protocol.LeaseHeader, lease)
	}
	return req, nil
}

func (c *Client) json(ctx context.Context, method, path, epoch, lease string, value, reply any) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(c.config.RequestTimeoutSeconds)*time.Second)
	defer cancel()
	var body io.Reader
	if value != nil {
		data, err := json.Marshal(value)
		if err != nil {
			return 0, err
		}
		body = bytes.NewReader(data)
	}
	req, err := c.request(ctx, method, path, epoch, lease, body)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, &HTTPError{resp.StatusCode}
	}
	if resp.StatusCode == http.StatusNoContent || reply == nil {
		return resp.StatusCode, nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, (2<<20)+1))
	if err != nil {
		return resp.StatusCode, err
	}
	if len(data) > 2<<20 {
		return resp.StatusCode, errors.New("oversized controller response")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(reply); err != nil {
		return resp.StatusCode, err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return resp.StatusCode, errors.New("trailing controller JSON")
	}
	return resp.StatusCode, nil
}

func wait(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// Run never executes a new lease while a previous completion is awaiting durable
// acknowledgement. Losing heartbeat or evidence delivery cancels local work.
func (c *Client) Run(ctx context.Context) error {
	if saved, err := c.loadPending(); err != nil {
		return err
	} else if saved != nil {
		if err := c.deliver(ctx, *saved); err != nil {
			return err
		}
	}
	registered := false
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := c.engine.Recover(ctx); err != nil {
			return fmt.Errorf("worker pre-lease quiescence: %w", err)
		}
		if !registered {
			_, err := c.json(ctx, http.MethodPost, "/register", c.epoch, "", protocol.Registration{Epoch: c.epoch, Quiescent: true}, nil)
			if err != nil {
				if errors.Is(err, ErrPeerIdentity) {
					return err
				}
				var status *HTTPError
				if errors.As(err, &status) && status.Status >= 400 && status.Status < 500 && status.Status != 429 {
					return err
				}
				if err := wait(ctx, time.Duration(c.config.PollSeconds)*time.Second); err != nil {
					return err
				}
				continue
			}
			registered = true
		}
		var lease protocol.Lease
		status, err := c.json(ctx, http.MethodPost, "/next", c.epoch, "", struct{}{}, &lease)
		if err != nil {
			if errors.Is(err, ErrPeerIdentity) {
				return err
			}
			var response *HTTPError
			if errors.As(err, &response) && response.Status >= 400 && response.Status < 500 && response.Status != 429 {
				return err
			}
			registered = false
		} else if status != http.StatusNoContent {
			if err := c.execute(ctx, lease); err != nil {
				return err
			}
			continue
		}
		if err := wait(ctx, time.Duration(c.config.PollSeconds)*time.Second); err != nil {
			return err
		}
	}
}

type pending struct {
	Epoch  string         `json:"epoch"`
	Lease  protocol.Lease `json:"lease"`
	Result worker.Result  `json:"result"`
}

func safeID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func (c *Client) execute(parent context.Context, lease protocol.Lease) error {
	if !safeID(lease.Job.ID) || lease.Token == "" || lease.Job.WorkerEpoch != c.epoch || lease.Job.Deadline == nil || lease.Job.State != model.Preparing {
		return errors.New("invalid controller lease")
	}
	lease.Job.LeaseToken = lease.Token
	ctx, deadlineCancel := context.WithDeadline(parent, *lease.Job.Deadline)
	defer deadlineCancel()
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	heartbeatDone := make(chan struct{})
	stopHeartbeat := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		ticker := time.NewTicker(time.Duration(c.config.HeartbeatSeconds) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopHeartbeat:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				var pulse protocol.Heartbeat
				_, err := c.json(ctx, http.MethodPost, "/jobs/"+lease.Job.ID+"/heartbeat", c.epoch, lease.Token, struct{}{}, &pulse)
				if err != nil {
					cancel(fmt.Errorf("controller heartbeat: %w", err))
					return
				}
				if pulse.Cancel {
					cancel(context.Canceled)
					return
				}
				if pulse.Deadline.IsZero() || time.Now().After(pulse.Deadline) {
					cancel(context.DeadlineExceeded)
					return
				}
			}
		}
	}()
	defer func() { close(stopHeartbeat); <-heartbeatDone }()
	sink := &remoteSink{client: c, ctx: ctx, jobID: lease.Job.ID, lease: lease.Token, cancel: cancel}
	result := worker.Result{State: model.Failed, Reason: "source transfer failed", Source: lease.Source, StartedAt: time.Now().UTC()}
	executed := false
	req, err := c.request(ctx, http.MethodGet, "/jobs/"+lease.Job.ID+"/source", c.epoch, lease.Token, nil)
	if err == nil {
		var resp *http.Response
		resp, err = c.http.Do(req)
		if err == nil {
			if resp.StatusCode != http.StatusOK {
				err = &HTTPError{resp.StatusCode}
			} else {
				executed = true
				result, err = c.engine.Execute(ctx, lease.Job, lease.Source, resp.Body, sink)
			}
			resp.Body.Close()
		}
	}
	if !executed {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		cleanupErr := c.engine.Recover(cleanupCtx)
		cleanupCancel()
		result.CleanupOK = cleanupErr == nil
		err = errors.Join(err, cleanupErr)
		if cleanupErr != nil {
			result.Reason = errors.Join(errors.New(result.Reason), cleanupErr).Error()
		}
	}
	if err != nil && result.Reason == "" {
		result.Reason = err.Error()
	}
	if result.State == "" {
		result.State = model.Failed
		result.CleanupOK = false
	}
	if result.FinishedAt.IsZero() {
		result.FinishedAt = time.Now().UTC()
	}
	if cause := context.Cause(ctx); cause != nil {
		if errors.Is(cause, context.DeadlineExceeded) {
			result.State = model.TimedOut
		} else {
			result.State = model.Cancelled
		}
		result.Reason = cause.Error()
	}
	if !result.CleanupOK {
		result.State = model.Failed
	}
	saved := pending{Epoch: c.epoch, Lease: lease, Result: result}
	if err := c.savePending(saved); err != nil {
		return err
	}
	// Finalization gets a separate bounded window after an execution deadline or
	// shutdown signal, so cancellation does not suppress cleanup evidence.
	finalCtx, finalCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer finalCancel()
	if err := c.deliver(finalCtx, saved); err != nil {
		return err
	}
	if !result.CleanupOK {
		return errors.New("worker cleanup failed; refusing another lease")
	}
	return nil
}

type remoteSink struct {
	client       *Client
	ctx          context.Context
	jobID, lease string
	cancel       context.CancelCauseFunc
	mu           sync.Mutex
}

func (s *remoteSink) Log(stream, text string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.client.json(s.ctx, http.MethodPost, "/jobs/"+s.jobID+"/logs", s.client.epoch, s.lease, protocol.Log{Stream: stream, Data: []byte(text)}, nil)
	if err != nil {
		s.cancel(err)
	}
	return err
}
func (s *remoteSink) Stage(state model.State) error {
	_, err := s.client.json(s.ctx, http.MethodPost, "/jobs/"+s.jobID+"/stage", s.client.epoch, s.lease, protocol.Stage{State: state}, nil)
	if err != nil {
		s.cancel(err)
	}
	return err
}

func (c *Client) savePending(value pending) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data) > 64<<20 {
		return errors.New("completion exceeds 64 MiB")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	tmp := "pending-" + hex.EncodeToString(nonce[:]) + ".tmp"
	f, err := c.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer c.root.Remove(tmp)
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := c.root.Rename(tmp, "pending.json"); err != nil {
		return err
	}
	dir, err := c.root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func (c *Client) loadPending() (*pending, error) {
	info, err := c.root.Lstat("pending.json")
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 64<<20 {
		return nil, errors.New("unsafe pending completion file")
	}
	f, err := c.root.Open("pending.json")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	dec := json.NewDecoder(io.LimitReader(f, (64<<20)+1))
	dec.DisallowUnknownFields()
	var value pending
	if err := dec.Decode(&value); err != nil {
		return nil, err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, errors.New("trailing completion JSON")
	}
	if !safeID(value.Lease.Job.ID) || value.Lease.Token == "" || value.Epoch == "" {
		return nil, errors.New("invalid pending completion")
	}
	return &value, nil
}

func (c *Client) deliver(ctx context.Context, saved pending) error {
	jobID := saved.Lease.Job.ID
	for _, artifact := range saved.Result.Artifacts {
		if !safeID(artifact.ID) || artifact.SizeBytes < 0 {
			return errors.New("invalid artifact manifest")
		}
		path, err := c.engine.ArtifactPath(jobID, artifact.ID)
		if err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() != artifact.SizeBytes {
			f.Close()
			return errors.New("artifact changed before upload")
		}
		req, err := c.request(ctx, http.MethodPut, "/jobs/"+jobID+"/artifacts/"+artifact.ID, saved.Epoch, saved.Lease.Token, f)
		if err != nil {
			f.Close()
			return err
		}
		metadata, err := json.Marshal(artifact)
		if err != nil {
			f.Close()
			return err
		}
		req.Header.Set(protocol.ArtifactHeader, base64.RawURLEncoding.EncodeToString(metadata))
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("Content-Length", strconv.FormatInt(artifact.SizeBytes, 10))
		req.ContentLength = artifact.SizeBytes
		resp, err := c.http.Do(req)
		f.Close()
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusGone {
			return c.ackPending(jobID)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return &HTTPError{resp.StatusCode}
		}
	}
	status, err := c.json(ctx, http.MethodPost, "/jobs/"+jobID+"/complete", saved.Epoch, saved.Lease.Token, saved.Result, nil)
	if err != nil && status != http.StatusGone {
		return err
	}
	return c.ackPending(jobID)
}
func (c *Client) ackPending(jobID string) error {
	if err := c.engine.RemoveExport(jobID); err != nil {
		return err
	}
	if err := c.root.Remove("pending.json"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

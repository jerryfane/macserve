// Package workerclient connects a credential-free native worker to its controller.
package workerclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jerryfane/macserve/internal/buildseal"
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
	// VerifiedTree is the Git tree computed from a job's extracted source
	// bytes, or "" when extraction did not verify one.
	VerifiedTree(string) string
	// LaneReady reports whether another job may start beside the running
	// ones (worker.Engine.LaneReady); worker.ErrDrain means not until the
	// worker is idle.
	LaneReady(context.Context) error
}

type Client struct {
	config  Config
	engine  Executor
	http    *http.Client
	root    *os.Root
	epoch   string
	sealKey ed25519.PrivateKey
	checks  Checks
}

var ErrPeerIdentity = errors.New("controller Unix peer UID mismatch")

// HTTPError is a non-2xx controller reply to Method Path (the socket URL
// path; no query, headers or body).
type HTTPError struct {
	Status       int
	Method, Path string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("controller HTTP status %d for %s %s", e.Status, e.Method, e.Path)
}

func statusError(resp *http.Response) *HTTPError {
	return &HTTPError{Status: resp.StatusCode, Method: resp.Request.Method, Path: resp.Request.URL.Path}
}

// New requires the lease authority (root registry, qualification record and
// seal key): a broker never executes a lease it resolved only from the
// controller's snapshot, and never reports a result without its seal.
func New(config Config, engine Executor) (*Client, error) {
	return NewWithChecks(config, engine, Checks{})
}

// NewWithChecks is New with the given host checks of the lease authority
// files.
func NewWithChecks(config Config, engine Executor, checks Checks) (*Client, error) {
	checks = checks.withDefaults()
	config, err := normalize(config)
	if err != nil {
		return nil, err
	}
	if engine == nil {
		return nil, errors.New("worker executor required")
	}
	if err := config.LeaseAuthority(); err != nil {
		return nil, err
	}
	sealKey, err := loadSealKey(checks, config.SealKeyFile)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(config.Root)
	if err != nil {
		return nil, err
	}
	epoch, err := newEpoch()
	if err != nil {
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
	return &Client{config: config, engine: engine, root: root, epoch: epoch, sealKey: sealKey, checks: checks, http: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("worker redirects are forbidden") }}}, nil
}

func (c *Client) Close() error { c.http.CloseIdleConnections(); return c.root.Close() }

func newEpoch() (string, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(nonce[:]), nil
}

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
		return resp.StatusCode, statusError(resp)
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

// laneDone is one lane's finished execution.
type laneDone struct {
	jobID     string
	cleanupOK bool
	err       error
}

// Run never executes a new lease while a saved completion from before it
// started is awaiting durable acknowledgement. Losing heartbeat or evidence
// delivery cancels local work.
//
// It executes up to max_concurrent_jobs leases at once, each on its own
// goroutine, under one epoch. Recover runs only while no lease executes.
// A lease whose cleanup was not verified fences its epoch at the controller;
// the client then drains: it asks for no lease, lets the other lanes finish,
// and registers a new epoch only after Recover verifies the idle account.
// An engine drain (an unattributed job-account process while jobs run)
// does the same. With one lane this is the sequential loop of a single-job
// worker.
func (c *Client) Run(ctx context.Context) (returned error) {
	defer func() {
		if ctx.Err() != nil && errors.Is(returned, ctx.Err()) {
			returned = nil
		}
	}()
	saved, err := c.loadPendings()
	if err != nil {
		return err
	}
	for _, value := range saved {
		if err := c.deliver(ctx, value); err != nil {
			return err
		}
	}
	lanes := c.config.Lanes()
	running := map[string]bool{}
	done := make(chan laneDone, lanes)
	var wg sync.WaitGroup
	// Lanes finish, deliver and clean up under their own bounded contexts
	// after ctx ends; Run returns only after every lane has.
	defer wg.Wait()
	var fatal error
	registered, draining := false, false
	finished := func(d laneDone) {
		delete(running, d.jobID)
		fatal = errors.Join(fatal, d.err)
		draining = draining || !d.cleanupOK
	}
	// pause waits one poll interval, returning early when a lane finishes.
	pause := func() error {
		timer := time.NewTimer(time.Duration(c.config.PollSeconds) * time.Second)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case d := <-done:
			finished(d)
		case <-timer.C:
		}
		return nil
	}
	for {
		for collected := false; !collected; {
			select {
			case d := <-done:
				finished(d)
			default:
				collected = true
			}
		}
		if fatal != nil {
			return fatal
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(running) == 0 {
			if draining {
				// Failed cleanup fenced the old epoch at the controller. A
				// new epoch is registered only after Recover verifies
				// quiescence.
				if c.epoch, err = newEpoch(); err != nil {
					return err
				}
				registered, draining = false, false
			}
			admissionErr := c.engine.Recover(ctx)
			statusErr := c.saveAdmissionStatus(admissionErr)
			if err := errors.Join(admissionErr, statusErr); err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				log.Printf("worker recovery refused admission; retrying after poll: %v", err)
				registered = false
				if err := wait(ctx, time.Duration(c.config.PollSeconds)*time.Second); err != nil {
					return err
				}
				continue
			}
		}
		if draining || len(running) == lanes {
			if err := pause(); err != nil {
				return err
			}
			continue
		}
		if !registered {
			_, err := c.json(ctx, http.MethodPost, "/register", c.epoch, "", protocol.Registration{Epoch: c.epoch, Quiescent: true, Lanes: lanes}, nil)
			if err != nil {
				if errors.Is(err, ErrPeerIdentity) {
					return err
				}
				var status *HTTPError
				if errors.As(err, &status) && status.Status >= 400 && status.Status < 500 && status.Status != 429 {
					return err
				}
				if err := pause(); err != nil {
					return err
				}
				continue
			}
			registered = true
		}
		if len(running) != 0 {
			// A lane beside running jobs: the engine must still admit one.
			if err := c.engine.LaneReady(ctx); err != nil {
				if errors.Is(err, worker.ErrDrain) {
					log.Printf("worker draining until idle: %v", err)
					draining = true
				}
				if err := pause(); err != nil {
					return err
				}
				continue
			}
		}
		request := protocol.NextRequest{Running: slices.Sorted(maps.Keys(running))}
		var lease protocol.Lease
		status, err := c.json(ctx, http.MethodPost, "/next", c.epoch, "", request, &lease)
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
			if running[lease.Job.ID] {
				return errors.New("controller offered a lease a lane already executes")
			}
			running[lease.Job.ID] = true
			wg.Add(1)
			go func() {
				defer wg.Done()
				cleanupOK, err := c.execute(ctx, lease)
				done <- laneDone{jobID: lease.Job.ID, cleanupOK: cleanupOK, err: err}
			}()
			continue
		}
		if err := pause(); err != nil {
			return err
		}
	}
}

// pending is a final result awaiting durable acknowledgement. Resolution
// and SourceTree are the worker's own lease resolution and computed source
// tree; Seal is the signed build seal over them and the result. A pending
// file written before seals existed has none and is sealed on delivery.
type pending struct {
	Epoch      string                `json:"epoch"`
	Lease      protocol.Lease        `json:"lease"`
	Result     worker.Result         `json:"result"`
	Resolution *buildseal.Resolution `json:"resolution,omitempty"`
	SourceTree string                `json:"source_tree,omitempty"`
	Seal       *buildseal.Envelope   `json:"seal,omitempty"`
	// file is the name it was loaded from; empty for a new completion.
	file string
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

func (c *Client) execute(parent context.Context, lease protocol.Lease) (bool, error) {
	if !safeID(lease.Job.ID) || lease.Token == "" || lease.Job.WorkerEpoch != c.epoch || lease.Job.Deadline == nil || lease.Job.State != model.Preparing {
		return false, errors.New("invalid controller lease")
	}
	lease.Job.LeaseToken = lease.Token
	// Every request of this lease carries the epoch it was leased under.
	epoch := lease.Job.WorkerEpoch
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
				_, err := c.json(ctx, http.MethodPost, "/jobs/"+lease.Job.ID+"/heartbeat", epoch, lease.Token, struct{}{}, &pulse)
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
	sink := &remoteSink{client: c, ctx: ctx, epoch: epoch, jobID: lease.Job.ID, lease: lease.Token, cancel: cancel}
	result := worker.Result{State: model.Failed, Reason: "source transfer failed", Source: lease.Source, StartedAt: time.Now().UTC()}
	executed := false
	resolution, err := c.resolveLease(lease.Job)
	if err != nil {
		result.Reason = worker.PublicReason(err)
	} else {
		var req *http.Request
		req, err = c.request(ctx, http.MethodGet, "/jobs/"+lease.Job.ID+"/source", epoch, lease.Token, nil)
		if err == nil {
			var resp *http.Response
			resp, err = c.http.Do(req)
			if err == nil {
				if resp.StatusCode != http.StatusOK {
					err = statusError(resp)
				} else {
					executed = true
					result, err = c.engine.Execute(ctx, lease.Job, lease.Source, resp.Body, sink)
				}
				resp.Body.Close()
			}
		}
	}
	if !executed {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		cleanupErr := c.engine.Recover(cleanupCtx)
		cleanupCancel()
		result.CleanupOK = cleanupErr == nil
		err = errors.Join(err, cleanupErr)
		if cleanupErr != nil {
			result.Reason = errors.Join(errors.New(result.Reason), errors.New(worker.PublicReason(cleanupErr))).Error()
		}
	}
	if err != nil {
		log.Printf("worker job %s failed: %v", lease.Job.ID, err)
		if result.Reason == "" {
			result.Reason = worker.PublicReason(err)
		}
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
	saved := pending{Epoch: epoch, Lease: lease, Result: result, Resolution: resolution}
	if executed {
		saved.SourceTree = c.engine.VerifiedTree(lease.Job.ID)
	}
	seal, err := c.seal(saved)
	if err != nil {
		return false, err
	}
	saved.Seal = &seal
	if err := c.savePending(saved); err != nil {
		return false, err
	}
	// Finalization gets a separate bounded window after an execution deadline or
	// shutdown signal, so cancellation does not suppress cleanup evidence.
	finalCtx, finalCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer finalCancel()
	if err := c.deliver(finalCtx, saved); err != nil {
		return false, err
	}
	if !result.CleanupOK {
		log.Printf("worker job %s cleanup unverified; retrying recovery after poll", lease.Job.ID)
	}
	return result.CleanupOK, nil
}

type remoteSink struct {
	client              *Client
	ctx                 context.Context
	epoch, jobID, lease string
	cancel              context.CancelCauseFunc
	mu                  sync.Mutex
}

func (s *remoteSink) Log(stream, text string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.client.json(s.ctx, http.MethodPost, "/jobs/"+s.jobID+"/logs", s.epoch, s.lease, protocol.Log{Stream: stream, Data: []byte(text)}, nil)
	if err != nil {
		s.cancel(err)
	}
	return err
}
func (s *remoteSink) Stage(state model.State) error {
	_, err := s.client.json(s.ctx, http.MethodPost, "/jobs/"+s.jobID+"/stage", s.epoch, s.lease, protocol.Stage{State: state}, nil)
	if err != nil {
		s.cancel(err)
	}
	return err
}

// admissionStatus is an observation, never an authority for clearing quarantine.
type admissionStatus struct {
	State     string    `json:"state"`
	Reason    string    `json:"reason"`
	CheckedAt time.Time `json:"checked_at"`
}

func (c *Client) saveAdmissionStatus(admissionErr error) error {
	status := admissionStatus{State: "admitting", CheckedAt: time.Now().UTC()}
	if admissionErr != nil {
		status.State = "not_admitting"
		status.Reason = admissionErr.Error()
	}
	data, err := json.Marshal(status)
	if err != nil {
		return err
	}
	if err := c.saveState("admission-status.json", data); err != nil {
		return fmt.Errorf("write admission status: %w", err)
	}
	return nil
}

// legacyPending is the one completion file of a worker before lanes.
const legacyPending = "pending.json"

// pendingName is the completion file of jobID: one per lane's job.
func pendingName(jobID string) string { return "pending-" + jobID + ".json" }

func (c *Client) savePending(value pending) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data) > 64<<20 {
		return errors.New("completion exceeds 64 MiB")
	}
	return c.saveState(pendingName(value.Lease.Job.ID), data)
}

func (c *Client) saveState(name string, data []byte) error {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	tmp := name + "-" + hex.EncodeToString(nonce[:]) + ".tmp"
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
	if err := c.root.Rename(tmp, name); err != nil {
		return err
	}
	dir, err := c.root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// loadPendings reads every saved completion: one per job, and a worker's
// from before lanes, sorted by file name.
func (c *Client) loadPendings() ([]pending, error) {
	dir, err := c.root.Open(".")
	if err != nil {
		return nil, err
	}
	names, err := dir.Readdirnames(-1)
	dir.Close()
	if err != nil {
		return nil, err
	}
	slices.Sort(names)
	var values []pending
	for _, name := range names {
		if name != legacyPending && !(strings.HasPrefix(name, "pending-") && strings.HasSuffix(name, ".json")) {
			continue
		}
		value, err := c.loadPending(name)
		if err != nil {
			return nil, err
		}
		if name != legacyPending && name != pendingName(value.Lease.Job.ID) {
			return nil, errors.New("pending completion file names another job")
		}
		values = append(values, value)
	}
	return values, nil
}

func (c *Client) loadPending(name string) (pending, error) {
	var value pending
	info, err := c.root.Lstat(name)
	if err != nil {
		return value, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 64<<20 {
		return value, errors.New("unsafe pending completion file")
	}
	f, err := c.root.Open(name)
	if err != nil {
		return value, err
	}
	defer f.Close()
	dec := json.NewDecoder(io.LimitReader(f, (64<<20)+1))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&value); err != nil {
		return value, err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return value, errors.New("trailing completion JSON")
	}
	if !safeID(value.Lease.Job.ID) || value.Lease.Token == "" || value.Epoch == "" {
		return value, errors.New("invalid pending completion")
	}
	value.file = name
	return value, nil
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
		// A non-nil body with ContentLength == 0 means unknown length to
		// net/http, which otherwise sends empty files as chunked uploads.
		if artifact.SizeBytes == 0 {
			req.Body = http.NoBody
		}
		resp, err := c.http.Do(req)
		f.Close()
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusGone {
			return c.ackPending(saved)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return statusError(resp)
		}
	}
	if saved.Seal == nil {
		// A pending completion from before seals: the lease was never
		// resolved against the registry here, so the seal carries no
		// resolution or tree and supports no success receipt.
		seal, err := c.seal(pending{Lease: saved.Lease, Result: saved.Result})
		if err != nil {
			return err
		}
		saved.Seal = &seal
	}
	status, err := c.json(ctx, http.MethodPost, "/jobs/"+jobID+"/complete", saved.Epoch, saved.Lease.Token, protocol.Completion{Result: saved.Result, Seal: *saved.Seal}, nil)
	if err != nil && status != http.StatusGone {
		return err
	}
	return c.ackPending(saved)
}

// ackPending removes an acknowledged completion's export and its file.
func (c *Client) ackPending(saved pending) error {
	if err := c.engine.RemoveExport(saved.Lease.Job.ID); err != nil {
		return err
	}
	name := saved.file
	if name == "" {
		name = pendingName(saved.Lease.Job.ID)
	}
	if err := c.root.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

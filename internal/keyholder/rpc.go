package keyholder

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/jerryfane/macserve/internal/githubapi"
	"github.com/jerryfane/macserve/internal/peercred"
)

// RPC bounds: a receipt request carries the job record and two worker
// results; a response carries at most one receipt or full manifest.
const (
	maxRequestBytes  = 32 << 20
	maxResponseBytes = 80 << 20
)

// Operations.
const (
	opToken       = "token"
	opSeal        = "seal"
	opManifest    = "manifest"
	opReceiptJobs = "receipt_jobs"
	opForget      = "forget"
)

// request is one controller → keyholder call, a single JSON line on a fresh
// connection.
type request struct {
	Op     string       `json:"op"`
	Repo   string       `json:"repo,omitempty"`
	Seal   *SealRequest `json:"seal,omitempty"`
	JobID  string       `json:"job_id,omitempty"`
	Digest string       `json:"digest,omitempty"`
	JobIDs []string     `json:"job_ids,omitempty"`
}

// response is the keyholder's single JSON line.
type response struct {
	OK       bool                         `json:"ok"`
	Error    string                       `json:"error,omitempty"`
	Refused  bool                         `json:"refused,omitempty"`
	NotFound bool                         `json:"not_found,omitempty"`
	Token    *githubapi.InstallationToken `json:"token,omitempty"`
	Receipt  json.RawMessage              `json:"receipt,omitempty"`
	Manifest json.RawMessage              `json:"manifest,omitempty"`
	JobIDs   []string                     `json:"job_ids,omitempty"`
}

// service is the Engine surface the server exposes.
type service interface {
	Token(context.Context, string) (githubapi.InstallationToken, error)
	Seal(context.Context, SealRequest) (json.RawMessage, error)
	Manifest(context.Context, string, string) (json.RawMessage, error)
	ReceiptJobs(context.Context) ([]string, error)
	Forget(context.Context, []string) error
}

// Server serves keyholder requests on a Unix socket to exactly one peer
// UID, the controller's.
type Server struct {
	Engine        service
	ControllerUID uint32
	Logger        *log.Logger
	// PeerUID returns a connection's kernel peer UID; nil uses peercred.
	PeerUID func(net.Conn) (uint32, error)
}

// Listen binds socket as the current (keyholder) user, removing only a
// stale socket this user owns, and grants the RPC group read/write (0660).
// The directory, owned by the keyholder and the RPC group 0750, is the
// access boundary; the peer UID check is the authority.
func Listen(socket string, rpcGID uint32) (net.Listener, error) {
	if info, err := os.Lstat(socket); err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if info.Mode()&os.ModeSocket == 0 || !ok || stat.Uid != uint32(os.Getuid()) {
			return nil, fmt.Errorf("%s exists and is not this account's socket", socket)
		}
		if err := os.Remove(socket); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		return nil, err
	}
	listener.SetUnlinkOnClose(true)
	if err := errors.Join(os.Chown(socket, -1, int(rpcGID)), os.Chmod(socket, 0o660)); err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}

// Serve accepts connections until ctx ends. A connection from any UID other
// than ControllerUID is closed unread.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handle(ctx, conn)
		}()
	}
}

func (s *Server) logf(format string, args ...any) {
	if s.Logger != nil {
		s.Logger.Printf(format, args...)
	}
}

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	peer := s.PeerUID
	if peer == nil {
		peer = peercred.UID
	}
	uid, err := peer(conn)
	if err != nil || uid != s.ControllerUID {
		s.logf("keyholder: refused connection from peer UID %d: %v", uid, err)
		return
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))
	line, err := readLine(bufio.NewReaderSize(conn, 64<<10), maxRequestBytes)
	if err != nil {
		s.logf("keyholder: request: %v", err)
		return
	}
	var req request
	if err := decodeStrict(line, &req); err != nil {
		writeResponse(conn, response{Error: "malformed request"})
		return
	}
	resp := s.dispatch(ctx, req)
	if !resp.OK {
		s.logf("keyholder: %s: %s", req.Op, resp.Error)
	}
	_ = writeResponse(conn, resp)
}

func (s *Server) dispatch(ctx context.Context, req request) response {
	var resp response
	var err error
	switch req.Op {
	case opToken:
		var token githubapi.InstallationToken
		if token, err = s.Engine.Token(ctx, req.Repo); err == nil {
			resp.Token = &token
		}
	case opSeal:
		if req.Seal == nil {
			err = refusal("seal request missing")
			break
		}
		resp.Receipt, err = s.Engine.Seal(ctx, *req.Seal)
	case opManifest:
		resp.Manifest, err = s.Engine.Manifest(ctx, req.JobID, req.Digest)
	case opReceiptJobs:
		resp.JobIDs, err = s.Engine.ReceiptJobs(ctx)
	case opForget:
		err = s.Engine.Forget(ctx, req.JobIDs)
	default:
		err = refusal("unknown operation")
	}
	if err != nil {
		var refused *RefusalError
		resp = response{Error: err.Error(), Refused: errors.As(err, &refused), NotFound: errors.Is(err, os.ErrNotExist)}
		if resp.Refused {
			resp.Error = refused.Reason
		}
		return resp
	}
	resp.OK = true
	return resp
}

func writeResponse(w io.Writer, resp response) error {
	line, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	_, err = w.Write(append(line, '\n'))
	return err
}

// readLine reads one newline-terminated line of at most max bytes.
func readLine(r *bufio.Reader, max int) ([]byte, error) {
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > max {
			return nil, errors.New("line too long")
		}
		if err == nil {
			return line[:len(line)-1], nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return nil, err
		}
	}
}

// Client calls the keyholder over its Unix socket. Every connection must be
// served by KeyholderUID (peer credentials), so a socket another account
// managed to bind is never sent a receipt request or believed for a token.
type Client struct {
	Socket       string
	KeyholderUID uint32
	// Timeout bounds one call; zero means 2 minutes.
	Timeout time.Duration
	// PeerUID returns a connection's kernel peer UID; nil uses peercred.
	PeerUID func(net.Conn) (uint32, error)
}

func (c *Client) call(ctx context.Context, req request) (response, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", c.Socket)
	if err != nil {
		return response{}, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	peer := c.PeerUID
	if peer == nil {
		peer = peercred.UID
	}
	uid, err := peer(conn)
	if err != nil {
		return response{}, err
	}
	if uid != c.KeyholderUID {
		return response{}, fmt.Errorf("keyholder socket peer UID %d is not the keyholder", uid)
	}
	line, err := json.Marshal(req)
	if err != nil {
		return response{}, err
	}
	if len(line) >= maxRequestBytes {
		return response{}, errors.New("keyholder request too large")
	}
	if _, err := conn.Write(append(line, '\n')); err != nil {
		return response{}, err
	}
	raw, err := readLine(bufio.NewReaderSize(conn, 64<<10), maxResponseBytes)
	if err != nil {
		if ctx.Err() != nil {
			return response{}, ctx.Err()
		}
		return response{}, fmt.Errorf("keyholder response: %w", err)
	}
	var resp response
	if err := decodeStrict(raw, &resp); err != nil {
		return response{}, fmt.Errorf("keyholder response: %w", err)
	}
	if !resp.OK {
		if resp.Error == "" {
			resp.Error = "unspecified"
		}
		switch {
		case resp.Refused:
			return resp, &RefusalError{Reason: resp.Error}
		case resp.NotFound:
			return resp, fmt.Errorf("keyholder: %s: %w", resp.Error, os.ErrNotExist)
		}
		return resp, fmt.Errorf("keyholder: %s", resp.Error)
	}
	return resp, nil
}

// Token returns a short-lived installation token for repo; it satisfies
// githubapi.TokenSource.
func (c *Client) Token(ctx context.Context, repo string) (githubapi.InstallationToken, error) {
	resp, err := c.call(ctx, request{Op: opToken, Repo: repo})
	if err != nil {
		return githubapi.InstallationToken{}, err
	}
	if resp.Token == nil {
		return githubapi.InstallationToken{}, errors.New("keyholder token response lacks a token")
	}
	return *resp.Token, nil
}

// Seal asks the keyholder to verify and sign a job's receipt.
func (c *Client) Seal(ctx context.Context, req SealRequest) (json.RawMessage, error) {
	resp, err := c.call(ctx, request{Op: opSeal, Seal: &req})
	if err != nil {
		return nil, err
	}
	if len(resp.Receipt) == 0 {
		return nil, errors.New("keyholder seal response lacks a receipt")
	}
	return resp.Receipt, nil
}

// Manifest returns a job's immutable full receipt manifest.
func (c *Client) Manifest(ctx context.Context, jobID, digest string) (json.RawMessage, error) {
	resp, err := c.call(ctx, request{Op: opManifest, JobID: jobID, Digest: digest})
	if err != nil {
		return nil, err
	}
	return resp.Manifest, nil
}

// Prune drops the keyholder's receipt manifests and release provenance of
// every job retained reports false for.
func (c *Client) Prune(ctx context.Context, retained func(string) (bool, error)) error {
	resp, err := c.call(ctx, request{Op: opReceiptJobs})
	if err != nil {
		return err
	}
	var drop []string
	for _, id := range resp.JobIDs {
		keep, err := retained(id)
		if err != nil {
			return err
		}
		if !keep {
			drop = append(drop, id)
		}
	}
	if len(drop) == 0 {
		return nil
	}
	_, err = c.call(ctx, request{Op: opForget, JobIDs: drop})
	return err
}

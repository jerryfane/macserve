package setup

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/jerryfane/macserve/internal/peercred"
)

// Verb is one request the root helper serves. The set is fixed; nothing
// else, and no path or argv, crosses from the wizard to root.
type Verb string

const (
	// VerbStatus returns the ledger.
	VerbStatus Verb = "status"
	// VerbPreflight records preflight with the generated deploy.env.
	VerbPreflight Verb = "preflight"
	// VerbInstall runs deploy-install with the recorded deploy.env.
	VerbInstall Verb = "install"
	// VerbGitHub detects the connect-github result and records the step.
	VerbGitHub Verb = "github"
	// VerbTools runs the Xcode system steps.
	VerbTools Verb = "tools"
	// VerbFDACheck checks Full Disk Access from a transient launchd job.
	VerbFDACheck Verb = "fda-check"
	// VerbJobLogin checks the job GUI session and the console owner.
	VerbJobLogin Verb = "job-login-check"
	// VerbOwnerActions re-checks both owner actions and records the step.
	VerbOwnerActions Verb = "owner-actions"
)

// Verbs is the helper's grammar.
var Verbs = []Verb{VerbStatus, VerbPreflight, VerbInstall, VerbGitHub, VerbTools, VerbFDACheck, VerbJobLogin, VerbOwnerActions}

// MaxRequest bounds one request line (deploy.env is at most 64 KiB).
const MaxRequest = 128 << 10

// Request is one line from the wizard. Env is the generated deploy.env and
// is accepted only with VerbPreflight.
type Request struct {
	Verb Verb   `json:"verb"`
	Env  string `json:"env,omitempty"`
}

// Response is one line from the helper. Ledger is the canonical ledger
// encoding after the verb; Done reports that the verb's detection or step
// succeeded; Detail explains what is missing.
type Response struct {
	Error  string `json:"error,omitempty"`
	Ledger []byte `json:"ledger,omitempty"`
	Done   bool   `json:"done,omitempty"`
	Detail string `json:"detail,omitempty"`
}

func validVerb(v Verb) bool {
	for _, known := range Verbs {
		if v == known {
			return true
		}
	}
	return false
}

// DecodeRequest parses one request line strictly: known fields only, one
// value in canonical encoding, a verb of the grammar, and Env only with
// preflight.
func DecodeRequest(line []byte) (Request, error) {
	var r Request
	if len(line) == 0 || len(line) > MaxRequest {
		return r, errors.New("empty or oversized request")
	}
	d := json.NewDecoder(bytes.NewReader(line))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return r, fmt.Errorf("malformed request: %w", err)
	}
	if d.Decode(new(any)) != io.EOF {
		return r, errors.New("malformed request: trailing data")
	}
	if !validVerb(r.Verb) {
		return r, fmt.Errorf("unknown verb %q", r.Verb)
	}
	if (r.Env != "") != (r.Verb == VerbPreflight) {
		return r, fmt.Errorf("verb %s: env is accepted with preflight only, and required there", r.Verb)
	}
	// Only the wizard's own encoding: no case-variant or duplicate keys.
	if canonical, err := json.Marshal(r); err != nil || !bytes.Equal(canonical, line) {
		return r, errors.New("malformed request: not in canonical form")
	}
	return r, nil
}

// readLine reads one newline-terminated line of at most max bytes.
func readLine(r *bufio.Reader, max int) ([]byte, error) {
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > max+1 {
			return nil, errors.New("request too long")
		}
		if err == nil {
			return bytes.TrimSuffix(line, []byte("\n")), nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			if len(line) > 0 && errors.Is(err, io.EOF) {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
	}
}

// Client is the wizard's connection to the root helper.
type Client struct {
	conn net.Conn
	in   *bufio.Reader
}

// Dial connects to the helper socket in dir. dir must be a directory owned
// by rootUID without group or other write (so only root could have made
// the socket), and the peer must run as rootUID.
func Dial(dir string, rootUID uint32) (*Client, error) {
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	uid, _, _, ok := statOwner(info)
	if !ok || !info.IsDir() || uid != rootUID || info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("%s is not a root-owned directory without group or other write", dir)
	}
	conn, err := net.DialTimeout("unix", filepath.Join(dir, SocketName), 5*time.Second)
	if err != nil {
		return nil, err
	}
	peer, err := peercred.UID(conn)
	if err != nil || peer != rootUID {
		conn.Close()
		return nil, fmt.Errorf("the setup helper socket is not served by root (peer uid %d, %v)", peer, err)
	}
	return &Client{conn: conn, in: bufio.NewReaderSize(conn, 64<<10)}, nil
}

// Close ends the session; the helper exits.
func (c *Client) Close() error { return c.conn.Close() }

// Call sends one request and returns the helper's response. A response
// error is returned as an error, with the response.
func (c *Client) Call(r Request) (Response, error) {
	var resp Response
	line, err := json.Marshal(r)
	if err != nil {
		return resp, err
	}
	if _, err := c.conn.Write(append(line, '\n')); err != nil {
		return resp, fmt.Errorf("root helper: %w", err)
	}
	reply, err := readLine(c.in, MaxLedger*2)
	if err != nil {
		return resp, fmt.Errorf("root helper ended the session: %w", err)
	}
	d := json.NewDecoder(bytes.NewReader(reply))
	d.DisallowUnknownFields()
	if err := d.Decode(&resp); err != nil {
		return resp, fmt.Errorf("root helper: malformed response: %w", err)
	}
	if resp.Error != "" {
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}

// DecodedLedger decodes the response ledger, if any.
func (r Response) DecodedLedger() (*Ledger, error) {
	if len(r.Ledger) == 0 {
		return nil, nil
	}
	return DecodeLedger(r.Ledger)
}

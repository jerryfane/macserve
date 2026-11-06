package onboarding

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/receipt"
)

// KeychainService is the owner's login keychain item that holds the API
// token (setup saves it there, decision D11).
const KeychainService = "macserve API token"

// Pins is the public /Library/macserve/config/deployment-pins.json.
type Pins struct {
	ReceiptKeyID     string `json:"receipt_key_id"`
	ReceiptPublicKey string `json:"receipt_public_key"`
	TLSCertSHA256    string `json:"tls_certificate_sha256"`
}

// BuildRequest is what `macserve build` submits.
type BuildRequest struct {
	Repo    string
	SHA     string
	Profile string // profile or template ID; empty picks the only match
	// RepoConfig is the local .macserve.json, if any; it is only parsed
	// (never run) so a broken file fails before submission. The worker
	// reads the file from the commit itself.
	RepoConfig []byte
}

// Build talks to the local macserve API. Endpoint is https://IP:PORT.
type Build struct {
	Endpoint string
	Pins     Pins
	// Token returns the API token (the owner's keychain outside tests). It
	// is sent only in the Authorization header and never printed.
	Token func(ctx context.Context) (string, error)
	// HTTP is the client; nil uses one pinned to Pins.TLSCertSHA256.
	HTTP  *http.Client
	Out   io.Writer
	Poll  time.Duration
	Sleep func(ctx context.Context, d time.Duration) error
	// NewKey returns the Idempotency-Key; nil uses 16 random bytes.
	NewKey func() (string, error)

	token string
}

var (
	repoName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9_.-]+$`)
	shaHex   = regexp.MustCompile(`^[0-9a-f]{40}$`)
	jobID    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
)

// ErrInterrupted means following stopped before the job finished; the job
// keeps running.
var ErrInterrupted = errors.New("stopped following; the job keeps running")

// APIError is a non-2xx API reply: its status and the API's error code.
type APIError struct {
	Status int
	Code   string
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("macserve API: %d %s", e.Status, e.Code)
	}
	return fmt.Sprintf("macserve API: %d", e.Status)
}

// ErrPinMismatch means the API answered with a certificate other than the
// installed controller's: possibly someone in the middle.
var ErrPinMismatch = errors.New("the API's TLS certificate is not this Mac's installed controller certificate (deployment-pins.json); possibly an interception, nothing was sent")

// PinnedClient trusts exactly the controller certificate whose DER sha256
// is fingerprint, over TLS 1.3.
func PinnedClient(fingerprint string) (*http.Client, error) {
	want, err := hex.DecodeString(fingerprint)
	if err != nil || len(want) != sha256.Size {
		return nil, errors.New("deployment-pins.json has no valid tls_certificate_sha256")
	}
	verify := func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("no controller certificate")
		}
		got := sha256.Sum256(cs.PeerCertificates[0].Raw)
		if subtle.ConstantTimeCompare(got[:], want) != 1 {
			return ErrPinMismatch
		}
		return nil
	}
	transport := &http.Transport{
		// Verification is the pin above, not a CA chain or a name.
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, VerifyConnection: verify},
		Proxy:             nil,
		ForceAttemptHTTP2: true,
	}
	return &http.Client{Transport: transport, Timeout: 60 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

func (b *Build) client() (*http.Client, error) {
	if b.HTTP != nil {
		return b.HTTP, nil
	}
	c, err := PinnedClient(b.Pins.TLSCertSHA256)
	if err != nil {
		return nil, err
	}
	b.HTTP = c
	return c, nil
}

func (b *Build) say(format string, args ...any) { fmt.Fprintf(b.Out, format+"\n", args...) }

// do sends one request. Error replies never echo the token or the body.
func (b *Build) do(ctx context.Context, method, path string, header map[string]string, input any, output any) error {
	c, err := b.client()
	if err != nil {
		return err
	}
	if b.token == "" {
		if b.token, err = b.Token(ctx); err != nil {
			return fmt.Errorf("cannot read the API token from your login keychain (%q)", KeychainService)
		}
		if b.token == "" || strings.ContainsAny(b.token, " \t\r\n") {
			return fmt.Errorf("the keychain item %q is not an API token", KeychainService)
		}
	}
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, b.Endpoint+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+b.token)
	req.Header.Set("Accept", "application/json")
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, ErrPinMismatch) {
			return ErrPinMismatch
		}
		return errors.New("cannot reach the macserve API at " + b.Endpoint)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var reply struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.Unmarshal(data, &reply)
		code := reply.Error.Code
		if !regexp.MustCompile(`^[a-z_]{1,64}$`).MatchString(code) {
			code = ""
		}
		return &APIError{Status: resp.StatusCode, Code: code}
	}
	if raw, ok := output.(*[]byte); ok {
		*raw = data
		return nil
	}
	if output != nil {
		if err := json.Unmarshal(data, output); err != nil {
			return errors.New("invalid macserve API reply")
		}
	}
	return nil
}

type capability struct {
	ID      string                `json:"id"`
	Repo    string                `json:"repo"`
	Owners  []string              `json:"owners"`
	Kind    model.Kind            `json:"kind"`
	Xcode   model.Xcode           `json:"xcode"`
	Flutter *model.FlutterRequest `json:"flutter,omitempty"`
}

type capabilities struct {
	Profiles  []capability `json:"profiles"`
	Templates []capability `json:"templates"`
	BlockedBy []string     `json:"blocked_by"`
}

// choose picks the profile or template for r from the capabilities.
func choose(c capabilities, r BuildRequest) (capability, error) {
	owner, _, _ := strings.Cut(r.Repo, "/")
	var matches []capability
	for _, p := range c.Profiles {
		if strings.EqualFold(p.Repo, r.Repo) && (r.Profile == "" || r.Profile == p.ID) {
			matches = append(matches, p)
		}
	}
	for _, t := range c.Templates {
		for _, o := range t.Owners {
			if strings.EqualFold(o, owner) && (r.Profile == "" || r.Profile == t.ID) {
				matches = append(matches, t)
				break
			}
		}
	}
	switch {
	case len(matches) == 1:
		return matches[0], nil
	case len(matches) == 0 && r.Profile != "":
		return capability{}, fmt.Errorf("no profile or template %q admits %s for your token", r.Profile, r.Repo)
	case len(matches) == 0:
		return capability{}, fmt.Errorf("no profile or template admits %s for your token", r.Repo)
	}
	var ids []string
	for _, m := range matches {
		ids = append(ids, m.ID)
	}
	return capability{}, fmt.Errorf("several profiles or templates admit %s (%s); choose one with --profile", r.Repo, strings.Join(ids, ", "))
}

func randomKey() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// Submit validates r, reads the capabilities and submits one job with a
// fresh Idempotency-Key. It returns the job ID and the exact request sent,
// which Follow binds the receipt to.
func (b *Build) Submit(ctx context.Context, r BuildRequest) (string, model.Request, error) {
	if !repoName.MatchString(r.Repo) {
		return "", model.Request{}, errors.New("--repo needs OWNER/NAME")
	}
	if !shaHex.MatchString(r.SHA) {
		return "", model.Request{}, errors.New("--sha needs a full 40-character lowercase commit SHA")
	}
	if r.RepoConfig != nil {
		if _, err := profiles.ParseRepoConfig(r.RepoConfig); err != nil {
			return "", model.Request{}, fmt.Errorf("%s is invalid: %v", profiles.RepoConfigFile, err)
		}
	}
	var caps capabilities
	if err := b.do(ctx, http.MethodGet, "/v1/capabilities", nil, nil, &caps); err != nil {
		return "", model.Request{}, err
	}
	chosen, err := choose(caps, r)
	if err != nil {
		return "", model.Request{}, err
	}
	if len(caps.BlockedBy) > 0 {
		b.say("macserve is not admitting jobs now (%s); the job waits in the queue.", strings.Join(caps.BlockedBy, ", "))
	}
	newKey := b.NewKey
	if newKey == nil {
		newKey = randomKey
	}
	key, err := newKey()
	if err != nil {
		return "", model.Request{}, err
	}
	request := model.Request{Repo: r.Repo, SHA: r.SHA, Kind: chosen.Kind, Profile: chosen.ID, Xcode: chosen.Xcode, Flutter: chosen.Flutter}
	var job struct {
		ID    string      `json:"id"`
		State model.State `json:"state"`
	}
	if err := b.do(ctx, http.MethodPost, "/v1/jobs", map[string]string{"Idempotency-Key": key}, request, &job); err != nil {
		return "", model.Request{}, err
	}
	if !jobID.MatchString(job.ID) {
		return "", model.Request{}, errors.New("invalid macserve API reply")
	}
	b.say("Submitted %s %s at %s with %s (Xcode %s): job %s.", request.Kind, r.Repo, r.SHA[:12], chosen.ID, chosen.Xcode.Version, job.ID)
	return job.ID, request, nil
}

// Result is a finished job. State, Complete and ExitCode come from the
// verified receipt when Receipt is set, and from the unsigned status
// otherwise.
type Result struct {
	ID       string
	State    model.State
	Receipt  bool // a receipt verified and matched the job
	Complete bool
	ExitCode *int
}

// Succeeded reports a verified, complete, successful receipt with exit
// code 0: the only result `macserve build` exits 0 for.
func (r Result) Succeeded() bool {
	return r.Receipt && r.State == model.Succeeded && r.Complete && r.ExitCode != nil && *r.ExitCode == 0
}

type jobStatus struct {
	ID        string         `json:"id"`
	State     model.State    `json:"state"`
	Repo      string         `json:"repo"`
	SHA       string         `json:"sha"`
	ExitCode  *int           `json:"exit_code"`
	Requested *model.Request `json:"requested"`
}

type logPage struct {
	Records []model.LogRecord `json:"records"`
	Next    string            `json:"next_cursor"`
	EOF     bool              `json:"eof"`
}

func (b *Build) sleep(ctx context.Context) error {
	if b.Sleep != nil {
		return b.Sleep(ctx, b.Poll)
	}
	t := time.NewTimer(b.Poll)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// ErrReceiptMismatch means a signed receipt is not the receipt of the job
// this command submitted or follows (another job's, or another request's).
var ErrReceiptMismatch = errors.New("receipt does not match the submitted job")

// Follow prints the job's logs until it is terminal and its logs reach eof,
// then verifies the receipt and binds it to job id and to the request
// Submit sent (want). With want nil (--follow of an earlier job) the
// receipt must match the request the API reports for id. A cancelled ctx
// returns ErrInterrupted; the job is not cancelled.
func (b *Build) Follow(ctx context.Context, id string, want *model.Request) (Result, error) {
	if !jobID.MatchString(id) {
		return Result{}, errors.New("invalid job ID")
	}
	base := "/v1/jobs/" + url.PathEscape(id)
	var cursor string
	var last model.State
	for {
		var status jobStatus
		if err := b.do(ctx, http.MethodGet, base, nil, nil, &status); err != nil {
			return Result{ID: id}, interrupted(ctx, err)
		}
		if status.ID != id {
			return Result{ID: id}, errors.New("the macserve API answered for another job")
		}
		if status.State != last {
			b.say("job %s: %s", id, status.State)
			last = status.State
		}
		eof := false
		for {
			var page logPage
			q := "?cursor=" + url.QueryEscape(cursor)
			if err := b.do(ctx, http.MethodGet, base+"/logs"+q, nil, nil, &page); err != nil {
				return Result{ID: id}, interrupted(ctx, err)
			}
			for _, r := range page.Records {
				b.say("%s", strings.TrimRight(r.Text, "\n"))
			}
			if page.Next != "" {
				cursor = page.Next
			}
			eof = page.EOF
			if len(page.Records) == 0 || eof {
				break
			}
		}
		if status.State.Terminal() && eof {
			if want == nil {
				if status.Requested == nil {
					return Result{ID: id}, errors.New("the macserve API did not report the job's request")
				}
				want = status.Requested
			}
			return b.finish(ctx, base, id, *want, status)
		}
		if err := b.sleep(ctx); err != nil {
			return Result{ID: id}, interrupted(ctx, err)
		}
	}
}

func interrupted(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ErrInterrupted
	}
	return err
}

// finish verifies the terminal job's receipt. A job the status reports as
// succeeded must have one; any other terminal job's receipt is checked if
// the API has one, and its absence leaves the unsigned status.
func (b *Build) finish(ctx context.Context, base, id string, want model.Request, status jobStatus) (Result, error) {
	res := Result{ID: id, State: status.State, ExitCode: status.ExitCode}
	var raw []byte
	if err := b.do(ctx, http.MethodGet, base+"/receipt", nil, nil, &raw); err != nil {
		var api *APIError
		if status.State != model.Succeeded && errors.As(err, &api) {
			return res, nil
		}
		return res, interrupted(ctx, err)
	}
	key, err := base64.StdEncoding.Strict().DecodeString(b.Pins.ReceiptPublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize || b.Pins.ReceiptKeyID == "" {
		return res, errors.New("deployment-pins.json has no valid receipt key")
	}
	p, err := receipt.Verify(raw, map[string]ed25519.PublicKey{b.Pins.ReceiptKeyID: key})
	if err != nil {
		return res, errors.New("the job's receipt does not verify against deployment-pins.json")
	}
	if p.JobID != id || !sameRequest(p.Request, want) {
		return res, ErrReceiptMismatch
	}
	return Result{ID: id, State: p.State, Receipt: true, Complete: p.Complete, ExitCode: p.ExitCode}, nil
}

// sameRequest compares the receipt's request with the one sent: repository
// (GitHub names are case-insensitive), commit, kind, profile or template
// and Xcode pins.
func sameRequest(got, want model.Request) bool {
	return strings.EqualFold(got.Repo, want.Repo) && got.SHA == want.SHA && got.Kind == want.Kind && got.Profile == want.Profile && got.Xcode == want.Xcode
}

// LocalRepo reads the repository at dir without running git or anything in
// the repository: the GitHub OWNER/NAME of remote "origin", the commit HEAD
// names and the bytes of .macserve.json (nil if absent).
func LocalRepo(dir string) (repo, sha string, config []byte, err error) {
	gitDir := filepath.Join(dir, ".git")
	if data, err := readSmall(gitDir, 4096); err == nil {
		// A worktree or submodule: ".git" is a file naming the git dir.
		line, ok := strings.CutPrefix(strings.TrimSpace(string(data)), "gitdir: ")
		if !ok {
			return "", "", nil, errors.New(".git is not a git directory")
		}
		if !filepath.IsAbs(line) {
			line = filepath.Join(dir, line)
		}
		gitDir = line
	}
	common := gitDir
	if data, err := readSmall(filepath.Join(gitDir, "commondir"), 4096); err == nil {
		c := strings.TrimSpace(string(data))
		if !filepath.IsAbs(c) {
			c = filepath.Join(gitDir, c)
		}
		common = c
	}
	head, err := readSmall(filepath.Join(gitDir, "HEAD"), 4096)
	if err != nil {
		return "", "", nil, errors.New("not at the root of a git repository; pass --repo and --sha")
	}
	sha = strings.TrimSpace(string(head))
	if ref, ok := strings.CutPrefix(sha, "ref: "); ok {
		if sha, err = resolveRef(gitDir, common, ref); err != nil {
			return "", "", nil, err
		}
	}
	if !shaHex.MatchString(sha) {
		return "", "", nil, errors.New("cannot read the commit HEAD names; pass --sha")
	}
	if cfg, err := readSmall(filepath.Join(common, "config"), 1<<20); err == nil {
		repo = originRepo(string(cfg))
	}
	config, err = readSmall(filepath.Join(dir, profiles.RepoConfigFile), profiles.MaxRepoConfigBytes+1)
	if errors.Is(err, fs.ErrNotExist) {
		config, err = nil, nil
	}
	return repo, sha, config, err
}

func readSmall(path string, max int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a file", filepath.Base(path))
	}
	if info.Size() > max {
		return nil, fmt.Errorf("%s is too large", filepath.Base(path))
	}
	return os.ReadFile(path)
}

var refName = regexp.MustCompile(`^refs/[A-Za-z0-9._/-]+$`)

func resolveRef(gitDir, common, ref string) (string, error) {
	if !refName.MatchString(ref) || strings.Contains(ref, "..") {
		return "", errors.New("HEAD names an invalid ref")
	}
	for _, d := range []string{gitDir, common} {
		if data, err := readSmall(filepath.Join(d, filepath.FromSlash(ref)), 4096); err == nil {
			return strings.TrimSpace(string(data)), nil
		}
	}
	packed, err := readSmall(filepath.Join(common, "packed-refs"), 64<<20)
	if err != nil {
		return "", errors.New("HEAD has no commit yet; commit, push and pass --sha")
	}
	for _, line := range strings.Split(string(packed), "\n") {
		if s, name, ok := strings.Cut(line, " "); ok && name == ref {
			return s, nil
		}
	}
	return "", errors.New("cannot resolve HEAD; pass --sha")
}

// originRepo returns OWNER/NAME of a github.com url of remote "origin".
func originRepo(cfg string) string {
	in := false
	for _, line := range strings.Split(cfg, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			in = line == `[remote "origin"]`
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !in || !ok || strings.TrimSpace(key) != "url" {
			continue
		}
		u := strings.TrimSpace(value)
		for _, prefix := range []string{"git@github.com:", "ssh://git@github.com/", "https://github.com/"} {
			if rest, ok := strings.CutPrefix(u, prefix); ok {
				rest = strings.TrimSuffix(strings.TrimSuffix(rest, "/"), ".git")
				if repoName.MatchString(rest) {
					return rest
				}
			}
		}
	}
	return ""
}

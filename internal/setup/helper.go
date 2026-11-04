package setup

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/jerryfane/macserve/internal/deploy"
	"github.com/jerryfane/macserve/internal/peercred"
)

// The helper socket. The directory is root-owned 0711: the owner can reach
// the socket by its fixed name but cannot list, create or replace entries.
// The socket itself is owner-owned 0600, so only the owner and root can
// connect, and the helper then checks the peer UID.
const (
	SocketDir  = "/private/var/db/macserve-setup"
	SocketName = "helper.sock"
)

// IdleTimeout ends the helper when no connection or request arrives.
const IdleTimeout = 15 * time.Minute

// Owner is the user who ran `macserve setup`: SUDO_UID, also the console
// user, and the ledger owner. GID and Home are the account's primary group
// and home directory, for the one step that runs as the owner.
type Owner struct {
	UID, GID uint32
	Name     string
	Home     string
}

// Cmd is one fixed command the helper runs: argv, environment and
// timeout. Commands run with cwd "/", no stdin and output to the terminal.
// Credential, if set, is the identity the command runs as instead of root.
type Cmd struct {
	Argv       []string
	Env        []string
	Timeout    time.Duration
	Credential *syscall.Credential
}

// FixedPath is the PATH of every command the helper runs.
const FixedPath = "PATH=/usr/bin:/bin:/usr/sbin:/sbin"

// Helper is the root side of setup. Every field that touches the host is
// injected; RootHelper builds the production one.
type Helper struct {
	Store Store
	// Root is deploy.Prefix (/Library/macserve).
	Root  string
	Owner Owner
	// SHA256 is the digest the wizard expects of the macserve binary that
	// install stages and deploy-install verifies.
	SHA256 string
	// Executable is the running macserve binary, copied for install.
	Executable string
	// Assets are the deploy-install assets at their relative paths.
	Assets map[string][]byte
	// Install is deploy.Install.
	Install func(deploy.Options, io.Writer, io.Writer) error
	// Exec runs a fixed command with output to Terminal.
	Exec func(context.Context, Cmd) error
	// Probe runs a fixed command, discarding output; nil error is success.
	Probe func(context.Context, Cmd) error
	// ConsoleUID reads the /dev/console owner.
	ConsoleUID func() (uint32, error)
	// ToolCheck applies the job toolchain policy to an executable.
	ToolCheck func(path string, jobUID uint32) error
	Boot      func() (Boot, error)
	Now       func() time.Time
	// Terminal is the owner's terminal (the helper's inherited stdout),
	// where deploy-install's account helper asks for the build account's
	// password. deploy-install's one-time API token line is taken out of
	// its output (tokenFilter) and returned to the wizard only.
	Terminal io.Writer
	// TerminalCheck requires Terminal to be a terminal, not a pipe or
	// file.
	TerminalCheck func() error
	// FDAWait bounds the wait for the transient launchd check.
	FDAWait time.Duration
	// Output runs a fixed command and returns its standard output and
	// exit status; err is set only when it could not run or timed out.
	Output func(context.Context, Cmd) (stdout []byte, status int, err error)
	// Qualify is the existing qualification and worker APIs the rounds and
	// approve-and-start call.
	Qualify Qualifier

	// started is set when this helper process started the services; it
	// allows one release-pause in the same run (never on a later run).
	started bool
}

func (h *Helper) configPath(name string) string { return filepath.Join(h.Root, "config", name) }

// Approved reports an approved qualification: activation-anchor.json or
// qualification.json exists. Setup changes after approval would break the
// activation anchor, so the helper then serves only the verbs that finish
// approve-and-start (ownApproval), and nothing on a Mac approved outside
// this setup ledger.
func (h *Helper) Approved() (bool, error) {
	for _, name := range []string{"activation-anchor.json", "qualification.json"} {
		_, err := os.Lstat(h.configPath(name))
		if err == nil {
			return true, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return false, err
		}
	}
	return false, nil
}

// ownApproval reports an approval this setup ledger recorded: round 2 is
// done, the owner typed approve during approve-and-start and qualify
// approve's files were recorded for it. startServices then compares those
// files exactly; their mere presence is never trusted.
func ownApproval(l *Ledger) bool {
	return l != nil && l.Approval != nil && l.Approval.Approved != nil && l.record(StepRound2).Status == StatusDone
}

// afterApproval are the only verbs served once the qualification is
// approved: they finish approve-and-start and change no bound file.
func afterApproval(v Verb) bool {
	return v == VerbStatus || v == VerbSummary || v == VerbApprove || v == VerbReleasePause
}

// load returns the ledger, refusing one that belongs to another user.
func (h *Helper) load() (*Ledger, LedgerLocation, error) {
	l, loc, err := h.Store.Load()
	if err != nil {
		return nil, loc, err
	}
	if l != nil && (l.OwnerUID != h.Owner.UID || l.Owner != h.Owner.Name) {
		return nil, loc, fmt.Errorf("the setup ledger belongs to %s (uid %d), not to you", l.Owner, l.OwnerUID)
	}
	return l, loc, nil
}

// errApproved refuses changes on an approved Mac.
var errApproved = errors.New("qualification is approved on this Mac; macserve setup changes nothing after approval")

// CheckStart refuses to start the helper on a Mac whose qualification is
// approved (unless by this setup ledger, to finish approve-and-start),
// whose ledger is someone else's, whose running binary is not the one the
// owner verified (checkExecutable), or (decision D12) whose
// /Library/macserve exists without a native ledger.
func (h *Helper) CheckStart() error {
	approved, err := h.Approved()
	if err != nil {
		return err
	}
	l, _, err := h.load()
	if err != nil {
		return err
	}
	if approved && !ownApproval(l) {
		return errApproved
	}
	if err := h.checkExecutable(l); err != nil {
		return err
	}
	if l == nil {
		if _, err := os.Lstat(h.Root); err == nil {
			return fmt.Errorf("%s exists without a native setup ledger; this Mac is managed by other tooling and macserve setup does not change it", h.Root)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

// checkExecutable re-hashes the helper's own executable and refuses a
// digest other than SHA256, the digest the owner verified before sudo
// (from the release's SHA256SUMS or --sha256). Once install is done the
// helper must be the installed /Library/macserve/bin/macserve and SHA256
// the digest install recorded, so a resumed setup runs only the binary
// deploy-install installed.
func (h *Helper) checkExecutable(l *Ledger) error {
	if !sha256Hex.MatchString(h.SHA256) {
		return errors.New("expected macserve digest missing")
	}
	got, err := fileSHA256(h.Executable)
	if err != nil {
		return err
	}
	if got != h.SHA256 {
		return fmt.Errorf("%s has SHA-256 %s, not the verified %s; nothing was changed", h.Executable, got, h.SHA256)
	}
	if l == nil || l.record(StepInstall).Status != StatusDone {
		return nil
	}
	if h.Executable != filepath.Join(h.Root, "bin", "macserve") {
		return fmt.Errorf("after install the setup helper must be %s/bin/macserve, not %s", h.Root, h.Executable)
	}
	if want := l.record(StepInstall).Inputs["macserve"]; h.SHA256 != want {
		return fmt.Errorf("the installed macserve has SHA-256 %s, not %s, the one install recorded", h.SHA256, want)
	}
	return nil
}

// fileSHA256 hashes a bounded regular file without following a link.
func fileSHA256(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > maxBinary {
		return "", fmt.Errorf("%s is not a bounded regular file", path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxBinary+1))
	if err != nil {
		return "", err
	}
	return digestHex(data), nil
}

// Handle serves one request. It never panics the helper: every failure is
// a response error.
func (h *Helper) Handle(r Request) Response {
	resp, err := h.handle(r)
	if err != nil {
		resp.Error = err.Error()
	}
	if l, _, lerr := h.load(); lerr == nil && l != nil {
		if data, eerr := l.Encode(); eerr == nil {
			resp.Ledger = data
		}
	}
	return resp
}

func (h *Helper) handle(r Request) (Response, error) {
	if r.Verb == VerbStatus {
		_, _, err := h.load()
		return Response{}, err
	}
	approved, err := h.Approved()
	if err != nil {
		return Response{}, err
	}
	l, loc, err := h.load()
	if err != nil {
		return Response{}, err
	}
	if approved && (!afterApproval(r.Verb) || !ownApproval(l)) {
		return Response{}, errApproved
	}
	if r.Verb == VerbPreflight {
		return h.preflight(l, r.Env)
	}
	if l == nil {
		return Response{}, errors.New("no setup ledger yet; preflight comes first")
	}
	next, done, err := l.Next()
	if err != nil {
		return Response{}, err
	}
	if done || !slices.Contains(verbSteps[r.Verb], next.Step) {
		return Response{}, fmt.Errorf("setup continues at %s; %s is not served there", next.Step, r.Verb)
	}
	if qualifierVerb(r.Verb) && (h.Qualify == nil || h.Output == nil) {
		return Response{}, fmt.Errorf("%s needs the qualification APIs, which this helper was not given", r.Verb)
	}
	switch r.Verb {
	case VerbInstall:
		return h.install(l, loc)
	case VerbGitHub:
		return h.github(l, loc)
	case VerbTools:
		return h.tools(l, loc)
	case VerbFDACheck:
		return h.fdaVerb(l, loc)
	case VerbJobLogin:
		return h.jobLoginVerb(l, loc)
	case VerbOwnerActions:
		return h.ownerActions(l, loc)
	case VerbRoundPrepare:
		return h.roundPrepare(l, loc, next.Step)
	case VerbRoundBegin:
		return h.roundBegin(l, loc, next.Step, r.SHA256)
	case VerbRoundJobProbe:
		return h.roundJobProbe(l, next.Step)
	case VerbRoundCollect:
		return h.roundCollect(l, loc, next.Step)
	case VerbReboot:
		return h.reboot(l, loc)
	case VerbSummary:
		return h.summaryVerb(l, loc)
	case VerbApprove:
		return h.approve(l, loc, r.SHA256)
	case VerbReleasePause:
		return h.releasePause(l)
	}
	return Response{}, fmt.Errorf("unknown verb %q", r.Verb)
}

// verbSteps is the step each verb serves: the ledger's next step must be
// one of them. Everything is served in ledger order only, and a failed
// step blocks every verb (Ledger.Next).
var verbSteps = map[Verb][]Step{
	VerbInstall:       {StepInstall},
	VerbGitHub:        {StepGitHub},
	VerbTools:         {StepTools},
	VerbFDACheck:      {StepOwnerActions},
	VerbJobLogin:      {StepOwnerActions, StepRound1, StepRound2},
	VerbOwnerActions:  {StepOwnerActions},
	VerbRoundPrepare:  {StepRound1, StepRound2},
	VerbRoundBegin:    {StepRound1, StepRound2},
	VerbRoundJobProbe: {StepRound1, StepRound2},
	VerbRoundCollect:  {StepRound1, StepRound2},
	VerbReboot:        {StepReboot},
	VerbSummary:       {StepApproveAndStart},
	VerbApprove:       {StepApproveAndStart},
	VerbReleasePause:  {StepFirstBuild},
}

// qualifierVerb reports a verb that calls Qualify or Output: the rounds,
// the reboot and approve-and-start. A helper built without them refuses
// those verbs instead of failing on a nil seam.
func qualifierVerb(v Verb) bool {
	switch v {
	case VerbRoundPrepare, VerbRoundBegin, VerbRoundJobProbe, VerbRoundCollect, VerbReboot, VerbSummary, VerbApprove, VerbReleasePause:
		return true
	}
	return false
}

// begin starts step s and saves the ledger. A retryable step that is
// already running in this boot is left as it is.
func (h *Helper) begin(l *Ledger, loc LedgerLocation, s Step) (Boot, error) {
	boot, err := h.Boot()
	if err != nil {
		return boot, fmt.Errorf("boot identity: %w", err)
	}
	if r := l.record(s); r.Status == StatusRunning && Retryable(s) && r.Boot.same(boot) {
		return boot, nil
	}
	if err := l.Begin(s, boot, h.Now()); err != nil {
		return boot, err
	}
	return boot, h.Store.Save(l, loc)
}

func (h *Helper) complete(l *Ledger, loc LedgerLocation, s Step, boot Boot, inputs map[string]string) error {
	if err := l.Complete(s, boot, inputs, h.Now()); err != nil {
		return err
	}
	return h.Store.Save(l, loc)
}

// fail records a non-retryable step as failed: it blocks every later
// step until the owner reconciles by hand.
func (h *Helper) fail(l *Ledger, loc LedgerLocation, s Step, cause error) error {
	if ferr := l.Fail(s, reason(cause), h.Now()); ferr != nil {
		return errors.Join(cause, ferr)
	}
	return errors.Join(cause, h.Store.Save(l, loc))
}

// reason is cause as 1-512 printable ASCII characters for the ledger.
func reason(cause error) string {
	var b strings.Builder
	for _, c := range cause.Error() {
		if c < 0x20 || c > 0x7e {
			c = ' '
		}
		if b.Len() >= 512 {
			break
		}
		b.WriteRune(c)
	}
	if strings.TrimSpace(b.String()) == "" {
		return "failed"
	}
	return b.String()
}

// preflight records the preflight step: the wizard's generated deploy.env
// must parse with deploy-install's parser (which requires a repository
// pin) and name the helper's owner. A new ledger is created in Staging.
func (h *Helper) preflight(l *Ledger, env string) (Response, error) {
	if l != nil && l.record(StepPreflight).Status == StatusDone {
		next, _, _ := l.Next()
		return Response{}, fmt.Errorf("preflight is already recorded; setup continues at %s", next.Step)
	}
	e, err := deploy.ParseEnvironment([]byte(env))
	if err != nil {
		return Response{}, fmt.Errorf("generated deploy.env: %w", err)
	}
	if e.OwnerUID != h.Owner.UID || e.OwnerUser != h.Owner.Name {
		return Response{}, errors.New("generated deploy.env names another owner than you")
	}
	if l == nil {
		if _, err := os.Lstat(h.Root); err == nil {
			return Response{}, fmt.Errorf("%s exists without a native setup ledger; this Mac is managed by other tooling", h.Root)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return Response{}, err
		}
		l = NewLedger(h.Owner.Name, h.Owner.UID, h.Now())
	}
	boot, err := h.begin(l, LedgerStaged, StepPreflight)
	if err != nil {
		return Response{}, err
	}
	if err := h.Store.StageFile(stagedEnv, []byte(env)); err != nil {
		return Response{}, err
	}
	if err := h.complete(l, LedgerStaged, StepPreflight, boot, map[string]string{"deploy.env": digestHex([]byte(env))}); err != nil {
		return Response{}, err
	}
	return Response{Done: true}, nil
}

// Serve accepts the wizard's connection on ln and serves it. Connections
// from any other UID are refused and closed; after the first accepted one
// the listener is closed. It returns when the wizard disconnects or after
// idle without a connection or request.
func (h *Helper) Serve(ln *net.UnixListener, idle time.Duration) error {
	defer ln.Close()
	var conn net.Conn
	for conn == nil {
		if err := ln.SetDeadline(time.Now().Add(idle)); err != nil {
			return err
		}
		c, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("no connection from macserve setup: %w", err)
		}
		uid, err := peercred.UID(c)
		if err != nil || uid != h.Owner.UID {
			h.audit("connect", "refused", fmt.Errorf("peer uid %d is not the owner (%v)", uid, err))
			c.Close()
			continue
		}
		conn = c
	}
	ln.Close()
	defer conn.Close()
	h.audit("connect", "accepted", nil)
	in := bufio.NewReaderSize(conn, 64<<10)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(idle)); err != nil {
			return err
		}
		line, err := readLine(in, MaxRequest)
		if errors.Is(err, io.EOF) {
			h.audit("disconnect", "finish", nil)
			return nil
		}
		if err != nil {
			h.audit("disconnect", "finish", err)
			return err
		}
		req, err := DecodeRequest(line)
		var resp Response
		if err != nil {
			h.audit("request", "refused", err)
			resp.Error = err.Error()
		} else {
			h.audit(req.Verb, "start", nil)
			resp = h.Handle(req)
			var ferr error
			if resp.Error != "" {
				ferr = errors.New(resp.Error)
			}
			h.audit(req.Verb, "finish", ferr)
		}
		out, err := json.Marshal(resp)
		if err != nil {
			return err
		}
		if err := conn.SetWriteDeadline(time.Now().Add(time.Minute)); err != nil {
			return err
		}
		if _, err := conn.Write(append(out, '\n')); err != nil {
			return err
		}
	}
}

func (h *Helper) audit(verb Verb, phase string, err error) {
	e := AuditEntry{At: h.Now().UTC(), Verb: verb, Phase: phase}
	if err != nil {
		e.Error = reason(err)
	}
	_ = h.Store.Audit(e)
}

package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ErrContamination identifies observed nonbaseline state, never an inability to
// inspect it. Only errors carrying this sentinel may create durable quarantine.
var ErrContamination = errors.New("job-user contamination observed")

const quarantineRecord = "admission-quarantine.json"

func (r *nativeRunner) loadBaseline() error {
	if r.baselinePath == "" {
		return errors.New("protected GUI baseline path unavailable")
	}
	baseline, err := loadBaseline(r.baselinePath, uint32(r.uid))
	if err != nil {
		return err
	}
	digest, err := PersistenceDigest(r.persistencePath, uint32(r.uid))
	if err != nil {
		return err
	}
	if baseline.PersistenceSHA256 != digest {
		return errors.New("reviewed persistence changed; baseline reset and requalification required")
	}
	r.scope.baseline = baseline
	return nil
}

const persistenceAdmissionTimeout = 30 * time.Second

// Admission observes without terminating or adopting unexpected processes.
// Delayed same-UID persistence after this snapshot remains a native trust limit.
func (r *nativeRunner) Admission(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, persistenceAdmissionTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.scope == nil || r.persistence == nil {
		return errors.New("native persistence inspection unavailable")
	}
	// A foreground job session is not the qualified state. This refuses, without
	// quarantine, before any job starts; a job already running is not cancelled.
	if r.console == nil {
		return errors.New("console admission inspection unavailable")
	}
	if err := r.console(); err != nil {
		return fmt.Errorf("job admission refused: %w", err)
	}
	if err := r.loadBaseline(); err != nil {
		return err
	}
	if err := r.persistence(ctx); err != nil {
		return err
	}
	// The process census has its own budget: it may wait toleratedChildWait
	// for children of tolerated launches to exit.
	cancel()
	quietCtx, quietCancel := context.WithTimeout(parent, r.scope.childWait+persistenceAdmissionTimeout)
	defer quietCancel()
	return r.scope.observeQuiet(quietCtx)
}

// observeQuiet refuses admission while any job process is outside the audited
// baseline. As in quiesce, that is contamination evidence only if no audited
// process is gone without a verified launchd relaunch. Residual processes that
// are all direct children of tolerated launches (see toleratedChildWait) are
// waited for up to s.childWait and then refused without quarantine; they are
// never admitted. A snapshot whose only refused processes exited before they
// could be verified (processCensus.vanished) is sampled again, at most
// maxUnsettledSnapshots times, then refused without quarantine
// (errAdmissionUnsettled). Admission needs two consecutive clean snapshots.
func (s *processScope) observeQuiet(ctx context.Context) error {
	var waitUntil time.Time
	unsettled := 0
	for clean := 0; ; {
		if err := ctx.Err(); err != nil {
			return err
		}
		samples, err := s.sample(ctx)
		if err != nil {
			return err
		}
		c, err := s.census(ctx, samples)
		if err != nil {
			return err
		}
		switch {
		case len(c.residual) == 0 && len(c.vanished) == 0:
			if clean++; clean == 2 {
				return nil
			}
		case len(c.residual) == 0:
			if unsettled++; unsettled > maxUnsettledSnapshots {
				return errAdmissionUnsettled
			}
			clean = 0
		default:
			if c.unresolved {
				return errRelaunchUnverified
			}
			if !c.toleratedChildren {
				return s.contaminated("processes outside audited GUI baseline", c)
			}
			if waitUntil.IsZero() {
				waitUntil = time.Now().Add(s.childWait)
			}
			if !time.Now().Before(waitUntil) {
				return errToleratedChildPersists
			}
			clean = 0
		}
		timer := time.NewTimer(s.interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// maxUnsettledSnapshots bounds how often one admission samples again because
// every refused process vanished before verification.
const maxUnsettledSnapshots = 10

// errAdmissionUnsettled is inconclusive, never contamination: nothing still
// running was refused.
var errAdmissionUnsettled = fmt.Errorf("job processes exited before they could be verified in %d admission snapshots; admission inconclusive", maxUnsettledSnapshots+1)

// QuarantineRecord is quarantineRecord: why the worker was quarantined, for
// the administrator who resets it (root-only, in the worker root). Only its
// presence quarantines; reset removes it.
type QuarantineRecord struct {
	Quarantined bool      `json:"quarantined"`
	Reason      string    `json:"reason"`
	RecordedAt  time.Time `json:"recorded_at"`
}

// quarantineReasonBytes bounds QuarantineRecord.Reason.
const quarantineReasonBytes = 8 << 10

// quarantine durably records contamination (quarantineRecord, with the full
// error, which lists the refused processes) and an admission refused for a
// persisting child of a tolerated launch (admissionInconclusiveRecord, never
// quarantine).
func (e *Engine) quarantine(err error) error {
	if errors.Is(err, errToleratedChildPersists) {
		err = errors.Join(err, e.recordInconclusive())
	}
	if !errors.Is(err, ErrContamination) {
		return err
	}
	record, marshalErr := json.Marshal(QuarantineRecord{Quarantined: true, Reason: clip(err.Error(), quarantineReasonBytes), RecordedAt: e.options.Now().UTC()})
	if marshalErr != nil {
		record = []byte(`{"quarantined":true}`)
	}
	return errors.Join(ErrRecovery, err, durableFile(e.root, quarantineRecord, record))
}

func (e *Engine) admission(ctx context.Context) error {
	if err := e.checkQuarantine(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if inspector, ok := e.options.Runner.(interface{ Admission(context.Context) error }); ok {
		if err := inspector.Admission(ctx); err != nil {
			return e.quarantine(err)
		}
	}
	return e.clearInconclusive()
}

func (e *Engine) checkQuarantine() error {
	_, err := e.root.Lstat(quarantineRecord)
	if err == nil {
		return fmt.Errorf("%w: administrator reset required", ErrRecovery)
	}
	if !os.IsNotExist(err) {
		return err
	}
	return nil
}

// This private marker selects admission shares without shortening cold full-scan
// command budgets or exposing a timeout override to callers.
type persistenceAdmissionContextKey struct{}

// Only these fixed, read-only commands are used. They do not use the job Runner,
// which permits recipes; probes have fixed environments, output bounds and deadlines.
func inspectCommand(ctx context.Context, credential *syscall.Credential, executable string, args ...string) (string, string, error) {
	// Allocate short fixed shares of the single 30s admission budget: cron and
	// metadata 2s each, six membership probes 1s each, login items 6s and BTM 8s.
	// The caller's remaining deadline always wins; no probe renews admission.
	// Partial output on expiry is unavailable inspection, never a clean census.
	hot, _ := ctx.Value(persistenceAdmissionContextKey{}).(bool)
	timeout := 5 * time.Second
	if hot {
		timeout = 2 * time.Second
	}
	switch {
	case executable == "/usr/bin/sfltool" && len(args) == 1 && args[0] == "dumpbtm":
		timeout = 30 * time.Second
		if hot {
			timeout = 8 * time.Second
		}
	case executable == "/usr/bin/dsmemberutil":
		timeout = 30 * time.Second
		if hot {
			timeout = time.Second
		}
	case executable == "/bin/launchctl" && len(args) == 6 && args[0] == "asuser" && args[3] == "_job-login-items":
		timeout = 30 * time.Second
		if hot {
			timeout = 6 * time.Second
		}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: credential}
	cmd.WaitDelay = 100 * time.Millisecond
	stdout, stderr := &boundedBuffer{max: 1 << 20}, &boundedBuffer{max: 1 << 20}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), errors.Join(err, stdout.err, stderr.err, ctx.Err())
}

func nativePersistenceInspector(options Options) func(context.Context) error {
	return func(ctx context.Context) error {
		return verifyHotPersistence(ctx, options, inspectHotPersistence)
	}
}

// Read-only hot inspection: fresh account surfaces, census and trusted writer
// roots. Full signed-code/tree verification is recorded separately.
func inspectHotPersistence(ctx context.Context, options Options, expected PersistenceManifest) error {
	if runtime.GOOS != "darwin" {
		return errors.New("native persistence inspection requires supported macOS")
	}
	account, err := user.LookupId(strconv.FormatUint(uint64(options.JobUID), 10))
	if err != nil || !filepath.IsAbs(accountHome(account)) {
		return errors.Join(err, errors.New("job account home unavailable"))
	}
	if err := inspectLaunchAgents(account.HomeDir); err != nil {
		return err
	}
	credential := &syscall.Credential{Uid: options.JobUID, Gid: options.JobGID, Groups: []uint32{}}
	out, diagnostic, err := inspectCommand(ctx, credential, "/usr/bin/crontab", "-l")
	if err := inspectCrontab(out, diagnostic, err, account.Username); err != nil {
		return err
	}
	// The fixed helper drops credentials before CoreServices; BTM is separate.
	out, diagnostic, err = inspectCommand(ctx, nil, "/bin/launchctl", "asuser", strconv.FormatUint(uint64(options.JobUID), 10), options.HelperPath, "_job-login-items", strconv.FormatUint(uint64(options.JobUID), 10), strconv.FormatUint(uint64(options.JobGID), 10))
	if err := inspectLoginItems(out, diagnostic, err); err != nil {
		return err
	}
	return inspectRegistrationAdmission(ctx, options, expected, backgroundCensus)
}

func accountHome(account *user.User) string {
	if account == nil {
		return ""
	}
	return account.HomeDir
}

func inspectLaunchAgents(home string) error {
	root, err := os.OpenRoot(home)
	if err != nil {
		return fmt.Errorf("inspect job home: %w", err)
	}
	defer root.Close()
	// Symlinks are not accepted, including a Library symlink outside the home.
	for _, name := range []string{"Library", "Library/LaunchAgents"} {
		info, err := root.Lstat(name)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return errors.Join(err, errors.New("LaunchAgents inspection unavailable"))
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: LaunchAgents path is not a non-symlink directory", ErrContamination)
		}
	}
	dir, err := root.Open("Library/LaunchAgents")
	if err != nil {
		return err
	}
	defer dir.Close()
	names, err := dir.Readdirnames(1)
	if len(names) != 0 {
		return fmt.Errorf("%w: job-user LaunchAgents present", ErrContamination)
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func inspectLoginItems(out, diagnostic string, commandErr error) error {
	if commandErr != nil || strings.TrimSpace(diagnostic) != "" {
		return errors.Join(commandErr, errors.New("login item inspection unavailable"))
	}
	count, err := strconv.ParseUint(strings.TrimSpace(out), 10, 32)
	if err != nil {
		return fmt.Errorf("login item census unsupported: %w", err)
	}
	if count != 0 {
		return fmt.Errorf("%w: legacy login items present", ErrContamination)
	}
	return nil
}

func inspectCrontab(out, diagnostic string, commandErr error, username string) error {
	if commandErr == nil && strings.TrimSpace(diagnostic) == "" {
		if out != "" {
			return fmt.Errorf("%w: nonempty job-user crontab", ErrContamination)
		}
		return nil
	}
	if errors.Is(commandErr, context.DeadlineExceeded) || errors.Is(commandErr, context.Canceled) {
		return commandErr
	}
	var exit *exec.ExitError
	if out == "" && errors.As(commandErr, &exit) && exit.ExitCode() == 1 && strings.TrimSpace(diagnostic) == "crontab: no crontab for "+username {
		return nil
	}
	return errors.Join(commandErr, errors.New("job-user crontab inspection unavailable"))
}

func PrivateJobLoginItems(args []string) error {
	if len(args) != 2 {
		return errors.New("invalid private login inspection arguments")
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	return PrivateJobExec(append(append([]string{}, args...), "/", executable, "_legacy-login-count"))
}

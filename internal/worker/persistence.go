package worker

import (
	"context"
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
func (r *nativeRunner) Admission(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, persistenceAdmissionTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.scope == nil || r.persistence == nil {
		return errors.New("native persistence inspection unavailable")
	}
	if err := r.loadBaseline(); err != nil {
		return err
	}
	if err := r.persistence(ctx); err != nil {
		return err
	}
	return r.scope.observeQuiet(ctx)
}

func (s *processScope) observeQuiet(ctx context.Context) error {
	for i := 0; i < 2; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		samples, err := s.sample(ctx)
		if err != nil {
			return err
		}
		residual, err := s.residual(samples)
		if err != nil {
			return err
		}
		if len(residual) != 0 {
			return fmt.Errorf("%w: processes outside audited GUI baseline", ErrContamination)
		}
		if i == 0 {
			timer := time.NewTimer(s.interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	return ctx.Err()
}

func (e *Engine) quarantine(err error) error {
	if !errors.Is(err, ErrContamination) {
		return err
	}
	return errors.Join(ErrRecovery, err, durableFile(e.root, quarantineRecord, []byte(`{"quarantined":true}`)))
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
	return nil
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

// Only these fixed, read-only commands are used. They do not use the job Runner,
// which permits recipes; probes have fixed environments, output bounds and deadlines.
func inspectCommand(ctx context.Context, credential *syscall.Credential, executable string, args ...string) (string, string, error) {
	// Metadata/cron probes stay short. A cold CoreServices GUI-domain connection
	// or host-wide BTM enumeration gets 30s, rather than the old AppleEvents 5s.
	// The enclosing admission/reset deadline still wins, and partial output on
	// any deadline remains an inspection failure, never an empty census.
	timeout := 5 * time.Second
	if executable == "/usr/bin/sfltool" && len(args) == 1 && args[0] == "dumpbtm" ||
		executable == "/usr/bin/dsmemberutil" ||
		executable == "/bin/launchctl" && len(args) == 6 && args[0] == "asuser" && args[3] == "_job-login-items" {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
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
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.Join(err, errors.New("LaunchAgents inspection unavailable"))
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

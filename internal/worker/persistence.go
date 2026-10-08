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
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const admissionRecord = "admission-quarantine.json"

func (r *nativeRunner) loadBaseline() error {
	if r.baselinePath == "" {
		return errors.New("protected GUI baseline path unavailable")
	}
	baseline, err := loadBaseline(r.baselinePath, uint32(r.uid))
	if err != nil {
		return err
	}
	r.scope.baseline = baseline
	return nil
}

// Admission observes without terminating or adopting unexpected processes.
// Delayed same-UID persistence after this snapshot remains a native trust limit.
func (r *nativeRunner) Admission(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
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
		samples, err := s.sample(ctx)
		if err != nil {
			return err
		}
		residual, err := s.residual(samples)
		if err != nil {
			return err
		}
		if len(residual) != 0 {
			return errors.New("processes outside audited GUI baseline require administrator reconciliation")
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
	return errors.Join(ErrRecovery, err, durableFile(e.root, admissionRecord, []byte(`{"administrator_reconciliation_required":true}`)))
}

func (e *Engine) admission(ctx context.Context) error {
	if _, err := e.root.Lstat(admissionRecord); !os.IsNotExist(err) {
		return errors.Join(ErrRecovery, errors.New("administrator reconciliation required"), err)
	}
	if inspector, ok := e.options.Runner.(interface{ Admission(context.Context) error }); ok {
		if err := inspector.Admission(ctx); err != nil {
			return e.quarantine(err)
		}
	}
	return nil
}

// Only these fixed, read-only commands are used. They do not use the job Runner,
// which permits recipes; probes have fixed environments, output bounds and deadlines.
func inspectCommand(ctx context.Context, credential *syscall.Credential, executable string, args ...string) (string, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
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
		// launchctl selects the existing GUI domain; the fixed private helper
		// drops all root credentials before osascript or its scripting additions load.
		out, diagnostic, err = inspectCommand(ctx, nil, "/bin/launchctl", "asuser", strconv.FormatUint(uint64(options.JobUID), 10), options.HelperPath, "_job-login-items", strconv.FormatUint(uint64(options.JobUID), 10), strconv.FormatUint(uint64(options.JobGID), 10))
		if err := inspectLoginItems(out, diagnostic, err); err != nil {
			return err
		}
		// Legacy System Events enumeration does not cover SMAppService. Require
		// an explicit empty per-UID Background Task Management census as well.
		out, diagnostic, err = inspectCommand(ctx, nil, "/usr/bin/sfltool", "dumpbtm")
		if err != nil || strings.TrimSpace(diagnostic) != "" {
			return errors.Join(err, errors.New("background login registration inspection unavailable"))
		}
		return inspectBackgroundItems(out, options.JobUID)
	}
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
		return errors.New("job-user LaunchAgents require administrator removal")
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func inspectLoginItems(out, diagnostic string, commandErr error) error {
	if commandErr != nil || strings.TrimSpace(out) != "0" || strings.TrimSpace(diagnostic) != "" {
		return errors.Join(commandErr, errors.New("login items present or inspection unavailable"))
	}
	return nil
}

func inspectCrontab(out, diagnostic string, commandErr error, username string) error {
	if out != "" {
		return errors.New("nonempty job-user crontab requires administrator removal")
	}
	if commandErr == nil && strings.TrimSpace(diagnostic) == "" {
		return nil
	}
	if errors.Is(commandErr, context.DeadlineExceeded) || errors.Is(commandErr, context.Canceled) {
		return commandErr
	}
	var exit *exec.ExitError
	if errors.As(commandErr, &exit) && exit.ExitCode() == 1 && strings.TrimSpace(diagnostic) == "crontab: no crontab for "+username {
		return nil
	}
	return errors.Join(commandErr, errors.New("job-user crontab inspection unavailable"))
}

var backgroundUID = regexp.MustCompile(`^Records for UID ([0-9]+) : [[:xdigit:]-]+$`)

// dumpbtm has no stable machine-readable schema. Only an explicitly present,
// empty UID section is accepted. Missing sections, records (including disabled
// registrations) and unknown target-section syntax all fail closed; deployments
// whose OS cannot provide this census must not enable native execution.
func inspectBackgroundItems(output string, uid uint32) error {
	found, target := false, false
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if match := backgroundUID.FindStringSubmatch(line); match != nil {
			target = match[1] == strconv.FormatUint(uint64(uid), 10)
			if target {
				if found {
					return errors.New("duplicate background registration UID census")
				}
				found = true
			}
			continue
		}
		if target && line != "" && strings.Trim(line, "=") != "" {
			return errors.New("background login registrations present or census syntax unsupported")
		}
	}
	if !found {
		return errors.New("explicit job-UID background registration census unavailable")
	}
	return nil
}

func PrivateJobLoginItems(args []string) error {
	if len(args) != 2 {
		return errors.New("invalid private login inspection arguments")
	}
	return PrivateJobExec(append(append([]string{}, args...), "/", "/usr/bin/osascript", "-e", `tell application "System Events" to count login items`))
}

package worker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jerryfane/macserve/internal/hostguard"
)

// ResetGUIBaseline is the sole administrator reset. It removes only job-user
// persistence and nonselected job-UID processes, then replaces the explicitly
// audited baseline. Modern BTM registrations are never reset globally: residual
// registrations must be resolved before this same command can succeed.
func ResetGUIBaseline(ctx context.Context, options Options, pids []int) error {
	if err := hostguard.BrokerIdentity(options.JobUID, options.JobGID, options.ControllerUID, options.OwnerUID); err != nil {
		return err
	}
	// Never permit an injected runner to bypass production inspection/identity.
	options.Runner = nil
	engine, err := New(options)
	if err != nil {
		return fmt.Errorf("stop the broker before administrator reset: %w", err)
	}
	defer engine.Close()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	runner := engine.options.Runner.(*nativeRunner)
	return engine.reset(ctx, func(ctx context.Context) error {
		baseline, err := runner.scope.resetBaseline(ctx, pids, bootIdentity, func(ctx context.Context) error {
			account, err := user.LookupId(strconv.FormatUint(uint64(options.JobUID), 10))
			if err != nil || !filepath.IsAbs(accountHome(account)) || accountHome(account) == "/" {
				return errors.Join(err, errors.New("job account home unavailable"))
			}
			return resetPersistence(ctx, options, account.HomeDir, account.Username, inspectCommand)
		})
		if err != nil {
			return err
		}
		if err := runner.persistence(ctx); err != nil {
			return err
		}
		return saveBaseline(options.BaselinePath, baseline)
	})
}

// reset shares ordinary ownership-ledger cleanup, but alone may clear the marker.
// Errors never create a quarantine merely because an administrator tried reset.
func (e *Engine) reset(ctx context.Context, prepare func(context.Context) error) error {

	if err := ctx.Err(); err != nil {
		return err
	}
	if err := prepare(ctx); err != nil {
		return err
	}
	if err := e.recoverOwned(ctx, true); err != nil {
		return err
	}
	inspector, ok := e.options.Runner.(interface{ Admission(context.Context) error })
	if !ok {
		return errors.New("reset requires full admission inspection")
	}
	if err := inspector.Admission(ctx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	marker, err := e.root.ReadFile(quarantineRecord)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	dir, err := e.root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := e.root.Remove(quarantineRecord); err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		return errors.Join(err, durableFile(e.root, quarantineRecord, marker))
	}
	return nil
}

func (s *processScope) resetBaseline(ctx context.Context, pids []int, boot func() (string, error), cleanup func(context.Context) error) (GUIBaseline, error) {
	bootID, err := boot()
	if err != nil {
		return GUIBaseline{}, err
	}
	samples, err := s.sample(ctx)
	if err != nil {
		return GUIBaseline{}, err
	}
	baseline, err := selectedBaseline(uint32(s.uid), pids, bootID, samples)
	if err != nil {
		return baseline, err
	}
	s.baseline = baseline
	if err := cleanup(ctx); err != nil {
		return baseline, err
	}
	if err := s.quiesce(ctx); err != nil {
		return baseline, err
	}
	audited, err := auditedBaseline(ctx, uint32(s.uid), pids, boot, s.sample)
	if err != nil {
		return baseline, err
	}
	if audited.Boot != bootID {
		return baseline, errors.New("boot identity changed during reset")
	}
	selected := make(map[int]string, len(baseline.Processes))
	for _, p := range baseline.Processes {
		selected[p.PID] = p.Start
	}
	for _, p := range audited.Processes {
		if selected[p.PID] != p.Start {
			return baseline, fmt.Errorf("%w: selected process changed during reset audit", ErrContamination)
		}
	}
	return baseline, ctx.Err()
}

// All command arguments are fixed or trusted account configuration. launchctl
// selects the job GUI domain; the helper drops credentials before osascript loads.
func resetPersistence(ctx context.Context, options Options, home, username string, command func(context.Context, *syscall.Credential, string, ...string) (string, string, error)) error {
	if err := resetLaunchAgents(ctx, home); err != nil {
		return err
	}
	credential := &syscall.Credential{Uid: options.JobUID, Gid: options.JobGID, Groups: []uint32{}}
	out, diagnostic, err := command(ctx, credential, "/usr/bin/crontab", "-l")
	if err := inspectCrontab(out, diagnostic, err, username); err != nil {
		if !errors.Is(err, ErrContamination) {
			return err
		}
		out, diagnostic, err = command(ctx, credential, "/usr/bin/crontab", "-r")
		if err != nil || strings.TrimSpace(out) != "" || strings.TrimSpace(diagnostic) != "" {
			return errors.Join(err, errors.New("job-user crontab removal failed"))
		}
	}
	_, diagnostic, err = command(ctx, nil, "/bin/launchctl", "asuser", strconv.FormatUint(uint64(options.JobUID), 10), options.HelperPath, "_job-exec", strconv.FormatUint(uint64(options.JobUID), 10), strconv.FormatUint(uint64(options.JobGID), 10), "/", "/usr/bin/osascript", "-e", `tell application "System Events" to delete every login item`)
	if err != nil || strings.TrimSpace(diagnostic) != "" {
		return errors.Join(err, errors.New("job-user legacy login item removal failed"))
	}
	return ctx.Err()
}

func resetLaunchAgents(ctx context.Context, home string) error {
	if err := inspectLaunchAgents(home); !errors.Is(err, ErrContamination) {
		return err
	}
	root, err := os.OpenRoot(home)
	if err != nil {
		return err
	}
	defer root.Close()
	dir, err := root.OpenRoot("Library/LaunchAgents")
	if err != nil {
		return err
	}
	defer dir.Close()
	entries, err := dir.Open(".")
	if err != nil {
		return err
	}
	defer entries.Close()
	names, err := entries.Readdirnames(-1)
	if err != nil {
		return err
	}
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := dir.RemoveAll(name); err != nil {
			return err
		}
	}
	return entries.Sync()
}

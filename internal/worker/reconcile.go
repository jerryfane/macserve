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

	"github.com/jerryfane/macserve/internal/hostguard"
)

// ResetGUIBaseline is the sole administrator reset. It removes only job-user
// persistence and nonselected job-UID processes, then replaces the explicitly
// audited baseline. Modern BTM registrations are never reset globally: residual
// registrations must be resolved before this same command can succeed. The
// result reports the saved baseline with its launchd provenance and the
// selected processes it dropped or replaced (see processScope.resetBaseline).
func ResetGUIBaseline(ctx context.Context, options Options, pids []int) (ResetResult, error) {
	if err := hostguard.BrokerIdentity(options.JobUID, options.JobGID, options.ControllerUID, options.OwnerUID); err != nil {
		return ResetResult{}, err
	}
	// Never permit an injected runner to bypass production inspection/identity.
	options.Runner = nil
	engine, err := New(options)
	if err != nil {
		return ResetResult{}, fmt.Errorf("stop the broker before administrator reset: %w", err)
	}
	defer engine.Close()
	ctx, cancel := context.WithTimeout(ctx, PersistenceOperationTimeout)
	defer cancel()
	runner := engine.options.Runner.(*nativeRunner)
	var saved ResetResult
	err = engine.reset(ctx, func(ctx context.Context) error {
		result, err := runner.scope.resetBaseline(ctx, pids, bootIdentity, func(ctx context.Context) error {
			account, err := user.LookupId(strconv.FormatUint(uint64(options.JobUID), 10))
			if err != nil || !filepath.IsAbs(accountHome(account)) || accountHome(account) == "/" {
				return errors.Join(err, errors.New("job account home unavailable"))
			}
			if err := resetPersistence(ctx, options, account.HomeDir, account.Username, inspectCommand); err != nil {
				return err
			}
			// Terminate job processes before the full attestation, as before,
			// so none writes persistence while it runs. It takes minutes;
			// resetBaseline settles again after it.
			if err := runner.scope.quiesce(ctx); err != nil {
				return err
			}
			return verifyPersistenceAttestation(ctx, options, true, collectPersistence)
		})
		if err != nil {
			return err
		}
		result.PersistenceSHA256, err = PersistenceDigest(options.PersistencePath, options.JobUID)
		if err != nil {
			return err
		}
		if err := saveBaseline(options.BaselinePath, result.GUIBaseline); err != nil {
			return err
		}
		saved = result
		return nil
	})
	return saved, err
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

// resetBaseline replaces the baseline with the administrator's selection as
// it survives reset. Reset takes minutes (the full persistence attestation in
// cleanup alone measured about two); Apple helpers in the job GUI session exit
// on their own in that time and launchd starts them again on demand, so:
//
//   - The environment launchctl prints for the job's gui and user domains is
//     recorded first; every later census refuses a difference (see
//     LaunchdEnvironment).
//   - Launchd provenance is recorded from the selected instances themselves
//     before cleanup (describeServices), while they still run.
//   - A requested PID already absent at start is dropped. One held by another
//     UID or a zombie refuses, and so does, at any later point, a selected PID
//     number held by a process that is not its verified relaunch.
//   - A selected process that exits is replaced by launchd's verified
//     relaunch (the v0.1.9 rule), kept as an exited identity when it has
//     provenance, or dropped. GUI anchors (selectAnchors) must survive.
//   - Unselected system LaunchAgents follow the adoption rule. Every other
//     job process is terminated as residual, including a relaunch that cannot
//     be verified.
//   - Survivors after termination still fail closed: contamination when every
//     audited process is running or verifiably relaunched, otherwise
//     inconclusive (ErrCleanup), as in quiesce.
//
// Dropping is safe because a reset defines the new baseline from what
// survives it: an exited process cannot be part of one. A job can only end
// its own UID's processes, which hides or retains nothing; nothing is added
// to the baseline without verification against launchd's own record; and the
// published baseline comes from a fresh audit after cleanup. cleanup runs
// under this policy and resetBaseline terminates and settles again after it.
func (s *processScope) resetBaseline(ctx context.Context, pids []int, boot func() (string, error), cleanup func(context.Context) error) (ResetResult, error) {
	if s.agents == nil {
		return ResetResult{}, errors.New("reset requires launchd process inspection")
	}
	bootID, err := boot()
	if err != nil {
		return ResetResult{}, err
	}
	env, err := launchdEnvironment(ctx, s.agents, s.uid)
	if err != nil {
		return ResetResult{}, err
	}
	samples, err := s.sample(ctx)
	if err != nil {
		return ResetResult{}, err
	}
	selected, dropped, err := selectedBaseline(uint32(s.uid), pids, bootID, env, samples)
	if err != nil {
		return ResetResult{}, err
	}
	selected = describeServices(ctx, s.agents, s.uid, selected)
	anchors, paths, err := selectAnchors(s.agents, selected)
	if err != nil {
		return ResetResult{}, err
	}
	adopt := &adoption{initial: make(map[int]string, len(samples)), terminate: make(map[int]string), reference: domainReferences(ctx, s.agents, s.uid, selected)}
	chosen := make(map[int]bool, len(selected.Processes))
	for _, p := range selected.Processes {
		chosen[p.PID] = true
	}
	for _, p := range samples {
		adopt.initial[p.pid] = p.start
	}
	hints := newServiceHints(s.agents, s.uid, nil)
	for _, p := range samples {
		if p.uid != s.uid || p.zombie || chosen[p.pid] {
			continue
		}
		if id, ok := adopt.qualifies(ctx, s.agents, s.uid, p, hints); ok {
			adopt.terminate[p.pid] = p.start
			adopt.adopted = append(adopt.adopted, id)
			selected.Processes = append(selected.Processes, id)
		}
	}
	s.baseline, s.adopt = selected, adopt
	defer func() { s.adopt = nil }()
	if err := cleanup(ctx); err != nil {
		return ResetResult{}, err
	}
	if err := s.quiesce(ctx); err != nil {
		return ResetResult{}, err
	}
	result, err := s.auditReset(ctx, anchors, paths, boot, bootID)
	if err != nil {
		return result, err
	}
	result.Dropped = append(dropped, result.Dropped...)
	s.baseline = result.GUIBaseline
	return result, ctx.Err()
}

// All command arguments are fixed or trusted account configuration. launchctl
// selects the job GUI domain; the helper drops credentials before CoreServices loads.
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
	// Native removal has not been qualified. Never delete or silently adopt a
	// legacy item: administrators must resolve it before this reset can proceed.
	out, diagnostic, err = command(ctx, nil, "/bin/launchctl", "asuser", strconv.FormatUint(uint64(options.JobUID), 10), options.HelperPath, "_job-login-items", strconv.FormatUint(uint64(options.JobUID), 10), strconv.FormatUint(uint64(options.JobGID), 10))
	if err := inspectLoginItems(out, diagnostic, err); err != nil {
		return err
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

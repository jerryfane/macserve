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
	"golang.org/x/sys/unix"
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
	// A baseline captured with the job session in the foreground would audit an
	// unqualified state; refuse before any cleanup.
	if err := hostguard.CheckConsole(options.OwnerUID); err != nil {
		return ResetResult{}, fmt.Errorf("worker-reset refused: %w", err)
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
	return resetLaunchAgentsWithStat(ctx, home, unix.Fstatat)
}

// resetLaunchAgentsWithStat removes every LaunchAgents entry with
// descriptor-relative, no-follow operations that never cross a mount. Like
// walkWorkspace, any nested filesystem (one the job attached under
// LaunchAgents, or a mount on Library or LaunchAgents itself) is contamination:
// a dry pass refuses before anything is removed, and the removal pass re-checks
// every directory it opens, so a mount that appears later is refused too.
func resetLaunchAgentsWithStat(ctx context.Context, home string, statat func(int, string, *unix.Stat_t, int) error) error {
	if err := inspectLaunchAgents(home); !errors.Is(err, ErrContamination) {
		return err
	}
	homeFD, err := unix.Open(home, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(homeFD)
	var st unix.Stat_t
	if err := unix.Fstat(homeFD, &st); err != nil {
		return err
	}
	device := uint64(st.Dev)
	fd := homeFD
	for _, name := range []string{"Library", "LaunchAgents"} {
		next, err := openSameDevice(fd, name, device, statat)
		if fd != homeFD {
			unix.Close(fd)
		}
		if err != nil {
			return err
		}
		fd = next
	}
	defer unix.Close(fd)
	for _, remove := range []bool{false, true} {
		if err := clearSameDevice(ctx, fd, device, remove, statat, 0); err != nil {
			return err
		}
	}
	return unix.Fsync(fd)
}

// openSameDevice opens a child directory without following links and refuses
// it, before and after opening, unless it is on device.
func openSameDevice(parent int, name string, device uint64, statat func(int, string, *unix.Stat_t, int) error) (int, error) {
	var st unix.Stat_t
	if err := statat(parent, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return -1, err
	}
	if uint64(st.Dev) != device {
		return -1, fmt.Errorf("%w: nested mount at LaunchAgents path %q", ErrContamination, name)
	}
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	if err := unix.Fstat(fd, &st); err != nil || uint64(st.Dev) != device {
		unix.Close(fd)
		if err == nil {
			err = fmt.Errorf("%w: nested mount at LaunchAgents path %q", ErrContamination, name)
		}
		return -1, err
	}
	return fd, nil
}

// clearSameDevice checks (remove=false) or removes (remove=true) the contents
// of the directory fd, which is on device. Unlinks happen only in directories
// whose open descriptor was verified to be on device, so no removal can reach
// into another filesystem.
func clearSameDevice(ctx context.Context, fd int, device uint64, remove bool, statat func(int, string, *unix.Stat_t, int) error, depth int) error {
	if depth > 64 {
		return fmt.Errorf("%w: LaunchAgents tree too deep", ErrContamination)
	}
	// A fresh open file description reads from the start on every pass.
	listFD, err := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	dir := os.NewFile(uintptr(listFD), "LaunchAgents")
	defer dir.Close()
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return err
	}
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return err
		}
		var st unix.Stat_t
		if err := statat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue
			}
			return err
		}
		if uint64(st.Dev) != device {
			return fmt.Errorf("%w: nested mount at LaunchAgents entry %q", ErrContamination, name)
		}
		if st.Mode&unix.S_IFMT == unix.S_IFDIR {
			child, err := openSameDevice(fd, name, device, statat)
			if err != nil {
				return err
			}
			err = clearSameDevice(ctx, child, device, remove, statat, depth+1)
			unix.Close(child)
			if err != nil {
				return err
			}
			if remove {
				if err := unix.Unlinkat(fd, name, unix.AT_REMOVEDIR); err != nil && !errors.Is(err, unix.ENOENT) {
					return err
				}
			}
			continue
		}
		if remove {
			if err := unix.Unlinkat(fd, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
				return err
			}
		}
	}
	return nil
}

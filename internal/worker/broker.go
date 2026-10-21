package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"
	"time"

	"github.com/jerryfane/macserve/internal/hostguard"
)

// ProcessIdentity is a kernel start identity, not a process name or an observed
// PID alone. Baselines are explicitly qualified by an administrator, never
// learned from processes found during worker startup. Service is optional
// launchd provenance verified at reset; see LaunchdService.
type ProcessIdentity struct {
	PID     int            `json:"pid"`
	Start   string         `json:"start"`
	Service LaunchdService `json:"service,omitzero"`
}

type GUIBaseline struct {
	JobUID            uint32              `json:"job_uid"`
	Boot              string              `json:"boot"`
	Processes         []ProcessIdentity   `json:"processes"`
	PersistenceSHA256 string              `json:"persistence_sha256"`
	Launchd           *LaunchdEnvironment `json:"launchd_environment"`
}

// LaunchdEnvironment is the root `environment` launchctl printed for the job's
// gui and user domains at reset. `launchctl setenv` there changes it and
// reaches every later launch in the domain; no process check can see that on
// a SIP-enabled host, where the kernel withholds the environment of system
// processes. The census refuses any later difference as contamination.
type LaunchdEnvironment struct {
	GUI  map[string]string `json:"gui"`
	User map[string]string `json:"user"`
}

type processScope struct {
	uid      int
	baseline GUIBaseline
	sample   processSampler
	// agents verifies launchd relaunches of absent audited processes. Nil
	// accepts none: every unaudited job-UID process is then residual.
	agents agentInspector
	// adopt is set only while worker-reset runs (see adoption).
	adopt    *adoption
	signal   func(context.Context, processSample, syscall.Signal) error
	interval time.Duration
	grace    time.Duration
}

func loadBaseline(path string, uid uint32) (GUIBaseline, error) {
	var baseline GUIBaseline
	if err := hostguard.RootConfig(path); err != nil {
		return baseline, err
	}
	file, err := os.Open(path)
	if err != nil {
		return baseline, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&baseline); err != nil {
		return baseline, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return baseline, errors.New("trailing GUI baseline data")
	}
	boot, err := bootIdentity()
	if err != nil {
		return baseline, err
	}
	if err := validateBaseline(baseline, uid, boot); err != nil {
		return baseline, err
	}
	return baseline, nil
}

func validateBaseline(b GUIBaseline, uid uint32, boot string) error {
	if b.JobUID != uid || b.Boot == "" || b.Boot != boot || len(b.Processes) == 0 || len(b.Processes) > 4096 {
		return errors.New("GUI baseline missing or belongs to another UID or boot; administrator reconciliation required")
	}
	if b.Launchd == nil {
		return errors.New("GUI baseline lacks the job launchd domain environment (written before v0.1.11); worker-reset required")
	}
	seen := make(map[int]bool, len(b.Processes))
	for _, p := range b.Processes {
		if p.PID <= 1 || p.Start == "" || seen[p.PID] || p.Service != (LaunchdService{}) && !p.Service.valid(p.PID) {
			return errors.New("invalid GUI baseline process identity")
		}
		seen[p.PID] = true
	}
	for _, p := range b.Processes {
		if p.Service.Domain == "pid" && !seen[p.Service.Owner] {
			return errors.New("GUI baseline XPC service owner is not audited")
		}
	}
	return nil
}

var (
	errBaselineChanged = errors.New("GUI baseline process changed; worker-reset required")
	// errRelaunchUnverified is inconclusive, never contamination evidence: v0.1.8
	// refused the same state ("disappeared") without durable quarantine.
	errRelaunchUnverified = errors.New("audited GUI process exited and a surviving job process could not be verified as its launchd relaunch; worker-reset required")
)

// processCensus is one snapshot classified against the audited baseline.
// Unresolved means some audited process is gone without a verified launchd
// relaunch in this snapshot. relaunched maps such an absent audited PID to
// its verified relaunch.
type processCensus struct {
	residual   []processSample
	unresolved bool
	relaunched map[int]processSample
}

// census classifies job-UID processes against the audited baseline. An audited
// PID now held by another UID or a zombie is refused. An audited PID that is
// simply absent is not: launchd-managed Apple helpers exit on their own, and a
// job can only end its own UID's processes, which hides or retains nothing. A
// new process stands in for an absent one only as launchd's verified relaunch
// of a recorded system service (see respawned); that includes a relaunch that
// lands on the exited audited PID number. Any other holder of an audited PID
// number is refused as a changed baseline. While worker-reset runs (s.adopt),
// the recorded unselected instances are residual although audited, and a new
// system LaunchAgent that launchd started may be adopted (see adoption).
func (s *processScope) census(ctx context.Context, samples []processSample) (processCensus, error) {
	if err := s.launchdUnchanged(ctx); err != nil {
		return processCensus{}, err
	}
	absent := make(map[int]string, len(s.baseline.Processes))
	for _, p := range s.baseline.Processes {
		absent[p.PID] = p.Start
	}
	var c processCensus
	var reused []int
	for _, p := range samples {
		if start, ok := absent[p.pid]; ok {
			if p.uid != s.uid || p.zombie || p.start == "" {
				return processCensus{}, errBaselineChanged
			}
			if p.start == start {
				delete(absent, p.pid)
				if s.adopt != nil && s.adopt.terminate[p.pid] == start {
					c.residual = append(c.residual, p)
				}
				continue
			}
			reused = append(reused, p.pid)
			c.residual = append(c.residual, p)
			continue
		}
		if p.uid != s.uid || p.zombie {
			continue
		}
		if p.pid <= 1 || p.start == "" {
			return processCensus{}, errors.New("job process identity unavailable")
		}
		c.residual = append(c.residual, p)
	}
	if len(absent) != 0 && len(c.residual) != 0 && s.agents != nil {
		c.residual, c.relaunched = respawned(ctx, s.agents, s.uid, s.baseline, absent, c.residual)
	}
	for _, pid := range reused {
		if slices.ContainsFunc(c.residual, func(p processSample) bool { return p.pid == pid }) {
			return processCensus{}, errBaselineChanged
		}
	}
	if s.adopt != nil && len(c.residual) != 0 && s.agents != nil {
		var adopted []ProcessIdentity
		c.residual, adopted = s.adopt.launchAgents(ctx, s.agents, s.uid, c.residual)
		// Adopted agents join the audited set at once, so later snapshots
		// verify their relaunches by recorded provenance, as for selections.
		s.baseline.Processes = append(s.baseline.Processes, adopted...)
		s.adopt.adopted = append(s.adopt.adopted, adopted...)
	}
	c.unresolved = len(c.relaunched) < len(absent)
	return c, nil
}

// launchdUnchanged refuses when the environment launchctl prints for the job's
// gui or user domain differs from the one recorded at reset (see
// LaunchdEnvironment); a difference is contamination evidence. A job that
// sets a variable, has launchd launch a service and unsets it again before
// this check runs is not seen here; LaunchdService.InheritedSHA256 then
// refuses that relaunch if launchctl prints the variable for it.
func (s *processScope) launchdUnchanged(ctx context.Context) error {
	// Every loaded or published baseline carries the record (validateBaseline);
	// only a scope no baseline was ever loaded into has none.
	if s.baseline.Launchd == nil {
		return nil
	}
	if s.agents == nil {
		return errors.New("job launchd domain environment unavailable")
	}
	now, err := launchdEnvironment(ctx, s.agents, s.uid)
	if err != nil {
		return err
	}
	if !maps.Equal(now.GUI, s.baseline.Launchd.GUI) || !maps.Equal(now.User, s.baseline.Launchd.User) {
		return fmt.Errorf("%w: job launchd domain environment changed since worker-reset (launchctl setenv)", ErrContamination)
	}
	return nil
}

// residual returns job-UID processes outside the audited baseline (see census).
func (s *processScope) residual(ctx context.Context, samples []processSample) ([]processSample, error) {
	c, err := s.census(ctx, samples)
	return c.residual, err
}

// quiesce terminates residual job processes. Processes that survive the
// deadline are contamination evidence only when every audited process is
// present or verifiably relaunched. If one is gone without a verified relaunch,
// a survivor may be launchd bringing it back (KeepAlive) in a way this host
// could not verify, so cleanup fails without durable quarantine, as in v0.1.8.
func (s *processScope) quiesce(ctx context.Context) error {
	termUntil := time.Now().Add(s.grace)
	// Require a second empty snapshot after a settling interval. Never waive a
	// failed observation, signal, changed baseline or deadline as successful cleanup.
	empty := false
	for {
		if err := ctx.Err(); err != nil {
			return errors.Join(ErrCleanup, err)
		}
		samples, err := s.sample(ctx)
		if err != nil {
			return errors.Join(ErrCleanup, err)
		}
		c, err := s.census(ctx, samples)
		if err != nil {
			return errors.Join(ErrCleanup, err)
		}
		if len(c.residual) == 0 {
			if empty {
				return nil
			}
			empty = true
		} else {
			if !time.Now().Before(termUntil.Add(s.grace)) {
				if c.unresolved {
					return errors.Join(ErrCleanup, errRelaunchUnverified)
				}
				return fmt.Errorf("%w: job processes remain after termination", ErrContamination)
			}
			empty = false
			sig := syscall.SIGTERM
			if !time.Now().Before(termUntil) {
				sig = syscall.SIGKILL
			}
			for _, p := range c.residual {
				if err := s.signal(ctx, p, sig); err != nil {
					return errors.Join(ErrCleanup, err)
				}
			}
		}
		timer := time.NewTimer(s.interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.Join(ErrCleanup, ctx.Err())
		case <-timer.C:
		}
	}
}

func (r *nativeRunner) Quiesce(ctx context.Context) error {
	if r.scope == nil {
		return errors.New("protected job process scope is required")
	}
	if err := r.loadBaseline(); err != nil {
		return err
	}
	return r.scope.quiesce(ctx)
}

// NewNativeRunner is only a root broker. There is no production same-UID mode.
func NewNativeRunner(options Options) (Runner, error) {
	if err := hostguard.BrokerIdentity(options.JobUID, options.JobGID, options.ControllerUID, options.OwnerUID); err != nil {
		return nil, err
	}
	for _, path := range []string{options.HelperPath} {
		if err := hostguard.RootConfig(path); err != nil {
			return nil, err
		}
	}
	for _, path := range []string{options.Root, options.ExportRoot, options.WorkspaceRoot} {
		if err := hostguard.RootDirectory(path); err != nil {
			return nil, err
		}
	}
	runner := newProcessRunner()
	runner.uid = int(options.JobUID)
	runner.sample = func(ctx context.Context) ([]processSample, error) {
		return sampleProcessesAs(ctx, &syscall.Credential{Uid: options.JobUID, Gid: options.JobGID, Groups: []uint32{}})
	}
	runner.command = func(command Command) *exec.Cmd {
		args := []string{"asuser", strconv.FormatUint(uint64(options.JobUID), 10), options.HelperPath, "_job-exec", strconv.FormatUint(uint64(options.JobUID), 10), strconv.FormatUint(uint64(options.JobGID), 10), command.Dir, command.Executable}
		args = append(args, command.Args...)
		return exec.Command("/bin/launchctl", args...)
	}
	runner.launchDir = "/"
	// Baseline inspection is deliberately deferred: sealed pending evidence must
	// remain deliverable even when a reboot or GUI restart requires reconciliation.
	runner.baselinePath = options.BaselinePath
	runner.persistencePath = options.PersistencePath
	runner.persistence = nativePersistenceInspector(options)
	runner.console = func() error { return hostguard.CheckConsole(options.OwnerUID) }
	runner.scope = &processScope{uid: runner.uid, sample: identityProcesses, agents: nativeAgents{}, interval: 50 * time.Millisecond, grace: 500 * time.Millisecond}
	runner.scope.signal = func(ctx context.Context, p processSample, sig syscall.Signal) error {
		// The kernel checks the job UID, not root, at the signal operation itself.
		// A PID reused by the owner/controller/another UID can never be signalled.
		cmd := exec.CommandContext(ctx, options.HelperPath, "_job-signal", strconv.Itoa(p.pid), p.start, strconv.Itoa(int(sig)))
		cmd.Dir = "/"
		cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: options.JobUID, Gid: options.JobGID, Groups: []uint32{}}}
		cmd.WaitDelay = 100 * time.Millisecond
		return cmd.Run()
	}
	runner.signalProcess = runner.scope.signal
	return runner, nil
}

type childCredentials struct {
	uid, euid, gid, egid func() int
	groups               func([]int) error
	setgid, setuid       func(int) error
}

func dropJobPrivileges(uid, gid int, c childCredentials) error {
	if c.uid() != 0 || c.euid() != 0 {
		return errors.New("private child must begin as root")
	}
	if err := c.groups([]int{}); err != nil {
		return err
	}
	if err := c.setgid(gid); err != nil {
		return err
	}
	if err := c.setuid(uid); err != nil {
		return err
	}
	if c.uid() != uid || c.euid() != uid || c.gid() != gid || c.egid() != gid {
		return errors.New("job privilege drop incomplete")
	}
	return nil
}

// PrivateJobExec is an exec-only root child reached after launchctl asuser has
// attached to the pre-existing GUI domain. Untrusted executable, cwd and loader
// activity happen only after supplementary groups and all UID/GID privileges drop.
func PrivateJobExec(args []string) error {
	if os.Getuid() != 0 || os.Geteuid() != 0 || len(args) < 4 {
		return errors.New("private job exec requires broker root identity")
	}
	uid, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil || uid < 501 {
		return errors.New("invalid job UID")
	}
	gid, err := strconv.ParseUint(args[1], 10, 32)
	if err != nil || gid == 0 {
		return errors.New("invalid job GID")
	}
	if !filepath.IsAbs(args[2]) || !filepath.IsAbs(args[3]) {
		return errors.New("private job paths must be absolute")
	}
	if err := dropJobPrivileges(int(uid), int(gid), childCredentials{uid: os.Getuid, euid: os.Geteuid, gid: os.Getgid, egid: os.Getegid, groups: syscall.Setgroups, setgid: syscall.Setgid, setuid: syscall.Setuid}); err != nil {
		return err
	}
	if err := os.Chdir(args[2]); err != nil {
		return err
	}
	executable, argv := backgroundCommand(args[3], args[4:])
	return syscall.Exec(executable, append([]string{executable}, argv...), os.Environ())
}

func PrivateJobSignal(args []string) error {
	if os.Geteuid() == 0 || os.Getuid() != os.Geteuid() || len(args) != 3 {
		return errors.New("private signal requires unprivileged job identity")
	}
	pid, err := strconv.Atoi(args[0])
	if err != nil || pid <= 1 || pid == os.Getpid() {
		return errors.New("invalid signal PID")
	}
	sig, err := strconv.Atoi(args[2])
	if err != nil || (syscall.Signal(sig) != syscall.SIGTERM && syscall.Signal(sig) != syscall.SIGKILL) {
		return errors.New("invalid cleanup signal")
	}
	samples, err := identityProcesses(context.Background())
	if err != nil {
		return err
	}
	return signalIdentity(samples, pid, args[1], os.Geteuid(), syscall.Signal(sig), syscall.Kill)
}

func signalIdentity(samples []processSample, pid int, start string, uid int, sig syscall.Signal, kill func(int, syscall.Signal) error) error {
	if uid == 0 || pid <= 1 || start == "" {
		return errors.New("unsafe signal identity")
	}
	for _, p := range samples {
		if p.pid != pid {
			continue
		}
		if p.uid != uid || p.start != start {
			return errors.New("signal target identity changed")
		}
		if p.zombie {
			return nil
		}
		if err := kill(pid, sig); err != nil && !errors.Is(err, syscall.ESRCH) {
			return fmt.Errorf("signal job process: %w", err)
		}
		return nil
	}
	return nil
}

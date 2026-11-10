package worker

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Lane attribution: which job-UID processes belong to which concurrently
// running job (design: PARALLEL-DESIGN.md §3). Processes of one UID cannot be
// told apart by the kernel, and process groups do not help (xcodebuild's
// children start their own), so the broker labels process instances (PID and
// kernel start time) by lineage:
//
//   - seeds: every command root the broker starts for the job (its direct
//     child, which keeps its PID through launchctl asuser, _job-exec and the
//     tool's exec); every launchd_sim whose arguments name a device directory
//     .../CoreSimulator/Devices/<UDID>/ of a UDID the job created; every
//     process whose executable lies under the job's workspace or one of its
//     device directories;
//   - propagation: a process first seen with a labelled parent instance
//     (same PID, started no later than the child) inherits its label;
//   - labels are sticky for the instance's lifetime: a daemon reparented to
//     launchd keeps its job.
//
// Unlabelled instances are judged by the existing census (baseline, verified
// relaunches, tolerated Apple and developer-tool launches); what remains is
// unattributed. The broker's own job-UID helpers (the _job-signal child) are
// neither: they are the broker's direct children that are not command roots.
type laneTracker struct {
	mu sync.Mutex
	// broker is the broker's PID: the parent of every command root.
	broker int
	uid    int
	// workspaceRoot holds each job's workspace <workspaceRoot>/<jobID>.
	workspaceRoot string
	// describe reads an instance's executable path and, for launchd_sim
	// only (wantArgs), its NUL-joined arguments.
	describe func(pid int, wantArgs bool) (processDescription, error)
	jobs     map[string]*laneJob
	labels   map[processInstance]string
	// conflicts are instances two jobs' seeds claimed; they are never any
	// job's and are judged as unattributed.
	conflicts map[processInstance]bool
	// lineage reads an instance's kernel unique ID and its parent's at fork
	// (darwin p_puniqueid); nil follows the PPID alone. unique caches it per
	// instance; uniqueLabel maps every unique ID ever labelled, while any job
	// runs, to its label, so a process whose parent exited and was never
	// reparented in a sample keeps its job.
	lineage     func(pid int, start string) (uint64, uint64, error)
	unique      map[processInstance][2]uint64
	uniqueLabel map[uint64]string
}

type processInstance struct {
	pid   int
	start string
}

type processDescription struct {
	executable string
	args       string
}

type laneJob struct {
	started time.Time
	// roots are command root PIDs the broker started and has not reaped.
	roots map[int]bool
	udids map[string]bool
}

// laneLabelConflict marks an instance two jobs claim.
const laneLabelConflict = "\x00conflict"

func newLaneTracker(broker, uid int, workspaceRoot string, describe func(int, bool) (processDescription, error)) *laneTracker {
	// The kernel reports executables by real path (/var is /private/var).
	if real, err := filepath.EvalSymlinks(workspaceRoot); err == nil && workspaceRoot != "" {
		workspaceRoot = real
	}
	return &laneTracker{broker: broker, uid: uid, workspaceRoot: workspaceRoot, describe: describe, jobs: map[string]*laneJob{}, labels: map[processInstance]string{}, conflicts: map[processInstance]bool{}, unique: map[processInstance][2]uint64{}, uniqueLabel: map[uint64]string{}}
}

func (t *laneTracker) begin(jobID string, started time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.jobs[jobID] = &laneJob{started: started, roots: map[int]bool{}, udids: map[string]bool{}}
}

// end forgets jobID's seeds. Labels of its live instances stay, so a process
// that outlives the job's cleanup is still its survivor, never unattributed.
func (t *laneTracker) end(jobID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.jobs, jobID)
	if len(t.jobs) == 0 {
		clear(t.uniqueLabel)
	}
}

func (t *laneTracker) addRoot(jobID string, pid int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if j := t.jobs[jobID]; j != nil {
		j.roots[pid] = true
	}
}

// removeRoot forgets a reaped command root: its PID may be reused.
func (t *laneTracker) removeRoot(jobID string, pid int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if j := t.jobs[jobID]; j != nil {
		delete(j.roots, pid)
	}
}

func (t *laneTracker) addDevice(jobID, udid string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if j := t.jobs[jobID]; j != nil {
		j.udids[strings.ToUpper(udid)] = true
	}
}

func (t *laneTracker) has(jobID string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.jobs[jobID] != nil
}

func (t *laneTracker) active() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.jobs) != 0
}

var deviceDirectory = regexp.MustCompile(`/CoreSimulator/Devices/([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})/`)

// startBefore reports whether start token a (kernel "sec:usec") is earlier
// than b. Unparseable tokens are never earlier.
func startBefore(a, b string) bool {
	as, au, aok := parseStart(a)
	bs, bu, bok := parseStart(b)
	if !aok || !bok {
		return false
	}
	return as < bs || as == bs && au < bu
}

func parseStart(s string) (int64, int64, bool) {
	sec, usec, ok := strings.Cut(s, ":")
	if !ok {
		return 0, 0, false
	}
	a, err1 := strconv.ParseInt(sec, 10, 64)
	b, err2 := strconv.ParseInt(usec, 10, 64)
	return a, b, err1 == nil && err2 == nil
}

func startTime(s string) (time.Time, bool) {
	sec, usec, ok := parseStart(s)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(sec, usec*1000), true
}

// update labels the instances of samples (one full process table) and
// forgets instances no longer listed.
func (t *laneTracker) update(samples []processSample) {
	t.mu.Lock()
	defer t.mu.Unlock()
	byPID := make(map[int]processSample, len(samples))
	for _, p := range samples {
		byPID[p.pid] = p
	}
	live := make(map[processInstance]bool, len(samples))
	for _, p := range samples {
		live[processInstance{p.pid, p.start}] = true
	}
	for i := range t.labels {
		if !live[i] {
			delete(t.labels, i)
		}
	}
	for i := range t.conflicts {
		if !live[i] {
			delete(t.conflicts, i)
		}
	}
	for i := range t.unique {
		if !live[i] {
			delete(t.unique, i)
		}
	}
	// A labelled instance's unique ID is recorded before it can exit
	// unsampled again; a new instance's lineage is read once.
	earliest, any := time.Time{}, false
	for _, j := range t.jobs {
		if !any || j.started.Before(earliest) {
			earliest, any = j.started, true
		}
	}
	if t.lineage != nil && any {
		for _, p := range samples {
			key := processInstance{p.pid, p.start}
			if p.uid != t.uid || p.zombie || p.pid <= 1 {
				continue
			}
			if _, ok := t.unique[key]; ok {
				continue
			}
			if started, ok := startTime(p.start); !ok || started.Before(earliest.Add(-time.Second)) {
				if _, labelled := t.labels[key]; !labelled {
					continue
				}
			}
			if u, parent, err := t.lineage(p.pid, p.start); err == nil {
				t.unique[key] = [2]uint64{u, parent}
			}
		}
	}
	visiting := map[int]bool{}
	var resolve func(p processSample) string
	resolve = func(p processSample) string {
		key := processInstance{p.pid, p.start}
		if label, ok := t.labels[key]; ok {
			if ids, known := t.unique[key]; known {
				t.uniqueLabel[ids[0]] = label
			}
			return label
		}
		if t.conflicts[key] || p.uid != t.uid || p.start == "" || p.pid <= 1 || visiting[p.pid] {
			return ""
		}
		visiting[p.pid] = true
		defer delete(visiting, p.pid)
		seed := t.seed(p)
		var inherited string
		if parent, ok := byPID[p.parent]; ok && p.parent > 1 && !startBefore(p.start, parent.start) {
			inherited = resolve(parent)
		}
		label := seed
		switch {
		case seed == laneLabelConflict || seed != "" && inherited != "" && seed != inherited:
			t.conflicts[key] = true
			return ""
		case seed == "":
			label = inherited
		}
		ids, known := t.unique[key]
		if label == "" && known {
			// The parent at fork, by kernel unique ID, even when it has
			// exited and this process was reparented.
			label = t.uniqueLabel[ids[1]]
		}
		if label != "" {
			t.labels[key] = label
			if known {
				t.uniqueLabel[ids[0]] = label
			}
		}
		return label
	}
	for _, p := range samples {
		if p.uid == t.uid && !p.zombie {
			resolve(p)
		}
	}
}

// seed is the job whose seed claims p, laneLabelConflict when two do, or "".
// Callers hold t.mu.
func (t *laneTracker) seed(p processSample) string {
	found := ""
	claim := func(job string) {
		if found == "" || found == job {
			found = job
		} else {
			found = laneLabelConflict
		}
	}
	started, startOK := startTime(p.start)
	for id, j := range t.jobs {
		if j.roots[p.pid] && p.parent == t.broker {
			claim(id)
		}
	}
	// Descriptions are read only for instances started while some job ran:
	// the audited session and older services are never seeds.
	recent := false
	for _, j := range t.jobs {
		if startOK && !started.Before(j.started.Add(-time.Second)) {
			recent = true
		}
	}
	if !recent || t.describe == nil {
		return found
	}
	// Never cached: an exec keeps the instance (PID and start) but changes
	// its executable, so an unlabelled instance is described every update.
	d, err := t.describe(p.pid, false)
	if err != nil {
		return found
	}
	if filepath.Base(d.executable) == "launchd_sim" {
		if full, err := t.describe(p.pid, true); err == nil {
			d = full
		}
	}
	for id, j := range t.jobs {
		if startOK && started.Before(j.started.Add(-time.Second)) {
			continue
		}
		if t.workspaceRoot != "" && strings.HasPrefix(d.executable, filepath.Join(t.workspaceRoot, id)+"/") {
			claim(id)
		}
		for _, text := range []string{d.executable, d.args} {
			for _, m := range deviceDirectory.FindAllStringSubmatch(text, -1) {
				if j.udids[strings.ToUpper(m[1])] {
					claim(id)
				}
			}
		}
	}
	return found
}

// laneClass splits samples: every live job-UID instance labelled jobID,
// every instance labelled with any job, and the broker's own helpers.
func (t *laneTracker) classify(samples []processSample, jobID string) (mine []processSample, labelled, helpers map[processInstance]bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	labelled, helpers = map[processInstance]bool{}, map[processInstance]bool{}
	for _, p := range samples {
		if p.uid != t.uid || p.zombie {
			continue
		}
		key := processInstance{p.pid, p.start}
		if label, ok := t.labels[key]; ok {
			labelled[key] = true
			if label == jobID {
				mine = append(mine, p)
			}
			continue
		}
		if p.parent == t.broker && !t.conflicts[key] {
			helpers[key] = true
		}
	}
	return mine, labelled, helpers
}

// footprint is jobID's charged footprint in samples (KiB) and the job UID's
// whole footprint.
func (t *laneTracker) footprint(samples []processSample, jobID string) (int64, int64, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	var mine, total int64
	for _, p := range samples {
		if p.uid != t.uid || p.zombie {
			continue
		}
		if p.footprintKiB < 0 || p.footprintKiB > (1<<62)-total {
			return 0, 0, errors.New("invalid worker memory sample")
		}
		total += p.footprintKiB
		if t.labels[processInstance{p.pid, p.start}] == jobID {
			mine += p.footprintKiB
		}
	}
	return mine, total, nil
}

// laneRunner is the runner side of concurrent jobs. A runner without it
// supports only one job at a time.
type laneRunner interface {
	Runner
	// BeginJob starts attributing processes to jobID; EndJob stops seeding.
	BeginJob(jobID string, started time.Time)
	EndJob(jobID string)
	// AttachDevice records a simulator UDID jobID created.
	AttachDevice(jobID, udid string)
	// QuiesceJob terminates jobID's labelled processes only: never a
	// baseline, tolerated, unattributed or another job's process. A survivor
	// is contamination.
	QuiesceJob(ctx context.Context, jobID string) error
	// Residue describes each job-UID process no job's lineage claims and the
	// census neither audits nor tolerates (unattributed), without signalling
	// any: one entry each, none when there is no residue.
	Residue(ctx context.Context) ([]string, error)
	// LaneAdmission is Admission while other jobs run: their labelled
	// processes are not residual, and an unattributed process refuses with
	// ErrDrain instead of contamination.
	LaneAdmission(ctx context.Context) error
}

func (r *nativeRunner) laneTracker() *laneTracker {
	r.lanesOnce.Do(func() {
		if r.lanes == nil {
			r.lanes = newLaneTracker(syscall.Getpid(), r.uid, r.workspaceRoot, r.describe)
			r.lanes.lineage = r.lineage
		}
	})
	return r.lanes
}

func (r *nativeRunner) BeginJob(jobID string, started time.Time) {
	r.laneTracker().begin(jobID, started)
	r.startLaneSampler()
}

func (r *nativeRunner) EndJob(jobID string) { r.laneTracker().end(jobID) }

func (r *nativeRunner) AttachDevice(jobID, udid string) { r.laneTracker().addDevice(jobID, udid) }

// startLaneSampler keeps labels current while any job runs, so a child is
// first seen while its parent is still listed (laneSampleInterval bounds
// the reparenting window).
func (r *nativeRunner) startLaneSampler() {
	r.samplerMu.Lock()
	defer r.samplerMu.Unlock()
	if r.samplerRunning {
		return
	}
	r.samplerRunning = true
	tracker := r.laneTracker()
	go func() {
		ticker := time.NewTicker(laneSampleInterval)
		defer ticker.Stop()
		for range ticker.C {
			r.samplerMu.Lock()
			if !tracker.active() {
				r.samplerRunning = false
				r.samplerMu.Unlock()
				return
			}
			r.samplerMu.Unlock()
			ctx, cancel := context.WithTimeout(context.Background(), r.sampleTimeout)
			samples, err := r.identities(ctx)
			cancel()
			if err == nil {
				tracker.update(samples)
			}
		}
	}()
}

const laneSampleInterval = 100 * time.Millisecond

func (r *nativeRunner) identities(ctx context.Context) ([]processSample, error) {
	if r.scope != nil && r.scope.sample != nil {
		return r.scope.sample(ctx)
	}
	return r.inspect(ctx)
}

// QuiesceJob is the lane quiesce: the quiesce algorithm (processScope.quiesce:
// SIGTERM in the first grace, SIGKILL after, an instance listed two graces
// after its first sighting is a survivor, settle after ten graces) restricted
// to jobID's labelled instances. Tolerated launches are never signalled here:
// they serve every job.
func (r *nativeRunner) QuiesceJob(ctx context.Context, jobID string) error {
	if r.scope == nil || r.scope.signal == nil {
		return errors.New("protected job process scope is required")
	}
	tracker := r.laneTracker()
	s := r.scope
	begun := time.Now()
	termUntil := begun.Add(s.grace)
	settleUntil := begun.Add(quiesceSettleGraces * s.grace)
	firstSeen := map[processInstance]time.Time{}
	empty := false
	for {
		if err := ctx.Err(); err != nil {
			return errors.Join(ErrCleanup, err)
		}
		sampled := time.Now()
		samples, err := s.sample(ctx)
		if err != nil {
			return errors.Join(ErrCleanup, err)
		}
		tracker.update(samples)
		mine, _, _ := tracker.classify(samples, jobID)
		if len(mine) == 0 {
			if empty {
				return nil
			}
			empty = true
		} else {
			empty = false
			survivor := false
			for _, p := range mine {
				key := processInstance{p.pid, p.start}
				first, seen := firstSeen[key]
				if !seen {
					first = sampled
					firstSeen[key] = first
				}
				survivor = survivor || !sampled.Before(first.Add(2*s.grace))
			}
			if survivor {
				return s.contaminated("job processes remain after lane termination", processCensus{residual: mine})
			}
			if !sampled.Before(settleUntil) {
				return s.contaminated("job processes keep appearing after lane termination", processCensus{residual: mine})
			}
			sig := syscall.SIGTERM
			if !time.Now().Before(termUntil) {
				sig = syscall.SIGKILL
			}
			for _, p := range mine {
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

// laneCensus is the census of samples without any job's labelled instances
// and the broker's helpers: the processes no running job accounts for.
func (r *nativeRunner) laneCensus(ctx context.Context, samples []processSample) (processCensus, error) {
	tracker := r.laneTracker()
	tracker.update(samples)
	_, labelled, helpers := tracker.classify(samples, "")
	rest := make([]processSample, 0, len(samples))
	for _, p := range samples {
		key := processInstance{p.pid, p.start}
		if !labelled[key] && !helpers[key] {
			rest = append(rest, p)
		}
	}
	return r.scope.census(ctx, rest)
}

func (r *nativeRunner) Residue(ctx context.Context) ([]string, error) {
	if r.scope == nil {
		return nil, errors.New("protected job process scope is required")
	}
	if err := r.loadBaseline(); err != nil {
		return nil, err
	}
	count := func() (map[processInstance]processSample, bool, error) {
		samples, err := r.scope.sample(ctx)
		if err != nil {
			return nil, false, err
		}
		c, err := r.laneCensus(ctx, samples)
		if err != nil {
			return nil, false, err
		}
		found := make(map[processInstance]processSample, len(c.residual))
		for _, p := range c.residual {
			found[processInstance{p.pid, p.start}] = p
		}
		return found, c.unresolved, nil
	}
	residue, unresolved, err := settledResidue(ctx, count)
	if err != nil {
		return nil, err
	}
	entries := make([]string, 0, len(residue)+1)
	for _, p := range residue {
		entries = append(entries, r.residueEntry(p))
	}
	if unresolved {
		entries = append(entries, "unresolved census: an audited process is gone without a verified relaunch")
	}
	return entries, nil
}

// residueEntry names an unattributed process for the root-only worker log:
// its PID, kernel parent, start, executable and arguments, each bounded.
func (r *nativeRunner) residueEntry(p processSample) string {
	entry := fmt.Sprintf("pid=%d ppid=%d start=%s", p.pid, p.parent, p.start)
	if r.describe == nil {
		return entry + " command=unavailable"
	}
	d, err := r.describe(p.pid, true)
	if err != nil {
		return entry + " command=unavailable"
	}
	return entry + fmt.Sprintf(" exe=%q args=%q", clip(d.executable, contaminationPathBytes), clip(strings.ReplaceAll(d.args, "\x00", " "), residueArgsBytes))
}

const residueArgsBytes = 400

// settledResidue returns the residual instances listed by count both now
// and residueSettle later, sorted by PID. unresolved reports a second census
// that was unresolved with no such instance: it counts as one.
func settledResidue(ctx context.Context, count func() (map[processInstance]processSample, bool, error)) ([]processSample, bool, error) {
	first, unresolved, err := count()
	if err != nil || len(first) == 0 && !unresolved {
		return nil, false, err
	}
	// Short-lived build helpers (SwiftPM's double-forked git, live
	// 2026-11-10) can be listed in one snapshot: only an instance still
	// running residueSettle later is residue.
	timer := time.NewTimer(residueSettle)
	select {
	case <-ctx.Done():
		timer.Stop()
		return nil, false, ctx.Err()
	case <-timer.C:
	}
	second, unresolved, err := count()
	if err != nil {
		return nil, false, err
	}
	var persisting []processSample
	for key, p := range second {
		if _, ok := first[key]; ok {
			persisting = append(persisting, p)
		}
	}
	slices.SortFunc(persisting, func(a, b processSample) int { return a.pid - b.pid })
	// An audited process gone without a verified relaunch: nothing here may
	// judge that while jobs run.
	return persisting, len(persisting) == 0 && unresolved, nil
}

// residueSettle is how long an unattributed process must persist to count
// as residue while jobs run.
var residueSettle = time.Second

func (r *nativeRunner) LaneAdmission(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, persistenceAdmissionTimeout)
	defer cancel()
	if r.scope == nil || r.persistence == nil {
		return errors.New("native persistence inspection unavailable")
	}
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
	cancel()
	quietCtx, quietCancel := context.WithTimeout(parent, r.scope.childWait+persistenceAdmissionTimeout)
	defer quietCancel()
	err := r.scope.observeQuietWith(quietCtx, r.laneCensus)
	if hasContamination(err) || errors.Is(err, errRelaunchUnverified) {
		// While other jobs run, an unattributed process cannot be judged:
		// the full quiesce at idle decides (see Engine.Recover).
		return fmt.Errorf("%w: %s", ErrDrain, PublicReason(err))
	}
	return err
}

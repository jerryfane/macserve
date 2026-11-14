package worker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/hostguard"
	"github.com/jerryfane/macserve/internal/model"
)

// laneFake is fakeRunner with lane attribution: it records which cleanup
// each job got and reports a configurable unattributed residue.
type laneFake struct {
	*fakeRunner
	mu      sync.Mutex
	events  []string
	residue int
	// gates blocks a job's recipe command until closed.
	gates map[string]chan struct{}
	// started is signalled when a job's recipe command starts.
	started chan string
}

func newLaneFake() *laneFake {
	f := &laneFake{fakeRunner: &fakeRunner{}, gates: map[string]chan struct{}{}, started: make(chan string, 8)}
	f.fakeRunner.hook = func(ctx context.Context, c Command, _, _ io.Writer) (bool, ProcessResult, error) {
		if c.Executable != "/usr/bin/xcodebuild" || len(c.Args) == 0 || c.Args[0] != "build" {
			return false, ProcessResult{}, nil
		}
		f.started <- c.JobID
		f.mu.Lock()
		gate := f.gates[c.JobID]
		f.mu.Unlock()
		if gate != nil {
			select {
			case <-gate:
			case <-ctx.Done():
				return true, ProcessResult{ExitCode: -1, CleanupOK: true}, ctx.Err()
			}
		}
		return false, ProcessResult{}, nil
	}
	f.fakeRunner.quiesce = func(ctx context.Context) error { f.event("quiesce"); return ctx.Err() }
	return f
}

func (f *laneFake) event(e string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e)
}

func (f *laneFake) take() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.events
	f.events = nil
	return out
}

func (f *laneFake) gate(job string) chan struct{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	ch := make(chan struct{})
	f.gates[job] = ch
	return ch
}

func (f *laneFake) Admission(ctx context.Context) error  { f.event("admission"); return ctx.Err() }
func (f *laneFake) BeginJob(job string, _ time.Time)     { f.event("begin " + job) }
func (f *laneFake) EndJob(job string)                    { f.event("end " + job) }
func (f *laneFake) AttachDevice(job, udid string)        { f.event("device " + job + " " + udid) }
func (f *laneFake) AdoptDevices(job string, _ time.Time) { f.event("adopt " + job) }
func (f *laneFake) QuiesceJob(ctx context.Context, job string) error {
	f.event("quiesce " + job)
	return ctx.Err()
}
func (f *laneFake) Residue(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	residue := make([]string, f.residue)
	for i := range residue {
		residue[i] = fmt.Sprintf("pid=%d exe=\"/usr/bin/leftover\"", 900+i)
	}
	return residue, nil
}
func (f *laneFake) LaneAdmission(ctx context.Context) error {
	f.event("lane-admission")
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.residue != 0 {
		return ErrDrain
	}
	return ctx.Err()
}

func laneEngine(t *testing.T, runner Runner, lanes int) *Engine {
	t.Helper()
	base := t.TempDir()
	engine, err := New(Options{Root: filepath.Join(base, "worker"), ExportRoot: filepath.Join(base, "exports"), WorkspaceRoot: filepath.Join(base, "workspaces"), Runner: runner, Lanes: lanes})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { engine.Close() })
	return engine
}

func fixtureLaneJob(t *testing.T, id string, kind model.Kind) model.Job {
	job := fixtureJob(t, kind)
	job.ID, job.LeaseToken = id, "lease-"+id
	return job
}

type laneOutcome struct {
	result Result
	err    error
}

func runLane(engine *Engine, job model.Job, source Source, data []byte) chan laneOutcome {
	out := make(chan laneOutcome, 1)
	go func() {
		result, err := engine.Execute(context.Background(), job, source, bytes.NewReader(data), nil)
		out <- laneOutcome{result, err}
	}()
	return out
}

func contains(events []string, want string) bool { return slices.Contains(events, want) }

// Two jobs run at once: the second is admitted beside the first without the
// full preflight quiesce, the first to finish stops only its own processes
// (idle verdict not_required) and lists the other as overlapping, and the
// last ends alone with the full quiesce and admission (verdict clean).
func TestLanesRunTwoJobsWithPerJobCleanup(t *testing.T) {
	runner := newLaneFake()
	engine := laneEngine(t, runner, 2)
	source, data := sourceFixture(t)
	gateA, gateB := runner.gate("job-a"), runner.gate("job-b")
	a := runLane(engine, fixtureLaneJob(t, "job-a", model.Build), source, data)
	if got := <-runner.started; got != "job-a" {
		t.Fatalf("started %s", got)
	}
	if events := runner.take(); !contains(events, "admission") || !contains(events, "quiesce") {
		t.Fatalf("solo start skipped full admission or preflight: %v", events)
	}
	b := runLane(engine, fixtureLaneJob(t, "job-b", model.Build), source, data)
	if got := <-runner.started; got != "job-b" {
		t.Fatalf("started %s", got)
	}
	if events := runner.take(); !contains(events, "lane-admission") || contains(events, "quiesce") || contains(events, "admission") {
		t.Fatalf("second job not admitted as a lane: %v", events)
	}
	close(gateA)
	first := <-a
	if first.err != nil || first.result.State != model.Succeeded || !first.result.CleanupOK {
		t.Fatalf("first job: %+v %v", first.result, first.err)
	}
	events := runner.take()
	if !contains(events, "quiesce job-a") || contains(events, "quiesce") || contains(events, "quiesce job-b") {
		t.Fatalf("first job's cleanup touched more than its lane: %v", events)
	}
	c := first.result.Concurrency
	if c == nil || c.IdleVerdict != IdleNotRequired || c.Attribution != AttributionLineage || c.MaxLanes != 2 || len(c.OverlappedJobs) != 1 || c.OverlappedJobs[0].JobID != "job-b" {
		t.Fatalf("first job concurrency: %+v", c)
	}
	close(gateB)
	second := <-b
	if second.err != nil || second.result.State != model.Succeeded || !second.result.CleanupOK {
		t.Fatalf("second job: %+v %v", second.result, second.err)
	}
	events = runner.take()
	if !contains(events, "quiesce") || !contains(events, "admission") || contains(events, "quiesce job-b") {
		t.Fatalf("last job did not end with the full idle check: %v", events)
	}
	c = second.result.Concurrency
	if c.IdleVerdict != IdleClean || len(c.OverlappedJobs) != 1 || c.OverlappedJobs[0].JobID != "job-a" {
		t.Fatalf("second job concurrency: %+v", c)
	}
	requireVerifiedTreeUntilAck(t, engine, "job-a", source.Tree)
	requireVerifiedTreeUntilAck(t, engine, "job-b", source.Tree)
	if err := engine.LaneReady(context.Background()); err != nil {
		t.Fatalf("idle engine not ready: %v", err)
	}
}

// An unattributed process left when a job ends beside another may be the
// job's own (attribution is not complete): the engine records it, gives the
// deferred verdict with the job's own cleanup result (the client holds the
// completion until the idle check, see workerclient), and drains: no new job
// starts. The sibling finishes; Recover, at idle, runs the full quiesce and
// admits again (Studio v0.1.47, 2026-11-12: a passing unit_test failed for
// launchd's Problem Reporter and SetStoreUpdateService beside the other lane).
func TestLaneResidueDrainsUntilIdleQuiesce(t *testing.T) {
	runner := newLaneFake()
	engine := laneEngine(t, runner, 2)
	source, data := sourceFixture(t)
	gateA, gateB := runner.gate("job-a"), runner.gate("job-b")
	a := runLane(engine, fixtureLaneJob(t, "job-a", model.Build), source, data)
	<-runner.started
	b := runLane(engine, fixtureLaneJob(t, "job-b", model.Build), source, data)
	<-runner.started
	runner.mu.Lock()
	runner.residue = 1
	runner.mu.Unlock()
	close(gateA)
	first := <-a
	if first.err != nil || !first.result.CleanupOK || first.result.State != model.Succeeded || first.result.Reason != "" || first.result.Concurrency.IdleVerdict != IdleDeferred || first.result.Concurrency.UnattributedResidue != 1 {
		t.Fatalf("residue beside a sibling failed the job: %+v %v", first.result, first.err)
	}
	if err := engine.LaneReady(context.Background()); !errors.Is(err, ErrDrain) {
		t.Fatalf("draining engine ready: %v", err)
	}
	if _, err := engine.Execute(context.Background(), fixtureLaneJob(t, "job-c", model.Build), source, bytes.NewReader(data), nil); !errors.Is(err, ErrDrain) {
		t.Fatalf("draining engine started a job: %v", err)
	}
	if err := engine.Recover(context.Background()); !errors.Is(err, ErrBusy) {
		t.Fatalf("Recover ran beside a job: %v", err)
	}
	runner.mu.Lock()
	runner.residue = 0
	runner.mu.Unlock()
	close(gateB)
	if second := <-b; second.err != nil || !second.result.CleanupOK {
		t.Fatalf("sibling: %+v %v", second.result, second.err)
	}
	runner.take()
	// The sibling ended alone with the full check, which ends the drain.
	if err := engine.LaneReady(context.Background()); err != nil {
		t.Fatalf("drain survived the idle check: %v", err)
	}
	if err := engine.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// The drain LaneReady starts beside a running job names the unattributed
// processes (PID and command), so the host log shows what drained it.
func TestLaneReadyDrainNamesUnattributedProcesses(t *testing.T) {
	runner := newLaneFake()
	engine := laneEngine(t, runner, 2)
	source, data := sourceFixture(t)
	gate := runner.gate("job-a")
	a := runLane(engine, fixtureLaneJob(t, "job-a", model.Build), source, data)
	<-runner.started
	runner.mu.Lock()
	runner.residue = 2
	runner.mu.Unlock()
	err := engine.LaneReady(context.Background())
	if !errors.Is(err, ErrDrain) || !strings.Contains(err.Error(), `2 unattributed job-account process(es): pid=900 exe="/usr/bin/leftover"; pid=901 exe="/usr/bin/leftover"`) {
		t.Fatalf("drain does not name the processes: %v", err)
	}
	runner.mu.Lock()
	runner.residue = 0
	runner.mu.Unlock()
	close(gate)
	<-a
}

// When the last two jobs both end beside each other, nothing ran the full
// check: Recover runs the full quiesce before admitting.
func TestRecoverQuiescesAfterLaneOnlyEndings(t *testing.T) {
	runner := newLaneFake()
	engine := laneEngine(t, runner, 2)
	engine.mu.Lock()
	engine.idlePending = true
	engine.mu.Unlock()
	if err := engine.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if events := runner.take(); len(events) < 2 || events[0] != "quiesce" || !contains(events, "admission") {
		t.Fatalf("Recover after lane endings: %v", events)
	}
	if err := engine.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if events := runner.take(); contains(events, "quiesce") {
		t.Fatalf("Recover quiesced without a pending idle check: %v", events)
	}
}

// simulator_script and ios_archive jobs run alone, and nothing starts beside them.
func TestExclusiveKindsRunAlone(t *testing.T) {
	runner := newLaneFake()
	engine := laneEngine(t, runner, 3)
	source, data := sourceFixture(t)
	gate := runner.gate("job-a")
	a := runLane(engine, fixtureLaneJob(t, "job-a", model.Build), source, data)
	<-runner.started
	job := fixtureLaneJob(t, "job-x", model.Build)
	job.Request.Kind = model.SimulatorScript
	if _, err := engine.Execute(context.Background(), job, source, bytes.NewReader(data), nil); !errors.Is(err, ErrBusy) {
		t.Fatalf("exclusive job started beside another: %v", err)
	}
	close(gate)
	<-a
	engine.mu.Lock()
	engine.running["job-x"] = &laneEntry{start: time.Now(), exclusive: true}
	engine.mu.Unlock()
	if _, err := engine.Execute(context.Background(), fixtureLaneJob(t, "job-b", model.Build), source, bytes.NewReader(data), nil); !errors.Is(err, ErrBusy) {
		t.Fatalf("job started beside an exclusive one: %v", err)
	}
	if err := engine.LaneReady(context.Background()); !errors.Is(err, ErrBusy) {
		t.Fatalf("lane ready beside an exclusive job: %v", err)
	}
	engine.leave("job-x")
}

// With one lane the engine is the single-job worker: a second job is busy,
// and every job ends with the full quiesce under the account rule.
func TestOneLaneKeepsSingleJobCleanup(t *testing.T) {
	runner := newLaneFake()
	engine := laneEngine(t, runner, 1)
	source, data := sourceFixture(t)
	gate := runner.gate("job-a")
	a := runLane(engine, fixtureLaneJob(t, "job-a", model.Build), source, data)
	<-runner.started
	if _, err := engine.Execute(context.Background(), fixtureLaneJob(t, "job-b", model.Build), source, bytes.NewReader(data), nil); !errors.Is(err, ErrBusy) {
		t.Fatalf("second job with one lane: %v", err)
	}
	close(gate)
	out := <-a
	events := runner.take()
	if out.err != nil || !out.result.CleanupOK || slices.ContainsFunc(events, func(e string) bool {
		return strings.HasPrefix(e, "begin") || strings.HasPrefix(e, "quiesce job") || e == "lane-admission"
	}) {
		t.Fatalf("one lane used lane attribution: %v %+v", events, out.result)
	}
	if c := out.result.Concurrency; c.Attribution != AttributionAccount || c.IdleVerdict != IdleClean || c.MaxLanes != 1 || c.Lane != 1 || len(c.OverlappedJobs) != 0 {
		t.Fatalf("one lane concurrency: %+v", c)
	}
	requireVerifiedTreeUntilAck(t, engine, "job-a", source.Tree)
}

// requireVerifiedTreeUntilAck checks the extracted tree the client seals
// after Execute returns is kept until the completion's export is removed.
func requireVerifiedTreeUntilAck(t *testing.T, engine *Engine, job, tree string) {
	t.Helper()
	if got := engine.VerifiedTree(job); got != tree {
		t.Fatalf("VerifiedTree(%s) after Execute = %q, want %q", job, got, tree)
	}
	if err := engine.RemoveExport(job); err != nil {
		t.Fatal(err)
	}
	if got := engine.VerifiedTree(job); got != "" {
		t.Fatalf("VerifiedTree(%s) after RemoveExport = %q", job, got)
	}
}

// A runner without lane attribution cannot run concurrent jobs.
func TestLanesRequireAttributingRunner(t *testing.T) {
	base := t.TempDir()
	if _, err := New(Options{Root: filepath.Join(base, "worker"), ExportRoot: filepath.Join(base, "exports"), WorkspaceRoot: filepath.Join(base, "workspaces"), Runner: &fakeRunner{}, Lanes: 2}); err == nil {
		t.Fatal("lanes accepted without attribution")
	}
}

// After an interrupted creation, a device a running sibling recorded is its
// own, not an unrecorded device; any other new device still is.
func TestInterruptedCreateIgnoresSiblingDevice(t *testing.T) {
	const sibling = "AAAAAAAA-1111-2222-3333-444444444444"
	runner := newLaneFake()
	engine := laneEngine(t, runner, 2)
	runner.fakeRunner.mu.Lock()
	runner.fakeRunner.deviceExists = true
	runner.fakeRunner.mu.Unlock()
	listing := `{"devices":{"runtime":[{"udid":"` + ownedUDID + `"},{"udid":"` + sibling + `"}]}}`
	inner := runner.fakeRunner.hook
	runner.fakeRunner.hook = func(ctx context.Context, c Command, out, stderr io.Writer) (bool, ProcessResult, error) {
		if strings.Join(c.Args, " ") == "simctl list devices --json" {
			_, err := io.WriteString(out, listing)
			return true, ProcessResult{CleanupOK: true}, err
		}
		return inner(ctx, c, out, stderr)
	}
	if err := engine.saveManifest(manifest{JobID: "job-b", DeveloperDir: "/Applications/Xcode.app/Contents/Developer", DeviceUDID: sibling}); err != nil {
		t.Fatal(err)
	}
	pending := manifest{JobID: "job-a", DeveloperDir: "/Applications/Xcode.app/Contents/Developer", DeviceCreatePending: true, DevicesBefore: []string{ownedUDID}}
	if err := engine.saveManifest(pending); err != nil {
		t.Fatal(err)
	}
	if err := engine.verifyDeviceCreation(context.Background(), &pending); err != nil {
		t.Fatalf("sibling device judged unrecorded: %v", err)
	}
	pending = manifest{JobID: "job-a", DeveloperDir: "/Applications/Xcode.app/Contents/Developer", DeviceCreatePending: true, DevicesBefore: []string{ownedUDID}}
	if err := engine.root.Remove("manifests/job-b.json"); err != nil {
		t.Fatal(err)
	}
	if err := engine.verifyDeviceCreation(context.Background(), &pending); !errors.Is(err, ErrContamination) {
		t.Fatalf("unrecorded device accepted: %v", err)
	}
}

// A worker restarted with several jobs' manifests (a broker crash while lanes
// ran) recovers every one at idle: the full quiesce, then each job's
// resources, before admitting again.
func TestRecoverCleansEveryLaneManifest(t *testing.T) {
	runner := newLaneFake()
	engine := laneEngine(t, runner, 2)
	for _, id := range []string{"job-a", "job-b"} {
		if err := engine.saveManifest(manifest{JobID: id, DeveloperDir: "/Applications/Xcode.app/Contents/Developer"}); err != nil {
			t.Fatal(err)
		}
		if err := engine.workspaces.Mkdir(id, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := engine.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	names, err := engine.registryNames()
	if err != nil || len(names) != 0 {
		t.Fatalf("manifests left: %v %v", names, err)
	}
	if events := runner.take(); !contains(events, "quiesce") || slices.ContainsFunc(events, func(e string) bool { return strings.HasPrefix(e, "quiesce job") }) {
		t.Fatalf("crash recovery did not use the full quiesce: %v", events)
	}
}

// censusFake is laneFake whose admissions first run the hot registered-root
// ACL census (inspectRegistrationRoots) over the root "/", with an ls the
// test controls.
type censusFake struct {
	*laneFake
	cmu sync.Mutex
	// cut is how many ls probes their deadline cuts short next; -1: all.
	cut int
	// probe answers a probe that is not cut short; nil: a clean listing.
	probe func(context.Context, registrationWriters, ...string) error
}

func newCensusFake() *censusFake { return &censusFake{laneFake: newLaneFake()} }

func (f *censusFake) set(cut int, probe func(context.Context, registrationWriters, ...string) error) {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	f.cut, f.probe = cut, probe
}

func (f *censusFake) acl(ctx context.Context, writers registrationWriters, args ...string) error {
	f.cmu.Lock()
	cut, probe := f.cut != 0, f.probe
	if f.cut > 0 {
		f.cut--
	}
	f.cmu.Unlock()
	if cut {
		// The production ls at a deadline that has passed: killed, or
		// never started, at it, as on a loaded host.
		expired, cancel := context.WithDeadline(ctx, time.Now())
		defer cancel()
		return registrationACLCommand(expired, writers, args...)
	}
	if probe != nil {
		return probe(ctx, writers, args...)
	}
	return nil
}

func (f *censusFake) census(ctx context.Context) error {
	f.event("census")
	roots := PersistenceManifest{Code: map[string]RegisteredCode{"fixture": {Path: "/"}}}
	return inspectRegistrationRoots(ctx, roots, registrationWritersFixture(), f.acl)
}

func (f *censusFake) Admission(ctx context.Context) error {
	if err := f.census(ctx); err != nil {
		return err
	}
	return f.laneFake.Admission(ctx)
}

func (f *censusFake) LaneAdmission(ctx context.Context) error {
	if err := f.census(ctx); err != nil {
		return err
	}
	return f.laneFake.LaneAdmission(ctx)
}

// A registered tree ACL census its deadline cut short observed nothing; the
// census retries and a job whose census then completes keeps its result
// (Studio v0.1.49, 2026-11-13: four lanes beside the periodic full scan).
func TestACLCensusCutShortIsRetried(t *testing.T) {
	runner := newCensusFake()
	engine := laneEngine(t, runner, 2)
	source, data := sourceFixture(t)
	runner.set(1, nil)
	result, err := engine.Execute(context.Background(), fixtureLaneJob(t, "job-a", model.Build), source, bytes.NewReader(data), nil)
	if err != nil || result.State != model.Succeeded || !result.CleanupOK || result.Reason != "" || result.Concurrency.IdleVerdict != IdleClean {
		t.Fatalf("census timeout failed the job: %+v %v", result, err)
	}
}

// A census still cut short when a job ends alone leaves the job's own
// successful cleanup to the idle Recover: the job keeps its result with its
// cleanup (idle verdict deferred, which the client holds until that check),
// and the engine drains until the check passes.
func TestACLCensusUnavailableAtJobEndDefersToIdleCheck(t *testing.T) {
	runner := newCensusFake()
	engine := laneEngine(t, runner, 2)
	source, data := sourceFixture(t)
	gate := runner.gate("job-a")
	a := runLane(engine, fixtureLaneJob(t, "job-a", model.Build), source, data)
	<-runner.started
	runner.set(-1, nil)
	close(gate)
	first := <-a
	if first.err != nil || first.result.State != model.Succeeded || !first.result.CleanupOK || first.result.Reason != "" || first.result.Concurrency.IdleVerdict != IdleDeferred || first.result.Concurrency.UnattributedResidue != 0 {
		t.Fatalf("unavailable census at job end: %+v %v", first.result, first.err)
	}
	if err := engine.LaneReady(context.Background()); !errors.Is(err, ErrDrain) {
		t.Fatalf("engine admits before the idle check: %v", err)
	}
	if _, err := engine.Execute(context.Background(), fixtureLaneJob(t, "job-b", model.Build), source, bytes.NewReader(data), nil); !errors.Is(err, ErrDrain) {
		t.Fatalf("job started before the idle check: %v", err)
	}
	runner.set(0, nil)
	runner.take()
	if err := engine.Recover(context.Background()); err != nil {
		t.Fatalf("clean idle check: %v", err)
	}
	if events := runner.take(); len(events) < 3 || events[0] != "quiesce" || !contains(events, "census") || !contains(events, "admission") {
		t.Fatalf("idle check was not the full quiesce and admission: %v", events)
	}
	if err := engine.LaneReady(context.Background()); err != nil {
		t.Fatalf("drain survived the idle check: %v", err)
	}
}

// An ACL census still cut short by its deadline at a job's admission
// observed nothing, and nothing of the job ran: only that job is refused,
// with the service's admission as its reason and cleanup_ok (idle verdict
// not_required). Nothing is quarantined, the engine does not drain, and the
// sibling and the next job run on. Studio v0.1.55, 2026-11-14, six lanes at
// load 28-37: a protected-input ACL inspection killed at its deadline 15 s
// into a job ("cannot inspect protected input ACL: signal: killed: context
// deadline exceeded") ended in cleanup_ok=false and quarantined the service
// until every lane was idle (#148). The registered tree census cut short
// (the Studio failure of 2026-11-13: lane 4 beside three jobs) also no
// longer drains.
func TestLaneAdmissionACLCensusUnavailableRefusesOnlyTheJob(t *testing.T) {
	protectedInputCut := func(context.Context, registrationWriters, ...string) error {
		expired, cancel := context.WithDeadline(context.Background(), time.Now())
		defer cancel()
		return hostguard.CheckProtectedPathContext(expired, "/", true)
	}
	for name, c := range map[string]struct {
		cut    int
		probe  func(context.Context, registrationWriters, ...string) error
		reason string
	}{
		"registered tree census": {cut: -1, reason: "lane admission: registered tree ACL census unavailable"},
		"protected input ACL":    {probe: protectedInputCut, reason: "lane admission: cannot inspect protected input ACL: context deadline exceeded"},
	} {
		t.Run(name, func(t *testing.T) {
			runner := newCensusFake()
			engine := laneEngine(t, runner, 2)
			source, data := sourceFixture(t)
			gate := runner.gate("job-a")
			a := runLane(engine, fixtureLaneJob(t, "job-a", model.Build), source, data)
			<-runner.started
			runner.set(c.cut, c.probe)
			result, err := engine.Execute(context.Background(), fixtureLaneJob(t, "job-b", model.Build), source, bytes.NewReader(data), nil)
			if !errors.Is(err, ErrACLCensusUnavailable) || result.State != model.Failed || !result.CleanupOK || result.Reason != c.reason || result.Concurrency.IdleVerdict != IdleNotRequired || result.FinishedAt.IsZero() {
				t.Fatalf("unavailable census at lane admission: %+v %v", result, err)
			}
			if _, err := engine.root.Lstat(quarantineRecord); err == nil {
				t.Fatal("a census cut short quarantined the worker")
			}
			if err := engine.LaneReady(context.Background()); err != nil {
				t.Fatalf("engine stopped admitting beside the running job: %v", err)
			}
			runner.set(0, nil)
			next := runLane(engine, fixtureLaneJob(t, "job-c", model.Build), source, data)
			if got := <-runner.started; got != "job-c" {
				t.Fatalf("started %s", got)
			}
			if third := <-next; third.err != nil || third.result.State != model.Succeeded || !third.result.CleanupOK {
				t.Fatalf("next job beside the sibling: %+v %v", third.result, third.err)
			}
			close(gate)
			if first := <-a; first.err != nil || first.result.State != model.Succeeded || !first.result.CleanupOK || first.result.Concurrency.IdleVerdict != IdleClean {
				t.Fatalf("sibling: %+v %v", first.result, first.err)
			}
		})
	}
}

// A job starting alone whose admission's ACL census is cut short is refused
// the same way ("admission: ..."), and the next job is admitted at once.
func TestSoloAdmissionACLCensusUnavailableRefusesOnlyTheJob(t *testing.T) {
	runner := newCensusFake()
	engine := laneEngine(t, runner, 2)
	source, data := sourceFixture(t)
	runner.set(-1, nil)
	result, err := engine.Execute(context.Background(), fixtureLaneJob(t, "job-a", model.Build), source, bytes.NewReader(data), nil)
	if !errors.Is(err, ErrACLCensusUnavailable) || result.State != model.Failed || !result.CleanupOK || result.Reason != "admission: registered tree ACL census unavailable" || result.Concurrency.IdleVerdict != IdleNotRequired {
		t.Fatalf("unavailable census at admission: %+v %v", result, err)
	}
	runner.set(0, nil)
	if next, err := engine.Execute(context.Background(), fixtureLaneJob(t, "job-b", model.Build), source, bytes.NewReader(data), nil); err != nil || next.State != model.Succeeded || !next.CleanupOK {
		t.Fatalf("next job: %+v %v", next, err)
	}
}

// An admission ACL check that ran and failed is no deadline and keeps its
// behavior: an ACL that grants the job account writes quarantines, and a
// census or protected-input inspection that failed on its own leaves the
// job's cleanup unverified, which fences the epoch. Neither is reported as
// the service's refusal (#148 changes nothing here).
func TestLaneAdmissionACLCheckThatRanStillFails(t *testing.T) {
	for name, probe := range map[string]func(context.Context, registrationWriters, ...string) error{
		"acl drift": func(_ context.Context, writers registrationWriters, _ ...string) error {
			return writers.checkACL(" 0: user:job allow write")
		},
		"ls failed": func(ctx context.Context, writers registrationWriters, _ ...string) error {
			return registrationACLCommand(ctx, writers, "-ldeb", "/nonexistent-macserve-fixture")
		},
		"protected input inspection failed": func(context.Context, registrationWriters, ...string) error {
			return fmt.Errorf("cannot inspect protected input ACL: %w", errors.New("exit status 1"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			runner := newCensusFake()
			engine := laneEngine(t, runner, 2)
			source, data := sourceFixture(t)
			gate := runner.gate("job-a")
			a := runLane(engine, fixtureLaneJob(t, "job-a", model.Build), source, data)
			<-runner.started
			runner.set(0, probe)
			result, err := engine.Execute(context.Background(), fixtureLaneJob(t, "job-b", model.Build), source, bytes.NewReader(data), nil)
			if err == nil || errors.Is(err, ErrACLCensusUnavailable) || result.CleanupOK {
				t.Fatalf("admission check that ran passed as a deadline: %+v %v", result, err)
			}
			_, quarantined := engine.root.Lstat(quarantineRecord)
			if drift := name == "acl drift"; drift != (quarantined == nil) || drift != errors.Is(err, ErrContamination) {
				t.Fatalf("quarantine %v for %s: %v", quarantined, name, err)
			}
			runner.set(0, nil)
			close(gate)
			<-a
		})
	}
}

// A census that ran fails the job's cleanup as before: an ACL that grants
// the job account writes quarantines, and an ls that failed before its
// deadline leaves the cleanup unverified. Both pass without the deferral.
func TestACLCensusThatRanStillFailsCleanup(t *testing.T) {
	for name, probe := range map[string]func(context.Context, registrationWriters, ...string) error{
		"acl drift": func(_ context.Context, writers registrationWriters, _ ...string) error {
			return writers.checkACL(" 0: user:job allow write")
		},
		"ls failed": func(ctx context.Context, writers registrationWriters, _ ...string) error {
			return registrationACLCommand(ctx, writers, "-ldeb", "/nonexistent-macserve-fixture")
		},
	} {
		t.Run(name, func(t *testing.T) {
			runner := newCensusFake()
			engine := laneEngine(t, runner, 2)
			source, data := sourceFixture(t)
			gate := runner.gate("job-a")
			a := runLane(engine, fixtureLaneJob(t, "job-a", model.Build), source, data)
			<-runner.started
			runner.set(0, probe)
			close(gate)
			first := <-a
			if first.err == nil || first.result.State != model.Failed || first.result.CleanupOK || first.result.Concurrency.IdleVerdict != IdleDeferred {
				t.Fatalf("census that ran passed the cleanup: %+v %v", first.result, first.err)
			}
			_, quarantined := engine.root.Lstat(quarantineRecord)
			if drift := name == "acl drift"; drift != (quarantined == nil) || drift != errors.Is(first.err, ErrContamination) {
				t.Fatalf("quarantine %v for %s: %v", quarantined, name, first.err)
			}
		})
	}
}

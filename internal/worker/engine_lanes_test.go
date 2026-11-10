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

func (f *laneFake) Admission(ctx context.Context) error { f.event("admission"); return ctx.Err() }
func (f *laneFake) BeginJob(job string, _ time.Time)    { f.event("begin " + job) }
func (f *laneFake) EndJob(job string)                   { f.event("end " + job) }
func (f *laneFake) AttachDevice(job, udid string)       { f.event("device " + job) }
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

// An unattributed process left when a job ends beside another leaves that
// job's cleanup unverified (deferred) and drains the engine: no new job
// starts. The sibling finishes; Recover, at idle, runs the full quiesce and
// admits again.
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
	if first.result.CleanupOK || first.result.State != model.Failed || first.result.Concurrency.IdleVerdict != IdleDeferred || first.result.Concurrency.UnattributedResidue != 1 || !strings.Contains(first.result.Reason, "unattributed") {
		t.Fatalf("residue not deferred: %+v", first.result)
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

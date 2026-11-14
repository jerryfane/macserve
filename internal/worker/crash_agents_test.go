package worker

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
)

// The Apple processes a crash starts in the job's session (Studio, v0.1.55,
// 2026-11-14 worker log): the crash dialog and two XPC services.
const (
	problemReporter    = "/System/Library/CoreServices/Problem Reporter.app/Contents/MacOS/Problem Reporter"
	setStoreUpdate     = "/System/Library/PrivateFrameworks/CascadeSets.framework/Versions/A/XPCServices/SetStoreUpdateService.xpc/Contents/MacOS/SetStoreUpdateService"
	speechSynthesisXPC = "/System/Library/Frameworks/ApplicationServices.framework/Versions/A/Frameworks/SpeechSynthesis.framework/Versions/A/XPCServices/SpeechSynthesisServerXPC.xpc/Contents/MacOS/SpeechSynthesisServerXPC"
)

// crashHost is a native runner over an in-memory job-account process table
// whose kernel facts come from fakeAgents; a signal ends the process.
type crashHost struct {
	runner    *nativeRunner
	agents    *fakeAgents
	mu        sync.Mutex
	live      map[int]processSample
	signalled []int
}

const crashUID = 600

func newCrashHost() *crashHost {
	h := &crashHost{agents: newFakeAgents(), live: map[int]processSample{}}
	for _, exe := range []string{problemReporter, setStoreUpdate, speechSynthesisXPC} {
		h.agents.sip[exe] = true
	}
	baseline := laneSample(50, 1, crashUID, time.Now().Unix()-1000)
	h.live[50] = baseline
	r := newProcessRunner()
	r.uid = crashUID
	r.scope = &processScope{uid: crashUID, baseline: GUIBaseline{Processes: []ProcessIdentity{{PID: 50, Start: baseline.start}}}, agents: h.agents, interval: time.Millisecond, grace: 20 * time.Millisecond,
		sample: func(context.Context) ([]processSample, error) {
			h.mu.Lock()
			defer h.mu.Unlock()
			out := make([]processSample, 0, len(h.live))
			for _, p := range h.live {
				out = append(out, p)
			}
			return out, nil
		},
		signal: func(_ context.Context, p processSample, _ syscall.Signal) error {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.signalled = append(h.signalled, p.pid)
			delete(h.live, p.pid)
			return nil
		}}
	r.lanes = trackerFor(syscall.Getpid(), crashUID, map[int]processDescription{})
	h.runner = r
	return h
}

// add starts a job-UID process with parent ppid at start whose kernel
// facts name exe; platform and its SIP flag are the agents' as set.
func (h *crashHost) add(pid, ppid int, start time.Time, exe string, platform bool) {
	p := processSample{pid: pid, parent: ppid, uid: crashUID, start: fmt.Sprintf("%d:%d", start.Unix(), start.Nanosecond()/1000), footprintKiB: 1024}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.live[pid] = p
	h.agents.procs[pid] = agentProcess{start: p.start, uid: crashUID, ppid: ppid, executable: exe, platform: platform}
}

func (h *crashHost) running(pid int) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, ok := h.live[pid]
	return ok
}

func (h *crashHost) samples() []processSample {
	return must(h.runner.scope.sample(context.Background()))
}

// residual is the lane census's unattributed PIDs, sorted.
func (h *crashHost) residual(t *testing.T) []int {
	t.Helper()
	c, err := h.runner.laneCensus(context.Background(), h.samples())
	if err != nil {
		t.Fatal(err)
	}
	var pids []int
	for _, p := range c.residual {
		pids = append(pids, p.pid)
	}
	slices.Sort(pids)
	return pids
}

// The crash dialog and its two XPC services, started by launchd while jobs
// run, are the running jobs' to stop: the lane census does not count them.
// Anything that fails one kernel fact stays unattributed: an unknown Apple
// agent, a crash agent older than every running job, a copy of the dialog
// outside SIP, one the job forked itself, and one that is not a platform
// binary (#146).
func TestLaneCensusLeavesCrashAgentsToRunningJobs(t *testing.T) {
	h := newCrashHost()
	now := time.Now()
	h.runner.lanes.begin("a", now.Add(-time.Minute))
	h.runner.lanes.begin("b", now.Add(-30*time.Second))
	h.add(100, 1, now, problemReporter, true)
	h.add(101, 1, now, setStoreUpdate, true)
	h.add(102, 1, now, speechSynthesisXPC, true)
	// Not crash agents.
	h.add(200, 1, now, "/System/Library/PrivateFrameworks/IMTransferServices.framework/IMTransferAgent.app/Contents/MacOS/IMTransferAgent", true)
	h.add(201, 1, now.Add(-2*time.Minute), problemReporter, true)
	h.add(202, 1, now, "/Users/job/Problem Reporter.app/Contents/MacOS/Problem Reporter", true)
	h.add(203, 1, now, problemReporter, true)
	h.agents.procs[203] = agentProcess{start: h.live[203].start, uid: crashUID, ppid: 1, executable: problemReporter + " ", platform: true}
	h.add(204, 300, now, problemReporter, true)
	h.add(205, 1, now, setStoreUpdate, false)
	if got, want := h.residual(t), []int{200, 201, 202, 203, 204, 205}; !slices.Equal(got, want) {
		t.Fatalf("unattributed %v, want %v", got, want)
	}
	// With no job running nothing is any job's: all of them are residual.
	h.runner.lanes.end("a")
	h.runner.lanes.end("b")
	if got := h.residual(t); !slices.Contains(got, 100) || !slices.Contains(got, 101) || !slices.Contains(got, 102) {
		t.Fatalf("crash agents left out with no job running: %v", got)
	}
}

// A job's lane quiesce stops the crash agents that started while it ran,
// with the quiesce's signals, and none that started before it began: those
// are an older job's to stop. One that starts after the lane quiesce of
// every job that began before it is no running job's: residue (#146).
func TestLaneQuiesceStopsCrashAgentsStartedDuringTheJob(t *testing.T) {
	h := newCrashHost()
	now := time.Now()
	h.runner.lanes.begin("old", now.Add(-time.Minute))
	h.runner.lanes.begin("new", now.Add(-10*time.Second))
	h.add(100, 1, now.Add(-30*time.Second), problemReporter, true)
	h.add(101, 1, now.Add(-30*time.Second), setStoreUpdate, true)
	h.add(102, 1, now.Add(-time.Second), speechSynthesisXPC, true)
	h.add(200, 1, now.Add(-time.Second), "/System/Library/PrivateFrameworks/CoreParsec.framework/parsec-fbf", true)
	h.runner.lanes.update(h.samples())
	if err := h.runner.QuiesceJob(context.Background(), "new"); err != nil {
		t.Fatal(err)
	}
	if h.running(102) || !h.running(100) || !h.running(101) || !h.running(200) || !h.running(50) {
		t.Fatalf("QuiesceJob(new) signalled %v", h.signalled)
	}
	if err := h.runner.QuiesceJob(context.Background(), "old"); err != nil {
		t.Fatal(err)
	}
	if h.running(100) || h.running(101) || !h.running(200) || !h.running(50) {
		t.Fatalf("QuiesceJob(old) signalled %v", h.signalled)
	}
	h.add(103, 1, time.Now(), problemReporter, true)
	if got := h.residual(t); !slices.Equal(got, []int{103, 200}) {
		t.Fatalf("unattributed after both lane quiesces %v, want [103 200]", got)
	}
}

// crashLanes is laneFake whose lane quiesce and residue are a native
// runner's over crashHost's process table.
type crashLanes struct {
	*laneFake
	host *crashHost
}

func (f *crashLanes) BeginJob(job string, started time.Time) {
	f.laneFake.BeginJob(job, started)
	f.host.runner.lanes.begin(job, started)
}

func (f *crashLanes) EndJob(job string) {
	f.laneFake.EndJob(job)
	f.host.runner.lanes.end(job)
}

func (f *crashLanes) QuiesceJob(ctx context.Context, job string) error {
	f.laneFake.event("quiesce " + job)
	return f.host.runner.QuiesceJob(ctx, job)
}

func (f *crashLanes) Residue(ctx context.Context) ([]string, error) {
	c, err := f.host.runner.laneCensus(ctx, f.host.samples())
	if err != nil {
		return nil, err
	}
	residue := []string{}
	for _, p := range c.residual {
		residue = append(residue, fmt.Sprintf("pid=%d", p.pid))
	}
	return residue, nil
}

// laneCrash runs job-a and job-b side by side; while both run, job-a's test
// crashes and launchd starts the processes add names. job-a then finalizes
// beside job-b. It returns job-a's outcome and job-b's gate and outcome.
func laneCrash(t *testing.T, add func(h *crashHost, at time.Time)) (*Engine, *crashHost, laneOutcome, chan struct{}, chan laneOutcome) {
	t.Helper()
	host := newCrashHost()
	runner := &crashLanes{laneFake: newLaneFake(), host: host}
	engine := laneEngine(t, runner, 2)
	source, data := sourceFixture(t)
	gateA, gateB := runner.gate("job-a"), runner.gate("job-b")
	a := runLane(engine, fixtureLaneJob(t, "job-a", model.Build), source, data)
	<-runner.started
	b := runLane(engine, fixtureLaneJob(t, "job-b", model.Build), source, data)
	<-runner.started
	add(host, time.Now())
	close(gateA)
	return engine, host, <-a, gateB, b
}

// Studio, v0.1.55, 2026-11-14: a crashing test made launchd start the crash
// dialog and two XPC services; every lane that finalized beside others then
// deferred its verdict and drained the engine, and six lanes sat idle for
// 30-40 minutes until the slowest job ended. Now the finalizing job stops
// them, keeps the verdict not_required, and new lanes start (#146).
func TestCrashAgentsBesideRunningJobsDoNotDeferOrDrain(t *testing.T) {
	engine, host, first, gateB, b := laneCrash(t, func(h *crashHost, at time.Time) {
		h.add(100, 1, at, problemReporter, true)
		h.add(101, 1, at, setStoreUpdate, true)
		h.add(102, 1, at, speechSynthesisXPC, true)
	})
	if first.err != nil || first.result.State != model.Succeeded || !first.result.CleanupOK || first.result.Concurrency.IdleVerdict != IdleNotRequired || first.result.Concurrency.UnattributedResidue != 0 {
		t.Fatalf("crash agents deferred the job: %+v %v", first.result, first.err)
	}
	for _, pid := range []int{100, 101, 102} {
		if host.running(pid) {
			t.Fatalf("crash agent %d survived the lane cleanup (signalled %v)", pid, host.signalled)
		}
	}
	if err := engine.LaneReady(context.Background()); err != nil {
		t.Fatalf("engine stopped admitting after the crash: %v", err)
	}
	close(gateB)
	if second := <-b; second.err != nil || !second.result.CleanupOK {
		t.Fatalf("sibling: %+v %v", second.result, second.err)
	}
}

// Any other unattributed process beside a running job still defers the
// finalizing job's verdict and drains the engine, and the lane cleanup does
// not signal it: only the idle check judges it (#146 changes nothing here).
func TestUnknownProcessBesideRunningJobsStillDefersAndDrains(t *testing.T) {
	const unknown = "/System/Library/PrivateFrameworks/IMTransferServices.framework/IMTransferAgent.app/Contents/MacOS/IMTransferAgent"
	engine, host, first, gateB, b := laneCrash(t, func(h *crashHost, at time.Time) {
		h.add(100, 1, at, problemReporter, true)
		h.add(200, 1, at, unknown, true)
		h.agents.sip[unknown] = true
	})
	if first.err != nil || first.result.State != model.Succeeded || !first.result.CleanupOK || first.result.Concurrency.IdleVerdict != IdleDeferred || first.result.Concurrency.UnattributedResidue != 1 {
		t.Fatalf("unknown process beside a sibling: %+v %v", first.result, first.err)
	}
	if !host.running(200) || host.running(100) {
		t.Fatalf("lane cleanup signalled %v", host.signalled)
	}
	if err := engine.LaneReady(context.Background()); !errors.Is(err, ErrDrain) {
		t.Fatalf("engine admits beside an unknown process: %v", err)
	}
	close(gateB)
	if second := <-b; second.err != nil || !second.result.CleanupOK {
		t.Fatalf("sibling: %+v %v", second.result, second.err)
	}
}

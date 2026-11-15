package worker

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/launchctlprint"
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
	r.scope = &processScope{uid: crashUID, baseline: GUIBaseline{Processes: []ProcessIdentity{{PID: 50, Start: baseline.start}}, Launchd: &LaunchdEnvironment{GUI: map[string]string{}, User: map[string]string{}}}, agents: h.agents, interval: time.Millisecond, grace: 20 * time.Millisecond,
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

// protectedCrashRunner is a native runner over scope's census and the
// mutable process table rows (every row launchd's child), whose signals end
// the process. One job runs from 15 s after the epoch, before every
// fixture's start.
func protectedCrashRunner(scope *processScope, rows []processSample) (*nativeRunner, func(int) bool, *[]int) {
	var mu sync.Mutex
	live := map[int]processSample{}
	for _, p := range rows {
		p.parent = 1
		live[p.pid] = p
	}
	var signalled []int
	scope.sample = func(context.Context) ([]processSample, error) {
		mu.Lock()
		defer mu.Unlock()
		out := make([]processSample, 0, len(live))
		for _, p := range live {
			out = append(out, p)
		}
		return out, nil
	}
	scope.signal = func(_ context.Context, p processSample, _ syscall.Signal) error {
		mu.Lock()
		defer mu.Unlock()
		signalled = append(signalled, p.pid)
		delete(live, p.pid)
		return nil
	}
	r := newProcessRunner()
	r.uid = scope.uid
	r.scope = scope
	r.lanes = trackerFor(syscall.Getpid(), scope.uid, map[int]processDescription{})
	r.lanes.begin("a", time.Unix(15, 0))
	running := func(pid int) bool {
		mu.Lock()
		defer mu.Unlock()
		_, ok := live[pid]
		return ok
	}
	return r, running, &signalled
}

// A crash agent's executable does not override the census: an instance of an
// allowlisted XPC service that is a verified launchd relaunch of an audited
// process, or a tolerated developer-tool launch, serves every job. A lane
// quiesce never signals it and the lane census (Residue, LaneReady,
// LaneAdmission) still judges it as before, while the plain crash dialog
// beside it is the job's to stop (#149 review).
func TestLaneQuiesceKeepsCensusProtectedCrashAgentExecutables(t *testing.T) {
	const dialog = 700
	type world struct {
		scope     *processScope
		agents    *fakeAgents
		rows      []processSample
		protected int
		// residual is what the lane census must leave unattributed.
		residual []int
	}
	worlds := map[string]func(t *testing.T) world{
		"verified relaunch": func(*testing.T) world {
			// The audited XPC service 101 of corespeechd (100) runs the
			// allowlisted SpeechSynthesisServerXPC; launchd relaunched both
			// (300, 301) after a crash. 200 is an escaped job process.
			s, agents, rows := relaunchWorld()
			xpc := speechXPCService(100)
			xpc.Executable = speechSynthesisXPC
			s.baseline.Processes[0].Service = xpc
			agents.run(301, "20:1", xpc)
			s.baseline.Launchd = &LaunchdEnvironment{GUI: map[string]string{}, User: map[string]string{}}
			return world{s, agents, rows, 301, []int{200}}
		},
		"tolerated developer-tool launch": func(t *testing.T) world {
			// SetStoreUpdateService as an XPCService of the job's user
			// domain, proven like CoreSimulatorService.
			s, agents, rows := devtoolWorld(t)
			const pid = 600
			bundle := strings.TrimSuffix(setStoreUpdate, "/Contents/MacOS/SetStoreUpdateService")
			target := "user/" + strconv.Itoa(testJobUID) + "/com.apple.CascadeSets.SetStoreUpdateService"
			agents.procs[pid] = agentProcess{start: "50:600", uid: testJobUID, ppid: 1, executable: setStoreUpdate, platform: true, program: setStoreUpdate, argv: joinArgs([]string{setStoreUpdate})}
			agents.services[target] = launchctlprint.Snapshot{Target: target, State: "running", PID: pid, Path: bundle, Type: "XPCService", BundleID: "com.apple.CascadeSets.SetStoreUpdateService", Program: setStoreUpdate}
			agents.bundles[bundle] = [2]string{"com.apple.CascadeSets.SetStoreUpdateService", "SetStoreUpdateService"}
			return world{s, agents, append(rows, sample(pid, "50:600")), pid, nil}
		},
	}
	for name, build := range worlds {
		t.Run(name, func(t *testing.T) {
			w := build(t)
			for _, exe := range []string{problemReporter, setStoreUpdate, speechSynthesisXPC} {
				w.agents.sip[exe] = true
			}
			w.agents.procs[dialog] = agentProcess{start: "60:0", uid: testJobUID, ppid: 1, executable: problemReporter, platform: true}
			rows := append(w.rows, sample(dialog, "60:0"))
			c, err := w.scope.census(context.Background(), rows)
			if err != nil || slices.Contains(pids(c.residual), w.protected) || c.unresolved {
				t.Fatalf("fixture: %d is not census-protected: residual %v unresolved %v (%v)", w.protected, pids(c.residual), c.unresolved, err)
			}
			r, running, signalled := protectedCrashRunner(w.scope, rows)
			lane, err := r.laneCensus(context.Background(), must(w.scope.sample(context.Background())))
			if err != nil || lane.unresolved || !slices.Equal(pids(lane.residual), w.residual) {
				t.Fatalf("lane census: residual %v unresolved %v (%v), want residual %v", pids(lane.residual), lane.unresolved, err, w.residual)
			}
			if err := r.QuiesceJob(context.Background(), "a"); err != nil {
				t.Fatal(err)
			}
			if !running(w.protected) || running(dialog) {
				t.Fatalf("lane quiesce signalled %v; protected %d must stay, dialog %d must go", *signalled, w.protected, dialog)
			}
		})
	}
}

// The Apple per-user agents of #155 (Studio, v0.1.58 worker log,
// 2026-11-13/15): Spotlight's importer, and WebKit's out-of-process
// services as the kernel names them, in the sealed OS cryptex.
const (
	mdworker         = "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework/Versions/A/Support/mdworker"
	webKitXPC        = "/System/Volumes/Preboot/Cryptexes/OS/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/"
	webKitGPU        = webKitXPC + "com.apple.WebKit.GPU.xpc/Contents/MacOS/com.apple.WebKit.GPU"
	webKitContent    = webKitXPC + "com.apple.WebKit.WebContent.xpc/Contents/MacOS/com.apple.WebKit.WebContent"
	webKitNetworking = webKitXPC + "com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking"
	selfIngestors    = "/System/Library/ExtensionKit/Extensions/"
	gmsIngestor      = selfIngestors + "GMSSELFIngestor.appex/Contents/MacOS/GMSSELFIngestor"
	telemetryIngest  = selfIngestors + "IFTelemetrySELFIngestor.appex/Contents/MacOS/IFTelemetrySELFIngestor"
	biomeIngestor    = selfIngestors + "BiomeSELFIngestor.appex/Contents/MacOS/BiomeSELFIngestor"
	reportIngestor   = selfIngestors + "AppleIntelligenceReportingSELFIngestor.appex/Contents/MacOS/AppleIntelligenceReportingSELFIngestor"
)

// sealAgents marks the #155 agents' executables SIP-restricted.
func sealAgents(h *crashHost) {
	for _, exe := range []string{mdworker, webKitGPU, webKitContent, webKitNetworking, gmsIngestor, telemetryIngest, biomeIngestor, reportIngestor} {
		h.agents.sip[exe] = true
	}
}

// Spotlight's mdworker, the SELF ingestor extensions and WebKit's GPU,
// WebContent and Networking services, started by launchd while jobs run,
// are the running jobs' to
// stop, like the crash dialog. A look-alike stays unattributed: the GPU
// service by the /System path launchd names (the kernel reports the
// cryptex one), a copy in the App cryptex or the job's home, one outside
// SIP, a non-platform mdworker, one the job forked itself, an mdworker
// older than every running job, and a GMSSELFIngestor copy in
// /Library/ExtensionKit (#155).
func TestLaneCensusLeavesSpotlightAndWebKitAgentsToRunningJobs(t *testing.T) {
	h := newCrashHost()
	sealAgents(h)
	now := time.Now()
	h.runner.lanes.begin("a", now.Add(-time.Minute))
	h.add(100, 1, now, mdworker, true)
	h.add(101, 1, now, webKitGPU, true)
	h.add(102, 1, now, webKitContent, true)
	h.add(103, 1, now, webKitNetworking, true)
	h.add(104, 1, now, gmsIngestor, true)
	h.add(105, 1, now, telemetryIngest, true)
	h.add(106, 1, now, biomeIngestor, true)
	h.add(107, 1, now, reportIngestor, true)
	const libraryGMS = "/Library/ExtensionKit/Extensions/GMSSELFIngestor.appex/Contents/MacOS/GMSSELFIngestor"
	h.agents.sip[libraryGMS] = true
	h.add(207, 1, now, libraryGMS, true)
	const systemGPU = "/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.GPU.xpc/Contents/MacOS/com.apple.WebKit.GPU"
	appGPU := strings.Replace(webKitGPU, "/Cryptexes/OS/", "/Cryptexes/App/", 1)
	for _, exe := range []string{systemGPU, appGPU} {
		h.agents.sip[exe] = true
	}
	h.add(200, 1, now, systemGPU, true)
	h.add(201, 1, now, appGPU, true)
	h.add(202, 1, now, "/Users/job/mdworker", true)
	h.add(203, 1, now, webKitGPU, true)
	h.agents.procs[203] = agentProcess{start: h.live[203].start, uid: crashUID, ppid: 1, executable: webKitGPU + "2", platform: true}
	h.add(204, 1, now, mdworker, false)
	h.add(205, 300, now, mdworker, true)
	h.add(206, 1, now.Add(-2*time.Minute), mdworker, true)
	if got, want := h.residual(t), []int{200, 201, 202, 203, 204, 205, 206, 207}; !slices.Equal(got, want) {
		t.Fatalf("unattributed %v, want %v", got, want)
	}
	h.agents.sip[webKitGPU] = false
	if got := h.residual(t); !slices.Contains(got, 101) {
		t.Fatalf("a WebKit GPU service outside SIP is not unattributed: %v", got)
	}
}

// Studio, v0.1.58, 2026-11-15: Spotlight's mdworker drained the engine at
// 10:45:41Z, and the WebKit GPU service deferred j_645b8263 at 13:18:15Z.
// Studio, v0.1.60, 16:40-16:50Z: the four SELF ingestors started at
// 16:39:00Z deferred j_ce4ce15b, j_c5e942db and j_bc451b92. Now the
// finalizing job stops them, keeps the verdict not_required, and new lanes
// start (#155).
func TestSpotlightAndWebKitAgentsBesideRunningJobsDoNotDeferOrDrain(t *testing.T) {
	engine, host, first, gateB, b := laneCrash(t, func(h *crashHost, at time.Time) {
		sealAgents(h)
		h.add(100, 1, at, mdworker, true)
		h.add(101, 1, at, webKitGPU, true)
		h.add(102, 1, at, webKitContent, true)
		h.add(103, 1, at, webKitNetworking, true)
		h.add(104, 1, at, gmsIngestor, true)
		h.add(105, 1, at, telemetryIngest, true)
		h.add(106, 1, at, biomeIngestor, true)
		h.add(107, 1, at, reportIngestor, true)
	})
	if first.err != nil || first.result.State != model.Succeeded || !first.result.CleanupOK || first.result.Concurrency.IdleVerdict != IdleNotRequired || first.result.Concurrency.UnattributedResidue != 0 {
		t.Fatalf("Apple agents deferred the job: %+v %v", first.result, first.err)
	}
	for _, pid := range []int{100, 101, 102, 103, 104, 105, 106, 107} {
		if host.running(pid) {
			t.Fatalf("agent %d survived the lane cleanup (signalled %v)", pid, host.signalled)
		}
	}
	if err := engine.LaneReady(context.Background()); err != nil {
		t.Fatalf("engine stopped admitting after the agents: %v", err)
	}
	close(gateB)
	if second := <-b; second.err != nil || !second.result.CleanupOK {
		t.Fatalf("sibling: %+v %v", second.result, second.err)
	}
}

// A look-alike of the WebKit GPU service (the same bundle in the App
// cryptex) beside a running job still defers the finalizing job's verdict
// and drains the engine, and the lane cleanup does not signal it (#155).
func TestLookAlikeAgentBesideRunningJobsStillDefersAndDrains(t *testing.T) {
	appGPU := strings.Replace(webKitGPU, "/Cryptexes/OS/", "/Cryptexes/App/", 1)
	engine, host, first, gateB, b := laneCrash(t, func(h *crashHost, at time.Time) {
		sealAgents(h)
		h.agents.sip[appGPU] = true
		h.add(100, 1, at, mdworker, true)
		h.add(200, 1, at, appGPU, true)
	})
	if first.err != nil || first.result.State != model.Succeeded || !first.result.CleanupOK || first.result.Concurrency.IdleVerdict != IdleDeferred || first.result.Concurrency.UnattributedResidue != 1 {
		t.Fatalf("look-alike beside a sibling: %+v %v", first.result, first.err)
	}
	if !host.running(200) || host.running(100) {
		t.Fatalf("lane cleanup signalled %v", host.signalled)
	}
	if err := engine.LaneReady(context.Background()); !errors.Is(err, ErrDrain) {
		t.Fatalf("engine admits beside a look-alike: %v", err)
	}
	close(gateB)
	if second := <-b; second.err != nil || !second.result.CleanupOK {
		t.Fatalf("sibling: %+v %v", second.result, second.err)
	}
}

// Studio, v0.1.58, 2026-11-15 13:17:13Z: j_7841d25a's lane admission found
// an audited GUI agent exited beside an unattributed process, most likely
// the WebKit GPU service started 12 s earlier, and failed with "could not be
// verified as its launchd relaunch" (cleanup unverified). A running job's
// crash agent is not unattributed, so the admission passes; an unknown
// process beside the exited agent still refuses it, and the lane quiesce
// still ends the agent (#155).
func TestLaneAdmissionBesideExitedAuditedAgentLeavesCrashAgentsToTheirJob(t *testing.T) {
	for _, tc := range []struct {
		name string
		exe  string
		want error
	}{
		{name: "WebKit GPU", exe: webKitGPU},
		{name: "mdworker", exe: mdworker},
		{name: "GMSSELFIngestor", exe: gmsIngestor},
		{name: "unknown", exe: "/System/Library/PrivateFrameworks/IMTransferServices.framework/IMTransferAgent.app/Contents/MacOS/IMTransferAgent", want: errRelaunchUnverified},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newCrashHost()
			sealAgents(h)
			h.agents.sip[tc.exe] = true
			now := time.Now()
			h.runner.lanes.begin("a", now.Add(-time.Minute))
			h.mu.Lock()
			delete(h.live, 50)
			h.mu.Unlock()
			h.add(100, 1, now, tc.exe, true)
			s := h.runner.scope
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := s.observeQuietWith(ctx, h.runner.laneCensus); !errors.Is(err, tc.want) || (tc.want == nil) != (err == nil) {
				t.Fatalf("lane admission census: %v, want %v", err, tc.want)
			}
			if err := h.runner.QuiesceJob(context.Background(), "a"); err != nil {
				t.Fatal(err)
			}
			if h.running(100) != (tc.want != nil) {
				t.Fatalf("lane quiesce signalled %v", h.signalled)
			}
		})
	}
}

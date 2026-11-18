package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
)

const (
	cloneOne = "C1000000-0000-0000-0000-000000000001"
	cloneTwo = "C2000000-0000-0000-0000-000000000002"
	// siblingClone is a clone of another job's simulator (job-10, whose
	// device name extends job-1's) made during job-1's test run.
	siblingClone = "C3000000-0000-0000-0000-000000000003"
	// staleClone is a clone of job-1's device name that XCTest's device set
	// held before job-1's test run started.
	staleClone = "C4000000-0000-0000-0000-000000000004"
)

const parallelConfig = `{"version":1,"work_dir":".","project":"Herdr.xcodeproj","scheme":"Herdr","ui_test":{"shards":{"iphone-terminal":["HerdrUITests/TerminalControlTests","HerdrUITests/TerminalSearchTests"]}}}`

// parallelUITestJob admits job-1 of a UI-test template; members, when not
// empty, are added to its JSON spelling (e.g. its parallel_testing opt-in).
func parallelUITestJob(t *testing.T, members string) model.Job {
	t.Helper()
	pin, err := json.Marshal(fixtureSimulator)
	if err != nil {
		t.Fatal(err)
	}
	if members != "" {
		members = "," + members
	}
	var template model.Template
	if err := json.Unmarshal([]byte(`{"id":"org-uitest-v1","version":1,"kind":"simulator_ui_test","owners":["example-org"],"xcode":{"version":"16.0","build":"16A242d"},"developer_dir":"/Applications/Xcode.app/Contents/Developer","simulators":[`+string(pin)+`]`+members+`}`), &template); err != nil {
		t.Fatal(err)
	}
	return admitTemplateJob(t, template, "iphone-terminal")
}

// testingSet is XCTest's device set (`simctl --set testing`) for
// fakeRunner: the test run (test-without-building) clones job-1's
// simulator twice, as xcodebuild parallel testing does, and, like a
// sibling's run, adds a clone of job-10's; xcodebuild leaves its clones (a
// run cut short). shutdown and delete act on a listed device. With onDisk,
// the set is a directory in the job's home, as on a Mac: a listing exits 1
// while it does not exist, and the test run creates it with its clones.
type testingSet struct {
	mu      sync.Mutex
	devices map[string]string
	deleted []string
	onDisk  bool
	// missing counts the listings that found no set directory.
	missing int
}

// testingSetDir is the testing set directory of c's environment.
func testingSetDir(c Command) string {
	for _, kv := range c.Env {
		if home, ok := strings.CutPrefix(kv, "HOME="); ok {
			return filepath.Join(home, "Library", "Developer", "XCTestDevices")
		}
	}
	return ""
}

func (s *testingSet) hook(_ context.Context, c Command, out, stderr io.Writer) (bool, ProcessResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if slices.Contains(c.Args, "test-without-building") {
		if s.onDisk {
			if err := os.MkdirAll(testingSetDir(c), 0o700); err != nil {
				return true, ProcessResult{}, err
			}
		}
		s.devices[cloneOne] = "Clone 1 of macserve-job-1"
		s.devices[cloneTwo] = "Clone 2 of macserve-job-1"
		s.devices[siblingClone] = "Clone 1 of macserve-job-10"
		return false, ProcessResult{}, nil
	}
	if len(c.Args) < 3 || c.Args[0] != "simctl" || c.Args[1] != "--set" || c.Args[2] != "testing" {
		return false, ProcessResult{}, nil
	}
	if s.onDisk {
		if _, err := os.Stat(testingSetDir(c)); err != nil {
			s.missing++
			_, err := io.WriteString(stderr, "Provided set path does not exist: "+testingSetDir(c)+"\n")
			return true, ProcessResult{ExitCode: 1, CleanupOK: true}, err
		}
	}
	switch args := c.Args[3:]; {
	case slices.Equal(args, []string{"list", "devices", "--json"}):
		var entries []string
		for udid, name := range s.devices {
			entries = append(entries, `{"udid":"`+udid+`","name":"`+name+`","state":"Booted"}`)
		}
		_, err := io.WriteString(out, `{"devices":{"com.apple.CoreSimulator.SimRuntime.iOS-18-0":[`+strings.Join(entries, ",")+`]}}`)
		return true, ProcessResult{CleanupOK: true}, err
	case len(args) == 2 && args[0] == "shutdown" && s.devices[args[1]] != "":
		return true, ProcessResult{CleanupOK: true}, nil
	case len(args) == 2 && args[0] == "delete" && s.devices[args[1]] != "":
		delete(s.devices, args[1])
		s.deleted = append(s.deleted, args[1])
		return true, ProcessResult{CleanupOK: true}, nil
	}
	return true, ProcessResult{ExitCode: 1, CleanupOK: true}, nil
}

func (s *testingSet) left() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Sorted(func(yield func(string) bool) {
		for udid := range s.devices {
			if !yield(udid) {
				return
			}
		}
	})
}

// The parallel-testing clones xcodebuild makes of a job's simulator, in
// XCTest's own device set, are the job's: a clone its run leaves is shut
// down and deleted with the job's own simulator, proved absent, and the
// job's cleanup succeeds. A clone of another job's simulator and one that
// was in the set before the run stay. Before, the worker listed only the
// default device set, and the clones were nobody's.
func TestParallelTestingCleanupDeletesTheJobsClones(t *testing.T) {
	report, err := os.ReadFile(filepath.Join("..", "evidence", "testdata", "herdrup-uitests.json"))
	if err != nil {
		t.Fatal(err)
	}
	set := &testingSet{devices: map[string]string{staleClone: "Clone 1 of macserve-job-1"}}
	runner := &fakeRunner{tests: string(report), hook: set.hook}
	engine := engineFixture(t, runner)
	source, data := checkoutFixture(t, map[string]string{".macserve.json": parallelConfig})
	result, err := engine.Execute(context.Background(), parallelUITestJob(t, `"parallel_testing":{"workers":2}`), source, bytes.NewReader(data), nil, nil)
	if err != nil || result.State != model.Succeeded || !result.CleanupOK {
		t.Fatalf("parallel-testing job: %+v %v", result, err)
	}
	if got := set.left(); !slices.Equal(got, []string{siblingClone, staleClone}) {
		t.Fatalf("XCTest devices after the job = %v, want the sibling's and the earlier clone", got)
	}
	if slices.Sort(set.deleted); !slices.Equal(set.deleted, []string{cloneOne, cloneTwo}) {
		t.Fatalf("deleted clones = %v", set.deleted)
	}
	assertExactCleanup(t, runner, true)
	if _, err := engine.root.Stat("manifests/job-1.json"); !os.IsNotExist(err) {
		t.Fatalf("manifest kept: %v", err)
	}
}

// A parallel-testing run stopped for exceeding its memory budget (the runner
// kills its process group and reports ErrMemoryLimit) fails the job, not
// the worker: xcodebuild cannot delete the clones it booted, so the job's
// cleanup does, proves them absent and leaves no quarantine.
func TestParallelTestingMemoryLimitCleansUpClonesWithoutQuarantine(t *testing.T) {
	set := &testingSet{devices: map[string]string{}}
	runner := &fakeRunner{}
	runner.hook = func(ctx context.Context, c Command, out, stderr io.Writer) (bool, ProcessResult, error) {
		handled, result, err := set.hook(ctx, c, out, stderr)
		if slices.Contains(c.Args, "test-without-building") {
			return true, ProcessResult{ExitCode: -1, Signal: "killed", CleanupOK: true, PeakMemoryMiB: 20481}, fmt.Errorf("%w: sampled 20481 MiB in the job's own processes, budget 20480 MiB", ErrMemoryLimit)
		}
		return handled, result, err
	}
	engine := engineFixture(t, runner)
	source, data := checkoutFixture(t, map[string]string{".macserve.json": parallelConfig})
	result, err := engine.Execute(context.Background(), parallelUITestJob(t, `"parallel_testing":{"workers":2},"memory_limit_mib":20480`), source, bytes.NewReader(data), nil, nil)
	if !errors.Is(err, ErrMemoryLimit) || errors.Is(err, ErrContamination) || errors.Is(err, ErrRecovery) || result.State != model.Failed || !result.CleanupOK {
		t.Fatalf("over-budget job: %+v %v", result, err)
	}
	if got := set.left(); !slices.Equal(got, []string{siblingClone}) {
		t.Fatalf("XCTest devices after the job = %v", got)
	}
	if err := engine.checkQuarantine(); err != nil {
		t.Fatalf("worker quarantined: %v", err)
	}
}

// Beside other jobs, the clones are the job's for the lane attribution while
// its test run runs: their launchd_sim and its children count against its
// memory budget and are stopped by its lane quiesce, not left as
// unattributed residue. The run, which boots its clones at once, starts
// a gap after the latest simulator boot (here the job's own).
func TestParallelTestingClonesAreTheJobsLaneDevices(t *testing.T) {
	report, err := os.ReadFile(filepath.Join("..", "evidence", "testdata", "herdrup-uitests.json"))
	if err != nil {
		t.Fatal(err)
	}
	runner := newLaneFake()
	runner.fakeRunner.tests = string(report)
	set := &testingSet{devices: map[string]string{}}
	attached := func(ids ...string) bool {
		runner.mu.Lock()
		defer runner.mu.Unlock()
		for _, id := range ids {
			if !slices.Contains(runner.events, "device job-1 "+id) {
				return false
			}
		}
		return true
	}
	var duringRun bool
	runner.fakeRunner.hook = func(ctx context.Context, c Command, out, stderr io.Writer) (bool, ProcessResult, error) {
		handled, result, err := set.hook(ctx, c, out, stderr)
		if slices.Contains(c.Args, "test-without-building") {
			// The run lasts until the watch has attached its clones.
			for deadline := time.Now().Add(10 * time.Second); !duringRun && time.Now().Before(deadline); time.Sleep(time.Millisecond) {
				duringRun = attached(cloneOne, cloneTwo)
			}
		}
		return handled, result, err
	}
	engine := laneEngine(t, runner, 3)
	clock := newTestClock(engine)
	source, data := checkoutFixture(t, map[string]string{".macserve.json": parallelConfig})
	result, err := engine.Execute(context.Background(), parallelUITestJob(t, `"parallel_testing":{"workers":2}`), source, bytes.NewReader(data), nil, nil)
	if err != nil || result.State != model.Succeeded || !result.CleanupOK {
		t.Fatalf("parallel-testing job: %+v %v", result, err)
	}
	if !duringRun {
		t.Fatal("the clones were not the job's while its test run ran")
	}
	events := runner.take()
	if !contains(events, "device job-1 "+ownedUDID) || contains(events, "device job-1 "+siblingClone) {
		t.Fatalf("lane devices: %v", events)
	}
	if got := set.left(); !slices.Equal(got, []string{siblingClone}) {
		t.Fatalf("XCTest devices after the job = %v", got)
	}
	if !slices.ContainsFunc(clock.waits(), func(d time.Duration) bool { return d > 5*time.Second && d <= 30*time.Second }) {
		t.Fatalf("test run not spaced from the simulator boot: pauses %v", clock.waits())
	}
}

// testClock is an engine's fake time: Options.Now reads it and every pause
// advances it (recording the wait) at once.
type testClock struct {
	now    atomic.Int64
	mu     sync.Mutex
	paused []time.Duration
}

func newTestClock(engine *Engine) *testClock {
	c := &testClock{}
	c.now.Store(time.Now().UnixNano())
	engine.options.Now = c.Now
	engine.pause = func(ctx context.Context, d time.Duration) error {
		c.mu.Lock()
		c.paused = append(c.paused, d)
		c.mu.Unlock()
		c.advance(d)
		time.Sleep(time.Millisecond)
		return ctx.Err()
	}
	return c
}

func (c *testClock) Now() time.Time          { return time.Unix(0, c.now.Load()) }
func (c *testClock) advance(d time.Duration) { c.now.Add(int64(d)) }
func (c *testClock) waits() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.paused)
}

// eventually polls cond every millisecond for up to limit of real time.
func eventually(limit time.Duration, cond func() bool) bool {
	for deadline := time.Now().Add(limit); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		if cond() {
			return true
		}
	}
	return cond()
}

// testingListing reports whether c lists XCTest's device set.
func testingListing(c Command) bool {
	return slices.Equal(c.Args, []string{"simctl", "--set", "testing", "list", "devices", "--json"})
}

// A clone the watch finds is the job's from then on, by UDID: it is saved in
// the job's manifest while the run runs (a restart recovers it from there),
// and deleted at the job's end even if it no longer bears its job's name.
// Before, the watch kept it only in memory, and finalization, which
// discovers by name, left a renamed clone behind.
func TestParallelTestingWatchPersistsCloneOwnership(t *testing.T) {
	report, err := os.ReadFile(filepath.Join("..", "evidence", "testdata", "herdrup-uitests.json"))
	if err != nil {
		t.Fatal(err)
	}
	runner := newLaneFake()
	runner.fakeRunner.tests = string(report)
	set := &testingSet{devices: map[string]string{}}
	var engine *Engine
	persisted := false
	runner.fakeRunner.hook = func(ctx context.Context, c Command, out, stderr io.Writer) (bool, ProcessResult, error) {
		handled, result, err := set.hook(ctx, c, out, stderr)
		if slices.Contains(c.Args, "test-without-building") {
			persisted = eventually(3*time.Second, func() bool {
				var m manifest
				return readJSON(engine.root, "manifests/job-1.json", &m) == nil && slices.Contains(m.TestClones, cloneOne)
			})
			set.mu.Lock()
			set.devices[cloneOne] = "Renamed clone"
			set.mu.Unlock()
		}
		return handled, result, err
	}
	engine = laneEngine(t, runner, 3)
	newTestClock(engine)
	source, data := checkoutFixture(t, map[string]string{".macserve.json": parallelConfig})
	result, err := engine.Execute(context.Background(), parallelUITestJob(t, `"parallel_testing":{"workers":2}`), source, bytes.NewReader(data), nil, nil)
	if err != nil || result.State != model.Succeeded || !result.CleanupOK {
		t.Fatalf("parallel-testing job: %+v %v", result, err)
	}
	if !persisted {
		t.Fatal("the watch did not save the clone it found in the job's manifest")
	}
	if got := set.left(); !slices.Equal(got, []string{siblingClone}) {
		t.Fatalf("XCTest devices after the job = %v, want only the sibling's clone", got)
	}
}

// A discovery listing whose process cleanup failed or found contamination
// fails the job and quarantines the worker, as the job's own commands do,
// although later listings succeed. Before, the watch dropped every listing
// error, and the job succeeded.
func TestParallelTestingWatchKeepsCleanupFailures(t *testing.T) {
	report, err := os.ReadFile(filepath.Join("..", "evidence", "testdata", "herdrup-uitests.json"))
	if err != nil {
		t.Fatal(err)
	}
	runner := newLaneFake()
	runner.fakeRunner.tests = string(report)
	set := &testingSet{devices: map[string]string{}}
	var running, failed atomic.Bool
	runner.fakeRunner.hook = func(ctx context.Context, c Command, out, stderr io.Writer) (bool, ProcessResult, error) {
		if testingListing(c) && running.Load() && failed.CompareAndSwap(false, true) {
			return true, ProcessResult{CleanupOK: false}, errors.Join(ErrCleanup, ErrContamination, errors.New("listing group still live after the cleanup window"))
		}
		handled, result, err := set.hook(ctx, c, out, stderr)
		if slices.Contains(c.Args, "test-without-building") {
			running.Store(true)
			eventually(3*time.Second, failed.Load)
		}
		return handled, result, err
	}
	engine := laneEngine(t, runner, 3)
	newTestClock(engine)
	source, data := checkoutFixture(t, map[string]string{".macserve.json": parallelConfig})
	result, err := engine.Execute(context.Background(), parallelUITestJob(t, `"parallel_testing":{"workers":2}`), source, bytes.NewReader(data), nil, nil)
	if !failed.Load() {
		t.Fatal("the watch never listed during the run")
	}
	if !errors.Is(err, ErrContamination) || result.State != model.Failed || result.CleanupOK {
		t.Fatalf("job after a contaminated discovery listing: %+v %v", result, err)
	}
	if engine.checkQuarantine() == nil {
		t.Fatal("worker not quarantined")
	}
}

// A boot on another lane while a parallel-testing run waits for the gap
// restarts the wait: the run starts simulatorBootGap after the latest boot,
// not after the one it first saw. Before, it started when its first wait
// ended, a second after the other lane's boot.
func TestParallelTestingRunWaitsForBootsDuringItsWait(t *testing.T) {
	engine := laneEngine(t, newLaneFake(), 3)
	clock := newTestClock(engine)
	engine.noteSimulatorBoot()
	var otherBoot time.Time
	engine.pause = func(ctx context.Context, d time.Duration) error {
		if otherBoot.IsZero() {
			clock.advance(d - time.Second)
			engine.noteSimulatorBoot()
			otherBoot = clock.Now()
			clock.advance(time.Second)
		} else {
			clock.advance(d)
		}
		return ctx.Err()
	}
	if err := engine.spaceSimulatorBoots(context.Background()); err != nil {
		t.Fatal(err)
	}
	if otherBoot.IsZero() {
		t.Fatal("the run did not wait")
	}
	if gap := clock.Now().Sub(otherBoot); gap < 30*time.Second {
		t.Fatalf("run started %s after another lane's boot", gap)
	}
}

// A lane census (here a sibling's residue count) first has every running
// clone watch claim the clones listed now, however long before its next
// periodic pass: their processes are then labelled, not unattributed.
func TestLaneCensusRefreshesCloneOwnershipFirst(t *testing.T) {
	runner := newLaneFake()
	set := &testingSet{devices: map[string]string{cloneOne: "Clone 1 of macserve-job-1"}}
	runner.fakeRunner.hook = set.hook
	engine := laneEngine(t, runner, 3)
	// The periodic pass never comes.
	engine.pause = func(ctx context.Context, _ time.Duration) error { <-ctx.Done(); return ctx.Err() }
	m := manifest{JobID: "job-1", DeveloperDir: "/Applications/Xcode.app/Contents/Developer", TestClonesPending: true}
	// Reached through an interface, so the test also builds, and fails,
	// against a watch without refresh or ownership.
	watcher, ok := any(engine).(interface {
		watchTestClones(context.Context, *manifest) func() error
	})
	if !ok {
		t.Fatal("engine has no clone watch that owns clones")
	}
	stop := watcher.watchTestClones(context.Background(), &m)
	if _, err := engine.laneResidue(context.Background(), "job-2", &Result{Concurrency: &Concurrency{}}); err != nil {
		t.Fatal(err)
	}
	if !contains(runner.take(), "device job-1 "+cloneOne) {
		t.Fatal("clone not the job's before the census")
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(m.TestClones, []string{cloneOne}) {
		t.Fatalf("manifest clones %v", m.TestClones)
	}
}

// The native lane census claims clones at its own boundary: it runs the
// census refresh before it labels and judges its sample, so a clone made
// just before that sample (here, found only by the refresh) is its job's,
// whatever the caller did between its own start and the census.
func TestNativeLaneCensusRefreshesBeforeJudging(t *testing.T) {
	h := newCrashHost()
	clone := cloneOne
	h.runner.lanes = trackerFor(syscall.Getpid(), crashUID, map[int]processDescription{
		400: {executable: "launchd_sim", args: "launchd_sim /Users/u/Library/Developer/XCTestDevices/" + clone + "/data/var/run/launchd_bootstrap.plist"},
	})
	h.runner.lanes.begin("ui", time.Now().Add(-time.Minute))
	h.add(400, 1, time.Now(), "launchd_sim", false)
	refresher, ok := any(h.runner).(interface{ SetCensusRefresh(func(context.Context)) })
	if !ok {
		t.Fatal("native runner has no census refresh")
	}
	refresher.SetCensusRefresh(func(context.Context) { h.runner.AttachDevice("ui", clone) })
	if got := h.residual(t); len(got) != 0 {
		t.Fatalf("clone process judged unattributed: %v", got)
	}
}

// A boot on another lane during the run's pre-run clone inventory counts:
// the spacing gate is the last step before the run, so the run starts
// simulatorBootGap after that boot. Before, the gate ran before the
// inventory, and the run started at once after a boot made meanwhile (#180
// review F3, observed gap 1 s).
func TestParallelTestingBootDuringCloneInventoryIsSpaced(t *testing.T) {
	report, err := os.ReadFile(filepath.Join("..", "evidence", "testdata", "herdrup-uitests.json"))
	if err != nil {
		t.Fatal(err)
	}
	runner := newLaneFake()
	runner.fakeRunner.tests = string(report)
	set := &testingSet{devices: map[string]string{}}
	var engine *Engine
	var clock *testClock
	var siblingBoot, run time.Time
	runner.fakeRunner.hook = func(ctx context.Context, c Command, out, stderr io.Writer) (bool, ProcessResult, error) {
		if testingListing(c) && siblingBoot.IsZero() {
			engine.noteSimulatorBoot()
			siblingBoot = clock.Now()
		}
		if slices.Contains(c.Args, "test-without-building") {
			run = clock.Now()
		}
		return set.hook(ctx, c, out, stderr)
	}
	engine = laneEngine(t, runner, 3)
	clock = newTestClock(engine)
	source, data := checkoutFixture(t, map[string]string{".macserve.json": parallelConfig})
	result, err := engine.Execute(context.Background(), parallelUITestJob(t, `"parallel_testing":{"workers":2}`), source, bytes.NewReader(data), nil, nil)
	if err != nil || result.State != model.Succeeded || !result.CleanupOK {
		t.Fatalf("parallel-testing job: %+v %v", result, err)
	}
	if siblingBoot.IsZero() || run.IsZero() {
		t.Fatalf("no inventory or run: boot %v run %v", siblingBoot, run)
	}
	if gap := run.Sub(siblingBoot); gap < 30*time.Second {
		t.Fatalf("run started %s after a boot during its clone inventory, want 30s", gap)
	}
}

// A UI-test job's xcodebuild commands run one simulator destination at a
// time with -jobs 4; parallel testing is off unless its template opts in,
// when the test run has that many workers.
func TestParallelTestingArguments(t *testing.T) {
	report, err := os.ReadFile(filepath.Join("..", "evidence", "testdata", "herdrup-uitests.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, members, enabled, workers string
	}{
		{"without the opt-in", "", "NO", ""},
		{"two workers", `"parallel_testing":{"workers":2}`, "YES", "2"},
		{"four workers", `"parallel_testing":{"workers":4}`, "YES", "4"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set := &testingSet{devices: map[string]string{}}
			runner := &fakeRunner{tests: string(report), hook: set.hook}
			engine := engineFixture(t, runner)
			source, data := checkoutFixture(t, map[string]string{".macserve.json": parallelConfig})
			result, err := engine.Execute(context.Background(), parallelUITestJob(t, tc.members), source, bytes.NewReader(data), nil, nil)
			if err != nil || result.State != model.Succeeded || !result.CleanupOK {
				t.Fatalf("job: %+v %v", result, err)
			}
			commands := checkoutCommands(runner)
			if len(commands) != 2 {
				t.Fatalf("recipe commands: %+v", commands)
			}
			test := commands[1].Args
			if !slices.Contains(test, "test-without-building") {
				t.Fatalf("test run: %q", test)
			}
			for _, args := range [][]string{commands[0].Args, test} {
				if argValue(args, "-parallel-testing-enabled") != tc.enabled || argValue(args, "-parallel-testing-worker-count") != tc.workers || argValue(args, "-maximum-concurrent-test-simulator-destinations") != "1" || argValue(args, "-jobs") != "4" {
					t.Fatalf("xcodebuild options: %q", args)
				}
				for _, flag := range []string{"-parallel-testing-enabled", "-parallel-testing-worker-count", "-maximum-concurrent-test-simulator-destinations", "-jobs"} {
					if n := strings.Count(" "+strings.Join(args, " ")+" ", " "+flag+" "); n > 1 {
						t.Fatalf("%s given %d times: %q", flag, n, args)
					}
				}
			}
		})
	}
}

// On a job home where Xcode has not yet made a clone, XCTest's device set
// does not exist and `simctl --set testing list` exits 1 ("Provided set path
// does not exist"): the run's starting inventory is empty, the worker does
// not create the set, and the clones the run then makes are still the
// job's and deleted. Before, that listing failed every parallel-testing job
// on a fresh job home (v0.1.66 qualification, org-ios-sim-uitest-v1).
func TestParallelTestingMissingSetIsAnEmptyInventory(t *testing.T) {
	report, err := os.ReadFile(filepath.Join("..", "evidence", "testdata", "herdrup-uitests.json"))
	if err != nil {
		t.Fatal(err)
	}
	set := &testingSet{devices: map[string]string{}, onDisk: true}
	existedBeforeRun := false
	runner := &fakeRunner{tests: string(report)}
	runner.hook = func(ctx context.Context, c Command, out, stderr io.Writer) (bool, ProcessResult, error) {
		if slices.Contains(c.Args, "test-without-building") {
			_, err := os.Lstat(testingSetDir(c))
			existedBeforeRun = !os.IsNotExist(err)
		}
		return set.hook(ctx, c, out, stderr)
	}
	engine := engineFixture(t, runner)
	source, data := checkoutFixture(t, map[string]string{".macserve.json": parallelConfig})
	result, err := engine.Execute(context.Background(), parallelUITestJob(t, `"parallel_testing":{"workers":2}`), source, bytes.NewReader(data), nil, nil)
	if err != nil || result.State != model.Succeeded || !result.CleanupOK {
		t.Fatalf("parallel-testing job on a fresh job home: %+v %v", result, err)
	}
	if set.missing == 0 || existedBeforeRun {
		t.Fatalf("listings without a set = %d, set existed before the run = %v", set.missing, existedBeforeRun)
	}
	if slices.Sort(set.deleted); !slices.Equal(set.deleted, []string{cloneOne, cloneTwo}) {
		t.Fatalf("deleted clones = %v", set.deleted)
	}
}

// The watch's polls before Xcode creates the set find no clones and do not
// fail the job; once the set appears mid-run, the next pass claims its
// clones of the job's simulator.
func TestParallelTestingWatchClaimsClonesOfASetMadeMidRun(t *testing.T) {
	report, err := os.ReadFile(filepath.Join("..", "evidence", "testdata", "herdrup-uitests.json"))
	if err != nil {
		t.Fatal(err)
	}
	runner := newLaneFake()
	runner.fakeRunner.tests = string(report)
	set := &testingSet{devices: map[string]string{}, onDisk: true}
	var engine *Engine
	polledMissing, claimed := false, false
	runner.fakeRunner.hook = func(ctx context.Context, c Command, out, stderr io.Writer) (bool, ProcessResult, error) {
		if slices.Contains(c.Args, "test-without-building") {
			// The starting inventory and at least one watch poll find no set.
			polledMissing = eventually(3*time.Second, func() bool {
				set.mu.Lock()
				defer set.mu.Unlock()
				return set.missing >= 2
			})
			handled, result, err := set.hook(ctx, c, out, stderr)
			claimed = eventually(3*time.Second, func() bool {
				var m manifest
				return readJSON(engine.root, "manifests/job-1.json", &m) == nil && slices.Contains(m.TestClones, cloneOne) && slices.Contains(m.TestClones, cloneTwo)
			})
			return handled, result, err
		}
		return set.hook(ctx, c, out, stderr)
	}
	engine = laneEngine(t, runner, 3)
	newTestClock(engine)
	source, data := checkoutFixture(t, map[string]string{".macserve.json": parallelConfig})
	result, err := engine.Execute(context.Background(), parallelUITestJob(t, `"parallel_testing":{"workers":2}`), source, bytes.NewReader(data), nil, nil)
	if err != nil || result.State != model.Succeeded || !result.CleanupOK {
		t.Fatalf("parallel-testing job: %+v %v", result, err)
	}
	if !polledMissing || !claimed {
		t.Fatalf("watch polled the missing set = %v, claimed the clones mid-run = %v", polledMissing, claimed)
	}
	if got := set.left(); !slices.Equal(got, []string{siblingClone}) {
		t.Fatalf("XCTest devices after the job = %v, want only the sibling's clone", got)
	}
}

// Only a set that does not exist is empty: a listing that fails while the
// set exists, or while its path cannot be checked (a stat error other than
// not-exist) or is not a directory, still fails the job before its run.
func TestParallelTestingUnlistableSetFails(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setUp func(dir string) error
	}{
		{"existing set", func(dir string) error { return os.MkdirAll(dir, 0o700) }},
		{"set is a file", func(dir string) error {
			if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
				return err
			}
			return os.WriteFile(dir, nil, 0o600)
		}},
		{"parent is a file (ENOTDIR)", func(dir string) error {
			if err := os.MkdirAll(filepath.Dir(filepath.Dir(dir)), 0o700); err != nil {
				return err
			}
			return os.WriteFile(filepath.Dir(dir), nil, 0o600)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ran := false
			runner := &fakeRunner{}
			runner.hook = func(_ context.Context, c Command, _, stderr io.Writer) (bool, ProcessResult, error) {
				if slices.Contains(c.Args, "test-without-building") {
					ran = true
				}
				if !testingListing(c) {
					return false, ProcessResult{}, nil
				}
				dir := testingSetDir(c)
				if _, err := os.Lstat(dir); os.IsNotExist(err) {
					if err := tc.setUp(dir); err != nil {
						return true, ProcessResult{}, err
					}
				}
				_, err := io.WriteString(stderr, "simctl failed\n")
				return true, ProcessResult{ExitCode: 1, CleanupOK: true}, err
			}
			engine := engineFixture(t, runner)
			source, data := checkoutFixture(t, map[string]string{".macserve.json": parallelConfig})
			result, err := engine.Execute(context.Background(), parallelUITestJob(t, `"parallel_testing":{"workers":2}`), source, bytes.NewReader(data), nil, nil)
			if err == nil || result.State == model.Succeeded || ran {
				t.Fatalf("job with an unlistable set: ran %v, %+v %v", ran, result, err)
			}
		})
	}
}

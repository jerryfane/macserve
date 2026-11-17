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
// run cut short). shutdown and delete act on a listed device.
type testingSet struct {
	mu      sync.Mutex
	devices map[string]string
	deleted []string
}

func (s *testingSet) hook(_ context.Context, c Command, out, _ io.Writer) (bool, ProcessResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if slices.Contains(c.Args, "test-without-building") {
		s.devices[cloneOne] = "Clone 1 of macserve-job-1"
		s.devices[cloneTwo] = "Clone 2 of macserve-job-1"
		s.devices[siblingClone] = "Clone 1 of macserve-job-10"
		return false, ProcessResult{}, nil
	}
	if len(c.Args) < 3 || c.Args[0] != "simctl" || c.Args[1] != "--set" || c.Args[2] != "testing" {
		return false, ProcessResult{}, nil
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
	result, err := engine.Execute(context.Background(), parallelUITestJob(t, `"parallel_testing":{"workers":2}`), source, bytes.NewReader(data), nil)
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
	result, err := engine.Execute(context.Background(), parallelUITestJob(t, `"parallel_testing":{"workers":2},"memory_limit_mib":20480`), source, bytes.NewReader(data), nil)
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
	var pausesMu sync.Mutex
	var pauses []time.Duration
	engine.pause = func(ctx context.Context, d time.Duration) error {
		pausesMu.Lock()
		pauses = append(pauses, d)
		pausesMu.Unlock()
		time.Sleep(time.Millisecond)
		return ctx.Err()
	}
	source, data := checkoutFixture(t, map[string]string{".macserve.json": parallelConfig})
	result, err := engine.Execute(context.Background(), parallelUITestJob(t, `"parallel_testing":{"workers":2}`), source, bytes.NewReader(data), nil)
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
	pausesMu.Lock()
	defer pausesMu.Unlock()
	if !slices.ContainsFunc(pauses, func(d time.Duration) bool { return d > 5*time.Second && d <= 30*time.Second }) {
		t.Fatalf("test run not spaced from the simulator boot: pauses %v", pauses)
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
			result, err := engine.Execute(context.Background(), parallelUITestJob(t, tc.members), source, bytes.NewReader(data), nil)
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

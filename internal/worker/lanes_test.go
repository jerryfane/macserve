package worker

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// laneFixture is a sanitized live process capture of the Studio's job
// account (testdata/lanes): the job UID's process table, sampled one or more
// times while jobs ran, with each process's executable (arguments dropped,
// except launchd_sim's device path).
type laneFixture struct {
	UID      int   `json:"uid"`
	Broker   int   `json:"broker"`
	JobStart int64 `json:"job_start"`
	Jobs     []struct {
		ID    string   `json:"id"`
		Roots []int    `json:"roots"`
		UDIDs []string `json:"udids"`
	} `json:"jobs"`
	samples [][]processSample
	exe     map[processInstance]processDescription
	// current is the sample being replayed, which describe reads.
	current []processSample
}

func loadLaneFixture(t *testing.T, name string) *laneFixture {
	t.Helper()
	meta, err := os.ReadFile(filepath.Join("testdata", "lanes", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	f := &laneFixture{exe: map[processInstance]processDescription{}}
	if err := json.Unmarshal(meta, f); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(filepath.Join("testdata", "lanes", name+".tsv.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	zr, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(zr)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "# sample ") {
			f.samples = append(f.samples, nil)
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 6 || len(f.samples) == 0 {
			t.Fatalf("bad fixture line %q", line)
		}
		var n [4]int
		for i := range n {
			if n[i], err = strconv.Atoi(fields[i]); err != nil {
				t.Fatal(err)
			}
		}
		p := processSample{pid: n[0], parent: n[1], uid: n[2], start: strconv.Itoa(n[3]) + ":0", footprintKiB: 1024}
		last := len(f.samples) - 1
		f.samples[last] = append(f.samples[last], p)
		f.exe[processInstance{p.pid, p.start}] = processDescription{executable: fields[4], args: fields[5]}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *laneFixture) tracker() *laneTracker {
	t := newLaneTracker(f.Broker, f.UID, "/Library/macserve/var/workspaces", func(pid int, wantArgs bool) (processDescription, error) {
		for _, p := range f.current {
			if p.pid == pid {
				d := f.exe[processInstance{p.pid, p.start}]
				if !wantArgs {
					d.args = ""
				}
				return d, nil
			}
		}
		return processDescription{}, syscall.ESRCH
	})
	for _, job := range f.Jobs {
		t.begin(job.ID, time.Unix(f.JobStart, 0))
		for _, root := range job.Roots {
			t.addRoot(job.ID, root)
		}
		for _, udid := range job.UDIDs {
			t.addDevice(job.ID, udid)
		}
	}
	return t
}

// sharedService is the trial prototype's rule for per-user services
// launchd starts for every job (CoreSimulatorService, testmanagerd, ...),
// which the broker's census tolerates.
func sharedService(p processSample, d processDescription) bool {
	if p.parent != 1 {
		return false
	}
	for _, root := range []string{"/Library/Developer/PrivateFrameworks/", "/System/", "/Library/Apple/System/Library/", "/usr/libexec/", "/usr/sbin/"} {
		if strings.HasPrefix(d.executable, root) {
			return true
		}
	}
	return false
}

// TestLaneAttributionSplitsLiveCaptures replays the live captures through the
// tracker: every job-UID process that started while the jobs ran is the
// lineage of exactly one job's command roots or devices, a launchd-started
// shared service, or the broker's own helper; none is unattributed, and no
// device subtree is attributed to another device's job.
func TestLaneAttributionSplitsLiveCaptures(t *testing.T) {
	for _, tc := range []struct {
		name string
		want map[string]int // labelled instances per job in the last sample
	}{
		// PARALLEL-DESIGN.md §2: device subtree 317 + command tree 3.
		{"attr-validate", map[string]int{"j_unit": 320}},
		// The trial's three lane devices (311, 170, 170) and the script's
		// tree (14 live in the last sample) in the first lane.
		{"three-lanes", map[string]int{"j_lane1": 311 + 14, "j_lane2": 170, "j_lane3": 170}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := loadLaneFixture(t, tc.name)
			tracker := f.tracker()
			for _, sample := range f.samples {
				f.current = sample
				tracker.update(sample)
			}
			last := f.samples[len(f.samples)-1]
			got := map[string]int{}
			var unattributed []string
			for _, p := range last {
				if p.uid != f.UID {
					continue
				}
				key := processInstance{p.pid, p.start}
				if label, ok := tracker.labels[key]; ok {
					got[label]++
					continue
				}
				started, _ := strconv.ParseInt(strings.TrimSuffix(p.start, ":0"), 10, 64)
				if started < f.JobStart || p.parent == f.Broker || sharedService(p, f.exe[key]) {
					continue
				}
				unattributed = append(unattributed, strconv.Itoa(p.pid)+" "+f.exe[key].executable)
			}
			if len(unattributed) != 0 {
				t.Fatalf("unattributed processes: %v", unattributed)
			}
			if len(tracker.conflicts) != 0 {
				t.Fatalf("conflicting seeds: %v", tracker.conflicts)
			}
			for job, n := range tc.want {
				if got[job] != n {
					t.Errorf("job %s has %d labelled processes, want %d (all: %v)", job, got[job], n, got)
				}
			}
			// Every labelled device process belongs to the job whose UDID its
			// lineage starts from: a launchd_sim names exactly its job's device.
			for _, p := range last {
				label, ok := tracker.labels[processInstance{p.pid, p.start}]
				d := f.exe[processInstance{p.pid, p.start}]
				if !ok || d.executable != "launchd_sim" {
					continue
				}
				for _, job := range f.Jobs {
					for _, udid := range job.UDIDs {
						if strings.Contains(d.args, udid) && label != job.ID {
							t.Errorf("launchd_sim %d of %s labelled %s", p.pid, job.ID, label)
						}
					}
				}
			}
		})
	}
}

// trackerFor is a tracker over in-memory processes with describe from exe.
func trackerFor(broker, uid int, exe map[int]processDescription) *laneTracker {
	return newLaneTracker(broker, uid, "/ws", func(pid int, wantArgs bool) (processDescription, error) {
		d, ok := exe[pid]
		if !ok {
			return d, syscall.ESRCH
		}
		if !wantArgs {
			d.args = ""
		}
		return d, nil
	})
}

func laneSample(pid, parent, uid int, start int64) processSample {
	return processSample{pid: pid, parent: parent, uid: uid, start: strconv.FormatInt(start, 10) + ":0", footprintKiB: 1024}
}

// A child reparented to launchd after its parent exits keeps its job: the
// label belongs to the instance, not to its current parent.
func TestLaneLabelSurvivesReparenting(t *testing.T) {
	const broker, uid = 100, 600
	now := time.Now().Unix()
	tracker := trackerFor(broker, uid, map[int]processDescription{})
	tracker.begin("a", time.Unix(now-10, 0))
	tracker.begin("b", time.Unix(now-10, 0))
	tracker.addRoot("a", 200)
	tracker.addRoot("b", 300)
	tracker.update([]processSample{laneSample(200, broker, uid, now), laneSample(201, 200, uid, now), laneSample(202, 201, uid, now), laneSample(300, broker, uid, now)})
	// 201 exits; its child 202 is reparented to launchd; the root is reaped.
	tracker.removeRoot("a", 200)
	tracker.update([]processSample{laneSample(202, 1, uid, now), laneSample(300, broker, uid, now), laneSample(301, 300, uid, now+1)})
	if got := tracker.labels[processInstance{202, strconv.FormatInt(now, 10) + ":0"}]; got != "a" {
		t.Fatalf("reparented child label %q, want a", got)
	}
	if got := tracker.labels[processInstance{301, strconv.FormatInt(now+1, 10) + ":0"}]; got != "b" {
		t.Fatalf("sibling child label %q, want b", got)
	}
	mine, _, _ := tracker.classify([]processSample{laneSample(202, 1, uid, now), laneSample(300, broker, uid, now), laneSample(301, 300, uid, now+1)}, "a")
	if len(mine) != 1 || mine[0].pid != 202 {
		t.Fatalf("job a's processes %v, want only the reparented 202", mine)
	}
}

// A reused PID never passes a label on: a process that started before the
// instance now holding its parent's PID is not that instance's child, and a
// reaped command root's PID seeds nothing.
func TestLaneLabelRefusesReusedIdentity(t *testing.T) {
	const broker, uid = 100, 600
	now := time.Now().Unix()
	tracker := trackerFor(broker, uid, map[int]processDescription{})
	tracker.begin("a", time.Unix(now-10, 0))
	tracker.addRoot("a", 200)
	tracker.update([]processSample{laneSample(200, broker, uid, now+5), laneSample(250, 200, uid, now+3)})
	if got := tracker.labels[processInstance{200, strconv.FormatInt(now+5, 10) + ":0"}]; got != "a" {
		t.Fatalf("root label %q, want a", got)
	}
	if label, ok := tracker.labels[processInstance{250, strconv.FormatInt(now+3, 10) + ":0"}]; ok {
		t.Fatalf("older process inherited %q from a reused parent PID", label)
	}
	tracker.removeRoot("a", 200)
	tracker.update([]processSample{laneSample(200, broker, uid, now+9)})
	if label, ok := tracker.labels[processInstance{200, strconv.FormatInt(now+9, 10) + ":0"}]; ok {
		t.Fatalf("reaped root PID seeded %q", label)
	}
}

// Seeds of two jobs claiming one process make it neither job's.
func TestLaneConflictingSeedsAttributeToNoJob(t *testing.T) {
	const broker, uid = 100, 600
	now := time.Now().Unix()
	udidA, udidB := "AAAAAAAA-0000-0000-0000-000000000001", "BBBBBBBB-0000-0000-0000-000000000002"
	exe := map[int]processDescription{
		400: {executable: "launchd_sim", args: "launchd_sim /Users/u/Library/Developer/CoreSimulator/Devices/" + udidA + "/data/var/run/launchd_bootstrap.plist"},
		// A process of A's device whose executable lies in B's device.
		401: {executable: "/Users/u/Library/Developer/CoreSimulator/Devices/" + udidB + "/data/x"},
	}
	tracker := trackerFor(broker, uid, exe)
	tracker.begin("a", time.Unix(now-10, 0))
	tracker.begin("b", time.Unix(now-10, 0))
	tracker.addDevice("a", udidA)
	tracker.addDevice("b", udidB)
	tracker.update([]processSample{laneSample(400, 1, uid, now), laneSample(401, 400, uid, now)})
	if tracker.labels[processInstance{400, strconv.FormatInt(now, 10) + ":0"}] != "a" {
		t.Fatal("device seed did not label its launchd_sim")
	}
	if _, ok := tracker.labels[processInstance{401, strconv.FormatInt(now, 10) + ":0"}]; ok || len(tracker.conflicts) != 1 {
		t.Fatalf("conflict attributed: labels=%v conflicts=%v", tracker.labels, tracker.conflicts)
	}
}

// QuiesceJob signals only the job's own labelled processes: never its
// sibling's, a shared service, the baseline or an unattributed process.
// A labelled survivor is contamination.
func TestQuiesceJobLeavesSiblingUntouched(t *testing.T) {
	const uid = 600
	broker := syscall.Getpid()
	now := time.Now().Unix()
	baseline := laneSample(50, 1, uid, now-1000)
	var mu sync.Mutex
	live := map[int]processSample{}
	for _, p := range []processSample{baseline, laneSample(200, broker, uid, now), laneSample(201, 200, uid, now), laneSample(202, 1, uid, now), laneSample(300, broker, uid, now), laneSample(301, 300, uid, now), laneSample(900, 1, uid, now)} {
		live[p.pid] = p
	}
	var signalled []int
	stubborn := false
	runner := newProcessRunner()
	runner.uid = uid
	runner.scope = &processScope{uid: uid, baseline: GUIBaseline{Processes: []ProcessIdentity{{PID: 50, Start: baseline.start}}}, interval: time.Millisecond, grace: 20 * time.Millisecond,
		sample: func(context.Context) ([]processSample, error) {
			mu.Lock()
			defer mu.Unlock()
			out := make([]processSample, 0, len(live))
			for _, p := range live {
				out = append(out, p)
			}
			return out, nil
		},
		signal: func(_ context.Context, p processSample, _ syscall.Signal) error {
			mu.Lock()
			defer mu.Unlock()
			signalled = append(signalled, p.pid)
			if !stubborn || p.pid != 201 {
				delete(live, p.pid)
			}
			return nil
		}}
	runner.lanes = trackerFor(broker, uid, map[int]processDescription{})
	runner.lanes.begin("a", time.Unix(now-10, 0))
	runner.lanes.begin("b", time.Unix(now-10, 0))
	runner.lanes.addRoot("a", 200)
	runner.lanes.addRoot("b", 300)
	runner.lanes.update(must(runner.scope.sample(context.Background())))
	// 202 was reparented before labelling: it is unattributed, not a's.
	if err := runner.QuiesceJob(context.Background(), "a"); err != nil {
		t.Fatal(err)
	}
	for _, pid := range signalled {
		if pid != 200 && pid != 201 {
			t.Fatalf("QuiesceJob(a) signalled %d (signalled %v)", pid, signalled)
		}
	}
	for _, pid := range []int{50, 202, 300, 301, 900} {
		if _, ok := live[pid]; !ok {
			t.Fatalf("process %d was stopped", pid)
		}
	}
	// A labelled process that ignores every signal is a survivor.
	stubborn = true
	live[301] = laneSample(301, 300, uid, now)
	runner.lanes.update(must(runner.scope.sample(context.Background())))
	live[201] = laneSample(201, 300, uid, now+1)
	runner.lanes.update(must(runner.scope.sample(context.Background())))
	err := runner.QuiesceJob(context.Background(), "b")
	if !errors.Is(err, ErrContamination) {
		t.Fatalf("survivor of b not contamination: %v", err)
	}
}

// Residue proves a process launchd's own only when launchd itself forked
// it. A job's child reparented to launchd before it was labelled keeps its
// fork parent, so it is never exempt, nor is a process whose lineage read
// fails.
func TestResidueExemptsOnlyLaunchdForkedProcesses(t *testing.T) {
	residueSettle = time.Millisecond
	t.Cleanup(func() { residueSettle = time.Second })
	const uid = 600
	broker := syscall.Getpid()
	now := time.Now().Unix()
	baseline := laneSample(50, 1, uid, now-1000)
	live := map[int]processSample{}
	// 202 is job a's escaped child: forked by 200, reparented to launchd
	// before any sample labelled it. 900 is Problem Reporter: launchd's.
	for _, p := range []processSample{baseline, laneSample(200, broker, uid, now), laneSample(202, 1, uid, now), laneSample(300, broker, uid, now), laneSample(900, 1, uid, now)} {
		live[p.pid] = p
	}
	runner := newProcessRunner()
	runner.uid = uid
	runner.scope = &processScope{uid: uid, baseline: GUIBaseline{Processes: []ProcessIdentity{{PID: 50, Start: baseline.start}}},
		sample: func(context.Context) ([]processSample, error) {
			out := make([]processSample, 0, len(live))
			for _, p := range live {
				out = append(out, p)
			}
			return out, nil
		}}
	forkParent := map[int]int{202: 200, 900: 1}
	runner.launchdForked = func(pid int, _ string) (bool, error) {
		parent, ok := forkParent[pid]
		if !ok {
			return false, errors.New("process changed during lineage read")
		}
		return parent == 1, nil
	}
	runner.lanes = trackerFor(broker, uid, map[int]processDescription{})
	runner.lanes.begin("a", time.Unix(now-10, 0))
	runner.lanes.begin("b", time.Unix(now-10, 0))
	runner.lanes.addRoot("a", 200)
	runner.lanes.addRoot("b", 300)
	delete(live, 200)
	runner.lanes.update(must(runner.scope.sample(context.Background())))
	residue, launchd, err := runner.residue(context.Background())
	if err != nil || len(residue) != 2 || launchd {
		t.Fatalf("escaped child beside launchd's process: %q launchd=%t %v", residue, launchd, err)
	}
	if !strings.Contains(strings.Join(residue, ";"), "pid=900 ppid=1 start="+laneSample(900, 1, uid, now).start+" command=unavailable forked_by=launchd") {
		t.Fatalf("launchd's process not named as such: %q", residue)
	}
	delete(live, 202)
	if residue, launchd, err := runner.residue(context.Background()); err != nil || len(residue) != 1 || !launchd {
		t.Fatalf("launchd's process alone: %q launchd=%t %v", residue, launchd, err)
	}
	// A lineage read that fails proves nothing.
	delete(forkParent, 900)
	if residue, launchd, err := runner.residue(context.Background()); err != nil || len(residue) != 1 || launchd {
		t.Fatalf("unread lineage exempted: %q launchd=%t %v", residue, launchd, err)
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// A process outside any job's lineage (reparented before it was first seen)
// whose executable lies in a job's workspace is that job's; a path in a
// sibling's workspace with the same prefix is not.
func TestLaneWorkspaceExecutableSeeds(t *testing.T) {
	const broker, uid = 100, 600
	now := time.Now().Unix()
	tracker := trackerFor(broker, uid, map[int]processDescription{
		500: {executable: "/ws/job-a/derived-data/Build/App"},
		501: {executable: "/ws/job-ab/derived-data/Build/App"},
	})
	tracker.begin("job-a", time.Unix(now-10, 0))
	tracker.update([]processSample{laneSample(500, 1, uid, now), laneSample(501, 1, uid, now)})
	if got := tracker.labels[processInstance{500, strconv.FormatInt(now, 10) + ":0"}]; got != "job-a" {
		t.Fatalf("workspace binary label %q", got)
	}
	if label, ok := tracker.labels[processInstance{501, strconv.FormatInt(now, 10) + ":0"}]; ok {
		t.Fatalf("prefix-sharing workspace labelled %q", label)
	}
}

// A process whose parent exited before any sample, and which was reparented
// to launchd, keeps its job through the kernel's parent unique ID at fork,
// also after the labelled ancestor itself exited; an unrelated reparented
// process does not.
func TestLaneLabelFollowsKernelParentAcrossExit(t *testing.T) {
	const broker, uid = 100, 600
	now := time.Now().Unix()
	ids := map[int][2]uint64{200: {1000, 1}, 201: {1001, 1000}, 202: {1002, 1001}, 300: {2000, 1}, 301: {2001, 9999}}
	tracker := trackerFor(broker, uid, map[int]processDescription{})
	tracker.lineage = func(pid int, _ string) (uint64, uint64, error) {
		v, ok := ids[pid]
		if !ok {
			return 0, 0, syscall.ESRCH
		}
		return v[0], v[1], nil
	}
	tracker.begin("a", time.Unix(now-10, 0))
	tracker.addRoot("a", 200)
	tracker.update([]processSample{laneSample(200, broker, uid, now), laneSample(201, 200, uid, now)})
	// 200 and 201 exit; 202 (forked by 201, never seen with it) is reparented.
	tracker.removeRoot("a", 200)
	tracker.update([]processSample{laneSample(202, 1, uid, now+1), laneSample(301, 1, uid, now+1)})
	if got := tracker.labels[processInstance{202, strconv.FormatInt(now+1, 10) + ":0"}]; got != "a" {
		t.Fatalf("orphan of an exited labelled parent labelled %q, want a", got)
	}
	if label, ok := tracker.labels[processInstance{301, strconv.FormatInt(now+1, 10) + ":0"}]; ok {
		t.Fatalf("unrelated reparented process labelled %q", label)
	}
	tracker.end("a")
	if len(tracker.uniqueLabel) != 0 {
		t.Fatal("unique-ID labels kept after every job ended")
	}
}

// A short-lived unattributed process seen in one snapshot is not residue;
// one still running residueSettle later is, and an unresolved census counts.
func TestResidueCountsOnlyPersistingProcesses(t *testing.T) {
	residueSettle = time.Millisecond
	t.Cleanup(func() { residueSettle = time.Second })
	a, b, c := processSample{pid: 10, start: "1:0"}, processSample{pid: 11, start: "1:0"}, processSample{pid: 12, start: "2:0"}
	snapshot := func(samples ...processSample) map[processInstance]processSample {
		out := map[processInstance]processSample{}
		for _, p := range samples {
			out[processInstance{p.pid, p.start}] = p
		}
		return out
	}
	for name, tc := range map[string]struct {
		snapshots      []map[processInstance]processSample
		unresolved     bool
		want           []processSample
		wantUnresolved bool
	}{
		"transient":  {[]map[processInstance]processSample{snapshot(a, b), snapshot(c)}, false, nil, false},
		"persisting": {[]map[processInstance]processSample{snapshot(a, b), snapshot(b, c)}, false, []processSample{b}, false},
		"none":       {[]map[processInstance]processSample{snapshot(), snapshot(a)}, false, nil, false},
		// An audited agent that exited with nothing unattributed beside it
		// is not residue (Studio v0.1.44-v0.1.46: every lane drain).
		"audited exit alone":      {[]map[processInstance]processSample{snapshot(), snapshot()}, true, nil, false},
		"audited exit, transient": {[]map[processInstance]processSample{snapshot(a), snapshot()}, true, nil, false},
		"audited exit beside new": {[]map[processInstance]processSample{snapshot(a), snapshot(c)}, true, nil, true},
	} {
		calls := 0
		got, unresolved, err := settledResidue(context.Background(), func() (map[processInstance]processSample, bool, error) {
			snapshot := tc.snapshots[calls]
			calls++
			return snapshot, tc.unresolved, nil
		})
		if err != nil || !slices.Equal(got, tc.want) || unresolved != tc.wantUnresolved {
			t.Errorf("%s: residue %v unresolved=%t %v, want %v unresolved=%t", name, got, unresolved, err, tc.want, tc.wantUnresolved)
		}
	}
}

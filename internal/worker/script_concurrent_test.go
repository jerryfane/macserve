package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/jerryfane/macserve/internal/model"
)

const (
	siblingUDID  = "BBBBBBBB-0000-0000-0000-000000000002"
	scriptUDID   = "CCCCCCCC-0000-0000-0000-000000000003"
	baselineUDID = "DDDDDDDD-0000-0000-0000-000000000004"
)

// concurrentScriptJob admits job id of the script template of
// testTemplateJob with "concurrent": true, read from its JSON spelling.
func concurrentScriptJob(t *testing.T, id string) model.Job {
	t.Helper()
	pin, err := json.Marshal(fixtureSimulator)
	if err != nil {
		t.Fatal(err)
	}
	var template model.Template
	if err := json.Unmarshal([]byte(`{"id":"org-script-v1","version":1,"kind":"simulator_script","owners":["example-org"],"xcode":{"version":"16.0","build":"16A242d"},"developer_dir":"/Applications/Xcode.app/Contents/Developer","simulators":[`+string(pin)+`],"concurrent":true}`), &template); err != nil {
		t.Fatal(err)
	}
	job := admitTemplateJob(t, template, scriptShard)
	job.ID, job.LeaseToken = id, "lease-"+id
	return job
}

// deviceSet is CoreSimulator's device set for fakeRunner: simctl create
// adds the creating job's device (job-1 gets ownedUDID, any other job
// siblingUDID), the script command creates scriptUDID as a script's own
// `simctl create` would, and simctl delete removes a device. A job with a
// gate holds its recipe command (a test run or the script) until the gate
// closes, after reporting it on started.
type deviceSet struct {
	mu      sync.Mutex
	devices []string
	deleted []string
	gates   map[string]chan struct{}
	started chan string
}

func (d *deviceSet) list() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Sorted(slices.Values(d.devices))
}

func (d *deviceSet) hook(ctx context.Context, c Command, out, _ io.Writer) (bool, ProcessResult, error) {
	args := strings.Join(c.Args, " ")
	d.mu.Lock()
	defer d.mu.Unlock()
	if gate := d.gates[c.JobID]; gate != nil && (c.Executable == "/bin/bash" || len(c.Args) > 0 && c.Args[0] == "test") {
		d.mu.Unlock()
		d.started <- c.JobID
		select {
		case <-gate:
		case <-ctx.Done():
		}
		d.mu.Lock()
	}
	switch {
	case args == "simctl list devices --json":
		entries := make([]string, len(d.devices))
		for i, id := range d.devices {
			entries[i] = `{"udid":"` + id + `"}`
		}
		_, err := io.WriteString(out, `{"devices":{"runtime":[`+strings.Join(entries, ",")+`]}}`)
		return true, ProcessResult{CleanupOK: true}, err
	case strings.HasPrefix(args, "simctl create macserve-"):
		id := siblingUDID
		if c.JobID == "job-1" {
			id = ownedUDID
		}
		d.devices = append(d.devices, id)
		_, err := io.WriteString(out, id+"\n")
		return true, ProcessResult{CleanupOK: true}, err
	case strings.HasPrefix(args, "simctl delete "):
		id := strings.TrimPrefix(args, "simctl delete ")
		d.devices = slices.DeleteFunc(d.devices, func(have string) bool { return have == id })
		d.deleted = append(d.deleted, id)
		return true, ProcessResult{CleanupOK: true}, nil
	case c.Executable == "/bin/bash":
		d.devices = append(d.devices, scriptUDID)
		for _, entry := range c.Env {
			if output, ok := strings.CutPrefix(entry, "MACSERVE_OUTPUT="); ok {
				return true, ProcessResult{CleanupOK: true}, os.WriteFile(filepath.Join(output, "summary.md"), []byte("# script\n"), 0600)
			}
		}
		return true, ProcessResult{ExitCode: 1, CleanupOK: true}, errors.New("script ran without MACSERVE_OUTPUT")
	}
	return false, ProcessResult{}, nil
}

func gatedDevices(devices []string, jobs ...string) *deviceSet {
	set := &deviceSet{devices: devices, gates: map[string]chan struct{}{}, started: make(chan string, len(jobs))}
	for _, job := range jobs {
		set.gates[job] = make(chan struct{})
	}
	return set
}

// A script job whose template opts in to concurrency runs beside a UI-test
// job: the simulator its script creates is attributed to it (its processes
// through the lane tracker, the device in its manifest) and shut down and
// deleted at its end, while the sibling's device and a device that existed
// before the script stay.
func TestConcurrentScriptRunsBesideTestAndDeletesItsDevices(t *testing.T) {
	runner := newLaneFake()
	set := gatedDevices([]string{baselineUDID}, "job-a")
	runner.fakeRunner.hook = set.hook
	engine := laneEngine(t, runner, 3)
	source, data := sourceFixture(t)
	a := runLane(engine, fixtureLaneJob(t, "job-a", model.SimulatorUITest), source, data)
	<-set.started
	runner.take()

	script := concurrentScriptJob(t, "job-1")
	scriptSource, scriptData := checkoutFixture(t, scriptCheckout)
	result, err := engine.Execute(context.Background(), script, scriptSource, bytes.NewReader(scriptData), nil)
	if err != nil || result.State != model.Succeeded || !result.CleanupOK {
		t.Fatalf("concurrent script job: %+v %v", result, err)
	}
	if c := result.Concurrency; c.Attribution != AttributionLineage || c.IdleVerdict != IdleNotRequired || len(c.OverlappedJobs) != 1 || c.OverlappedJobs[0].JobID != "job-a" {
		t.Fatalf("script lane record: %+v", c)
	}
	events := runner.take()
	for _, want := range []string{"adopt job-1", "device job-1 " + ownedUDID, "device job-1 " + scriptUDID, "quiesce job-1"} {
		if !contains(events, want) {
			t.Fatalf("missing %q in %v", want, events)
		}
	}
	for _, other := range []string{siblingUDID, baselineUDID} {
		if contains(events, "device job-1 "+other) {
			t.Fatalf("script adopted %s: %v", other, events)
		}
	}
	if contains(events, "quiesce") {
		t.Fatalf("script beside a running job quiesced the whole account: %v", events)
	}
	if got, want := set.list(), []string{siblingUDID, baselineUDID}; !slices.Equal(got, want) {
		t.Fatalf("devices after the script = %v, want %v", got, want)
	}
	if got := shutdowns(runner.fakeRunner); !slices.Contains(got, scriptUDID) || !slices.Contains(got, ownedUDID) || slices.Contains(got, siblingUDID) || slices.Contains(got, baselineUDID) {
		t.Fatalf("shutdowns = %v", got)
	}
	if _, err := engine.root.Stat("manifests/job-1.json"); !os.IsNotExist(err) {
		t.Fatalf("script manifest kept: %v", err)
	}

	close(set.gates["job-a"])
	if out := <-a; out.err != nil || !out.result.CleanupOK {
		t.Fatalf("sibling job: %+v %v", out.result, out.err)
	}
	if got := set.list(); !slices.Equal(got, []string{baselineUDID}) {
		t.Fatalf("devices after both jobs = %v", got)
	}
}

func shutdowns(runner *fakeRunner) []string {
	var ids []string
	for _, c := range simctl(runner, "shutdown") {
		ids = append(ids, c.Args[2])
	}
	return ids
}

// Beside a running concurrent script job a build job starts, but no other
// concurrent script job, and no script job of a template without the opt-in.
func TestConcurrentScriptAdmitsOthersButNotAnotherScript(t *testing.T) {
	runner := newLaneFake()
	set := gatedDevices(nil, "job-1")
	runner.fakeRunner.hook = set.hook
	engine := laneEngine(t, runner, 3)
	source, data := checkoutFixture(t, scriptCheckout)
	script := runLane(engine, concurrentScriptJob(t, "job-1"), source, data)
	<-set.started
	if _, err := engine.Execute(context.Background(), concurrentScriptJob(t, "job-2"), source, bytes.NewReader(data), nil); !errors.Is(err, ErrBusy) {
		t.Fatalf("second concurrent script started: %v", err)
	}
	plain := testTemplateJob(t, model.SimulatorScript, scriptShard)
	plain.ID, plain.LeaseToken = "job-3", "lease-job-3"
	if _, err := engine.Execute(context.Background(), plain, source, bytes.NewReader(data), nil); !errors.Is(err, ErrBusy) {
		t.Fatalf("exclusive script started beside a job: %v", err)
	}
	buildSource, buildData := sourceFixture(t)
	if result, err := engine.Execute(context.Background(), fixtureLaneJob(t, "job-b", model.Build), buildSource, bytes.NewReader(buildData), nil); err != nil || !result.CleanupOK {
		t.Fatalf("build beside a concurrent script: %+v %v", result, err)
	}
	close(set.gates["job-1"])
	if out := <-script; out.err != nil || !out.result.CleanupOK {
		t.Fatalf("concurrent script: %+v %v", out.result, out.err)
	}
}

// writeManifest stores a resource manifest in its JSON spelling.
func writeManifest(t *testing.T, engine *Engine, job, spelling string) {
	t.Helper()
	if err := durableFile(engine.root, "manifests/"+job+".json", []byte(spelling)); err != nil {
		t.Fatal(err)
	}
}

// After a restart, Recover adopts and deletes the devices a concurrent
// script created since its recorded start, and keeps the devices that
// existed before it.
func TestRecoverDeletesDevicesOfInterruptedScript(t *testing.T) {
	runner := &fakeRunner{}
	set := &deviceSet{devices: []string{baselineUDID, scriptUDID}}
	runner.hook = set.hook
	engine := engineFixture(t, runner)
	writeManifest(t, engine, "job-z", `{"job_id":"job-z","developer_dir":"/Applications/Xcode.app/Contents/Developer","devices_before":null,"script_devices_pending":true,"script_devices_before":["`+baselineUDID+`"]}`)
	if err := engine.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := set.list(); !slices.Equal(got, []string{baselineUDID}) || !slices.Equal(set.deleted, []string{scriptUDID}) {
		t.Fatalf("devices %v, deleted %v", got, set.deleted)
	}
	if _, err := engine.root.Stat("manifests/job-z.json"); !os.IsNotExist(err) {
		t.Fatalf("recovered manifest kept: %v", err)
	}
}

// A script device that survives its deletion stays recorded and is
// contamination.
func TestScriptDeviceSurvivingDeletionIsContamination(t *testing.T) {
	runner := &fakeRunner{}
	set := &deviceSet{devices: []string{scriptUDID}}
	runner.hook = func(ctx context.Context, c Command, out, stderr io.Writer) (bool, ProcessResult, error) {
		if strings.HasPrefix(strings.Join(c.Args, " "), "simctl delete ") {
			return true, ProcessResult{CleanupOK: true}, nil
		}
		return set.hook(ctx, c, out, stderr)
	}
	engine := engineFixture(t, runner)
	writeManifest(t, engine, "job-z", `{"job_id":"job-z","developer_dir":"/Applications/Xcode.app/Contents/Developer","devices_before":null,"script_devices":["`+scriptUDID+`"]}`)
	if err := engine.Recover(context.Background()); !errors.Is(err, ErrContamination) {
		t.Fatalf("surviving script device: %v", err)
	}
	data, err := engine.root.ReadFile("manifests/job-z.json")
	if err != nil || !strings.Contains(string(data), scriptUDID) {
		t.Fatalf("surviving device no longer recorded: %s %v", data, err)
	}
}

// A device that appeared after a concurrent script's recorded start is that
// script's to adopt, not an unrecorded device of a sibling's interrupted
// creation; a device that was in the script's start inventory still is.
func TestInterruptedCreateLeavesScriptDevicesToTheScript(t *testing.T) {
	runner := &fakeRunner{}
	set := &deviceSet{devices: []string{baselineUDID, scriptUDID}}
	runner.hook = set.hook
	engine := engineFixture(t, runner)
	writeManifest(t, engine, "job-s", `{"job_id":"job-s","developer_dir":"/Applications/Xcode.app/Contents/Developer","devices_before":null,"script_devices_pending":true,"script_devices_before":["`+baselineUDID+`"]}`)
	pending := manifest{JobID: "job-a", DeveloperDir: "/Applications/Xcode.app/Contents/Developer", DeviceCreatePending: true, DevicesBefore: []string{}}
	if err := engine.saveManifest(pending); err != nil {
		t.Fatal(err)
	}
	if err := engine.verifyDeviceCreation(context.Background(), &pending); !errors.Is(err, ErrContamination) || !strings.Contains(err.Error(), baselineUDID) {
		t.Fatalf("device in the script's start inventory: %v", err)
	}
	set.devices = []string{scriptUDID}
	if err := engine.verifyDeviceCreation(context.Background(), &pending); err != nil {
		t.Fatalf("script's device judged unrecorded: %v", err)
	}
}

// A device a script process creates after the cleanup's first inventory,
// before the job's processes are stopped, is still adopted and deleted: the
// recorded start is released only after a second inventory once they are
// stopped.
func TestScriptDeviceCreatedDuringFinalizationIsDeleted(t *testing.T) {
	const lateUDID = "EEEEEEEE-0000-0000-0000-000000000005"
	set := &deviceSet{devices: []string{baselineUDID}}
	runner := &fakeRunner{hook: set.hook}
	var mu sync.Mutex
	finalizing := false
	runner.quiesce = func(ctx context.Context) error {
		set.mu.Lock()
		defer set.mu.Unlock()
		mu.Lock()
		defer mu.Unlock()
		// The first quiesce after the script ran is the cleanup's: the late
		// creation completes just before it stops the creator.
		if finalizing && slices.Contains(set.deleted, scriptUDID) && !slices.Contains(set.devices, lateUDID) && !slices.Contains(set.deleted, lateUDID) {
			set.devices = append(set.devices, lateUDID)
		}
		return ctx.Err()
	}
	inner := set.hook
	runner.hook = func(ctx context.Context, c Command, out, stderr io.Writer) (bool, ProcessResult, error) {
		if c.Executable == "/bin/bash" {
			mu.Lock()
			finalizing = true
			mu.Unlock()
		}
		return inner(ctx, c, out, stderr)
	}
	engine := engineFixture(t, runner)
	source, data := checkoutFixture(t, scriptCheckout)
	result, err := engine.Execute(context.Background(), concurrentScriptJob(t, "job-1"), source, bytes.NewReader(data), nil)
	if err != nil || result.State != model.Succeeded || !result.CleanupOK {
		t.Fatalf("script job: %+v %v", result, err)
	}
	if got := set.list(); !slices.Equal(got, []string{baselineUDID}) || !slices.Contains(set.deleted, lateUDID) {
		t.Fatalf("devices %v, deleted %v", got, set.deleted)
	}
}

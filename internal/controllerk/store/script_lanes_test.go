package store

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
)

// templateAdmission admits a job of an org template of kind, read from its
// JSON spelling: a script template with "concurrent": true when concurrent
// is set.
func templateAdmission(t *testing.T, kind model.Kind, concurrent bool) model.Admission {
	t.Helper()
	id := "org-" + strings.ReplaceAll(string(kind), "_", "-") + "-v1"
	spelling := `{"id":"` + id + `","version":1,"kind":"` + string(kind) + `","owners":["example-org"],"xcode":{"version":"27.0","build":"27A100"},"developer_dir":"/Applications/ExampleToolchain.app/Contents/Developer",` +
		`"simulators":[{"runtime":"com.apple.CoreSimulator.SimRuntime.iOS-27-0","runtime_build":"24A434","device_type":"com.apple.CoreSimulator.SimDeviceType.iPhone-18-Pro"}]`
	if concurrent {
		spelling += `,"concurrent":true`
	}
	var template model.Template
	if err := json.Unmarshal([]byte(spelling+"}"), &template); err != nil {
		t.Fatal(err)
	}
	registry, err := profiles.New(nil, []model.Template{template})
	if err != nil {
		t.Fatal(err)
	}
	admission, err := registry.Resolve(model.Request{Repo: "example-org/example-app", SHA: strings.Repeat("c", 40), Kind: kind, Profile: id, Xcode: template.Xcode, Shard: "shard"})
	if err != nil {
		t.Fatal(err)
	}
	return admission
}

func enqueueAdmission(t *testing.T, s *Store, key string, admission model.Admission, now time.Time) model.Job {
	t.Helper()
	job, _, err := s.Enqueue(context.Background(), "principal", key, admission, now)
	if err != nil {
		t.Fatal(err)
	}
	return job
}

// A script job whose template opts in to concurrency is claimed beside a UI
// test and a UI test beside it, each in its own lane.
func TestClaimRunsConcurrentScriptBesideTests(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t, Options{})
	ui := templateAdmission(t, model.SimulatorUITest, false)
	script := templateAdmission(t, model.SimulatorScript, true)
	first := enqueueAdmission(t, s, "ui-1", ui, testNow)
	scriptJob := enqueueAdmission(t, s, "script", script, testNow.Add(time.Second))
	second := enqueueAdmission(t, s, "ui-2", ui, testNow.Add(2*time.Second))
	for i, want := range []model.Job{first, scriptJob, second} {
		got := claimLanes(t, s, "epoch", testNow.Add(time.Duration(3+i)*time.Second), 4)
		if got.ID != want.ID || got.Lane != i+1 {
			t.Fatalf("claim %d: %s lane %d, want %s lane %d", i, got.ID, got.Lane, want.ID, i+1)
		}
	}
	active, err := s.ActiveJobs(ctx)
	if err != nil || len(active) != 3 {
		t.Fatalf("active = %d %v", len(active), err)
	}
}

// While a concurrent script job runs, the next one waits, and the jobs
// behind it are claimed meanwhile; it is claimed when the first ends.
func TestClaimQueuedConcurrentScriptDoesNotBlockJobsBehindIt(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t, Options{})
	ui := templateAdmission(t, model.SimulatorUITest, false)
	script := templateAdmission(t, model.SimulatorScript, true)
	first := enqueueAdmission(t, s, "script-1", script, testNow)
	waiting := enqueueAdmission(t, s, "script-2", script, testNow.Add(time.Second))
	behind := enqueueAdmission(t, s, "ui", ui, testNow.Add(2*time.Second))
	running := claimLanes(t, s, "epoch", testNow.Add(3*time.Second), 4)
	if running.ID != first.ID {
		t.Fatalf("claimed %s, want %s", running.ID, first.ID)
	}
	if got := claimLanes(t, s, "epoch", testNow.Add(4*time.Second), 4); got.ID != behind.ID {
		t.Fatalf("claimed %s, want the job behind the waiting script %s", got.ID, behind.ID)
	}
	_, err := s.Claim(ctx, "epoch", testNow.Add(5*time.Second), 4)
	requireError(t, err, ErrNoJob)
	if got := getJob(t, s, waiting.ID); got.State != model.Queued {
		t.Fatalf("second concurrent script claimed beside the first: %s", got.State)
	}
	finishJob(t, s, running, model.Succeeded, true, testNow.Add(6*time.Second))
	if got := claimLanes(t, s, "epoch", testNow.Add(7*time.Second), 4); got.ID != waiting.ID {
		t.Fatalf("claimed %s, want %s", got.ID, waiting.ID)
	}
}

// A script job without the opt-in keeps today's rule: as the head it waits
// for idle and nothing behind it is claimed; once claimed it runs alone.
func TestClaimPlainScriptStaysExclusive(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t, Options{})
	ui := templateAdmission(t, model.SimulatorUITest, false)
	plain := templateAdmission(t, model.SimulatorScript, false)
	first := enqueueAdmission(t, s, "ui-1", ui, testNow)
	script := enqueueAdmission(t, s, "script", plain, testNow.Add(time.Second))
	later := enqueueAdmission(t, s, "ui-2", ui, testNow.Add(2*time.Second))
	running := claimLanes(t, s, "epoch", testNow.Add(3*time.Second), 4)
	if running.ID != first.ID {
		t.Fatalf("claimed %s, want %s", running.ID, first.ID)
	}
	_, err := s.Claim(ctx, "epoch", testNow.Add(4*time.Second), 4)
	requireError(t, err, ErrNoJob)
	if got := getJob(t, s, later.ID); got.State != model.Queued {
		t.Fatalf("job behind an exclusive script head claimed: %s", got.State)
	}
	finishJob(t, s, running, model.Succeeded, true, testNow.Add(5*time.Second))
	if got := claimLanes(t, s, "epoch", testNow.Add(6*time.Second), 4); got.ID != script.ID {
		t.Fatalf("claimed %s, want %s", got.ID, script.ID)
	}
	_, err = s.Claim(ctx, "epoch", testNow.Add(7*time.Second), 4)
	requireError(t, err, ErrNoJob)
}

package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
)

func TestReplayNormalizesSnapshotAndNeverRecreatesPrunedJobs(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t, Options{Retention: time.Hour})
	job := enqueueJob(t, s, "principal", "retained", testNow)
	request := job.Request
	request.Repo = strings.ToUpper(request.Repo)
	request.SHA = strings.ToUpper(request.SHA)
	request.TimeoutSeconds = 0
	replay, err := s.Replay(ctx, "principal", "retained", request)
	if err != nil || replay.ID != job.ID || replay.Request.TimeoutSeconds != job.Profile.DefaultTimeoutSeconds {
		t.Fatalf("snapshot replay: %+v %v", replay, err)
	}
	changed := request
	changed.SHA = strings.Repeat("b", 40)
	_, err = s.Replay(ctx, "principal", "retained", changed)
	requireError(t, err, ErrConflict)
	_, err = s.Replay(ctx, "other-principal", "retained", request)
	requireError(t, err, ErrNotFound)
	if _, err := s.Cancel(ctx, job.ID, "finished", testNow); err != nil {
		t.Fatal(err)
	}
	if err := s.Prune(ctx, testNow.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	_, err = s.Replay(ctx, "principal", "retained", request)
	requireError(t, err, ErrNotFound)
	_, err = s.Lookup(ctx, "principal", "retained")
	requireError(t, err, ErrNotFound)
	// A genuinely new admission can reuse the retired key, but it carries
	// only the new caller's admitted profile, not the deleted snapshot.
	admission := admissionFixture()
	admission.Profile.Version++
	admission.Profile.DefaultTimeoutSeconds = 120
	admission.Request.TimeoutSeconds = 120
	setDigest(&admission)
	fresh, reused, err := s.Enqueue(ctx, "principal", "retained", admission, testNow.Add(time.Hour))
	if err != nil || reused || fresh.ID == job.ID || fresh.Profile.Version != 2 || fresh.Request.TimeoutSeconds != 120 {
		t.Fatalf("fresh admission: %+v replay=%v err=%v", fresh, reused, err)
	}
}

// Admission resolves an omitted simulator to a test template's first pin, so
// replay does too: omitting it replays a job that admitted the first pin and
// conflicts with one that explicitly chose another.
func TestReplayOmittedSimulatorIsTemplateFirstPin(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t, Options{})
	pins := []model.Simulator{
		{Runtime: "com.apple.CoreSimulator.SimRuntime.iOS-18-5", RuntimeBuild: "22F77", DeviceType: "com.apple.CoreSimulator.SimDeviceType.iPhone-16"},
		{Runtime: "com.apple.CoreSimulator.SimRuntime.iOS-18-5", RuntimeBuild: "22F77", DeviceType: "com.apple.CoreSimulator.SimDeviceType.iPad-Pro-11-inch-M4-8GB"},
	}
	template := model.Template{ID: "org-test-v1", Version: 1, Kind: model.SimulatorUITest, Owners: []string{"example-org"}, Xcode: model.Xcode{Version: "27.0", Build: "27A100"}, DeveloperDir: "/Applications/ExampleToolchain.app/Contents/Developer", Simulators: pins, DefaultTimeoutSeconds: 600, MaxTimeoutSeconds: 600, MemoryLimitMiB: 512}
	registry, err := profiles.New(nil, []model.Template{template})
	if err != nil {
		t.Fatal(err)
	}
	omitted := model.Request{Repo: "example-org/example-app", SHA: strings.Repeat("a", 40), Kind: model.SimulatorUITest, Profile: template.ID, Xcode: template.Xcode, Shard: "terminal"}
	for key, pin := range map[string]*model.Simulator{"first": nil, "second": &pins[1]} {
		request := omitted
		request.Simulator = pin
		admission, err := registry.Resolve(request)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.Enqueue(ctx, "principal", key, admission, testNow); err != nil {
			t.Fatal(err)
		}
	}
	if job, err := s.Replay(ctx, "principal", "first", omitted); err != nil || *job.Request.Simulator != pins[0] {
		t.Fatalf("omitted simulator replay of the first pin: %+v %v", job, err)
	}
	second := omitted
	second.Simulator = &pins[1]
	if _, err := s.Replay(ctx, "principal", "second", second); err != nil {
		t.Fatalf("explicit second-pin replay: %v", err)
	}
	_, err = s.Replay(ctx, "principal", "second", omitted)
	requireError(t, err, ErrConflict)
}

package receipt

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/worker"
)

var receiptFlutterPin = model.FlutterPin{Version: "3.41.9", SDKSHA256: strings.Repeat("a", 64), RubySHA256: strings.Repeat("b", 64), CocoaPodsVersion: "1.16.2", GemsSHA256: strings.Repeat("c", 64)}

// flutterTemplateFixture is a successful Flutter template build job: its
// request names the pinned Flutter version, the worker reports the recipe
// derived from a flutter .macserve.json and observed exactly the pinned
// Flutter and CocoaPods.
func flutterTemplateFixture(t *testing.T) (Options, model.Job, worker.Result, Expected) {
	t.Helper()
	options, job, result, expected := fixture(t, model.Build)
	pin := receiptFlutterPin
	template := model.Template{ID: "org-flutter-build-v1", Version: 1, Kind: model.Build, Owners: []string{"example-org"}, Xcode: job.Profile.Xcode, DeveloperDir: job.Profile.DeveloperDir, DefaultTimeoutSeconds: 300, MaxTimeoutSeconds: 600, MemoryLimitMiB: 8192, Flutter: &pin}
	snapshot := profiles.TemplateSnapshot(template, job.Request.Repo)
	digest, err := snapshot.SnapshotDigest()
	if err != nil {
		t.Fatal(err)
	}
	job.Profile, job.ProfileDigest, job.Request.Profile = snapshot, digest, snapshot.ID
	job.Request.Flutter = &model.FlutterRequest{Version: pin.Version}
	request, err := json.Marshal(job.Request)
	if err != nil {
		t.Fatal(err)
	}
	job.RequestDigest = hashBytes(request)
	config := model.RepoConfig{Version: 1, WorkDir: "apps/mobile/ios", Workspace: "Runner.xcworkspace", Scheme: "Runner", Flutter: &model.FlutterConfig{AppDir: "apps/mobile"}}
	derived, err := profiles.Derive(snapshot, config)
	if err != nil {
		t.Fatal(err)
	}
	result.Observation.Recipe = &model.RepoRecipe{ConfigSHA256: strings.Repeat("f", 64), Config: config, WorkDir: derived.WorkDir, Prepare: derived.Prepare, Run: derived.Run}
	result.Observation.Flutter = &worker.FlutterObservation{FrameworkVersion: "3.41.9", DartSDKVersion: "3.11.5", Ruby: "ruby 3.4.6", CocoaPods: "1.16.2"}
	result.Commands[0].Executable, result.Commands[0].Args = derived.Run.Executable, derived.Run.Args
	expected.Profile, expected.ProfileDigest = snapshot.ID, digest
	return options, job, result, expected
}

func sealRefused(t *testing.T, options Options, job model.Job, result worker.Result) {
	t.Helper()
	signer, err := NewSigner(options)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()
	if _, err := signer.Seal(context.Background(), job, result); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unproven flutter observation sealed: %v", err)
	}
}

// A Flutter template receipt carries the observed Flutter toolchain and
// validates only when it is exactly the pin's; a non-Flutter receipt carries
// none.
func TestFlutterReceiptRequiresPinnedObservation(t *testing.T) {
	options, job, result, expected := flutterTemplateFixture(t)
	_, _, p := sealFixture(t, options, job, result)
	if err := ValidateSuccess(p, expected); err != nil {
		t.Fatal(err)
	}
	if p.Observation.Flutter != *result.Observation.Flutter || p.Request.Flutter == nil || p.Request.Flutter.Version != "3.41.9" {
		t.Fatalf("receipt flutter evidence: %+v %+v", p.Observation.Flutter, p.Request.Flutter)
	}
	for name, mutate := range map[string]func(*worker.Result){
		"observation missing":       func(r *worker.Result) { r.Observation.Flutter = nil },
		"framework version differs": func(r *worker.Result) { r.Observation.Flutter.FrameworkVersion = "3.41.8" },
		"cocoapods differs":         func(r *worker.Result) { r.Observation.Flutter.CocoaPods = "1.15.2" },
		"dart version missing":      func(r *worker.Result) { r.Observation.Flutter.DartSDKVersion = "" },
		"ruby missing":              func(r *worker.Result) { r.Observation.Flutter.Ruby = "" },
	} {
		t.Run(name, func(t *testing.T) {
			options, job, result, _ := flutterTemplateFixture(t)
			mutate(&result)
			sealRefused(t, options, job, result)
		})
	}
	t.Run("present for a non-Flutter template", func(t *testing.T) {
		options, job, result, _ := templateFixture(t)
		result.Observation.Flutter = &worker.FlutterObservation{FrameworkVersion: "3.41.9", DartSDKVersion: "3.11.5", Ruby: "ruby 3.4.6", CocoaPods: "1.16.2"}
		sealRefused(t, options, job, result)
	})
	// A non-Flutter receipt's payload has no flutter key at all.
	options, job, result, _ = templateFixture(t)
	_, raw, _ := sealFixture(t, options, job, result)
	if strings.Contains(string(raw), `"flutter"`) {
		t.Fatalf("non-flutter receipt names flutter: %s", raw)
	}
}

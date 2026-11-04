package receipt

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/worker"
)

// templateFixture is an org-template build job: its admitted profile is the
// template snapshot with no recipe, and the worker reports the recipe it
// derived from the repository's .macserve.json.
func templateFixture(t *testing.T) (Options, model.Job, worker.Result, Expected) {
	t.Helper()
	options, job, result, expected := fixture(t, model.Build)
	template := model.Template{ID: "ios-build", Version: 1, Kind: model.Build, Owners: []string{"example-org"}, Xcode: job.Profile.Xcode, DeveloperDir: job.Profile.DeveloperDir, DefaultTimeoutSeconds: 300, MaxTimeoutSeconds: 600, MemoryLimitMiB: 8192}
	snapshot := profiles.TemplateSnapshot(template, job.Request.Repo)
	digest, err := snapshot.SnapshotDigest()
	if err != nil {
		t.Fatal(err)
	}
	job.Profile, job.ProfileDigest, job.Request.Profile = snapshot, digest, snapshot.ID
	request, err := json.Marshal(job.Request)
	if err != nil {
		t.Fatal(err)
	}
	job.RequestDigest = hashBytes(request)
	config := model.RepoConfig{Version: 1, WorkDir: "ios", Project: "App.xcodeproj", Scheme: "App"}
	derived, err := profiles.Derive(snapshot, config)
	if err != nil {
		t.Fatal(err)
	}
	result.Observation.Recipe = &model.RepoRecipe{ConfigSHA256: strings.Repeat("f", 64), Config: config, WorkDir: derived.WorkDir, Prepare: derived.Prepare, Run: derived.Run}
	result.Commands[0].Executable, result.Commands[0].Args = derived.Run.Executable, derived.Run.Args
	expected.Profile, expected.ProfileDigest = snapshot.ID, digest
	return options, job, result, expected
}

func TestTemplateJobSealsAgainstDerivedRecipe(t *testing.T) {
	options, job, result, expected := templateFixture(t)
	_, _, p := sealFixture(t, options, job, result)
	if err := ValidateSuccess(p, expected); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*worker.Result){
		"recipe differs from derivation": func(r *worker.Result) {
			r.Observation.Recipe.Run.Args = append(append([]string(nil), r.Observation.Recipe.Run.Args...), "-allowProvisioningUpdates")
		},
		"derived executable never ran":     func(r *worker.Result) { r.Commands[0].Executable = "/bin/sh" },
		"derived executable failed":        func(r *worker.Result) { r.Commands[0].ExitCode = 65 },
		"derived executable was signalled": func(r *worker.Result) { r.Commands[0].Signal = "SIGKILL" },
		"recipe missing":                   func(r *worker.Result) { r.Observation.Recipe = nil },
	} {
		t.Run(name, func(t *testing.T) {
			options, job, result, _ := templateFixture(t)
			mutate(&result)
			signer, err := NewSigner(options)
			if err != nil {
				t.Fatal(err)
			}
			defer signer.Close()
			if _, err := signer.Seal(context.Background(), job, result); !errors.Is(err, ErrInvalid) {
				t.Fatalf("template success with unproven recipe sealed: %v", err)
			}
		})
	}
}

// testTemplateFixture is a successful org test-template job of kind for the
// shard "terminal": its admitted snapshot has no required tests, the worker
// reports the recipe derived from .macserve.json, and the summary is the
// captured herdrup suite parsed against the shard's bundle-relative
// Target/Class selectors.
func testTemplateFixture(t *testing.T, kind model.Kind) (Options, model.Job, worker.Result, Expected) {
	t.Helper()
	options, job, result, expected := fixture(t, model.SimulatorUITest)
	template := model.Template{ID: "org-test-v1", Version: 1, Kind: kind, Owners: []string{"example-org"}, Xcode: job.Profile.Xcode, DeveloperDir: job.Profile.DeveloperDir, Simulators: []model.Simulator{*job.Profile.Simulator}, DefaultTimeoutSeconds: 300, MaxTimeoutSeconds: 600, MemoryLimitMiB: 8192}
	registry, err := profiles.New(nil, []model.Template{template})
	if err != nil {
		t.Fatal(err)
	}
	admission, err := registry.Resolve(model.Request{Repo: job.Request.Repo, SHA: job.Request.SHA, Kind: kind, Profile: template.ID, Xcode: template.Xcode, Shard: "terminal", TimeoutSeconds: 300})
	if err != nil {
		t.Fatal(err)
	}
	job.Request, job.Profile, job.ProfileDigest = admission.Request, admission.Profile, admission.ProfileDigest
	request, err := json.Marshal(job.Request)
	if err != nil {
		t.Fatal(err)
	}
	job.RequestDigest = hashBytes(request)
	selectors := []string{"HerdrUITests/TerminalControlTests", "HerdrUITests/TerminalSearchTests"}
	shards := &model.TestShards{Shards: map[string][]string{"terminal": selectors}}
	config := model.RepoConfig{Version: 1, WorkDir: ".", Project: "Herdr.xcodeproj", Scheme: "Herdr", UITest: shards, UnitTest: shards}
	derived, err := profiles.Derive(job.Profile, config)
	if err != nil {
		t.Fatal(err)
	}
	result.Observation.Recipe = &model.RepoRecipe{ConfigSHA256: strings.Repeat("f", 64), Config: config, WorkDir: derived.WorkDir, Prepare: derived.Prepare, Run: derived.Run, Shard: derived.Shard, RequiredTests: derived.RequiredTests}
	result.Commands[0].Executable, result.Commands[0].Args = derived.Run.Executable, derived.Run.Args
	report, err := os.ReadFile(filepath.Join("..", "evidence", "testdata", "herdrup-uitests.json"))
	if err != nil {
		t.Fatal(err)
	}
	summary, err := evidence.ParseTests(report, derived.RequiredTests)
	if err != nil {
		t.Fatal(err)
	}
	summary.XCResultSHA256 = result.Summary.XCResultSHA256
	result.Summary = &summary
	expected.Profile, expected.ProfileDigest, expected.Kind, expected.Simulator, expected.RequiredTests = template.ID, admission.ProfileDigest, kind, admission.Request.Simulator, selectors
	return options, job, result, expected
}

// A template test job's receipt binds its shard's selectors: the signer seals
// the derived required tests, success validation compares them on the
// effective profile rather than the empty snapshot, and the suite's
// bundle-relative cases count as executing them.
func TestTemplateUITestReceiptValidates(t *testing.T) {
	for _, kind := range []model.Kind{model.SimulatorUITest, model.UnitTest} {
		t.Run(string(kind), func(t *testing.T) {
			options, job, result, expected := testTemplateFixture(t, kind)
			_, _, p := sealFixture(t, options, job, result)
			if err := ValidateSuccess(p, expected); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(p.Tests.Required, expected.RequiredTests) || !slices.Equal(p.Tests.ExecutedRequired, expected.RequiredTests) {
				t.Fatalf("sealed test evidence %+v", p.Tests)
			}
			snapshot := expected
			snapshot.RequiredTests = job.Profile.RequiredTests
			if ValidateSuccess(p, snapshot) == nil {
				t.Fatal("receipt matched the snapshot's empty required tests")
			}
		})
	}
}

// Receipt test evidence counts a required selector as executed by the same
// bundle-relative rule as evidence.ParseTests: real Xcode records
// class-relative case IDs under a plan-rooted suite path, and a selector of
// another target, class or method is not executed.
func TestRequiredExecutedMatchesBundleRelative(t *testing.T) {
	report, err := os.ReadFile(filepath.Join("..", "evidence", "testdata", "herdrup-uitests.json"))
	if err != nil {
		t.Fatal(err)
	}
	executed := []string{"HerdrUITests/TerminalControlTests", "HerdrUITests/TerminalSearchTests/testEngineAndWiringAgree()", "HerdrUITests/TerminalResizeTests/testAppBackgroundReleasesClaimAndReturnReclaims"}
	summary, err := evidence.ParseTests(report, executed)
	if err != nil {
		t.Fatal(err)
	}
	if got := testEvidence(model.SimulatorUITest, executed, &summary).ExecutedRequired; !slices.Equal(got, executed) {
		t.Fatalf("executed required %q, want %q", got, executed)
	}
	others := []string{"OtherUITests/TerminalControlTests", "Herdr/TerminalControlTests", "HerdrUITests/TerminalResizeTests/testEngineAndWiringAgree"}
	if got := testEvidence(model.SimulatorUITest, others, &summary).ExecutedRequired; len(got) != 0 {
		t.Fatalf("unexecuted selectors counted: %q", got)
	}
}

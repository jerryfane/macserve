package receipt

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/worker"
)

// scriptTemplateFixture is a successful org script-template job for the shard
// "duo": the worker reports the recipe derived from .macserve.json, the
// script ran on the job's simulator, and its outputs are artifacts. It has no
// test summary or test artifacts.
func scriptTemplateFixture(t *testing.T) (Options, model.Job, worker.Result, Expected) {
	t.Helper()
	options, job, result, expected := fixture(t, model.SimulatorUITest)
	template := model.Template{ID: "org-script-v1", Version: 1, Kind: model.SimulatorScript, Owners: []string{"example-org"}, Xcode: job.Profile.Xcode, DeveloperDir: job.Profile.DeveloperDir, Simulators: []model.Simulator{*job.Profile.Simulator}, DefaultTimeoutSeconds: 300, MaxTimeoutSeconds: 600, MemoryLimitMiB: 8192}
	registry, err := profiles.New(nil, []model.Template{template})
	if err != nil {
		t.Fatal(err)
	}
	admission, err := registry.Resolve(model.Request{Repo: job.Request.Repo, SHA: job.Request.SHA, Kind: model.SimulatorScript, Profile: template.ID, Xcode: template.Xcode, Shard: "duo", TimeoutSeconds: 300})
	if err != nil {
		t.Fatal(err)
	}
	job.Request, job.Profile, job.ProfileDigest = admission.Request, admission.Profile, admission.ProfileDigest
	request, err := json.Marshal(job.Request)
	if err != nil {
		t.Fatal(err)
	}
	job.RequestDigest = hashBytes(request)
	config := model.RepoConfig{Version: 1, WorkDir: ".", Project: "Herdr.xcodeproj", Scheme: "Herdr", Script: &model.ScriptShards{Shards: map[string]model.ScriptShard{"duo": {Run: "Tools/ci/duo-screenshots.sh"}}}}
	derived, err := profiles.Derive(job.Profile, config)
	if err != nil {
		t.Fatal(err)
	}
	result.Observation.Recipe = &model.RepoRecipe{ConfigSHA256: strings.Repeat("f", 64), Config: config, WorkDir: derived.WorkDir, Prepare: derived.Prepare, Run: derived.Run, Shard: derived.Shard}
	result.Commands[0].Executable, result.Commands[0].Args = derived.Run.Executable, derived.Run.Args
	result.Summary = nil
	logs := result.Artifacts[:2]
	expires := logs[0].ExpiresAt
	result.Artifacts = append(slices.Clone(logs),
		evidence.Artifact{ID: "portrait", Name: "output/duo/portrait.png", MediaType: "image/png", SizeBytes: 100, SHA256: hashBytes([]byte("portrait")), ExpiresAt: expires},
		evidence.Artifact{ID: "summary", Name: "output/summary.md", MediaType: "text/markdown", SizeBytes: 10, SHA256: hashBytes([]byte("summary")), ExpiresAt: expires},
	)
	expected.Profile, expected.ProfileDigest, expected.Kind, expected.Simulator, expected.RequiredTests = template.ID, admission.ProfileDigest, model.SimulatorScript, admission.Request.Simulator, nil
	return options, job, result, expected
}

// A script job's receipt proves the derived script ran on the pinned
// simulator with no test evidence: tests are "tests_not_run" with no
// required tests, and test evidence, a missing simulator pin or an unproven
// script refuse.
func TestTemplateScriptReceiptValidates(t *testing.T) {
	options, job, result, expected := scriptTemplateFixture(t)
	_, _, p := sealFixture(t, options, job, result)
	if err := ValidateSuccess(p, expected); err != nil {
		t.Fatal(err)
	}
	if p.Tests.Status != "tests_not_run" || len(p.Tests.Required) != 0 || p.Tests.Tests != 0 || p.Request.Kind != model.SimulatorScript || p.Request.Shard != "duo" || p.ArtifactCount != 4 {
		t.Fatalf("sealed script evidence %+v", p)
	}
	unpinned := p
	unpinned.Request.Simulator = nil
	if missing := incomplete(unpinned); !slices.Contains(missing, "simulator pin") {
		t.Fatalf("script receipt without a simulator pin: %q", missing)
	}
	tested := p
	tested.Tests.Status, tested.Tests.Tests, tested.Tests.Passed = "parsed", 1, 1
	if missing := incomplete(tested); !slices.Contains(missing, "script test scope") {
		t.Fatalf("script receipt with test counts: %q", missing)
	}
	for name, mutate := range map[string]func(*worker.Result){
		"test summary": func(r *worker.Result) {
			r.Summary = &evidence.Summary{SchemaVersion: 1, ParserVersion: "xcresult-tests-0.4.0", ParseStatus: "parsed", Tests: 1, Passed: 1, Cases: []evidence.TestCase{{ID: "Suite/testWorks", Suite: "Suite", Name: "testWorks", Outcome: "passed", Attempt: 1}}, XCResultSHA256: hashBytes([]byte("archive"))}
		},
		"script never ran":        func(r *worker.Result) { r.Commands[0].Executable = "/usr/bin/xcrun" },
		"script failed":           func(r *worker.Result) { r.Commands[0].ExitCode = 1 },
		"other script reported":   func(r *worker.Result) { r.Observation.Recipe.Run.Args = []string{"${CHECKOUT}/other.sh"} },
		"simulator build dropped": func(r *worker.Result) { r.Observation.Recipe.Prepare = nil },
		"simulator not observed":  func(r *worker.Result) { r.Observation.DeviceUDID = "" },
		"recipe missing":          func(r *worker.Result) { r.Observation.Recipe = nil },
	} {
		t.Run(name, func(t *testing.T) {
			options, job, result, _ := scriptTemplateFixture(t)
			mutate(&result)
			signer, err := NewSigner(options)
			if err != nil {
				t.Fatal(err)
			}
			defer signer.Close()
			if _, err := signer.Seal(context.Background(), job, result); !errors.Is(err, ErrInvalid) {
				t.Fatalf("unproven script success sealed: %v", err)
			}
		})
	}
}

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

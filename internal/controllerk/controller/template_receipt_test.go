package controller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/receipt"
	"github.com/jerryfane/macserve/internal/worker"
)

// A successful org-template job completes through the worker socket with the
// production signer: its admitted snapshot has no recipe, so the receipt must
// be validated against the recipe derived from the reported .macserve.json.
func TestTemplateJobCompletesWithSignedReceipt(t *testing.T) {
	f := newRuntime(t)
	c := f.controller
	template := model.Template{ID: "ios-build", Version: 1, Kind: model.Build, Owners: []string{"example-org"}, Xcode: model.Xcode{Version: "27.0", Build: "27A100"}, DeveloperDir: "/Applications/ExampleToolchain.app/Contents/Developer", DefaultTimeoutSeconds: 600, MaxTimeoutSeconds: 600, MemoryLimitMiB: 512}
	snapshot := profiles.TemplateSnapshot(template, "example-org/example-app")
	digest, err := snapshot.SnapshotDigest()
	if err != nil {
		t.Fatal(err)
	}
	admission := model.Admission{Request: model.Request{Repo: snapshot.Repo, SHA: strings.Repeat("a", 40), Kind: model.Build, Profile: snapshot.ID, Xcode: snapshot.Xcode, TimeoutSeconds: 600}, Profile: snapshot, ProfileDigest: digest}
	if _, _, err := f.db.Enqueue(context.Background(), "owner", "template", admission, f.now); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	signer, err := receipt.NewSigner(receipt.Options{Root: filepath.Join(t.TempDir(), "receipts"), KeyID: "key-1", PrivateKey: key, Service: receipt.ServiceIdentity{ID: "service", HostID: "host", Version: "1.0", BinarySHA256: strings.Repeat("d", 64)}, Repository: func(_ context.Context, job model.Job) (receipt.Repository, error) {
		return receipt.Repository{ID: 123, Name: job.Request.Repo}, nil
	}, Now: c.options.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { signer.Close() })
	c.options.Seal = signer.Seal
	lease := f.dispatch(t)
	config := model.RepoConfig{Version: 1, WorkDir: "ios", Project: "App.xcodeproj", Scheme: "App"}
	derived, err := profiles.Derive(lease.Job.Profile, config)
	if err != nil {
		t.Fatal(err)
	}
	zero := 0
	// The receipt manifest requires distinct artifact ids, so stdout differs
	// from the empty stderr log.
	result := worker.Result{State: model.Succeeded, CleanupOK: true, ExitCode: &zero, StartedAt: f.now, FinishedAt: f.now, Source: lease.Source, Observation: worker.Observation{Xcode: lease.Job.Profile.Xcode, Architecture: "arm64", SDKVersion: "18.5", SDKBuild: "22F77", SwiftVersion: "6.2", OSVersion: "26.0", OSBuild: "25A1"}, Artifacts: []evidence.Artifact{f.artifact(t, lease.Job, "evidence/stdout.log", []byte("** BUILD SUCCEEDED **\n")), f.artifact(t, lease.Job, "evidence/stderr.log", nil)}}
	result.Observation.Recipe = &model.RepoRecipe{ConfigSHA256: strings.Repeat("f", 64), Config: config, WorkDir: derived.WorkDir, Prepare: derived.Prepare, Run: derived.Run}
	// A success claim without the derived recipe's command is refused with a
	// definite client status, not an opaque 500, and leaves the job open.
	result.Commands = []worker.ExecutedCommand{{Executable: "/bin/sh", StartedAt: result.StartedAt, FinishedAt: result.FinishedAt}}
	if status := lifecycleRequest(t, c, lease, "/complete", result); status != http.StatusUnprocessableEntity {
		t.Fatalf("unproven template success: HTTP %d", status)
	}
	result.Commands = []worker.ExecutedCommand{{Executable: derived.Run.Executable, Args: derived.Run.Args, StartedAt: result.StartedAt, FinishedAt: result.FinishedAt}}
	if status := lifecycleRequest(t, c, lease, "/complete", result); status != http.StatusNoContent {
		t.Fatalf("template completion: HTTP %d", status)
	}
	job, err := f.db.Get(context.Background(), lease.Job.ID)
	if err != nil || job.State != model.Succeeded {
		t.Fatalf("template job state: %+v %v", job, err)
	}
	raw, err := c.Receipt(context.Background(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	p, err := receipt.Verify(raw, map[string]ed25519.PublicKey{"key-1": key.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	if err := receipt.ValidateSuccess(p, receipt.Expected{RepositoryID: 123, Repo: snapshot.Repo, SHA: admission.Request.SHA, Profile: snapshot.ID, ProfileDigest: digest, Kind: model.Build, Xcode: snapshot.Xcode}); err != nil {
		t.Fatal(err)
	}
}

// A successful org test-template job (simulator_ui_test or unit_test)
// completes through the worker socket with the production signer. Its
// admitted snapshot has no required tests: the controller reparses the
// captured herdrup suite against the shard's bundle-relative selectors, the
// signer seals them and success validation accepts the receipt. A selector
// with no executed case turns the success claim into a failure.
func TestTemplateTestJobsCompleteWithSignedReceipt(t *testing.T) {
	selectors := []string{"HerdrUITests/TerminalControlTests", "HerdrUITests/TerminalSearchTests"}
	report, err := os.ReadFile(filepath.Join("..", "..", "evidence", "testdata", "herdrup-uitests.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		kind      model.Kind
		selectors []string
		want      model.State
	}{
		{"simulator_ui_test", model.SimulatorUITest, selectors, model.Succeeded},
		{"unit_test", model.UnitTest, selectors, model.Succeeded},
		{"selector not executed", model.SimulatorUITest, append(slices.Clone(selectors), "HerdrUITests/MissingTests"), model.Failed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRuntime(t)
			c := f.controller
			template := model.Template{ID: "org-test-v1", Version: 1, Kind: tc.kind, Owners: []string{"example-org"}, Xcode: model.Xcode{Version: "27.0", Build: "27A100"}, DeveloperDir: "/Applications/ExampleToolchain.app/Contents/Developer", Simulators: []model.Simulator{{Runtime: "com.apple.CoreSimulator.SimRuntime.iOS-18-5", RuntimeBuild: "22F77", DeviceType: "com.apple.CoreSimulator.SimDeviceType.iPhone-16"}}, DefaultTimeoutSeconds: 600, MaxTimeoutSeconds: 600, MemoryLimitMiB: 512}
			registry, err := profiles.New(nil, []model.Template{template})
			if err != nil {
				t.Fatal(err)
			}
			admission, err := registry.Resolve(model.Request{Repo: "example-org/example-app", SHA: strings.Repeat("a", 40), Kind: tc.kind, Profile: template.ID, Xcode: template.Xcode, Shard: "terminal", TimeoutSeconds: 600})
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := f.db.Enqueue(context.Background(), "owner", "template", admission, f.now); err != nil {
				t.Fatal(err)
			}
			key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
			signer, err := receipt.NewSigner(receipt.Options{Root: filepath.Join(t.TempDir(), "receipts"), KeyID: "key-1", PrivateKey: key, Service: receipt.ServiceIdentity{ID: "service", HostID: "host", Version: "1.0", BinarySHA256: strings.Repeat("d", 64)}, Repository: func(_ context.Context, job model.Job) (receipt.Repository, error) {
				return receipt.Repository{ID: 123, Name: job.Request.Repo}, nil
			}, Now: c.options.Now})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { signer.Close() })
			c.options.Seal = signer.Seal
			lease := f.dispatch(t)
			shards := &model.TestShards{Shards: map[string][]string{"terminal": tc.selectors}}
			config := model.RepoConfig{Version: 1, WorkDir: ".", Project: "Herdr.xcodeproj", Scheme: "Herdr", UITest: shards, UnitTest: shards}
			derived, err := profiles.Derive(lease.Job.Profile, config)
			if err != nil {
				t.Fatal(err)
			}
			zero := 0
			// The receipt manifest requires distinct artifact ids, so stdout
			// differs from the empty stderr log.
			result := worker.Result{State: model.Succeeded, CleanupOK: true, ExitCode: &zero, StartedAt: f.now, FinishedAt: f.now, Source: lease.Source, Observation: worker.Observation{Xcode: lease.Job.Profile.Xcode, Architecture: "arm64", SDKVersion: "18.5", SDKBuild: "22F77", SwiftVersion: "6.2", OSVersion: "26.0", OSBuild: "25A1", RuntimeVersion: "18.5", RuntimeBuild: "22F77", DeviceUDID: "device-fixture"}, Artifacts: []evidence.Artifact{f.artifact(t, lease.Job, "evidence/stdout.log", []byte("** TEST EXECUTE SUCCEEDED **\n")), f.artifact(t, lease.Job, "evidence/stderr.log", nil), f.artifact(t, lease.Job, "evidence/tests.json", report), f.artifact(t, lease.Job, "results.xcresult.tar.gz", []byte("sealed result fixture"))}}
			result.Observation.Recipe = &model.RepoRecipe{ConfigSHA256: strings.Repeat("f", 64), Config: config, WorkDir: derived.WorkDir, Prepare: derived.Prepare, Run: derived.Run, Shard: derived.Shard, RequiredTests: derived.RequiredTests}
			result.Commands = []worker.ExecutedCommand{{Executable: derived.Run.Executable, Args: derived.Run.Args, StartedAt: result.StartedAt, FinishedAt: result.FinishedAt}}
			if status := lifecycleRequest(t, c, lease, "/complete", result); status != http.StatusNoContent {
				t.Fatalf("template test completion: HTTP %d", status)
			}
			job, err := f.db.Get(context.Background(), lease.Job.ID)
			if err != nil || job.State != tc.want {
				t.Fatalf("template test job state: %+v %v", job, err)
			}
			var saved Completion
			if err := json.Unmarshal(job.Result, &saved); err != nil {
				t.Fatal(err)
			}
			if saved.Result.Summary == nil || !slices.Equal(saved.Result.Summary.RequiredTests, tc.selectors) {
				t.Fatalf("tests not reparsed against the shard: %+v", saved.Result.Summary)
			}
			p, err := receipt.Verify(saved.Receipt, map[string]ed25519.PublicKey{"key-1": key.Public().(ed25519.PublicKey)})
			if err != nil {
				t.Fatal(err)
			}
			err = receipt.ValidateSuccess(p, receipt.Expected{RepositoryID: 123, Repo: admission.Request.Repo, SHA: admission.Request.SHA, Profile: template.ID, ProfileDigest: admission.ProfileDigest, Kind: tc.kind, Xcode: template.Xcode, Simulator: admission.Request.Simulator, RequiredTests: tc.selectors})
			if tc.want == model.Succeeded && err != nil {
				t.Fatal(err)
			}
			if tc.want == model.Failed && (err == nil || job.Reason != "test evidence did not prove success" || saved.Result.Summary.ParseStatus == "parsed") {
				t.Fatalf("unexecuted selector: reason %q, validation %v", job.Reason, err)
			}
		})
	}
}

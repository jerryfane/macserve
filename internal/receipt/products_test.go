package receipt

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/worker"
)

// buildForTestingFixture is a succeeded build-for-testing producer job of a
// build template: the worker ran the derived arm64 build-for-testing and
// exported test-products.tar.
func buildForTestingFixture(t *testing.T) (Options, model.Job, worker.Result, Expected) {
	t.Helper()
	options, job, result, expected := fixture(t, model.Build)
	template := model.Template{ID: "ios-build", Version: 1, Kind: model.Build, Owners: []string{"example-org"}, Xcode: job.Profile.Xcode, DeveloperDir: job.Profile.DeveloperDir, DefaultTimeoutSeconds: 300, MaxTimeoutSeconds: 600, MemoryLimitMiB: 8192}
	registry, err := profiles.New(nil, []model.Template{template})
	if err != nil {
		t.Fatal(err)
	}
	admission, err := registry.Resolve(model.Request{Repo: job.Request.Repo, SHA: job.Request.SHA, Kind: model.Build, Profile: template.ID, Xcode: template.Xcode, TimeoutSeconds: 300, BuildForTesting: true})
	if err != nil {
		t.Fatal(err)
	}
	job.Request, job.Profile, job.ProfileDigest = admission.Request, admission.Profile, admission.ProfileDigest
	request, err := json.Marshal(job.Request)
	if err != nil {
		t.Fatal(err)
	}
	job.RequestDigest = hashBytes(request)
	config := model.RepoConfig{Version: 1, WorkDir: ".", Project: "Herdr.xcodeproj", Scheme: "Herdr"}
	derived, err := profiles.Derive(job.Profile, config)
	if err != nil {
		t.Fatal(err)
	}
	result.Observation.Recipe = &model.RepoRecipe{ConfigSHA256: strings.Repeat("f", 64), Config: config, WorkDir: derived.WorkDir, Prepare: derived.Prepare, Run: derived.Run}
	result.Observation.Xctestrun = "Herdr_iphonesimulator27.1-arm64.xctestrun"
	result.Commands[0].Executable, result.Commands[0].Args = derived.Run.Executable, derived.Run.Args
	result.Artifacts = append(result.Artifacts, evidence.Artifact{ID: "products", Name: profiles.TestProductsArtifact, MediaType: "application/x-tar", SizeBytes: 240 << 20, SHA256: hashBytes([]byte("products")), ExpiresAt: result.Artifacts[0].ExpiresAt})
	expected.Profile, expected.ProfileDigest, expected.BuildForTesting = template.ID, admission.ProfileDigest, true
	return options, job, result, expected
}

// A producer's success receipt validates only against a build-for-testing
// expectation: the plain build check's expectation refuses it, and a plain
// build's receipt cannot satisfy a producer expectation.
func TestBuildForTestingReceiptBindsTheFlag(t *testing.T) {
	options, job, result, expected := buildForTestingFixture(t)
	_, _, p := sealFixture(t, options, job, result)
	if err := ValidateSuccess(p, expected); err != nil {
		t.Fatal(err)
	}
	if !p.Request.BuildForTesting {
		t.Fatalf("receipt request %+v", p.Request)
	}
	plain := expected
	plain.BuildForTesting = false
	if err := ValidateSuccess(p, plain); !errors.Is(err, ErrInvalid) {
		t.Fatalf("producer receipt satisfied a plain build expectation: %v", err)
	}
	options, job, result, expected = templateFixture(t)
	_, _, p = sealFixture(t, options, job, result)
	expected.BuildForTesting = true
	if err := ValidateSuccess(p, expected); !errors.Is(err, ErrInvalid) {
		t.Fatalf("plain build receipt satisfied a producer expectation: %v", err)
	}
}

// A producer success without its test-products.tar is never sealed.
func TestBuildForTestingSuccessRequiresTestProducts(t *testing.T) {
	options, job, result, _ := buildForTestingFixture(t)
	result.Artifacts = result.Artifacts[:len(result.Artifacts)-1]
	signer, err := NewSigner(options)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()
	if _, err := signer.Seal(context.Background(), job, result); !errors.Is(err, ErrInvalid) {
		t.Fatalf("producer success without test products sealed: %v", err)
	}
}

package keyholder

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/buildseal"
	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/worker"
)

var buildTemplate = model.Template{ID: "org-ios-sim-build-v1", Version: 1, Kind: model.Build, Owners: []string{"acme"}, Xcode: model.Xcode{Version: "27.0", Build: "27A100"}, DeveloperDir: "/Applications/Xcode.app/Contents/Developer"}

const productsXctestrun = "App_iphonesimulator27.0-arm64.xctestrun"

// newProductsFixture is a succeeded build-for-testing job admitted from the
// registry and the worker result it reported: its test-products.tar
// artifact and the .xctestrun it observed.
func newProductsFixture(t *testing.T, buildForTesting bool) *fixture {
	t.Helper()
	f := newFixture(t, scopedRelease)
	registry, err := profiles.New(nil, []model.Template{buildTemplate})
	if err != nil {
		t.Fatal(err)
	}
	admission, err := registry.Resolve(model.Request{Repo: repo, SHA: commit, Kind: model.Build, Profile: buildTemplate.ID, Xcode: buildTemplate.Xcode, BuildForTesting: buildForTesting})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(admission.Request)
	sum := sha256.Sum256(raw)
	f.job.Request, f.job.Profile, f.job.ProfileDigest, f.job.RequestDigest, f.job.ReleaseProvenance = admission.Request, admission.Profile, admission.ProfileDigest, hex.EncodeToString(sum[:]), nil
	f.resolved = buildseal.Resolution{ProfileID: buildTemplate.ID, ProfileVersion: buildTemplate.Version, ProfileDigest: admission.ProfileDigest, Xcode: buildTemplate.Xcode, DeveloperDir: buildTemplate.DeveloperDir}
	expires := f.result.Artifacts[0].ExpiresAt
	f.result.Commands = []worker.ExecutedCommand{{Executable: "/usr/bin/xcrun", Args: []string{"xcodebuild", "build-for-testing"}}}
	f.result.Artifacts = []evidence.Artifact{f.result.Artifacts[0]}
	if buildForTesting {
		f.result.Artifacts = append(f.result.Artifacts, evidence.Artifact{ID: "products", Name: profiles.TestProductsArtifact, MediaType: "application/x-tar", SizeBytes: 240 << 20, SHA256: digestOf("products"), ExpiresAt: expires})
		f.result.Observation.Xctestrun = productsXctestrun
	}
	return f
}

// The worker seal of a succeeded build-for-testing job names its products
// digest and .xctestrun, and the keyholder signs its receipt; a plain build
// job's seal names neither.
func TestBuildForTestingReceiptBindsSealedProducts(t *testing.T) {
	f := newProductsFixture(t, true)
	req := f.request(t)
	seal, err := buildseal.Verify(req.Seal, f.engine.options.SealKeys)
	if err != nil {
		t.Fatal(err)
	}
	if seal.ProductsSHA256 != digestOf("products") || seal.Xctestrun != productsXctestrun || seal.SourceTree != tree || !seal.Request.BuildForTesting {
		t.Fatalf("seal %+v", seal)
	}
	if _, err := f.engine.Seal(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	plain := newProductsFixture(t, false)
	req = plain.request(t)
	if seal, err = buildseal.Verify(req.Seal, plain.engine.options.SealKeys); err != nil || seal.ProductsSHA256 != "" || seal.Xctestrun != "" {
		t.Fatalf("plain build seal %+v %v", seal, err)
	}
	if _, err := plain.engine.Seal(context.Background(), req); err != nil {
		t.Fatal(err)
	}
}

// A success receipt of a build-for-testing job needs the products the
// worker sealed, exactly as the result carries them; no other job's seal may
// name products.
func TestBuildForTestingReceiptRefusedWithoutSealedProducts(t *testing.T) {
	for name, tc := range map[string]struct {
		buildForTesting bool
		mutate          func(*fixture)
		request         func(*testing.T, *fixture, SealRequest) SealRequest
	}{
		"no products artifact": {true, func(f *fixture) { f.result.Artifacts = f.result.Artifacts[:1] }, nil},
		"no xctestrun":         {true, func(f *fixture) { f.result.Observation.Xctestrun = "" }, nil},
		"invalid xctestrun":    {true, func(f *fixture) { f.result.Observation.Xctestrun = "../App.xctestrun" }, nil},
		"products dropped by the controller": {true, nil, func(_ *testing.T, _ *fixture, req SealRequest) SealRequest {
			req.Result.Artifacts = req.Result.Artifacts[:1]
			return req
		}},
		"forged products digest": {true, nil, func(t *testing.T, f *fixture, req SealRequest) SealRequest {
			return resealed(t, f, req, func(s *buildseal.Seal) { s.ProductsSHA256 = strings.Repeat("f", 64) })
		}},
		"forged xctestrun": {true, nil, func(t *testing.T, f *fixture, req SealRequest) SealRequest {
			return resealed(t, f, req, func(s *buildseal.Seal) { s.Xctestrun = "Other.xctestrun" })
		}},
		"products named for a plain build": {false, nil, func(t *testing.T, f *fixture, req SealRequest) SealRequest {
			return resealed(t, f, req, func(s *buildseal.Seal) { s.ProductsSHA256, s.Xctestrun = digestOf("products"), productsXctestrun })
		}},
	} {
		t.Run(name, func(t *testing.T) {
			f := newProductsFixture(t, tc.buildForTesting)
			if tc.mutate != nil {
				tc.mutate(f)
			}
			req := f.request(t)
			if tc.request != nil {
				req = tc.request(t, f, req)
			}
			refused(t, f, req)
		})
	}
}

// A build-for-testing job that failed before it sealed products still gets
// its failure receipt.
func TestFailedBuildForTestingReceiptSigned(t *testing.T) {
	f := newProductsFixture(t, true)
	one := 1
	f.result.State, f.result.ExitCode, f.result.Reason = model.Failed, &one, "test products: archive refused: 0 .xctestrun files, want exactly one"
	f.result.Artifacts = f.result.Artifacts[:1]
	f.result.Observation.Xctestrun = ""
	if _, err := f.engine.Seal(context.Background(), f.request(t)); err != nil {
		t.Fatal(err)
	}
}

// resealed is req with its worker seal edited by edit and signed again with
// the worker's key: a seal only the worker could forge.
func resealed(t *testing.T, f *fixture, req SealRequest, edit func(*buildseal.Seal)) SealRequest {
	t.Helper()
	seal, err := buildseal.Verify(req.Seal, f.engine.options.SealKeys)
	if err != nil {
		t.Fatal(err)
	}
	edit(&seal)
	if req.Seal, err = buildseal.Sign(f.sealKey, "worker", seal); err != nil {
		t.Fatal(err)
	}
	return req
}

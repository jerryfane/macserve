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
	"github.com/jerryfane/macserve/internal/receipt"
	"github.com/jerryfane/macserve/internal/worker"
)

var consumerTemplate = model.Template{ID: "org-ios-sim-uitest-v1", Version: 1, Kind: model.SimulatorUITest, Owners: []string{"acme"}, Xcode: buildTemplate.Xcode, DeveloperDir: buildTemplate.DeveloperDir,
	Simulators: []model.Simulator{{Runtime: "com.apple.CoreSimulator.SimRuntime.iOS-27-0", RuntimeBuild: "24A100", DeviceType: "com.apple.CoreSimulator.SimDeviceType.iPhone-18-Pro"}}}

var productsConfig = model.RepoConfig{Version: 1, WorkDir: ".", Project: "App.xcodeproj", Scheme: "App", UITest: &model.TestShards{Shards: map[string][]string{"smoke": {"AppUITests/SmokeTests"}}}}

// recipeOf is the worker's recipe evidence of snapshot under productsConfig.
func recipeOf(t *testing.T, snapshot model.Profile) *model.RepoRecipe {
	t.Helper()
	derived, err := profiles.Derive(snapshot, productsConfig)
	if err != nil {
		t.Fatal(err)
	}
	return &model.RepoRecipe{ConfigSHA256: digestOf("config"), Config: productsConfig, WorkDir: derived.WorkDir, Prepare: derived.Prepare, Run: derived.Run, Shard: derived.Shard, RequiredTests: derived.RequiredTests}
}

// signedProducer has the keyholder sign a succeeded build-for-testing
// producer's receipt and returns the fixture, the reference a consumer of
// it names and the producer's verified seal and its digest.
func signedProducer(t *testing.T) (*fixture, model.ProductsRef, buildseal.Seal, string) {
	t.Helper()
	f := newProductsFixture(t, true)
	f.job.ID = "j_producer"
	f.result.Observation.Recipe = recipeOf(t, f.job.Profile)
	req := f.request(t)
	if _, err := f.engine.Seal(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	seal, err := buildseal.Verify(req.Seal, f.engine.options.SealKeys)
	if err != nil || seal.RecipeDigest == "" {
		t.Fatalf("producer seal %+v %v", seal, err)
	}
	f.signer.jobs, f.signer.approvals, f.signer.products = nil, nil, nil
	return f, model.ProductsRef{ProducerJobID: f.job.ID, SHA256: digestOf("products"), Xctestrun: productsXctestrun}, seal, req.Seal.SealDigest()
}

// asConsumer turns f into a succeeded consumer job of ref at sha, admitted
// from the registry, whose worker verified and imported the products.
func asConsumer(t *testing.T, f *fixture, ref model.ProductsRef, sha string) {
	t.Helper()
	registry, err := profiles.New(nil, []model.Template{consumerTemplate})
	if err != nil {
		t.Fatal(err)
	}
	admission, err := registry.Resolve(model.Request{Repo: repo, SHA: sha, Kind: model.SimulatorUITest, Profile: consumerTemplate.ID, Xcode: consumerTemplate.Xcode, Shard: "smoke", Products: &ref})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(admission.Request)
	sum := sha256.Sum256(raw)
	f.job.ID = "j_consumer"
	f.job.Request, f.job.Profile, f.job.ProfileDigest, f.job.RequestDigest = admission.Request, admission.Profile, admission.ProfileDigest, hex.EncodeToString(sum[:])
	f.resolved = buildseal.Resolution{ProfileID: consumerTemplate.ID, ProfileVersion: consumerTemplate.Version, ProfileDigest: admission.ProfileDigest, Xcode: consumerTemplate.Xcode, DeveloperDir: consumerTemplate.DeveloperDir}
	f.result.Source.Commit = sha
	f.result.Commands = []worker.ExecutedCommand{{Executable: "/usr/bin/xcrun", Args: []string{"xcodebuild", "test-without-building"}}}
	f.result.Artifacts = []evidence.Artifact{f.result.Artifacts[0]}
	f.result.Observation.Xctestrun = ""
	f.result.Observation.ImportedProducts = ref.SHA256
	f.result.Observation.Recipe = recipeOf(t, f.job.Profile)
}

// A consumer's receipt binds the producer from the keyholder's own record
// of the producer's signed success: its job ID, seal digest and recipe
// digest, the source tree both jobs computed, the products the consumer's
// worker verified and imported, and the .xctestrun.
func TestConsumerReceiptBindsProducerFromKeyholderRecord(t *testing.T) {
	f, ref, producer, producerSeal := signedProducer(t)
	asConsumer(t, f, ref, commit)
	req := f.request(t)
	seal, err := buildseal.Verify(req.Seal, f.engine.options.SealKeys)
	if err != nil || seal.ImportedProductsSHA256 != ref.SHA256 {
		t.Fatalf("consumer seal %+v %v", seal, err)
	}
	if _, err := f.engine.Seal(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	want := receipt.Products{ProducerJobID: "j_producer", ProducerSealSHA256: producerSeal, ProducerRecipeDigest: producer.RecipeDigest, SourceTree: tree, ProductsSHA256: digestOf("products"), Xctestrun: productsXctestrun, SelectorsSource: "repo_config"}
	if len(f.signer.products) != 1 || f.signer.products[0] == nil || *f.signer.products[0] != want {
		t.Fatalf("receipt products %+v, want %+v", f.signer.products, want)
	}
	// A replay of the producer's seal keeps its record.
	if err := f.engine.recordProducer(producer, producerSeal); err != nil {
		t.Fatal(err)
	}
}

// A consumer's success receipt is refused unless the keyholder signed the
// producer's success and the consumer imported exactly that producer's
// products for the same commit, tree and Xcode; no other job's seal may
// name imported products.
func TestConsumerReceiptRefusedWithoutProducerBinding(t *testing.T) {
	other := strings.Repeat("b", 40)
	for name, tc := range map[string]struct {
		mutate  func(*testing.T, *fixture, model.ProductsRef)
		request func(*testing.T, *fixture, SealRequest) SealRequest
	}{
		"producer never signed": {func(t *testing.T, f *fixture, ref model.ProductsRef) {
			ref.ProducerJobID = "j_unsigned"
			asConsumer(t, f, ref, commit)
		}, nil},
		"nothing imported": {func(t *testing.T, f *fixture, ref model.ProductsRef) {
			asConsumer(t, f, ref, commit)
			f.result.Observation.ImportedProducts = ""
		}, nil},
		"other products imported": {func(t *testing.T, f *fixture, ref model.ProductsRef) { asConsumer(t, f, ref, commit) }, func(t *testing.T, f *fixture, req SealRequest) SealRequest {
			return resealed(t, f, req, func(s *buildseal.Seal) { s.ImportedProductsSHA256 = strings.Repeat("f", 64) })
		}},
		"another commit": {func(t *testing.T, f *fixture, ref model.ProductsRef) { asConsumer(t, f, ref, other) }, nil},
		"another source tree": {func(t *testing.T, f *fixture, ref model.ProductsRef) { asConsumer(t, f, ref, commit) }, func(t *testing.T, f *fixture, req SealRequest) SealRequest {
			return resealed(t, f, req, func(s *buildseal.Seal) { s.SourceTree = strings.Repeat("8", 40) })
		}},
		"no source tree": {func(t *testing.T, f *fixture, ref model.ProductsRef) { asConsumer(t, f, ref, commit) }, func(t *testing.T, f *fixture, req SealRequest) SealRequest {
			return resealed(t, f, req, func(s *buildseal.Seal) { s.SourceTree = "" })
		}},
		"another digest named": {func(t *testing.T, f *fixture, ref model.ProductsRef) {
			ref.SHA256 = strings.Repeat("e", 64)
			asConsumer(t, f, ref, commit)
		}, nil},
		"another xctestrun named": {func(t *testing.T, f *fixture, ref model.ProductsRef) {
			ref.Xctestrun = "Other.xctestrun"
			asConsumer(t, f, ref, commit)
		}, nil},
		"imported products on a job that consumes none": {func(t *testing.T, f *fixture, ref model.ProductsRef) {
			asConsumer(t, f, ref, commit)
			f.job = newProductsFixture(t, false).job
			f.job.ID = "j_consumer"
			f.resolved = buildseal.Resolution{ProfileID: buildTemplate.ID, ProfileVersion: buildTemplate.Version, ProfileDigest: f.job.ProfileDigest, Xcode: buildTemplate.Xcode, DeveloperDir: buildTemplate.DeveloperDir}
			f.result.Observation.Recipe, f.result.Observation.ImportedProducts = nil, ""
		}, func(t *testing.T, f *fixture, req SealRequest) SealRequest {
			return resealed(t, f, req, func(s *buildseal.Seal) { s.ImportedProductsSHA256 = digestOf("products") })
		}},
	} {
		t.Run(name, func(t *testing.T) {
			f, ref, _, _ := signedProducer(t)
			tc.mutate(t, f, ref)
			req := f.request(t)
			if tc.request != nil {
				req = tc.request(t, f, req)
			}
			refused(t, f, req)
		})
	}
}

// A consumer that failed before it imported anything (its products were
// evicted) still gets its failure receipt, without a producer binding.
func TestFailedConsumerReceiptSignedWithoutBinding(t *testing.T) {
	f, ref, _, _ := signedProducer(t)
	asConsumer(t, f, ref, commit)
	one := 1
	f.result.State, f.result.ExitCode, f.result.Reason = model.Failed, &one, "test products: download: unavailable"
	f.result.Observation.ImportedProducts = ""
	if _, err := f.engine.Seal(context.Background(), f.request(t)); err != nil {
		t.Fatal(err)
	}
	if len(f.signer.products) != 1 || f.signer.products[0] != nil {
		t.Fatalf("failure receipt products %+v", f.signer.products)
	}
}

// Only a signed producer success is recorded, a record names one seal, and
// Forget drops it with the producer's other records.
func TestProducerRecordLifecycle(t *testing.T) {
	failed := newProductsFixture(t, true)
	failed.job.ID = "j_producer"
	one := 1
	failed.result.State, failed.result.ExitCode = model.Failed, &one
	if _, err := failed.engine.Seal(context.Background(), failed.request(t)); err != nil {
		t.Fatal(err)
	}
	var record producerRecord
	if err := failed.engine.loadRecord(producerRecordName("j_producer"), &record); err == nil {
		t.Fatal("a failed producer was recorded")
	}
	f, ref, producer, _ := signedProducer(t)
	if err := f.engine.recordProducer(producer, strings.Repeat("9", 64)); err == nil {
		t.Fatal("another seal of a recorded producer replaced its record")
	}
	if err := f.engine.Forget(context.Background(), []string{"j_producer"}); err != nil {
		t.Fatal(err)
	}
	asConsumer(t, f, ref, commit)
	refused(t, f, f.request(t))
}

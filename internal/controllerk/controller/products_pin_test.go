package controller

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/buildseal"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
)

// consumerAdmission is a UI test template job of the runtime fixture's
// repository and commit that runs from products.
func consumerAdmission(t *testing.T, products model.ProductsRef) model.Admission {
	t.Helper()
	simulator := model.Simulator{Runtime: "com.apple.CoreSimulator.SimRuntime.iOS-27-0", RuntimeBuild: "24A434", DeviceType: "com.apple.CoreSimulator.SimDeviceType.iPhone-18-Pro"}
	template := model.Template{ID: "org-ios-sim-uitest-v1", Version: 1, Kind: model.SimulatorUITest, Owners: []string{"example-org"}, Xcode: model.Xcode{Version: "27.0", Build: "27A100"}, DeveloperDir: "/Applications/ExampleToolchain.app/Contents/Developer", Simulators: []model.Simulator{simulator}, DefaultTimeoutSeconds: 600, MaxTimeoutSeconds: 600, MemoryLimitMiB: 512}
	registry, err := profiles.New(nil, []model.Template{template})
	if err != nil {
		t.Fatal(err)
	}
	admission, err := registry.Resolve(model.Request{Repo: "example-org/example-app", SHA: strings.Repeat("a", 40), Kind: model.SimulatorUITest, Profile: template.ID, Xcode: template.Xcode, Simulator: &simulator, Shard: "smoke", TimeoutSeconds: 600, Products: &products})
	if err != nil {
		t.Fatal(err)
	}
	return admission
}

// The products pool never evicts the products an unfinished consumer job
// names, even past the budget and before newer bytes: the consumer still
// downloads them. Once the consumer ends they are ordinary bytes again.
func TestProductsPoolKeepsProductsOfUnfinishedConsumers(t *testing.T) {
	f := newRuntime(t)
	ctx := context.Background()
	if _, _, err := f.db.Enqueue(ctx, "owner", "producer", buildForTestingAdmission(t), f.now); err != nil {
		t.Fatal(err)
	}
	lease := f.dispatch(t)
	consumed := f.artifact(t, lease.Job, profiles.TestProductsArtifact, []byte("consumed products"))
	result := f.result(t, lease)
	result.Artifacts = append(result.Artifacts, consumed)
	result.Observation.Xctestrun = "App_iphonesimulator27.0-arm64.xctestrun"
	config := model.RepoConfig{Version: 1, WorkDir: ".", Project: "App.xcodeproj", Scheme: "App"}
	derived, err := profiles.Derive(lease.Job.Profile, config)
	if err != nil {
		t.Fatal(err)
	}
	result.Observation.Recipe = &model.RepoRecipe{ConfigSHA256: strings.Repeat("f", 64), Config: config, WorkDir: derived.WorkDir, Prepare: derived.Prepare, Run: derived.Run}
	if err := f.controller.complete(ctx, lease.Job, result, buildseal.Envelope{}); err != nil {
		t.Fatal(err)
	}
	ref := model.ProductsRef{ProducerJobID: lease.Job.ID, SHA256: consumed.SHA256, Xctestrun: result.Observation.Xctestrun}
	consumer, _, err := f.db.Enqueue(ctx, "owner", "consumer", consumerAdmission(t, ref), f.now)
	if err != nil {
		t.Fatal(err)
	}
	// Newer bytes no consumer names.
	other := pooledProduct(t, f, "other products!!", "gone", f.now.Add(maxProductAge/2))
	root := filepath.Join(f.controller.options.Root, productsDir)
	trim := func(limit int64) {
		t.Helper()
		f.controller.evidenceMu.Lock()
		defer f.controller.evidenceMu.Unlock()
		if err := f.controller.trimProducts(ctx, 0, limit); err != nil {
			t.Fatal(err)
		}
	}
	trim(consumed.SizeBytes)
	if _, err := os.Stat(filepath.Join(root, consumed.SHA256+".tar")); err != nil {
		t.Fatalf("consumed products evicted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, other+".tar")); !os.IsNotExist(err) {
		t.Fatalf("unpinned products kept: %v", err)
	}
	if _, err := f.db.Cancel(ctx, consumer.ID, "test", model.CancelReason{Source: model.CancelClient, Principal: "owner"}, f.now); err != nil {
		t.Fatal(err)
	}
	trim(0)
	if _, err := os.Stat(filepath.Join(root, consumed.SHA256+".tar")); !os.IsNotExist(err) {
		t.Fatalf("products of an ended consumer kept: %v", err)
	}
}

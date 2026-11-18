package controller

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/buildseal"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/protocol"
)

// getProducts asks the worker socket's handler, served over a real
// connection (the route sets a write deadline) as the authenticated worker,
// for job's products with epoch and token.
func getProducts(t *testing.T, c *Controller, job, epoch, token string) (int, string) {
	t.Helper()
	server := httptest.NewUnstartedServer(c.handler())
	server.Config.ConnContext = func(ctx context.Context, _ net.Conn) context.Context { return context.WithValue(ctx, peerKey{}, true) }
	server.Start()
	defer server.Close()
	r, err := http.NewRequest(http.MethodGet, server.URL+protocol.Prefix+"/jobs/"+job+"/products", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set(protocol.EpochHeader, epoch)
	r.Header.Set(protocol.LeaseHeader, token)
	resp, err := server.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// consumerLease completes a build-for-testing producer whose products the
// pool holds, admits a UI-test consumer of them and returns the producer's
// lease and the consumer's.
func consumerLease(t *testing.T, f *runtimeFixture, content string) (protocol.Lease, protocol.Lease, string) {
	t.Helper()
	ctx := context.Background()
	if _, _, err := f.db.Enqueue(ctx, "owner", "producer", buildForTestingAdmission(t), f.now); err != nil {
		t.Fatal(err)
	}
	producer := f.dispatch(t)
	products := f.artifact(t, producer.Job, profiles.TestProductsArtifact, []byte(content))
	result := f.result(t, producer)
	result.Artifacts = append(result.Artifacts, products)
	result.Observation.Xctestrun = "App_iphonesimulator27.0-arm64.xctestrun"
	config := model.RepoConfig{Version: 1, WorkDir: ".", Project: "App.xcodeproj", Scheme: "App"}
	derived, err := profiles.Derive(producer.Job.Profile, config)
	if err != nil {
		t.Fatal(err)
	}
	result.Observation.Recipe = &model.RepoRecipe{ConfigSHA256: strings.Repeat("f", 64), Config: config, WorkDir: derived.WorkDir, Prepare: derived.Prepare, Run: derived.Run}
	if err := f.controller.complete(ctx, producer.Job, result, buildseal.Envelope{}); err != nil {
		t.Fatal(err)
	}
	if done, err := f.db.Get(ctx, producer.Job.ID); err != nil || done.State != model.Succeeded {
		t.Fatalf("producer %s %q %v", done.State, done.Reason, err)
	}
	ui := model.Template{ID: "org-ios-sim-uitest-v1", Version: 1, Kind: model.SimulatorUITest, Owners: []string{"example-org"}, Xcode: producer.Job.Request.Xcode, DeveloperDir: producer.Job.Profile.DeveloperDir, Simulators: []model.Simulator{{Runtime: "com.apple.CoreSimulator.SimRuntime.iOS-18-5", RuntimeBuild: "22F77", DeviceType: "com.apple.CoreSimulator.SimDeviceType.Example"}}, DefaultTimeoutSeconds: 600, MaxTimeoutSeconds: 600, MemoryLimitMiB: 512}
	registry, err := profiles.New(nil, []model.Template{ui})
	if err != nil {
		t.Fatal(err)
	}
	ref := model.ProductsRef{ProducerJobID: producer.Job.ID, SHA256: products.SHA256, Xctestrun: result.Observation.Xctestrun}
	admission, err := registry.Resolve(model.Request{Repo: producer.Job.Request.Repo, SHA: producer.Job.Request.SHA, Kind: model.SimulatorUITest, Profile: ui.ID, Xcode: ui.Xcode, Shard: "smoke", TimeoutSeconds: 600, Products: &ref})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.db.Enqueue(ctx, "owner", "consumer", admission, f.now); err != nil {
		t.Fatal(err)
	}
	return producer, f.dispatch(t), products.SHA256
}

// The products route serves a consumer's products only to the worker
// holding that consumer's offered lease, and only while its bytes are
// pooled: a wrong token, another job's lease, a cancelled lease, a job that
// consumes nothing and evicted bytes are all refused, without serving bytes.
func TestProductsRouteServesOnlyTheConsumerLeaseHolder(t *testing.T) {
	f := newRuntime(t)
	producer, consumer, digest := consumerLease(t, f, "sealed products tar")
	id, epoch := consumer.Job.ID, consumer.Job.WorkerEpoch
	if status, body := getProducts(t, f.controller, id, epoch, consumer.Token); status != http.StatusOK || body != "sealed products tar" {
		t.Fatalf("lease holder: %d %q", status, body)
	}
	for name, tc := range map[string]struct{ job, epoch, token string }{
		"wrong token":               {id, epoch, "not-the-lease"},
		"wrong epoch":               {id, "epoch-b", consumer.Token},
		"another job's lease":       {id, epoch, producer.Token},
		"finished producer's lease": {producer.Job.ID, epoch, producer.Token},
	} {
		if status, body := getProducts(t, f.controller, tc.job, tc.epoch, tc.token); status == http.StatusOK || body == "sealed products tar" {
			t.Fatalf("%s: served %d", name, status)
		}
	}
	if err := f.db.EvictProduct(context.Background(), digest, f.now); err != nil {
		t.Fatal(err)
	}
	if status, _ := getProducts(t, f.controller, id, epoch, consumer.Token); status != http.StatusGone {
		t.Fatalf("evicted products: %d, want 410", status)
	}

	cancelled := newRuntime(t)
	_, lease, _ := consumerLease(t, cancelled, "cancelled consumer's products")
	if _, err := cancelled.db.Cancel(context.Background(), lease.Job.ID, "operator", model.CancelReason{Source: model.CancelClient, Principal: "owner"}, cancelled.now); err != nil {
		t.Fatal(err)
	}
	if status, _ := getProducts(t, cancelled.controller, lease.Job.ID, lease.Job.WorkerEpoch, lease.Token); status != http.StatusGone {
		t.Fatalf("cancelled lease: %d, want 410", status)
	}

	plain := newRuntime(t)
	build := plain.lease(t, model.Build)
	if status, _ := getProducts(t, plain.controller, build.Job.ID, build.Job.WorkerEpoch, build.Token); status != http.StatusNotFound {
		t.Fatalf("job without products: %d, want 404", status)
	}
}

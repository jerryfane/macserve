package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/buildseal"
	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/protocol"
)

// uploadRequest puts data as the lease's artifact name through the worker
// socket's handler, as the worker does, and returns the status.
func uploadRequest(t *testing.T, c *Controller, lease protocol.Lease, name string, data []byte) (int, evidence.Artifact) {
	t.Helper()
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	a := evidence.Artifact{ID: digest, SHA256: digest, Name: name, MediaType: "application/octet-stream", SizeBytes: int64(len(data)), ExpiresAt: c.options.Now().Add(7 * 24 * time.Hour)}
	header, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPut, protocol.Prefix+"/jobs/"+lease.Job.ID+"/artifacts/"+a.ID, bytes.NewReader(data))
	r = r.WithContext(context.WithValue(r.Context(), peerKey{}, true))
	r.Header.Set(protocol.EpochHeader, lease.Job.WorkerEpoch)
	r.Header.Set(protocol.LeaseHeader, lease.Token)
	r.Header.Set(protocol.ArtifactHeader, base64.RawURLEncoding.EncodeToString(header))
	w := httptest.NewRecorder()
	c.handler().ServeHTTP(w, r)
	return w.Code, a
}

// succeededProducer runs a build-for-testing producer of content to success
// and returns the products reference a consumer of it names.
func succeededProducer(t *testing.T, f *runtimeFixture, content string) model.ProductsRef {
	t.Helper()
	ctx := context.Background()
	if _, _, err := f.db.Enqueue(ctx, "owner", "producer-"+content, buildForTestingAdmission(t), f.now); err != nil {
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
	return model.ProductsRef{ProducerJobID: producer.Job.ID, SHA256: products.SHA256, Xctestrun: result.Observation.Xctestrun}
}

// Pinned products filling the pool never stop the worker: the producer's
// upload is answered (never 413, which the worker treats as fatal), its
// completion is accepted, and the producer fails durably with a products
// pool reason. The pinned bytes stay, the service is not quarantined, and
// the same worker epoch is leased the next job (review F1).
func TestPinnedProductsPoolFullFailsTheProducerAndKeepsTheWorker(t *testing.T) {
	f := newRuntime(t)
	ctx := context.Background()
	c := f.controller
	ref := succeededProducer(t, f, "pinned products!")
	pinned := ref.SHA256
	// A queued consumer pins its products, which fill the pool.
	c.productsBudget = int64(len("pinned products!")) + 8
	if _, _, err := f.db.Enqueue(ctx, "owner", "producer-2", buildForTestingAdmission(t), f.now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.db.Enqueue(ctx, "owner", "pinning-consumer", consumerAdmission(t, ref), f.now); err != nil {
		t.Fatal(err)
	}
	producer := f.dispatch(t)
	if !producer.Job.Request.BuildForTesting {
		t.Fatalf("dispatched %+v", producer.Job.Request)
	}
	status, products := uploadRequest(t, c, producer, profiles.TestProductsArtifact, []byte("products that do not fit"))
	if status/100 != 2 {
		t.Fatalf("products upload into a full pinned pool: %d", status)
	}
	result := f.result(t, producer)
	result.Artifacts = append(result.Artifacts, products)
	result.Observation.Xctestrun = "App_iphonesimulator27.0-arm64.xctestrun"
	if status := lifecycleRequest(t, c, producer, "/complete", result); status != http.StatusNoContent {
		t.Fatalf("completion %d", status)
	}
	done, err := f.db.Get(ctx, producer.Job.ID)
	if err != nil || done.State != model.Failed || !strings.Contains(done.Reason, "products pool has no room") {
		t.Fatalf("producer %s %q %v", done.State, done.Reason, err)
	}
	if _, err := os.Stat(filepath.Join(c.options.Root, productsDir, pinned+".tar")); err != nil {
		t.Fatalf("pinned products evicted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(c.options.Root, productsDir, products.SHA256+".tar")); !os.IsNotExist(err) {
		t.Fatalf("refused products stored: %v", err)
	}
	state, err := f.db.ServiceState(ctx)
	if err != nil || state.Quarantined {
		t.Fatalf("service %+v %v", state, err)
	}
	next := f.dispatch(t)
	if next.Job.WorkerEpoch != producer.Job.WorkerEpoch || next.Job.Request.Products == nil {
		t.Fatalf("worker not leased the next job: %+v", next.Job)
	}
}

// A consumer admitted after a trim took its candidate snapshot, naming
// products the snapshot found unpinned, keeps them: the eviction rechecks
// pins in the store transaction that records it, and only then removes the
// bytes (review F3).
func TestProductsTrimKeepsProductsAConsumerPinnedAfterItsSnapshot(t *testing.T) {
	f := newRuntime(t)
	ctx := context.Background()
	ref := succeededProducer(t, f, "consumed later")
	digest := ref.SHA256
	var admitted model.Job
	f.controller.afterProductsSnapshot = func() {
		job, _, err := f.db.Enqueue(ctx, "owner", "late-consumer", consumerAdmission(t, ref), f.now)
		if err != nil {
			t.Errorf("consumer refused after the snapshot: %v", err)
		}
		admitted = job
	}
	f.controller.evidenceMu.Lock()
	err := f.controller.trimProducts(ctx, 0, 0)
	f.controller.evidenceMu.Unlock()
	if err != nil && !errors.Is(err, evidence.ErrArtifactLimit) {
		t.Fatal(err)
	}
	if admitted.ID == "" {
		t.Fatal("no consumer admitted")
	}
	if _, err := os.Stat(filepath.Join(f.controller.options.Root, productsDir, digest+".tar")); err != nil {
		t.Fatalf("products of an admitted consumer evicted: %v", err)
	}
	if p, err := f.db.GetProduct(ctx, digest); err != nil || p.EvictedAt != nil {
		t.Fatalf("ledger %+v %v", p, err)
	}
	if _, err := f.db.EvictUnpinnedProduct(ctx, digest, f.now); err != nil {
		t.Fatal(err)
	}
	if p, _ := f.db.GetProduct(ctx, digest); p.EvictedAt != nil {
		t.Fatal("pinned digest evicted by EvictUnpinnedProduct")
	}
}

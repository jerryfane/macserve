package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/buildseal"
	"github.com/jerryfane/macserve/internal/controllerk/store"
	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
)

// buildForTestingAdmission is a build-for-testing producer admission of the
// runtime fixture's repository from a build template.
func buildForTestingAdmission(t *testing.T) model.Admission {
	t.Helper()
	template := model.Template{ID: "org-ios-sim-build-v1", Version: 1, Kind: model.Build, Owners: []string{"example-org"}, Xcode: model.Xcode{Version: "27.0", Build: "27A100"}, DeveloperDir: "/Applications/ExampleToolchain.app/Contents/Developer", DefaultTimeoutSeconds: 600, MaxTimeoutSeconds: 600, MemoryLimitMiB: 512}
	registry, err := profiles.New(nil, []model.Template{template})
	if err != nil {
		t.Fatal(err)
	}
	admission, err := registry.Resolve(model.Request{Repo: "example-org/example-app", SHA: strings.Repeat("a", 40), Kind: model.Build, Profile: template.ID, Xcode: template.Xcode, TimeoutSeconds: 600, BuildForTesting: true})
	if err != nil {
		t.Fatal(err)
	}
	return admission
}

// A build-for-testing job's test-products.tar is stored in the products
// pool, content-addressed and recorded in the ledger, never in the job's
// export directory or the evidence pool's accounting; its download and
// completion verification read it from there. A plain build job's artifact
// of the same name stays an ordinary export.
func TestBuildForTestingProductsStoredInProductsPool(t *testing.T) {
	f := newRuntime(t)
	if _, _, err := f.db.Enqueue(context.Background(), "owner", "producer", buildForTestingAdmission(t), f.now); err != nil {
		t.Fatal(err)
	}
	lease := f.dispatch(t)
	if !lease.Job.Request.BuildForTesting {
		t.Fatalf("lease %+v", lease.Job.Request)
	}
	pool := f.controller.poolBytes
	products := f.artifact(t, lease.Job, profiles.TestProductsArtifact, []byte("deterministic products tar"))
	root := f.controller.options.Root
	if info, err := os.Stat(filepath.Join(root, productsDir, products.SHA256+".tar")); err != nil || info.Size() != products.SizeBytes {
		t.Fatalf("products not pooled: %v %v", info, err)
	}
	if _, err := os.Stat(filepath.Join(root, "artifacts", lease.Job.ID, products.ID)); !os.IsNotExist(err) {
		t.Fatalf("products in the export directory: %v", err)
	}
	if f.controller.poolBytes != pool {
		t.Fatalf("evidence pool charged for products: %d -> %d", pool, f.controller.poolBytes)
	}
	record, err := f.db.GetProduct(context.Background(), products.SHA256)
	if err != nil || record.JobID != lease.Job.ID || record.Bytes != products.SizeBytes || record.EvictedAt != nil {
		t.Fatalf("ledger %+v %v", record, err)
	}
	result := f.result(t, lease)
	result.Artifacts = append(result.Artifacts, products)
	if err := f.controller.complete(context.Background(), lease.Job, result, buildseal.Envelope{}); err != nil {
		t.Fatal(err)
	}
	file, artifact, err := f.controller.Artifact(context.Background(), lease.Job.ID, products.ID)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(file)
	file.Close()
	if string(data) != "deterministic products tar" || artifact.Name != profiles.TestProductsArtifact {
		t.Fatalf("download %q %+v", data, artifact)
	}
	// The evidence pool's trim never touches the products pool.
	f.controller.evidenceMu.Lock()
	err = f.controller.trimPool(context.Background(), 0, 0)
	f.controller.evidenceMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, productsDir, products.SHA256+".tar")); err != nil {
		t.Fatalf("evidence trim evicted products: %v", err)
	}

	plain := newRuntime(t)
	plainLease := plain.lease(t, model.Build)
	named := plain.artifact(t, plainLease.Job, profiles.TestProductsArtifact, []byte("not products"))
	if _, err := os.Stat(filepath.Join(plain.controller.options.Root, "artifacts", plainLease.Job.ID, named.ID)); err != nil {
		t.Fatalf("plain build artifact not exported: %v", err)
	}
	if _, err := plain.db.GetProduct(context.Background(), named.SHA256); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("plain build artifact recorded as products: %v", err)
	}
}

// The products pool evicts untracked bytes and bytes unused for seven days,
// then the least recently used until it fits its budget, never the bytes of
// a producer job still running; every eviction of a tracked digest, and a
// tracked digest whose bytes are gone, leaves its proof in the ledger.
func TestProductsPoolEvictsExpiredThenLeastRecentlyUsed(t *testing.T) {
	f := newRuntime(t)
	ctx := context.Background()
	if _, _, err := f.db.Enqueue(ctx, "owner", "producer", buildForTestingAdmission(t), f.now); err != nil {
		t.Fatal(err)
	}
	active := f.dispatch(t)
	root := filepath.Join(f.controller.options.Root, productsDir)
	put := func(content string, job string, used time.Time, record bool) string {
		sum := sha256.Sum256([]byte(content))
		digest := hex.EncodeToString(sum[:])
		if err := os.WriteFile(filepath.Join(root, digest+".tar"), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if record {
			if err := f.db.RecordProduct(ctx, digest, int64(len(content)), job, used); err != nil {
				t.Fatal(err)
			}
		}
		return digest
	}
	now := f.now
	untracked := put("untracked", "", now, false)
	expired := put("expired!", "gone-1", now.Add(-maxProductAge), true)
	oldest := put("oldest!!", "gone-2", now.Add(-3*time.Hour), true)
	older := put("older!!!", "gone-3", now.Add(-2*time.Hour), true)
	newest := put("newest!!", "gone-4", now.Add(-time.Hour), true)
	// The running producer uploaded its products, last used before all
	// others: protected by its upload, not by the ledger.
	running := f.artifact(t, active.Job, profiles.TestProductsArtifact, []byte("running!")).SHA256
	if err := f.db.RecordProduct(ctx, running, 8, active.Job.ID, now.Add(-4*time.Hour)); err != nil {
		t.Fatal(err)
	}
	missing := strings.Repeat("9", 64)
	if err := f.db.RecordProduct(ctx, missing, 8, "gone-5", now); err != nil {
		t.Fatal(err)
	}
	f.controller.evidenceMu.Lock()
	err := f.controller.trimProducts(ctx, 8, 32)
	f.controller.evidenceMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	for digest, kept := range map[string]bool{untracked: false, expired: false, oldest: false, older: true, newest: true, running: true} {
		_, err := os.Stat(filepath.Join(root, digest+".tar"))
		if kept != (err == nil) {
			t.Fatalf("%s kept=%t: %v", digest, kept, err)
		}
	}
	for digest, evicted := range map[string]bool{expired: true, oldest: true, missing: true, older: false, newest: false, running: false} {
		p, err := f.db.GetProduct(ctx, digest)
		if err != nil || (p.EvictedAt != nil) != evicted || evicted && !p.EvictedAt.Equal(now) {
			t.Fatalf("%s ledger %+v %v, want evicted=%t", digest, p, err, evicted)
		}
	}
	// A pool the running producer alone overfills refuses the reservation.
	f.controller.evidenceMu.Lock()
	err = f.controller.trimProducts(ctx, 8, 8)
	f.controller.evidenceMu.Unlock()
	if err == nil {
		t.Fatal("overfull products pool accepted a reservation")
	}
	if _, err := os.Stat(filepath.Join(root, running+".tar")); err != nil {
		t.Fatalf("running producer's bytes evicted: %v", err)
	}
}

// pooledProduct writes content into the products pool as an untracked or
// ledger-recorded product of job, last used at used, and returns its digest.
func pooledProduct(t *testing.T, f *runtimeFixture, content, job string, used time.Time) string {
	t.Helper()
	sum := sha256.Sum256([]byte(content))
	digest := hex.EncodeToString(sum[:])
	if err := os.WriteFile(filepath.Join(f.controller.options.Root, productsDir, digest+".tar"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.db.RecordProduct(context.Background(), digest, int64(len(content)), job, used); err != nil {
		t.Fatal(err)
	}
	return digest
}

// Products are stored once per digest: when another producer stores the
// same bytes, the ledger names it, yet the running producer that uploaded
// them first still keeps them from eviction (review F1).
func TestProductsPoolProtectsEveryActiveProducerOfASharedDigest(t *testing.T) {
	f := newRuntime(t)
	ctx := context.Background()
	if _, _, err := f.db.Enqueue(ctx, "owner", "producer", buildForTestingAdmission(t), f.now); err != nil {
		t.Fatal(err)
	}
	lease := f.dispatch(t)
	products := f.artifact(t, lease.Job, profiles.TestProductsArtifact, []byte("shared products"))
	// A second, already finished producer stored the same bytes later.
	if err := f.db.RecordProduct(ctx, products.SHA256, products.SizeBytes, "finished-producer", f.now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	f.offset.Store(int64(2 * maxProductAge))
	f.controller.evidenceMu.Lock()
	err := f.controller.trimProducts(ctx, 0, 1<<20)
	f.controller.evidenceMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.controller.options.Root, productsDir, products.SHA256+".tar")); err != nil {
		t.Fatalf("running producer's shared products evicted: %v", err)
	}
}

// Downloading products is a use: under budget pressure the products
// downloaded most recently outlive ones stored later but not used since
// (review F3).
func TestProductsPoolEvictionCountsDownloads(t *testing.T) {
	f := newRuntime(t)
	ctx := context.Background()
	if _, _, err := f.db.Enqueue(ctx, "owner", "producer", buildForTestingAdmission(t), f.now); err != nil {
		t.Fatal(err)
	}
	lease := f.dispatch(t)
	downloaded := f.artifact(t, lease.Job, profiles.TestProductsArtifact, []byte("downloaded"))
	result := f.result(t, lease)
	result.Artifacts = append(result.Artifacts, downloaded)
	if err := f.controller.complete(ctx, lease.Job, result, buildseal.Envelope{}); err != nil {
		t.Fatal(err)
	}
	later := pooledProduct(t, f, "stored later", "other-producer", f.now.Add(time.Hour))
	f.offset.Store(int64(2 * time.Hour))
	file, _, err := f.controller.Artifact(ctx, lease.Job.ID, downloaded.ID)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	f.controller.evidenceMu.Lock()
	err = f.controller.trimProducts(ctx, 0, downloaded.SizeBytes)
	f.controller.evidenceMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(f.controller.options.Root, productsDir)
	if _, err := os.Stat(filepath.Join(root, downloaded.SHA256+".tar")); err != nil {
		t.Fatalf("recently downloaded products evicted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, later+".tar")); !os.IsNotExist(err) {
		t.Fatalf("least recently used products kept: %v", err)
	}
	if p, err := f.db.GetProduct(ctx, downloaded.SHA256); err != nil || p.JobID != lease.Job.ID {
		t.Fatalf("download changed the producer: %+v %v", p, err)
	}
}

// An upload of products is acknowledged only once the products directory
// holding them is synced: a failed sync fails the upload and records
// nothing, and the retry syncs before it records (review F2).
func TestProductsUploadSyncsPoolDirectoryBeforeRecording(t *testing.T) {
	f := newRuntime(t)
	ctx := context.Background()
	if _, _, err := f.db.Enqueue(ctx, "owner", "producer", buildForTestingAdmission(t), f.now); err != nil {
		t.Fatal(err)
	}
	lease := f.dispatch(t)
	data := []byte("products to sync")
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	a := evidence.Artifact{ID: digest, Name: profiles.TestProductsArtifact, MediaType: "application/x-tar", SizeBytes: int64(len(data)), SHA256: digest, ExpiresAt: f.now.Add(time.Hour)}
	failed := errors.New("injected directory sync failure")
	var synced []string
	f.controller.syncProducts = func(dir *os.File) error {
		synced = append(synced, filepath.Base(dir.Name()))
		if _, err := f.db.GetProduct(ctx, digest); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("product recorded before its directory sync: %v", err)
		}
		return failed
	}
	if err := f.controller.putArtifact(ctx, lease.Job, a, bytes.NewReader(data)); !errors.Is(err, failed) {
		t.Fatalf("upload with a failed directory sync: %v", err)
	}
	if _, err := f.db.GetProduct(ctx, digest); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unsynced product recorded: %v", err)
	}
	if manifest, err := f.controller.uploaded(lease.Job.ID); err != nil || len(manifest) != 0 {
		t.Fatalf("unsynced product acknowledged: %+v %v", manifest, err)
	}
	f.controller.syncProducts = func(dir *os.File) error {
		synced = append(synced, filepath.Base(dir.Name()))
		return dir.Sync()
	}
	if err := f.controller.putArtifact(ctx, lease.Job, a, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	if len(synced) != 2 || synced[0] != productsDir || synced[1] != productsDir {
		t.Fatalf("synced %q", synced)
	}
	if p, err := f.db.GetProduct(ctx, digest); err != nil || p.JobID != lease.Job.ID {
		t.Fatalf("retried product %+v %v", p, err)
	}
}

// completedProducer is a finished build-for-testing job whose
// test-products.tar holds content, stored in the products pool.
func completedProducer(t *testing.T, f *runtimeFixture, content string) (model.Job, evidence.Artifact) {
	t.Helper()
	ctx := context.Background()
	if _, _, err := f.db.Enqueue(ctx, "owner", "producer-"+content, buildForTestingAdmission(t), f.now); err != nil {
		t.Fatal(err)
	}
	lease := f.dispatch(t)
	products := f.artifact(t, lease.Job, profiles.TestProductsArtifact, []byte(content))
	result := f.result(t, lease)
	result.Artifacts = append(result.Artifacts, products)
	if err := f.controller.complete(ctx, lease.Job, result, buildseal.Envelope{}); err != nil {
		t.Fatal(err)
	}
	return lease.Job, products
}

// A trim that took its candidate snapshot before a download touched a
// product does not evict it: each eviction re-reads the use time under the
// lock the download holds while it opens and touches, so the touched
// product survives and the trim evicts the next candidate instead (review
// F3 race).
func TestProductsTrimKeepsProductDownloadedAfterItsSnapshot(t *testing.T) {
	f := newRuntime(t)
	ctx := context.Background()
	job, downloaded := completedProducer(t, f, "downloaded")
	other := pooledProduct(t, f, "unused bytes", "other-producer", f.now.Add(time.Minute))
	f.offset.Store(int64(time.Hour))
	snapshotted, resume := make(chan struct{}), make(chan struct{})
	f.controller.afterProductsSnapshot = func() { close(snapshotted); <-resume }
	trimmed := make(chan error, 1)
	go func() {
		f.controller.evidenceMu.Lock()
		defer f.controller.evidenceMu.Unlock()
		trimmed <- f.controller.trimProducts(ctx, 0, downloaded.SizeBytes)
	}()
	<-snapshotted
	file, _, err := f.controller.Artifact(ctx, job.ID, downloaded.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	close(resume)
	if err := <-trimmed; err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(f.controller.options.Root, productsDir)
	if _, err := os.Stat(filepath.Join(root, downloaded.SHA256+".tar")); err != nil {
		t.Fatalf("product downloaded after the trim's snapshot evicted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, other+".tar")); !os.IsNotExist(err) {
		t.Fatalf("next candidate kept: %v", err)
	}
	if p, err := f.db.GetProduct(ctx, downloaded.SHA256); err != nil || p.EvictedAt != nil {
		t.Fatalf("ledger %+v %v", p, err)
	}
}

// A download that opened products before they are evicted reads them to
// the end from its descriptor.
func TestProductsDownloadSurvivesEvictionAfterOpen(t *testing.T) {
	f := newRuntime(t)
	ctx := context.Background()
	job, products := completedProducer(t, f, "streamed products")
	file, _, err := f.controller.Artifact(ctx, job.ID, products.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	f.controller.evidenceMu.Lock()
	err = f.controller.trimProducts(ctx, 0, 0)
	f.controller.evidenceMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.controller.options.Root, productsDir, products.SHA256+".tar")); !os.IsNotExist(err) {
		t.Fatalf("products not evicted: %v", err)
	}
	if data, err := io.ReadAll(file); err != nil || string(data) != "streamed products" {
		t.Fatalf("open download after eviction read %q %v", data, err)
	}
}

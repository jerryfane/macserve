package controller

import (
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
	running := put("running!", active.Job.ID, now.Add(-4*time.Hour), true)
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

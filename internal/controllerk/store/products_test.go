package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
)

// A build-for-testing producer is admitted only as a build template job
// whose snapshot carries the request's flag; an admission whose request
// and snapshot disagree, or that sets the flag for an explicit profile, is
// refused.
func TestEnqueueBuildForTestingAdmission(t *testing.T) {
	template := model.Template{ID: "org-ios-sim-build-v1", Version: 1, Kind: model.Build, Owners: []string{"example-org"}, Xcode: model.Xcode{Version: "27.0", Build: "27A100"}, DeveloperDir: "/Applications/ExampleToolchain.app/Contents/Developer"}
	registry, err := profiles.New(nil, []model.Template{template})
	if err != nil {
		t.Fatal(err)
	}
	admission, err := registry.Resolve(model.Request{Repo: "example-org/example-app", SHA: strings.Repeat("c", 40), Kind: model.Build, Profile: template.ID, Xcode: template.Xcode, BuildForTesting: true})
	if err != nil {
		t.Fatal(err)
	}
	s, _ := newStore(t, Options{})
	job := enqueueAdmission(t, s, "producer", admission, testNow)
	if got := getJob(t, s, job.ID); !got.Request.BuildForTesting || !got.Profile.BuildForTesting {
		t.Fatalf("stored producer %+v %+v", got.Request, got.Profile)
	}
	unflagged := admission
	unflagged.Profile.BuildForTesting = false
	snapshotOnly := admission
	snapshotOnly.Request.BuildForTesting = false
	explicit := admissionFixture()
	explicit.Request.BuildForTesting, explicit.Profile.BuildForTesting = true, true
	for name, a := range map[string]model.Admission{"request only": unflagged, "snapshot only": snapshotOnly, "explicit profile": explicit} {
		if _, _, err := s.Enqueue(context.Background(), "principal", name, a, testNow); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// undoProductsSchema returns a current database to version 8, for tests
// that emulate an older database.
const undoProductsSchema = "DROP TABLE products;"

// A version 8 database migrates to 9: it gains the empty products ledger,
// keeps its jobs, and records, re-records and evicts products.
func TestProductsMigrationFromVersion8(t *testing.T) {
	ctx := context.Background()
	s, path := newStore(t, Options{})
	job := enqueueJob(t, s, "principal", "key", testNow)
	if _, err := s.db.ExecContext(ctx, undoProductsSchema+"PRAGMA user_version=8;"); err != nil {
		t.Fatal(err)
	}
	requireError(t, s.Close(), nil)
	s = openStore(t, path, Options{})
	var version int
	requireError(t, s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version), nil)
	if version != SchemaVersion || SchemaVersion != 9 {
		t.Fatalf("user_version = %d, SchemaVersion = %d", version, SchemaVersion)
	}
	if got := getJob(t, s, job.ID); got.ID != job.ID {
		t.Fatalf("migrated job = %+v", got)
	}
	if retained, err := s.RetainedProducts(ctx); err != nil || len(retained) != 0 {
		t.Fatalf("migrated products = %+v, %v", retained, err)
	}
	digest := strings.Repeat("a", 64)
	requireError(t, s.RecordProduct(ctx, digest, 240<<20, job.ID, testNow), nil)
	requireError(t, s.EvictProduct(ctx, digest, testNow.Add(time.Hour)), nil)
	p, err := s.GetProduct(ctx, digest)
	if err != nil || p.Bytes != 240<<20 || p.JobID != job.ID || p.EvictedAt == nil || !p.EvictedAt.Equal(testNow.Add(time.Hour)) {
		t.Fatalf("eviction proof = %+v, %v", p, err)
	}
}

// Products are content-addressed: storing the same digest again moves its
// use time and producer, keeps its creation time while retained, and
// re-enters an evicted digest with a new creation time. Evicting keeps the
// first eviction time.
func TestRecordProductKeepsOneRowPerDigest(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t, Options{})
	digest := strings.Repeat("b", 64)
	requireError(t, s.RecordProduct(ctx, digest, 10, "job-1", testNow), nil)
	requireError(t, s.RecordProduct(ctx, digest, 10, "job-2", testNow.Add(time.Minute)), nil)
	p, err := s.GetProduct(ctx, digest)
	if err != nil || p.JobID != "job-2" || !p.CreatedAt.Equal(testNow) || !p.UsedAt.Equal(testNow.Add(time.Minute)) || p.EvictedAt != nil {
		t.Fatalf("re-recorded product = %+v, %v", p, err)
	}
	requireError(t, s.EvictProduct(ctx, digest, testNow.Add(2*time.Minute)), nil)
	requireError(t, s.EvictProduct(ctx, digest, testNow.Add(3*time.Minute)), nil)
	if p, err = s.GetProduct(ctx, digest); err != nil || p.EvictedAt == nil || !p.EvictedAt.Equal(testNow.Add(2*time.Minute)) {
		t.Fatalf("evicted product = %+v, %v", p, err)
	}
	if retained, err := s.RetainedProducts(ctx); err != nil || len(retained) != 0 {
		t.Fatalf("retained after eviction = %+v, %v", retained, err)
	}
	requireError(t, s.RecordProduct(ctx, digest, 10, "job-3", testNow.Add(4*time.Minute)), nil)
	retained, err := s.RetainedProducts(ctx)
	if err != nil || len(retained) != 1 || retained[0].JobID != "job-3" || !retained[0].CreatedAt.Equal(testNow.Add(4*time.Minute)) || retained[0].EvictedAt != nil {
		t.Fatalf("re-entered product = %+v, %v", retained, err)
	}
	requireError(t, s.RecordProduct(ctx, "ABC", 10, "job-4", testNow), ErrInvalid)
	requireError(t, s.RecordProduct(ctx, digest, -1, "job-4", testNow), ErrInvalid)
}

// Prune drops eviction proofs once job metadata retention has passed since
// the eviction, and never a retained product's record.
func TestPruneDropsOldEvictionProofsOnly(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t, Options{Retention: 24 * time.Hour})
	old, recent, kept := strings.Repeat("c", 64), strings.Repeat("d", 64), strings.Repeat("e", 64)
	for _, digest := range []string{old, recent, kept} {
		requireError(t, s.RecordProduct(ctx, digest, 1, "job", testNow), nil)
	}
	requireError(t, s.EvictProduct(ctx, old, testNow), nil)
	requireError(t, s.EvictProduct(ctx, recent, testNow.Add(23*time.Hour)), nil)
	counts, err := s.Prune(ctx, testNow.Add(25*time.Hour))
	if err != nil || counts.Products != 1 {
		t.Fatalf("prune = %+v, %v", counts, err)
	}
	if _, err := s.GetProduct(ctx, old); err != ErrNotFound {
		t.Fatalf("old proof survived: %v", err)
	}
	for _, digest := range []string{recent, kept} {
		if _, err := s.GetProduct(ctx, digest); err != nil {
			t.Fatalf("%s: %v", digest, err)
		}
	}
}

// A consumer is admitted only against a succeeded build-for-testing
// producer of the same repository and commit whose sealed products the
// reference names exactly, while the pool still holds them.
func TestEnqueueConsumerAdmission(t *testing.T) {
	ctx := context.Background()
	xcode := model.Xcode{Version: "27.0", Build: "27A100"}
	build := model.Template{ID: "org-ios-sim-build-v1", Version: 1, Kind: model.Build, Owners: []string{"example-org"}, Xcode: xcode, DeveloperDir: "/Applications/ExampleToolchain.app/Contents/Developer"}
	ui := model.Template{ID: "org-ios-sim-uitest-v1", Version: 1, Kind: model.SimulatorUITest, Owners: []string{"example-org"}, Xcode: xcode, DeveloperDir: build.DeveloperDir, Simulators: []model.Simulator{{Runtime: "com.apple.CoreSimulator.SimRuntime.iOS-27-0", RuntimeBuild: "24A100", DeviceType: "com.apple.CoreSimulator.SimDeviceType.iPhone-18-Pro"}}}
	registry, err := profiles.New(nil, []model.Template{build, ui})
	if err != nil {
		t.Fatal(err)
	}
	sha := strings.Repeat("c", 40)
	producerAdmission, err := registry.Resolve(model.Request{Repo: "example-org/example-app", SHA: sha, Kind: model.Build, Profile: build.ID, Xcode: xcode, BuildForTesting: true})
	if err != nil {
		t.Fatal(err)
	}
	s, _ := newStore(t, Options{})
	producer := enqueueAdmission(t, s, "producer", producerAdmission, testNow)
	digest := strings.Repeat("d", 64)
	ref := model.ProductsRef{ProducerJobID: producer.ID, SHA256: digest, Xctestrun: "App_iphonesimulator27.0-arm64.xctestrun"}
	consumer := func(ref model.ProductsRef, sha string) model.Admission {
		a, err := registry.Resolve(model.Request{Repo: "example-org/example-app", SHA: sha, Kind: model.SimulatorUITest, Profile: ui.ID, Xcode: xcode, Shard: "smoke", Products: &ref})
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	enqueue := func(key string, a model.Admission) error {
		_, _, err := s.Enqueue(ctx, "principal", key, a, testNow)
		return err
	}
	if err := enqueue("queued producer", consumer(ref, sha)); !errors.Is(err, ErrProductsUnavailable) {
		t.Fatalf("queued producer: %v", err)
	}
	completion := `{"input_digest":"x","result":{"state":"succeeded","artifacts":[{"name":"evidence/stdout.log","sha256":"` + strings.Repeat("1", 64) + `"},{"name":"test-products.tar","sha256":"` + digest + `"}],"observation":{"xctestrun":"` + ref.Xctestrun + `"}}}`
	if _, err := s.db.ExecContext(ctx, "UPDATE jobs SET state='succeeded',result=? WHERE id=?", completion, producer.ID); err != nil {
		t.Fatal(err)
	}
	got, err := ProducerProducts(getJob(t, s, producer.ID))
	if err != nil || got != ref {
		t.Fatalf("ProducerProducts = %+v %v", got, err)
	}
	if err := enqueue("unpooled", consumer(ref, sha)); !errors.Is(err, ErrProductsUnavailable) {
		t.Fatalf("bytes never pooled: %v", err)
	}
	if err := s.RecordProduct(ctx, digest, 240<<20, producer.ID, testNow); err != nil {
		t.Fatal(err)
	}
	otherDigest, otherXctestrun, unknown := ref, ref, ref
	otherDigest.SHA256 = strings.Repeat("e", 64)
	otherXctestrun.Xctestrun = "Other.xctestrun"
	unknown.ProducerJobID = "j_unknown"
	for name, tc := range map[string]struct {
		admission model.Admission
		want      error
	}{
		"another commit":   {consumer(ref, strings.Repeat("b", 40)), ErrInvalid},
		"another digest":   {consumer(otherDigest, sha), ErrInvalid},
		"another name":     {consumer(otherXctestrun, sha), ErrInvalid},
		"unknown producer": {consumer(unknown, sha), ErrProductsUnavailable},
	} {
		if err := enqueue(name, tc.admission); !errors.Is(err, tc.want) {
			t.Fatalf("%s: %v, want %v", name, err, tc.want)
		}
	}
	admitted := consumer(ref, sha)
	mismatched := admitted
	mismatched.Profile.Products = &otherDigest
	if err := enqueue("snapshot mismatch", mismatched); !errors.Is(err, ErrInvalid) {
		t.Fatalf("snapshot mismatch: %v", err)
	}
	if err := enqueue("consumer", admitted); err != nil {
		t.Fatal(err)
	}
	if err := s.EvictProduct(ctx, digest, testNow.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := enqueue("evicted", consumer(ref, sha)); !errors.Is(err, ErrProductsUnavailable) {
		t.Fatalf("evicted: %v", err)
	}
}

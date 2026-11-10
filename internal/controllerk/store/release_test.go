package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/controllerconfig"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
)

func archiveAdmission(t *testing.T) model.Admission {
	t.Helper()
	archive := model.Template{ID: "org-archive-v1", Version: 1, Kind: model.IOSArchive, Owners: []string{"example-org"}, Xcode: model.Xcode{Version: "27.0", Build: "27A100"}, DeveloperDir: "/Applications/ExampleToolchain.app/Contents/Developer", MemoryLimitMiB: 512}
	registry, err := profiles.New(nil, []model.Template{archive})
	if err != nil {
		t.Fatal(err)
	}
	sha := strings.Repeat("b", 40)
	admission, err := registry.Resolve(model.Request{Repo: "example-org/example-app", SHA: sha, Kind: model.IOSArchive, Profile: archive.ID, Xcode: archive.Xcode, Release: &model.ReleaseRequest{BuildName: "1.2.3", BuildNumber: "42"}})
	if err != nil {
		t.Fatal(err)
	}
	admission.ReleaseProvenance = &model.ReleaseProvenance{RepositoryID: 12345, DefaultBranch: "main", HeadSHA: sha, ResolvedAt: testNow, Source: model.ProvenanceGitHubApp}
	return admission
}

// An ios_archive admission's provenance is stored with the job and read back
// exactly, across a reopen and through an idempotent replay.
func TestEnqueueArchivePersistsReleaseProvenance(t *testing.T) {
	ctx := context.Background()
	s, path := newStore(t, Options{})
	admission := archiveAdmission(t)
	job, replay, err := s.Enqueue(ctx, "principal", "archive", admission, testNow)
	if err != nil || replay {
		t.Fatalf("enqueue: replay=%v err=%v", replay, err)
	}
	if job.ReleaseProvenance == nil || *job.ReleaseProvenance != *admission.ReleaseProvenance || !reflect.DeepEqual(job.Request.Release, &model.ReleaseRequest{BuildName: "1.2.3", BuildNumber: "42"}) {
		t.Fatalf("archive job: %+v", job)
	}
	requireError(t, s.Close(), nil)
	s = openStore(t, path, Options{})
	if got := getJob(t, s, job.ID); !reflect.DeepEqual(got, job) {
		t.Fatalf("reopened job:\n%+v\nwant\n%+v", got, job)
	}
	// A replay keeps its first admission's provenance, like its snapshot.
	later := admission
	later.ReleaseProvenance = &model.ReleaseProvenance{RepositoryID: 12345, DefaultBranch: "main", HeadSHA: admission.Request.SHA, ResolvedAt: testNow.Add(time.Hour), Source: model.ProvenanceGitHubApp}
	again, replay, err := s.Enqueue(ctx, "principal", "archive", later, testNow.Add(time.Hour))
	if err != nil || !replay || !reflect.DeepEqual(again, job) {
		t.Fatalf("replay: %+v %v %v", again, replay, err)
	}
	plain := enqueueJob(t, s, "principal", "plain", testNow)
	if plain.ReleaseProvenance != nil || getJob(t, s, plain.ID).ReleaseProvenance != nil {
		t.Fatal("build job gained release provenance")
	}
}

// Enqueue re-checks the release binding of every admission, whichever
// admission path built it.
func TestEnqueueRefusesUnboundRelease(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t, Options{})
	for name, edit := range map[string]func(*model.Admission){
		"release mismatch": func(a *model.Admission) {
			a.Request.Release = &model.ReleaseRequest{BuildName: "1.2.3", BuildNumber: "43"}
		},
		"snapshot release nil": func(a *model.Admission) { a.Profile.Release = nil },
		"request release nil":  func(a *model.Admission) { a.Request.Release, a.Profile.Release = nil, nil },
		"invalid release": func(a *model.Admission) {
			bad := model.ReleaseRequest{BuildName: "1.2.3", BuildNumber: "042"}
			a.Request.Release, a.Profile.Release = &bad, &bad
		},
		"missing provenance":   func(a *model.Admission) { a.ReleaseProvenance = nil },
		"head mismatch":        func(a *model.Admission) { a.ReleaseProvenance.HeadSHA = strings.Repeat("c", 40) },
		"repository id zero":   func(a *model.Admission) { a.ReleaseProvenance.RepositoryID = 0 },
		"qualification source": func(a *model.Admission) { a.ReleaseProvenance.Source = model.ProvenanceQualification },
		"empty branch":         func(a *model.Admission) { a.ReleaseProvenance.DefaultBranch = "" },
		"unsafe branch":        func(a *model.Admission) { a.ReleaseProvenance.DefaultBranch = "main..dev" },
		"zero resolved_at":     func(a *model.Admission) { a.ReleaseProvenance.ResolvedAt = time.Time{} },
		"local resolved_at":    func(a *model.Admission) { a.ReleaseProvenance.ResolvedAt = testNow.In(time.FixedZone("x", 3600)) },
	} {
		admission := archiveAdmission(t)
		edit(&admission)
		_, _, err := s.Enqueue(ctx, "principal", name, admission, testNow)
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: error = %v; want %v", name, err, ErrInvalid)
		}
	}
	for name, edit := range map[string]func(*model.Admission){
		"provenance": func(a *model.Admission) {
			a.ReleaseProvenance = &model.ReleaseProvenance{RepositoryID: 12345, DefaultBranch: "main", HeadSHA: a.Request.SHA, ResolvedAt: testNow, Source: model.ProvenanceGitHubApp}
		},
		"request release":  func(a *model.Admission) { a.Request.Release = &model.ReleaseRequest{BuildName: "1", BuildNumber: "1"} },
		"snapshot release": func(a *model.Admission) { a.Profile.Release = &model.ReleaseRequest{BuildName: "1", BuildNumber: "1"} },
	} {
		admission := admissionFixture()
		edit(&admission)
		setDigest(&admission)
		_, _, err := s.Enqueue(ctx, "principal", "build-"+name, admission, testNow)
		requireError(t, err, ErrInvalid)
	}
	// An explicit profile can never run an archive, even with provenance.
	explicit := admissionFixture()
	explicit.Request.Kind, explicit.Profile.Kind = model.IOSArchive, model.IOSArchive
	release := model.ReleaseRequest{BuildName: "1", BuildNumber: "1"}
	explicit.Request.Release, explicit.Profile.Release = &release, &release
	explicit.ReleaseProvenance = &model.ReleaseProvenance{RepositoryID: 12345, DefaultBranch: "main", HeadSHA: explicit.Request.SHA, ResolvedAt: testNow, Source: model.ProvenanceGitHubApp}
	setDigest(&explicit)
	_, _, err := s.Enqueue(ctx, "principal", "explicit-archive", explicit, testNow)
	requireError(t, err, ErrInvalid)
}

// A version 3 database gains the provenance column; its jobs read back with
// none, and it then admits archive jobs.
func TestReleaseMigrationKeepsVersion3Jobs(t *testing.T) {
	ctx := context.Background()
	s, path := newStore(t, Options{})
	old := enqueueJob(t, s, "principal", "old", testNow)
	_, err := s.db.ExecContext(ctx, undoLaneSchema+"DROP TABLE signings; ALTER TABLE jobs DROP COLUMN release_provenance; ALTER TABLE jobs DROP COLUMN cancel_reason; PRAGMA user_version=3;")
	requireError(t, err, nil)
	requireError(t, s.Close(), nil)
	s = openStore(t, path, Options{})
	var version int
	requireError(t, s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version), nil)
	if version != SchemaVersion {
		t.Fatalf("user_version = %d", version)
	}
	if got := getJob(t, s, old.ID); got.ReleaseProvenance != nil || !reflect.DeepEqual(got, old) {
		t.Fatalf("migrated job: %+v", got)
	}
	job, _, err := s.Enqueue(ctx, "principal", "archive", archiveAdmission(t), testNow)
	if err != nil || job.ReleaseProvenance == nil || job.ReleaseProvenance.RepositoryID != 12345 {
		t.Fatalf("archive after migration: %+v %v", job, err)
	}
	future := SchemaVersion + 1
	if _, err := s.db.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version=%d", future)); err != nil {
		t.Fatal(err)
	}
	requireError(t, s.Close(), nil)
	if _, err := Open(path, Options{}); err == nil || !strings.Contains(err.Error(), fmt.Sprintf("unsupported store schema version %d", future)) {
		t.Fatalf("future schema opened: %v", err)
	}
}

// release:archive and release:sign are grantable scopes; an unknown release
// scope is not.
func TestPrincipalsAcceptReleaseArchiveScope(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t, Options{})
	token := strings.Repeat("7", 64)
	digest := sha256.Sum256([]byte(token))
	releaser := controllerconfig.Principal{ID: "releaser", TokenSHA256: hex.EncodeToString(digest[:]), Repositories: []string{"example-org/*"}, Scopes: []string{"jobs:submit", "release:archive"}}
	requireError(t, s.ReplacePrincipals(ctx, []controllerconfig.Principal{releaser}), nil)
	got, err := s.Authenticate(ctx, token)
	if err != nil || !got.HasScope("release:archive") || !got.HasScope("jobs:submit") || got.HasScope("service:admin") || got.HasScope("release:sign") {
		t.Fatalf("releaser = %+v, %v", got, err)
	}
	signer := releaser
	signer.Scopes = []string{"release:sign"}
	requireError(t, s.ReplacePrincipals(ctx, []controllerconfig.Principal{signer}), nil)
	if got, err := s.Authenticate(ctx, token); err != nil || !got.HasScope("release:sign") || got.HasScope("release:archive") {
		t.Fatalf("signer = %+v, %v", got, err)
	}
	unknown := releaser
	unknown.Scopes = []string{"release:upload"}
	requireError(t, s.ReplacePrincipals(ctx, []controllerconfig.Principal{unknown}), ErrInvalid)
}

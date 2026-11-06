package receipt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/worker"
)

// archiveTemplateFixture is a successful org ios_archive template job at
// release 1.4.0 (42), native or Flutter (with one Dart define): admitted
// through the registry, bound at admission to the repository's default
// branch head through the GitHub App, and exporting the sealed archive tar
// and its signing manifest. It has no test summary.
func archiveTemplateFixture(t *testing.T, flutter bool) (Options, model.Job, worker.Result, Expected) {
	t.Helper()
	options, job, result, expected := fixture(t, model.Build)
	template := model.Template{ID: "org-ios-archive-v1", Version: 1, Kind: model.IOSArchive, Owners: []string{"example-org"}, Xcode: job.Profile.Xcode, DeveloperDir: job.Profile.DeveloperDir, DefaultTimeoutSeconds: 300, MaxTimeoutSeconds: 600, MemoryLimitMiB: 8192}
	request := model.Request{Repo: job.Request.Repo, SHA: job.Request.SHA, Kind: model.IOSArchive, Profile: template.ID, Xcode: template.Xcode, TimeoutSeconds: 300, Release: &model.ReleaseRequest{BuildName: "1.4.0", BuildNumber: "42"}}
	config := model.RepoConfig{Version: 1, WorkDir: ".", Project: "App.xcodeproj", Scheme: "App"}
	if flutter {
		pin := receiptFlutterPin
		template.Flutter = &pin
		request.Flutter = &model.FlutterRequest{Version: pin.Version}
		request.Release.DartDefines = map[string]string{"API_BASE_URL": "https://api.example.com"}
		config = model.RepoConfig{Version: 1, WorkDir: "apps/mobile/ios", Workspace: "Runner.xcworkspace", Scheme: "Runner", Flutter: &model.FlutterConfig{AppDir: "apps/mobile"}}
		result.Observation.Flutter = &worker.FlutterObservation{FrameworkVersion: pin.Version, DartSDKVersion: "3.11.5", Ruby: "ruby 3.4.6", CocoaPods: pin.CocoaPodsVersion}
	}
	registry, err := profiles.New(nil, []model.Template{template})
	if err != nil {
		t.Fatal(err)
	}
	admission, err := registry.Resolve(request)
	if err != nil {
		t.Fatal(err)
	}
	job.Request, job.Profile, job.ProfileDigest = admission.Request, admission.Profile, admission.ProfileDigest
	job.ReleaseProvenance = &model.ReleaseProvenance{RepositoryID: 123, DefaultBranch: "main", HeadSHA: job.Request.SHA, ResolvedAt: job.CreatedAt.Add(-time.Second), Source: model.ProvenanceGitHubApp}
	raw, err := json.Marshal(job.Request)
	if err != nil {
		t.Fatal(err)
	}
	job.RequestDigest = hashBytes(raw)
	derived, err := profiles.Derive(job.Profile, config)
	if err != nil {
		t.Fatal(err)
	}
	result.Observation.Recipe = &model.RepoRecipe{ConfigSHA256: strings.Repeat("f", 64), Config: config, WorkDir: derived.WorkDir, Prepare: derived.Prepare, Run: derived.Run}
	result.Commands[0].Executable, result.Commands[0].Args = derived.Run.Executable, derived.Run.Args
	result.Summary = nil
	logs := result.Artifacts[:2]
	expires := logs[0].ExpiresAt
	result.Artifacts = append(slices.Clone(logs),
		evidence.Artifact{ID: "archive", Name: profiles.ArchiveArtifact, MediaType: "application/x-tar", SizeBytes: 4096, SHA256: hashBytes([]byte("archive tar")), ExpiresAt: expires},
		evidence.Artifact{ID: "manifest", Name: profiles.SigningManifestArtifact, MediaType: "application/json", SizeBytes: 512, SHA256: hashBytes([]byte("signing manifest")), ExpiresAt: expires},
	)
	expected.Profile, expected.ProfileDigest, expected.Kind, expected.RequiredTests, expected.Release = template.ID, admission.ProfileDigest, model.IOSArchive, nil, admission.Request.Release
	return options, job, result, expected
}

// fullPayload is the private full manifest a sealed receipt commits to.
func fullPayload(t *testing.T, signer *Signer, p Payload) Payload {
	t.Helper()
	raw, err := signer.Manifest(context.Background(), p.JobID, p.Manifest.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	var full Payload
	if err := strictDecode(raw, &full); err != nil {
		t.Fatal(err)
	}
	return full
}

func archiveSealRefused(t *testing.T, options Options, job model.Job, result worker.Result) {
	t.Helper()
	signer, err := NewSigner(options)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()
	if _, err := signer.Seal(context.Background(), job, result); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unproven archive success sealed: %v", err)
	}
}

// An ios_archive receipt, compact and full, binds the admitted release, the
// GitHub App's default-branch provenance and the signing manifest artifact's
// SHA-256, and validates with no test evidence.
func TestArchiveReceiptValidates(t *testing.T) {
	for _, flutter := range []bool{false, true} {
		t.Run(map[bool]string{false: "native", true: "flutter"}[flutter], func(t *testing.T) {
			options, job, result, expected := archiveTemplateFixture(t, flutter)
			signer, _, p := sealFixture(t, options, job, result)
			full := fullPayload(t, signer, p)
			for form, payload := range map[string]Payload{"compact": p, "full": full} {
				if err := ValidateSuccess(payload, expected); err != nil {
					t.Fatalf("%s: %v", form, err)
				}
				v := payload.ReleaseProvenance
				if !profiles.SameRelease(payload.Release, job.Request.Release) || v == nil || v.RepositoryID != 123 || v.DefaultBranch != "main" || v.HeadSHA != job.Request.SHA || !v.ResolvedAt.Equal(job.ReleaseProvenance.ResolvedAt) || v.Source != model.ProvenanceGitHubApp {
					t.Fatalf("%s release evidence: %+v %+v", form, payload.Release, v)
				}
				if payload.SigningManifestSHA256 != hashBytes([]byte("signing manifest")) || payload.Tests.Status != "tests_not_run" || payload.ArtifactCount != 4 {
					t.Fatalf("%s archive evidence: %+v", form, payload)
				}
			}
			if flutter && p.Release.DartDefines["API_BASE_URL"] != "https://api.example.com" {
				t.Fatalf("dart defines: %+v", p.Release)
			}
			for name, release := range map[string]*model.ReleaseRequest{
				"no expected release":    nil,
				"other build number":     {BuildName: "1.4.0", BuildNumber: "43", DartDefines: p.Release.DartDefines},
				"other build name":       {BuildName: "1.4.1", BuildNumber: "42", DartDefines: p.Release.DartDefines},
				"other dart define sets": {BuildName: "1.4.0", BuildNumber: "42", DartDefines: map[string]string{"API_BASE_URL": "https://staging.example.com"}},
			} {
				t.Run(name, func(t *testing.T) {
					e := expected
					e.Release = release
					if err := ValidateSuccess(p, e); !errors.Is(err, ErrInvalid) {
						t.Fatalf("mismatched release policy accepted: %v", err)
					}
				})
			}
		})
	}
}

// Seal refuses archive success whose release provenance does not bind the
// GitHub App's default-branch head for this repository and commit, or whose
// archive evidence is incomplete.
func TestArchiveReceiptRefusesUnprovenRelease(t *testing.T) {
	for name, mutate := range map[string]func(*model.Job, *worker.Result){
		"provenance missing":        func(j *model.Job, _ *worker.Result) { j.ReleaseProvenance = nil },
		"qualification provenance":  func(j *model.Job, _ *worker.Result) { j.ReleaseProvenance.Source = model.ProvenanceQualification },
		"other repository id":       func(j *model.Job, _ *worker.Result) { j.ReleaseProvenance.RepositoryID = 124 },
		"zero repository id":        func(j *model.Job, _ *worker.Result) { j.ReleaseProvenance.RepositoryID = 0 },
		"other head":                func(j *model.Job, _ *worker.Result) { j.ReleaseProvenance.HeadSHA = strings.Repeat("e", 40) },
		"empty default branch":      func(j *model.Job, _ *worker.Result) { j.ReleaseProvenance.DefaultBranch = "" },
		"lock default branch":       func(j *model.Job, _ *worker.Result) { j.ReleaseProvenance.DefaultBranch = "release/main.lock" },
		"traversing default branch": func(j *model.Job, _ *worker.Result) { j.ReleaseProvenance.DefaultBranch = "main/../dev" },
		"resolved after admission":  func(j *model.Job, _ *worker.Result) { j.ReleaseProvenance.ResolvedAt = j.CreatedAt.Add(time.Second) },
		"never resolved":            func(j *model.Job, _ *worker.Result) { j.ReleaseProvenance.ResolvedAt = time.Time{} },
		"signing manifest missing":  func(_ *model.Job, r *worker.Result) { r.Artifacts = r.Artifacts[:3] },
		"archive missing":           func(_ *model.Job, r *worker.Result) { r.Artifacts = slices.Delete(r.Artifacts, 2, 3) },
		"archive renamed":           func(_ *model.Job, r *worker.Result) { r.Artifacts[2].Name = "App.xcarchive.tar.gz" },
		"signing manifest renamed":  func(_ *model.Job, r *worker.Result) { r.Artifacts[3].Name = "evidence/signing-manifest.json" },
		"empty archive":             func(_ *model.Job, r *worker.Result) { r.Artifacts[2].SizeBytes = 0 },
		"test summary": func(_ *model.Job, r *worker.Result) {
			r.Summary = &evidence.Summary{SchemaVersion: 1, ParseStatus: "parsed"}
		},
		"archive never ran": func(_ *model.Job, r *worker.Result) { r.Commands[0].Executable = "/bin/sh" },
		"recipe at other build number": func(_ *model.Job, r *worker.Result) {
			r.Observation.Recipe.Run.Args = slices.Clone(r.Observation.Recipe.Run.Args)
			i := slices.Index(r.Observation.Recipe.Run.Args, "CURRENT_PROJECT_VERSION=42")
			r.Observation.Recipe.Run.Args[i] = "CURRENT_PROJECT_VERSION=43"
		},
		"snapshot release differs": func(j *model.Job, _ *worker.Result) {
			j.Profile.Release = &model.ReleaseRequest{BuildName: "1.4.0", BuildNumber: "41"}
			j.ProfileDigest, _ = j.Profile.SnapshotDigest()
		},
		"request simulator": func(j *model.Job, _ *worker.Result) {
			j.Request.Simulator = &model.Simulator{Runtime: "com.apple.CoreSimulator.SimRuntime.iOS-26-0", RuntimeBuild: "23A100", DeviceType: "iPhone"}
		},
		"request release dropped": func(j *model.Job, _ *worker.Result) { j.Request.Release = nil },
		"request build number moved": func(j *model.Job, _ *worker.Result) {
			j.Request.Release = &model.ReleaseRequest{BuildName: "1.4.0", BuildNumber: "43"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			options, job, result, _ := archiveTemplateFixture(t, false)
			mutate(&job, &result)
			raw, err := json.Marshal(job.Request)
			if err != nil {
				t.Fatal(err)
			}
			job.RequestDigest = hashBytes(raw)
			archiveSealRefused(t, options, job, result)
		})
	}
}

// incomplete names exactly the archive evidence a tampered payload lacks.
func TestArchiveReceiptIncompleteFields(t *testing.T) {
	options, job, result, _ := archiveTemplateFixture(t, true)
	signer, _, p := sealFixture(t, options, job, result)
	full := fullPayload(t, signer, p)
	other := &model.ReleaseRequest{BuildName: "1.4.0", BuildNumber: "42"}
	for name, tc := range map[string]struct {
		base   Payload
		mutate func(*Payload)
		want   string
	}{
		"release missing":                {p, func(p *Payload) { p.Release = nil }, "release"},
		"release without dart define":    {p, func(p *Payload) { p.Release = other }, "release"},
		"invalid release":                {p, func(p *Payload) { p.Release.BuildNumber, p.Request.Release.BuildNumber = "042", "042" }, "release"},
		"provenance missing":             {p, func(p *Payload) { p.ReleaseProvenance = nil }, "release provenance"},
		"qualification provenance":       {p, func(p *Payload) { p.ReleaseProvenance.Source = model.ProvenanceQualification }, "release provenance"},
		"provenance repository id":       {p, func(p *Payload) { p.ReleaseProvenance.RepositoryID = 124 }, "release provenance"},
		"provenance head":                {p, func(p *Payload) { p.ReleaseProvenance.HeadSHA = strings.Repeat("e", 40) }, "release provenance"},
		"manifest digest missing":        {p, func(p *Payload) { p.SigningManifestSHA256 = "" }, "signing manifest digest"},
		"manifest digest malformed":      {p, func(p *Payload) { p.SigningManifestSHA256 = strings.Repeat("A", 64) }, "signing manifest digest"},
		"manifest digest not artifact's": {full, func(p *Payload) { p.SigningManifestSHA256 = hashBytes([]byte("other manifest")) }, "archive artifacts"},
		"tests counted":                  {p, func(p *Payload) { p.Tests.Status, p.Tests.Tests, p.Tests.Passed = "parsed", 1, 1 }, "archive test scope"},
	} {
		t.Run(name, func(t *testing.T) {
			tampered := tc.base
			release, provenance := *tc.base.Release, *tc.base.ReleaseProvenance
			request := *tc.base.Request.Release
			tampered.Release, tampered.ReleaseProvenance, tampered.Request.Release = &release, &provenance, &request
			tc.mutate(&tampered)
			if missing := incomplete(tampered); !slices.Contains(missing, tc.want) {
				t.Fatalf("missing %q, want %q", missing, tc.want)
			}
		})
	}
}

// No other kind's receipt carries a release, release provenance or signing
// manifest digest, and none of their keys appear in its bytes.
func TestNonArchiveReceiptsCarryNoReleaseEvidence(t *testing.T) {
	options, job, result, expected := templateFixture(t)
	signer, raw, p := sealFixture(t, options, job, result)
	full := fullPayload(t, signer, p)
	manifest, err := canonicalValue(full)
	if err != nil {
		t.Fatal(err)
	}
	core, err := canonicalValue(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, encoded := range [][]byte{raw, core, manifest} {
		for _, key := range []string{`"release"`, `"release_provenance"`, `"signing_manifest_sha256"`} {
			if bytes.Contains(encoded, []byte(key)) {
				t.Fatalf("build receipt names %s: %s", key, encoded)
			}
		}
	}
	for name, mutate := range map[string]func(*Payload){
		"release":         func(p *Payload) { p.Release = &model.ReleaseRequest{BuildName: "1.0", BuildNumber: "1"} },
		"request release": func(p *Payload) { p.Request.Release = &model.ReleaseRequest{BuildName: "1.0", BuildNumber: "1"} },
		"release provenance": func(p *Payload) {
			p.ReleaseProvenance = &model.ReleaseProvenance{RepositoryID: 123, DefaultBranch: "main", HeadSHA: p.Request.SHA, ResolvedAt: p.CreatedAt, Source: model.ProvenanceGitHubApp}
		},
		"signing manifest digest": func(p *Payload) { p.SigningManifestSHA256 = hashBytes([]byte("signing manifest")) },
	} {
		t.Run(name, func(t *testing.T) {
			tampered := p
			mutate(&tampered)
			if missing := incomplete(tampered); !slices.Contains(missing, "release evidence") {
				t.Fatalf("build receipt with %s: %q", name, missing)
			}
			if ValidateSuccess(tampered, expected) == nil {
				t.Fatalf("build receipt with %s validated", name)
			}
		})
	}
	// A build job admitted with a release, which admission refuses, does not seal.
	options, job, result, _ = templateFixture(t)
	job.Request.Release = &model.ReleaseRequest{BuildName: "1.0", BuildNumber: "1"}
	request, err := json.Marshal(job.Request)
	if err != nil {
		t.Fatal(err)
	}
	job.RequestDigest = hashBytes(request)
	archiveSealRefused(t, options, job, result)
}

// A job without release provenance keeps its pre-ios_archive input digest:
// the signer's replay identity omits the absent field.
func TestInputDigestUnchangedWithoutReleaseProvenance(t *testing.T) {
	options, job, result, _ := templateFixture(t)
	_, _, p := sealFixture(t, options, job, result)
	approval := Approval{Intake: "private_api", Identity: job.Principal, AttemptID: job.ID}
	legacy := struct {
		JobID, Principal, ProfileDigest, RequestDigest, WorkerEpoch string
		Request                                                     model.Request
		Profile                                                     model.Profile
		CreatedAt                                                   time.Time
		Deadline                                                    *time.Time
		Service                                                     ServiceIdentity
		Repository                                                  Repository
		Approval                                                    Approval
		Result                                                      worker.Result
	}{job.ID, job.Principal, job.ProfileDigest, job.RequestDigest, job.WorkerEpoch, job.Request, job.Profile, job.CreatedAt, job.Deadline, options.Service, Repository{ID: 123, Name: job.Request.Repo}, approval, result}
	want, err := valueDigest(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if p.InputDigest != want {
		t.Fatalf("input digest %s, want pre-archive %s", p.InputDigest, want)
	}
	// An archive job's provenance is part of its replay identity.
	options, archiveJob, archiveResult, _ := archiveTemplateFixture(t, false)
	_, _, first := sealFixture(t, options, archiveJob, archiveResult)
	archiveJob.ReleaseProvenance.ResolvedAt = archiveJob.ReleaseProvenance.ResolvedAt.Add(-time.Second)
	options.Root = filepath.Join(t.TempDir(), "receipts")
	_, _, second := sealFixture(t, options, archiveJob, archiveResult)
	if first.InputDigest == second.InputDigest {
		t.Fatal("release provenance does not change the input digest")
	}
}

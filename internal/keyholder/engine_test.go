package keyholder

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/buildseal"
	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/githubapi"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/receipt"
	"github.com/jerryfane/macserve/internal/worker"
)

const (
	repo   = "acme/app"
	repoID = 123
)

var (
	pin      = model.FlutterPin{Version: "3.41.9", SDKSHA256: strings.Repeat("b", 64), RubySHA256: strings.Repeat("c", 64), CocoaPodsVersion: "1.16.2", GemsSHA256: strings.Repeat("e", 64)}
	template = model.Template{ID: "org-flutter-archive-v1", Version: 1, Kind: model.IOSArchive, Owners: []string{"acme"}, Xcode: model.Xcode{Version: "27.0", Build: "27A100"}, DeveloperDir: "/Applications/Xcode.app/Contents/Developer", Flutter: &pin}
	commit   = strings.Repeat("a", 40)
	tree     = strings.Repeat("7", 40)
	defines  = map[string]string{"API_BASE_URL": "https://api.example.com", "FLAVOR": "prod"}
)

type fakeGitHub struct {
	head   githubapi.BranchHead
	trees  map[string]string
	tokens map[string]githubapi.InstallationToken
	repos  map[string][]githubapi.Repository
	calls  int
}

func (g *fakeGitHub) InstallationRepositories(_ context.Context, owner string) ([]githubapi.Repository, error) {
	return g.repos[owner], nil
}

func (g *fakeGitHub) InstallationToken(_ context.Context, r string) (githubapi.InstallationToken, error) {
	t, ok := g.tokens[r]
	if !ok {
		return githubapi.InstallationToken{}, errors.New("not installed")
	}
	return t, nil
}
func (g *fakeGitHub) DefaultBranchHead(context.Context, string) (githubapi.BranchHead, error) {
	g.calls++
	return g.head, nil
}
func (g *fakeGitHub) CommitTree(_ context.Context, _, sha string) (string, error) {
	t, ok := g.trees[sha]
	if !ok {
		return "", errors.New("no such commit")
	}
	return t, nil
}

// fakeSigner records what the keyholder asked it to sign.
type fakeSigner struct {
	jobs      []model.Job
	approvals []receipt.Approval
}

func (s *fakeSigner) Seal(ctx context.Context, job model.Job, _ worker.Result) (json.RawMessage, error) {
	a, err := ApprovalFromContext(ctx, job)
	if err != nil {
		return nil, err
	}
	s.jobs = append(s.jobs, job)
	s.approvals = append(s.approvals, a)
	return json.RawMessage(`{"signed":true}`), nil
}
func (s *fakeSigner) Manifest(context.Context, string, string) (json.RawMessage, error) {
	return nil, nil
}
func (s *fakeSigner) Prune(context.Context, func(string) (bool, error)) error { return nil }

type fixture struct {
	engine   *Engine
	signer   *fakeSigner
	github   *fakeGitHub
	scope    ReleaseScope
	sealKey  ed25519.PrivateKey
	job      model.Job
	result   worker.Result
	resolved buildseal.Resolution
}

func digestOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// newFixture is a succeeded Flutter ios_archive job admitted from the
// registry, the worker result it reported and a scope that authorizes it.
func newFixture(t *testing.T, release model.ReleaseRequest) *fixture {
	t.Helper()
	registry, err := profiles.New(nil, []model.Template{template})
	if err != nil {
		t.Fatal(err)
	}
	request := model.Request{Repo: repo, SHA: commit, Kind: model.IOSArchive, Profile: template.ID, Xcode: template.Xcode, Flutter: &model.FlutterRequest{Version: pin.Version}, Release: &model.ReleaseRequest{BuildName: "1.4.0", BuildNumber: "42", DartDefines: maps.Clone(defines)}}
	admission, err := registry.Resolve(request)
	if err != nil {
		t.Fatal(err)
	}
	// The controller may fabricate any job record; the worker seal is what
	// binds it. The fixture's release is set after admission.
	admission.Request.Release = &release
	raw, _ := json.Marshal(admission.Request)
	sum := sha256.Sum256(raw)
	created := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	deadline := created.Add(time.Hour)
	job := model.Job{ID: "job-1", Principal: "owner", Request: admission.Request, Profile: admission.Profile, ProfileDigest: admission.ProfileDigest, RequestDigest: hex.EncodeToString(sum[:]), State: model.Finalizing, CreatedAt: created, Deadline: &deadline, WorkerEpoch: "epoch-1",
		// Controller-supplied provenance naming another repository: ignored.
		ReleaseProvenance: &model.ReleaseProvenance{RepositoryID: 999, DefaultBranch: "evil", HeadSHA: commit, ResolvedAt: created, Source: model.ProvenanceGitHubApp}}
	zero := 0
	expires := created.Add(24 * time.Hour)
	result := worker.Result{State: model.Succeeded, ExitCode: &zero, CleanupOK: true, StartedAt: created.Add(time.Minute), FinishedAt: created.Add(10 * time.Minute), Source: worker.Source{Commit: commit, Tree: tree, SHA256: strings.Repeat("d", 64), SizeBytes: 4096}, Commands: []worker.ExecutedCommand{{Executable: "/usr/bin/xcrun", Args: []string{"xcodebuild", "archive"}}},
		Artifacts: []evidence.Artifact{
			{ID: "stdout", Name: "evidence/stdout.log", MediaType: "text/plain", SizeBytes: 3, SHA256: digestOf("out"), ExpiresAt: expires},
			{ID: "archive", Name: profiles.ArchiveArtifact, MediaType: "application/x-tar", SizeBytes: 4096, SHA256: digestOf("archive"), ExpiresAt: expires},
			{ID: "manifest", Name: profiles.SigningManifestArtifact, MediaType: "application/json", SizeBytes: 512, SHA256: digestOf("manifest"), ExpiresAt: expires},
		}}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{signer: &fakeSigner{}, sealKey: key, job: job, result: result,
		github:   &fakeGitHub{head: githubapi.BranchHead{RepositoryID: repoID, Branch: "main", SHA: commit}, trees: map[string]string{commit: tree}, tokens: map[string]githubapi.InstallationToken{}},
		resolved: buildseal.Resolution{ProfileID: template.ID, ProfileVersion: template.Version, ProfileDigest: admission.ProfileDigest, Xcode: template.Xcode, DeveloperDir: template.DeveloperDir, Flutter: &pin},
		scope:    ReleaseScope{Schema: ReleaseScopeSchema, Repositories: map[string]ReleaseEntry{repo: {RepositoryID: repoID, ProfileID: template.ID, ProfileVersion: template.Version, ProfileDigest: admission.ProfileDigest, Xcode: template.Xcode, Flutter: &pin, DartDefines: maps.Clone(defines)}}},
	}
	f.engine, err = NewEngine(Options{Signer: f.signer, SealKeys: map[string]ed25519.PublicKey{"worker": key.Public().(ed25519.PublicKey)}, Policy: Policy{Repositories: map[string]int64{repo: repoID}, Owners: []string{"acme"}}, GitHub: f.github,
		ReleaseScope: func() (ReleaseScope, error) { return f.scope, f.scope.Validate() },
		ReleaseDir:   filepath.Join(t.TempDir(), "release"), Now: func() time.Time { return created.Add(11 * time.Minute) }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.engine.Close() })
	return f
}

// request is the controller's receipt request with a seal the worker
// signed over the fixture's job, result, resolution and tree.
func (f *fixture) request(t *testing.T) SealRequest {
	t.Helper()
	resolved := f.resolved
	seal, err := buildseal.New(f.job, &resolved, tree, f.result, f.result.FinishedAt)
	if err != nil {
		t.Fatal(err)
	}
	env, err := buildseal.Sign(f.sealKey, "worker", seal)
	if err != nil {
		t.Fatal(err)
	}
	return SealRequest{Job: f.job, Worker: f.result, Result: f.result, Seal: env, Approval: receipt.Approval{Intake: "private_api", Identity: "owner", AttemptID: f.job.ID}}
}

var scopedRelease = model.ReleaseRequest{BuildName: "1.4.0", BuildNumber: "42", DartDefines: defines}

func refused(t *testing.T, f *fixture, req SealRequest) {
	t.Helper()
	if _, err := f.engine.Seal(context.Background(), req); err == nil {
		t.Fatal("release receipt signed")
	} else {
		t.Log(err)
	}
	if len(f.signer.jobs) != 0 {
		t.Fatal("refused request reached the receipt signer")
	}
}

// A release receipt in scope is signed with the keyholder's own provenance;
// the controller's is ignored, and a retry reuses the recorded check.
func TestReleaseReceiptSignedWithKeyholderProvenance(t *testing.T) {
	f := newFixture(t, scopedRelease)
	req := f.request(t)
	for range 2 {
		if _, err := f.engine.Seal(context.Background(), req); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.signer.jobs) != 2 || f.github.calls != 1 {
		t.Fatalf("signed %d, GitHub checks %d", len(f.signer.jobs), f.github.calls)
	}
	for _, job := range f.signer.jobs {
		v := job.ReleaseProvenance
		if v == nil || v.RepositoryID != repoID || v.DefaultBranch != "main" || v.HeadSHA != commit || v.Source != model.ProvenanceGitHubApp || !v.ResolvedAt.Equal(f.signer.jobs[0].ReleaseProvenance.ResolvedAt) {
			t.Fatalf("provenance %+v", v)
		}
	}
	if f.signer.approvals[0].Identity != "owner" {
		t.Fatalf("approval %+v", f.signer.approvals[0])
	}
}

func TestReleaseReceiptRefusedOutsideScope(t *testing.T) {
	for name, tc := range map[string]struct {
		release model.ReleaseRequest
		mutate  func(*fixture)
	}{
		"non-head commit":       {scopedRelease, func(f *fixture) { f.github.head.SHA = strings.Repeat("f", 40) }},
		"tree mismatch":         {scopedRelease, func(f *fixture) { f.github.trees[commit] = strings.Repeat("6", 40) }},
		"wrong repository id":   {scopedRelease, func(f *fixture) { f.github.head.RepositoryID = 456 }},
		"repository not scoped": {scopedRelease, func(f *fixture) { f.scope.Repositories = map[string]ReleaseEntry{} }},
		"scope repository id": {scopedRelease, func(f *fixture) {
			e := f.scope.Repositories[repo]
			e.RepositoryID = 456
			f.scope.Repositories[repo] = e
		}},
		"extra dart define":        {model.ReleaseRequest{BuildName: "1.4.0", BuildNumber: "42", DartDefines: map[string]string{"API_BASE_URL": "https://api.example.com", "FLAVOR": "prod", "DEBUG": "1"}}, nil},
		"missing dart define":      {model.ReleaseRequest{BuildName: "1.4.0", BuildNumber: "42", DartDefines: map[string]string{"API_BASE_URL": "https://api.example.com"}}, nil},
		"different dart define":    {model.ReleaseRequest{BuildName: "1.4.0", BuildNumber: "42", DartDefines: map[string]string{"API_BASE_URL": "https://evil.example.com", "FLAVOR": "prod"}}, nil},
		"no dart defines":          {model.ReleaseRequest{BuildName: "1.4.0", BuildNumber: "42"}, nil},
		"bad build number":         {model.ReleaseRequest{BuildName: "1.4.0", BuildNumber: "1234567890", DartDefines: defines}, nil},
		"non-numeric build number": {model.ReleaseRequest{BuildName: "1.4.0", BuildNumber: "42a", DartDefines: defines}, nil},
		"bad build name":           {model.ReleaseRequest{BuildName: "1.4.0.1", BuildNumber: "42", DartDefines: defines}, nil},
		"profile digest": {scopedRelease, func(f *fixture) {
			e := f.scope.Repositories[repo]
			e.ProfileDigest = strings.Repeat("0", 64)
			f.scope.Repositories[repo] = e
		}},
		"profile version": {scopedRelease, func(f *fixture) {
			e := f.scope.Repositories[repo]
			e.ProfileVersion = 2
			f.scope.Repositories[repo] = e
		}},
		"xcode pin":             {scopedRelease, func(f *fixture) { f.resolved.Xcode.Build = "27A101" }},
		"flutter pin":           {scopedRelease, func(f *fixture) { other := pin; other.Version = "3.41.10"; f.resolved.Flutter = &other }},
		"no release scope file": {scopedRelease, func(f *fixture) { f.scope = ReleaseScope{} }},
		"no keyholder app":      {scopedRelease, func(f *fixture) { f.engine.options.GitHub = nil }},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, tc.release)
			if tc.mutate != nil {
				tc.mutate(f)
			}
			refused(t, f, f.request(t))
		})
	}
}

// The seal must be the worker's, over exactly this job and result; the
// controller may only normalize the result the way completion does.
func TestReceiptRefusedWithoutMatchingWorkerSeal(t *testing.T) {
	for name, mutate := range map[string]func(*fixture, *SealRequest){
		"forged seal key": func(f *fixture, r *SealRequest) {
			_, other, _ := ed25519.GenerateKey(rand.Reader)
			var seal buildseal.Seal
			json.Unmarshal(r.Seal.Seal, &seal)
			r.Seal, _ = buildseal.Sign(other, "worker", seal)
		},
		"other job":      func(_ *fixture, r *SealRequest) { r.Job.ID = "job-2" },
		"other request":  func(_ *fixture, r *SealRequest) { r.Job.Request.Release.BuildNumber = "43" },
		"other snapshot": func(_ *fixture, r *SealRequest) { r.Job.Profile.DeveloperDir = "/tmp/Xcode.app/Contents/Developer" },
		"other worker result": func(_ *fixture, r *SealRequest) {
			r.Worker.PeakMemoryMiB = 7
			r.Result.PeakMemoryMiB = 7
		},
		"normalized success the worker did not report": func(f *fixture, r *SealRequest) {
			r.Worker.State, r.Worker.Reason = model.Failed, "build failed"
			resolved := f.resolved
			seal, _ := buildseal.New(r.Job, &resolved, tree, r.Worker, r.Worker.FinishedAt)
			r.Seal, _ = buildseal.Sign(f.sealKey, "worker", seal)
		},
		"artifact the worker did not report": func(_ *fixture, r *SealRequest) {
			r.Result.Artifacts = append(r.Result.Artifacts, evidence.Artifact{ID: "x", Name: "extra", SHA256: digestOf("x")})
		},
		"success without registry resolution": func(f *fixture, r *SealRequest) {
			seal, _ := buildseal.New(r.Job, nil, tree, r.Worker, r.Worker.FinishedAt)
			r.Seal, _ = buildseal.Sign(f.sealKey, "worker", seal)
		},
		"no computed tree": func(f *fixture, r *SealRequest) {
			resolved := f.resolved
			seal, _ := buildseal.New(r.Job, &resolved, "", r.Worker, r.Worker.FinishedAt)
			r.Seal, _ = buildseal.Sign(f.sealKey, "worker", seal)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, scopedRelease)
			req := f.request(t)
			mutate(f, &req)
			refused(t, f, req)
		})
	}
}

// Completion normalization (artifact expiry shortened, a state downgrade
// with its reason) still yields a receipt, without release provenance.
func TestNormalizedFailureReceiptSigned(t *testing.T) {
	f := newFixture(t, scopedRelease)
	req := f.request(t)
	req.Result.State, req.Result.Reason = model.Failed, "artifact bytes do not match manifest"
	req.Result.Artifacts = slices.Clone(req.Result.Artifacts[:1])
	req.Result.Artifacts[0].ExpiresAt = req.Result.Artifacts[0].ExpiresAt.Add(-time.Hour)
	if _, err := f.engine.Seal(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if len(f.signer.jobs) != 1 || f.signer.jobs[0].ReleaseProvenance != nil || f.github.calls != 0 {
		t.Fatalf("failure receipt: %+v calls %d", f.signer.jobs, f.github.calls)
	}
}

func TestTokenMintedOnlyForPolicyRepositories(t *testing.T) {
	f := newFixture(t, scopedRelease)
	expires := time.Now().Add(time.Hour)
	f.github.tokens[repo] = githubapi.InstallationToken{Token: "ghs_pinned", ExpiresAt: expires, RepositoryID: repoID}
	f.github.tokens["acme/other"] = githubapi.InstallationToken{Token: "ghs_owner", ExpiresAt: expires, RepositoryID: 77}
	f.github.tokens["mallory/app"] = githubapi.InstallationToken{Token: "ghs_outside", ExpiresAt: expires, RepositoryID: 88}
	for _, allowed := range []string{repo, "acme/other"} {
		if token, err := f.engine.Token(context.Background(), allowed); err != nil || token.Token == "" {
			t.Fatalf("%s: %+v %v", allowed, token, err)
		}
	}
	for _, outside := range []string{"mallory/app", "Acme/App", "acme", "acme/app/../x", ""} {
		var refusal *RefusalError
		if _, err := f.engine.Token(context.Background(), outside); !errors.As(err, &refusal) {
			t.Fatalf("token minted for %q outside policy: %v", outside, err)
		}
	}
	f.github.tokens[repo] = githubapi.InstallationToken{Token: "ghs_moved", ExpiresAt: expires, RepositoryID: 456}
	if _, err := f.engine.Token(context.Background(), repo); err == nil {
		t.Fatal("token for a pinned repository with another ID")
	}
}

// An owner-form pull policy pins its owner's account ID: tokens for that
// owner's repositories require it (a renamed or re-registered login never
// mints), other owners are still refused, and only pinned owners are listed,
// keeping exactly the repositories of the pinned account.
func TestOwnerPolicyMintsAndListsOnlyPinnedOwnerRepositories(t *testing.T) {
	f := newFixture(t, scopedRelease)
	f.engine.options.Policy.OwnerIDs = map[string]int64{"acme": 900}
	expires := time.Now().Add(time.Hour)
	f.github.tokens["acme/app2"] = githubapi.InstallationToken{Token: "ghs_owner", ExpiresAt: expires, RepositoryID: 77, OwnerID: 900}
	f.github.tokens["acme/taken"] = githubapi.InstallationToken{Token: "ghs_taken", ExpiresAt: expires, RepositoryID: 78, OwnerID: 901}
	f.github.tokens["mallory/app"] = githubapi.InstallationToken{Token: "ghs_outside", ExpiresAt: expires, RepositoryID: 88, OwnerID: 900}
	f.github.tokens[repo] = githubapi.InstallationToken{Token: "ghs_pinned", ExpiresAt: expires, RepositoryID: repoID, OwnerID: 901}
	ctx := context.Background()
	if token, err := f.engine.Token(ctx, "acme/app2"); err != nil || token.Token != "ghs_owner" {
		t.Fatalf("owner policy repository: %+v %v", token, err)
	}
	// The repository-ID pin governs a pinned repository on its own.
	if token, err := f.engine.Token(ctx, repo); err != nil || token.Token != "ghs_pinned" {
		t.Fatalf("pinned repository: %+v %v", token, err)
	}
	var refusal *RefusalError
	for _, outside := range []string{"acme/taken", "mallory/app"} {
		if _, err := f.engine.Token(ctx, outside); !errors.As(err, &refusal) {
			t.Fatalf("token minted for %s: %v", outside, err)
		}
	}
	owner := func(id int64, login string) githubapi.RepositoryOwner {
		return githubapi.RepositoryOwner{Login: login, ID: id}
	}
	f.github.repos = map[string][]githubapi.Repository{"acme": {
		{ID: 77, FullName: "acme/app2", Owner: owner(900, "acme")},
		{ID: 78, FullName: "acme/taken", Owner: owner(901, "acme")},
		{ID: 79, FullName: "other/app", Owner: owner(900, "other")},
	}}
	listed, err := f.engine.Repositories(ctx, "acme")
	if err != nil || len(listed) != 1 || listed[0].ID != 77 {
		t.Fatalf("owner listing: %+v %v", listed, err)
	}
	for _, unlisted := range []string{"mallory", "other", ""} {
		if _, err := f.engine.Repositories(ctx, unlisted); !errors.As(err, &refusal) {
			t.Fatalf("listing for %q: %v", unlisted, err)
		}
	}
	f.github.repos["acme"] = make([]githubapi.Repository, githubapi.MaxInstallationRepositories+1)
	if _, err := f.engine.Repositories(ctx, "acme"); !errors.As(err, &refusal) {
		t.Fatalf("unbounded listing accepted: %v", err)
	}
}

// The server answers only the controller UID; the client trusts only the
// keyholder UID; a refusal crosses the socket as a RefusalError.
func TestRPCPeerChecksAndRefusal(t *testing.T) {
	f := newFixture(t, scopedRelease)
	dir, err := shortTempDir(t)
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "k.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	peer := uint32(501)
	server := &Server{Engine: f.engine, ControllerUID: 501, PeerUID: func(net.Conn) (uint32, error) { return peer, nil }}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go server.Serve(ctx, listener)
	client := &Client{Socket: socket, KeyholderUID: 220, PeerUID: func(net.Conn) (uint32, error) { return 220, nil }}
	f.github.tokens[repo] = githubapi.InstallationToken{Token: "ghs_pinned", ExpiresAt: time.Now().Add(time.Hour), RepositoryID: repoID}
	if token, err := client.Token(ctx, repo); err != nil || token.Token != "ghs_pinned" {
		t.Fatalf("token over RPC: %+v %v", token, err)
	}
	var refusal *RefusalError
	if _, err := client.Token(ctx, "mallory/app"); !errors.As(err, &refusal) {
		t.Fatalf("refusal over RPC: %v", err)
	}
	if _, err := client.Repositories(ctx, "acme"); !errors.As(err, &refusal) {
		t.Fatalf("listing without an owner pin over RPC: %v", err)
	}
	f.engine.options.Policy.OwnerIDs = map[string]int64{"acme": 900}
	f.github.repos = map[string][]githubapi.Repository{"acme": {{ID: 77, FullName: "acme/app2", Owner: githubapi.RepositoryOwner{Login: "acme", ID: 900}, DefaultBranch: "main"}}}
	if listed, err := client.Repositories(ctx, "acme"); err != nil || len(listed) != 1 || listed[0].ID != 77 || listed[0].Owner.ID != 900 || listed[0].DefaultBranch != "main" {
		t.Fatalf("listing over RPC: %+v %v", listed, err)
	}
	if receipt, err := client.Seal(ctx, f.request(t)); err != nil || string(receipt) != `{"signed":true}` {
		t.Fatalf("seal over RPC: %s %v", receipt, err)
	}
	peer = 502
	if _, err := client.Token(ctx, repo); err == nil {
		t.Fatal("server answered a non-controller peer")
	}
	impostor := &Client{Socket: socket, KeyholderUID: 220, PeerUID: func(net.Conn) (uint32, error) { return 221, nil }}
	if _, err := impostor.Token(ctx, repo); err == nil || !strings.Contains(err.Error(), "not the keyholder") {
		t.Fatalf("client trusted a non-keyholder socket: %v", err)
	}
}

// shortTempDir is a temporary directory short enough for a Unix socket path.
func shortTempDir(t *testing.T) (string, error) {
	dir, err := os.MkdirTemp("/tmp", "kh")
	if err == nil {
		t.Cleanup(func() { os.RemoveAll(dir) })
	}
	return dir, err
}

package api

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/githubapi"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/store"
)

const archiveToken = "5555555555555555555555555555555555555555555555555555555555555555"

// fakeHeads answers every resolution with head or err and records each
// repository it resolved.
type fakeHeads struct {
	head  githubapi.BranchHead
	err   error
	repos []string
}

func (f *fakeHeads) DefaultBranchHead(_ context.Context, repo string) (githubapi.BranchHead, error) {
	f.repos = append(f.repos, repo)
	return f.head, f.err
}

// archiveSetup serves an ios_archive template and a build template for
// themartianapp to a principal with scopes, resolving heads through heads.
func archiveSetup(t *testing.T, heads BranchHeads, scopes ...string) (*fixture, model.Request) {
	t.Helper()
	f := setup(t)
	base := model.Template{Version: 1, Owners: []string{"themartianapp"}, Xcode: model.Xcode{Version: "27.0", Build: "27A100"}, DeveloperDir: "/Applications/Example.app/Contents/Developer"}
	archive, build := base, base
	archive.ID, archive.Kind = "org-ios-archive-v1", model.IOSArchive
	build.ID, build.Kind = "org-build-v1", model.Build
	registry, err := profiles.New(nil, []model.Template{archive, build})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.db.ReplacePrincipals(context.Background(), []store.Principal{f.owner, principal(archiveToken, "releaser", "themartianapp/*", scopes...)}); err != nil {
		t.Fatal(err)
	}
	f.options.Profiles, f.options.BranchHeads = registry, heads
	if f.handler, err = New(f.options); err != nil {
		t.Fatal(err)
	}
	return f, model.Request{Repo: "TheMartianApp/App", SHA: strings.Repeat("c", 40), Kind: model.IOSArchive, Profile: archive.ID, Xcode: archive.Xcode, Release: &model.ReleaseRequest{BuildName: "2.0.1", BuildNumber: "17"}}
}

func submitArchive(t *testing.T, f *fixture, key string, request model.Request) (int, string) {
	t.Helper()
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	w := perform(f.handler, "POST", "/v1/jobs", archiveToken, key, string(data))
	return w.Code, w.Body.String()
}

func TestArchiveSubmitRequiresReleaseScope(t *testing.T) {
	heads := &fakeHeads{head: githubapi.BranchHead{RepositoryID: 77, Branch: "main", SHA: strings.Repeat("c", 40)}}
	f, request := archiveSetup(t, heads, "jobs:submit", "jobs:read")
	if code, body := submitArchive(t, f, "archive", request); code != 403 || !strings.Contains(body, `"forbidden"`) {
		t.Fatalf("archive without release:archive: %d %s", code, body)
	}
	releaser, err := f.db.Authenticate(context.Background(), archiveToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Submit(context.Background(), f.db, f.options.Profiles, heads, releaser, "direct", request, testTime); !errors.Is(err, ErrForbidden) {
		t.Fatalf("direct archive without release:archive: %v", err)
	}
	// release:archive alone is not submission.
	f, request = archiveSetup(t, heads, "release:archive", "jobs:read")
	if code, body := submitArchive(t, f, "archive", request); code != 403 {
		t.Fatalf("archive without jobs:submit: %d %s", code, body)
	}
	if len(heads.repos) != 0 {
		t.Fatalf("refused submission resolved heads: %v", heads.repos)
	}
}

func TestArchiveSubmitRecordsDefaultBranchProvenance(t *testing.T) {
	heads := &fakeHeads{head: githubapi.BranchHead{RepositoryID: 77, Branch: "release/2.x", SHA: strings.Repeat("c", 40)}}
	f, request := archiveSetup(t, heads, "jobs:submit", "jobs:read", "release:archive")
	if code, body := submitArchive(t, f, "archive", request); code != 202 {
		t.Fatalf("archive submit: %d %s", code, body)
	}
	job, err := f.db.Lookup(context.Background(), "releaser", "archive")
	if err != nil {
		t.Fatal(err)
	}
	want := model.ReleaseProvenance{RepositoryID: 77, DefaultBranch: "release/2.x", HeadSHA: strings.Repeat("c", 40), ResolvedAt: testTime, Source: model.ProvenanceGitHubApp}
	if job.ReleaseProvenance == nil || *job.ReleaseProvenance != want || job.ReleaseProvenance.ResolvedAt.Location().String() != "UTC" {
		t.Fatalf("provenance = %+v", job.ReleaseProvenance)
	}
	if !reflect.DeepEqual(job.Request.Release, request.Release) || !reflect.DeepEqual(job.Profile.Release, request.Release) {
		t.Fatalf("release not bound: %+v %+v", job.Request.Release, job.Profile.Release)
	}
	if strings.Join(heads.repos, ",") != "themartianapp/app" {
		t.Fatalf("resolved %v", heads.repos)
	}
	// A replay returns the first admission without resolving the head again,
	// even after the branch moved.
	heads.head.SHA = strings.Repeat("d", 40)
	if code, body := submitArchive(t, f, "archive", request); code != 200 || len(heads.repos) != 1 {
		t.Fatalf("replay: %d %s %v", code, body, heads.repos)
	}
}

func TestArchiveSubmitRefusesCommitOtherThanDefaultBranchHead(t *testing.T) {
	head := strings.Repeat("e", 40)
	heads := &fakeHeads{head: githubapi.BranchHead{RepositoryID: 77, Branch: "main", SHA: head}}
	f, request := archiveSetup(t, heads, "jobs:submit", "release:archive")
	code, body := submitArchive(t, f, "archive", request)
	if code != 409 || !strings.Contains(body, "not_default_branch_head") || !strings.Contains(body, request.SHA) || !strings.Contains(body, head) || !strings.Contains(body, "main") {
		t.Fatalf("head mismatch: %d %s", code, body)
	}
	if _, err := f.db.Lookup(context.Background(), "releaser", "archive"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("refused archive stored: %v", err)
	}
	// A failed resolution is retryable and names no GitHub detail.
	heads.err = errors.New("secret upstream detail")
	if code, body := submitArchive(t, f, "other", request); code != 503 || strings.Contains(body, "secret upstream detail") {
		t.Fatalf("resolution failure: %d %s", code, body)
	}
}

func TestArchiveSubmitRefusedWithoutGitHubApp(t *testing.T) {
	f, request := archiveSetup(t, nil, "jobs:submit", "release:archive")
	if code, body := submitArchive(t, f, "archive", request); code != 422 || !strings.Contains(body, "requires the controller's GitHub App") {
		t.Fatalf("archive without GitHub App: %d %s", code, body)
	}
	if _, err := f.db.Lookup(context.Background(), "releaser", "archive"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("refused archive stored: %v", err)
	}
}

func TestNonArchiveSubmitNeverResolvesHeads(t *testing.T) {
	heads := &fakeHeads{err: errors.New("must not be called")}
	f, archive := archiveSetup(t, heads, "jobs:submit", "release:archive")
	build := model.Request{Repo: archive.Repo, SHA: archive.SHA, Kind: model.Build, Profile: "org-build-v1", Xcode: archive.Xcode}
	if code, body := submitArchive(t, f, "build", build); code != 202 {
		t.Fatalf("build submit: %d %s", code, body)
	}
	job, err := f.db.Lookup(context.Background(), "releaser", "build")
	if err != nil || job.ReleaseProvenance != nil {
		t.Fatalf("build job: %+v %v", job.ReleaseProvenance, err)
	}
	// A build request carrying a release is refused, still without a lookup.
	build.Release = archive.Release
	if code, body := submitArchive(t, f, "build-release", build); code != 422 {
		t.Fatalf("build with release: %d %s", code, body)
	}
	if len(heads.repos) != 0 {
		t.Fatalf("non-archive submit resolved heads: %v", heads.repos)
	}
}

func TestCapabilitiesListArchiveTemplate(t *testing.T) {
	f, _ := archiveSetup(t, nil, "jobs:read")
	w := perform(f.handler, "GET", "/v1/capabilities", archiveToken, "", "")
	var body struct {
		Templates []struct {
			ID         string     `json:"id"`
			Kind       model.Kind `json:"kind"`
			Owners     []string   `json:"owners"`
			RepoConfig string     `json:"repo_config"`
		} `json:"templates"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); w.Code != 200 || err != nil {
		t.Fatalf("capabilities: %d %s %v", w.Code, w.Body.String(), err)
	}
	kinds := map[string]model.Kind{}
	for _, item := range body.Templates {
		kinds[item.ID] = item.Kind
		if item.ID == "org-ios-archive-v1" && (strings.Join(item.Owners, ",") != "themartianapp" || item.RepoConfig != ".macserve.json") {
			t.Fatalf("archive template entry: %+v", item)
		}
	}
	if len(kinds) != 2 || kinds["org-ios-archive-v1"] != model.IOSArchive || kinds["org-build-v1"] != model.Build {
		t.Fatalf("templates: %s", w.Body.String())
	}
}

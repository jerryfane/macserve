package githubpull

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/controllerk/store"
	"github.com/jerryfane/macserve/internal/githubapi"
	"github.com/jerryfane/macserve/internal/githubwire"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
)

const (
	ownerAuthor   = int64(38183696)
	ownerBot      = int64(41000001)
	martianID     = int64(900)
	jerryID       = int64(38183696)
	nativeBuild   = "org-build-v1"
	flutterBuild  = "org-flutter-build-v1"
	nativeConfig  = `{"version":1,"work_dir":".","project":"App.xcodeproj","scheme":"App"}`
	flutterConfig = `{"version":1,"work_dir":"apps/mobile/ios","workspace":"Runner.xcworkspace","scheme":"Runner","flutter":{"app_dir":"apps/mobile"}}`
)

func headSHA(c byte) string { return strings.Repeat(string(c), 40) }

func base64Std(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// orgGitHub is a GitHub of several accounts: the keyholder side (installation
// listings and token mints) and the REST endpoints the poller reads.
type orgGitHub struct {
	mu       sync.Mutex
	server   *httptest.Server
	now      time.Time
	repos    map[string]githubapi.Repository // by lowercase full name
	listing  map[string][]string             // owner → full names
	pulls    map[string][]githubapi.PullRequest
	files    map[string]string // full name + "@" + sha → .macserve.json
	checks   map[int64]githubapi.Check
	comments map[string][]githubapi.Comment // full name → one page of PR comments
	fileGets int
	listings int
}

func (g *orgGitHub) token(_ context.Context, repo string) (githubapi.InstallationToken, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	r, ok := g.repos[repo]
	if !ok {
		return githubapi.InstallationToken{}, errors.New("repository is not installed")
	}
	return githubapi.InstallationToken{Token: "tok-" + strconv.FormatInt(r.ID, 10), ExpiresAt: g.now.Add(time.Hour), RepositoryID: r.ID, OwnerID: r.Owner.ID}, nil
}

func (g *orgGitHub) list(_ context.Context, owner string) ([]githubapi.Repository, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.listings++
	var repos []githubapi.Repository
	for _, name := range g.listing[owner] {
		repos = append(repos, g.repos[name])
	}
	return repos, nil
}

func (g *orgGitHub) serve(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	encode := func(value any) {
		if err := json.NewEncoder(w).Encode(value); err != nil {
			panic(err)
		}
	}
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/repos/"), "/", 3)
	if !strings.HasPrefix(r.URL.Path, "/repos/") || len(parts) < 2 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	name := strings.ToLower(parts[0] + "/" + parts[1])
	repo, ok := g.repos[name]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	rest := ""
	if len(parts) == 3 {
		rest = parts[2]
	}
	pullJSON := func(p githubapi.PullRequest) any {
		return map[string]any{"number": p.Number, "state": p.State, "draft": p.Draft, "head": map[string]any{"sha": p.HeadSHA, "repo": map[string]any{"id": p.HeadRepositoryID}}, "user": map[string]any{"id": p.AuthorID}, "base": map[string]any{"ref": p.BaseRef}, "updated_at": g.now.Format(time.RFC3339)}
	}
	checkJSON := func(c githubapi.Check) any {
		return map[string]any{"id": c.ID, "name": c.Name, "head_sha": c.HeadSHA, "external_id": c.ExternalID, "status": c.Status, "conclusion": c.Conclusion, "app": map[string]any{"id": c.AppID}, "output": c.Output}
	}
	switch {
	case rest == "":
		encode(map[string]any{"id": repo.ID, "full_name": repo.FullName, "default_branch": repo.DefaultBranch, "owner": map[string]any{"login": repo.Owner.Login, "id": repo.Owner.ID}})
	case rest == "pulls":
		items := make([]any, 0)
		for _, p := range g.pulls[name] {
			items = append(items, pullJSON(p))
		}
		encode(items)
	case strings.HasPrefix(rest, "pulls/"):
		number, _ := strconv.Atoi(strings.TrimPrefix(rest, "pulls/"))
		for _, p := range g.pulls[name] {
			if p.Number == number {
				encode(pullJSON(p))
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	case rest == "issues/comments":
		items := make([]any, 0)
		if r.URL.Query().Get("page") == "1" {
			for _, c := range g.comments[name] {
				items = append(items, map[string]any{"id": c.ID, "body": c.Body, "user": map[string]any{"id": c.AuthorID}, "issue_url": g.server.URL + "/repos/" + name + "/issues/" + strconv.Itoa(c.PullRequest), "created_at": c.CreatedAt.Format(time.RFC3339), "updated_at": c.UpdatedAt.Format(time.RFC3339)})
			}
		}
		encode(items)
	case rest == "contents/.macserve.json":
		g.fileGets++
		content, ok := g.files[name+"@"+r.URL.Query().Get("ref")]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		encode(map[string]any{"type": "file", "size": len(content), "encoding": "base64", "content": base64Std(content)})
	case strings.HasPrefix(rest, "commits/") && strings.HasSuffix(rest, "/check-runs"):
		sha := strings.TrimSuffix(strings.TrimPrefix(rest, "commits/"), "/check-runs")
		runs := make([]any, 0)
		for _, c := range g.checks {
			if c.HeadSHA == sha {
				runs = append(runs, checkJSON(c))
			}
		}
		encode(map[string]any{"total_count": len(runs), "check_runs": runs})
	case rest == "check-runs" && r.Method == http.MethodPost:
		var input githubapi.CheckInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		id := int64(len(g.checks) + 1)
		g.checks[id] = githubapi.Check{ID: id, Name: input.Name, HeadSHA: input.HeadSHA, ExternalID: input.ExternalID, Status: input.Status, Conclusion: input.Conclusion, AppID: 11, Output: input.Output}
		w.WriteHeader(http.StatusCreated)
		encode(checkJSON(g.checks[id]))
	case strings.HasPrefix(rest, "check-runs/"):
		id, _ := strconv.ParseInt(strings.TrimPrefix(rest, "check-runs/"), 10, 64)
		c, ok := g.checks[id]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method == http.MethodPatch {
			var input githubapi.CheckInput
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			c.Status, c.Conclusion, c.ExternalID, c.Output = input.Status, input.Conclusion, input.ExternalID, input.Output
			g.checks[id] = c
		}
		encode(checkJSON(c))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// install adds (or moves) a repository, replacing any repository of that ID
// or name: name now has id under owner login and account ID, listed by the
// installation of listedBy ("" lists it nowhere).
func (g *orgGitHub) install(name string, id int64, ownerID int64, listedBy string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for old, r := range g.repos {
		if r.ID != id && old != name {
			continue
		}
		delete(g.repos, old)
		for owner, names := range g.listing {
			var kept []string
			for _, n := range names {
				if n != old {
					kept = append(kept, n)
				}
			}
			g.listing[owner] = kept
		}
	}
	login, _, _ := strings.Cut(name, "/")
	g.repos[name] = githubapi.Repository{ID: id, FullName: name, DefaultBranch: "main", Owner: githubapi.RepositoryOwner{Login: login, ID: ownerID}}
	if listedBy != "" {
		g.listing[listedBy] = append(g.listing[listedBy], name)
	}
}

type ownerFixture struct {
	p       *Poller
	s       *store.Store
	remote  *orgGitHub
	options Options
}

// restart replaces the poller with a new one over the same store and GitHub,
// as a controller restart does: no in-memory poll state survives.
func (f *ownerFixture) restart(t *testing.T) {
	t.Helper()
	p, err := New(f.options)
	if err != nil {
		t.Fatal(err)
	}
	f.p = p
}

func orgTemplates() []model.Template {
	pin := model.FlutterPin{Version: "3.41.9", SDKSHA256: strings.Repeat("1", 64), RubySHA256: strings.Repeat("2", 64), CocoaPodsVersion: "1.16.2", GemsSHA256: strings.Repeat("3", 64)}
	native := model.Template{ID: nativeBuild, Version: 1, Kind: model.Build, Owners: []string{"jerryfane", "themartianapp"}, Xcode: model.Xcode{Version: "26.0", Build: "17A100"}, DeveloperDir: "/Applications/ExampleToolchain.app/Contents/Developer", DefaultTimeoutSeconds: 60, MaxTimeoutSeconds: 600, MemoryLimitMiB: 512}
	flutter := native
	flutter.ID, flutter.Flutter = flutterBuild, &pin
	return []model.Template{native, flutter}
}

func ownerPolicy(owner string, id int64) githubwire.Policy {
	return githubwire.Policy{Owner: owner, OwnerID: id, AuthorIDs: []int64{ownerAuthor, ownerBot}, DefaultBranch: true, Profiles: []string{flutterBuild, nativeBuild}, PolicyRevision: 1}
}

func newOwnerFixture(t *testing.T, policies ...githubwire.Policy) (*ownerFixture, error) {
	t.Helper()
	return newOrgFixture(t, orgTemplates(), policies...)
}

// newOrgFixture is an org GitHub and a poller over a registry of templates.
func newOrgFixture(t *testing.T, templates []model.Template, policies ...githubwire.Policy) (*ownerFixture, error) {
	t.Helper()
	remote := &orgGitHub{now: time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC), repos: make(map[string]githubapi.Repository), listing: make(map[string][]string), pulls: make(map[string][]githubapi.PullRequest), files: make(map[string]string), checks: make(map[int64]githubapi.Check), comments: make(map[string][]githubapi.Comment)}
	remote.server = httptest.NewServer(http.HandlerFunc(remote.serve))
	t.Cleanup(remote.server.Close)
	now := func() time.Time { remote.mu.Lock(); defer remote.mu.Unlock(); return remote.now }
	client, err := githubapi.NewBrokered(githubapi.BrokeredOptions{AppID: 11, Tokens: remote.token, Listing: remote.list, Repositories: map[string]int64{"themartianapp/tandem": 1447740988}, Owners: []string{"jerryfane", "themartianapp"}, HTTP: githubapi.HTTPOptions{BaseURL: remote.server.URL, Client: remote.server.Client(), Now: now}})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := profiles.New(nil, templates)
	if err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(filepath.Join(t.TempDir(), "private", "queue.sqlite"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	options := Options{Store: s, Profiles: registry, Client: client, Policies: policies, VerifyReceipt: func(model.Job, int64, json.RawMessage) error {
		return errors.New("no test receipt is cryptographically trusted")
	}, Now: now}
	p, err := New(options)
	if err != nil {
		return nil, err
	}
	return &ownerFixture{p: p, s: s, remote: remote, options: options}, nil
}

func (f *ownerFixture) pull(repo string, pr githubapi.PullRequest, config string) {
	f.remote.mu.Lock()
	defer f.remote.mu.Unlock()
	pr.State = "open"
	f.remote.pulls[repo] = append(f.remote.pulls[repo], pr)
	if config != "" {
		f.remote.files[repo+"@"+pr.HeadSHA] = config
	}
}

func (f *ownerFixture) poll(t *testing.T) {
	t.Helper()
	if err := f.p.Poll(context.Background()); err != nil {
		t.Fatalf("poll: %v", err)
	}
}

func (f *ownerFixture) active(t *testing.T, repositoryID int64) []store.GitHubRun {
	t.Helper()
	runs, err := f.s.GitHubActiveRuns(context.Background(), repositoryID)
	if err != nil {
		t.Fatal(err)
	}
	return runs
}

func (f *ownerFixture) job(t *testing.T, id string) model.Job {
	t.Helper()
	job, err := f.s.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return job
}

// An owner policy builds only same-repository PRs by a listed author into an
// allowed base of a repository its owner account's installation lists, with
// the first template the head's .macserve.json admits. Other authors, forks,
// other bases, other owners and heads without an admitting .macserve.json get
// no run and no check.
func TestOwnerPolicyAdmitsOnlyListedAuthorsSameRepositoryPullsIntoMain(t *testing.T) {
	f, err := newOwnerFixture(t, ownerPolicy("themartianapp", martianID))
	if err != nil {
		t.Fatal(err)
	}
	const app, other = "themartianapp/app", "someone-else/app"
	f.remote.install(app, 501, martianID, "themartianapp")
	f.remote.install(other, 601, 1234, "themartianapp")
	f.remote.install("jerryfane/tool", 701, jerryID, "jerryfane")
	f.pull(app, githubapi.PullRequest{Number: 1, HeadSHA: headSHA('1'), HeadRepositoryID: 501, AuthorID: ownerAuthor, BaseRef: "main"}, nativeConfig)
	f.pull(app, githubapi.PullRequest{Number: 2, HeadSHA: headSHA('2'), HeadRepositoryID: 501, AuthorID: 999, BaseRef: "main"}, nativeConfig)
	f.pull(app, githubapi.PullRequest{Number: 3, HeadSHA: headSHA('3'), HeadRepositoryID: 9999, AuthorID: ownerAuthor, BaseRef: "main"}, nativeConfig)
	f.pull(app, githubapi.PullRequest{Number: 4, HeadSHA: headSHA('4'), HeadRepositoryID: 501, AuthorID: ownerAuthor, BaseRef: "develop"}, nativeConfig)
	f.pull(app, githubapi.PullRequest{Number: 5, HeadSHA: headSHA('5'), HeadRepositoryID: 501, AuthorID: ownerBot, BaseRef: "main"}, flutterConfig)
	f.pull(app, githubapi.PullRequest{Number: 6, HeadSHA: headSHA('6'), HeadRepositoryID: 501, AuthorID: ownerAuthor, BaseRef: "main"}, "")
	f.pull(other, githubapi.PullRequest{Number: 1, HeadSHA: headSHA('7'), HeadRepositoryID: 601, AuthorID: ownerAuthor, BaseRef: "main"}, nativeConfig)
	f.pull("jerryfane/tool", githubapi.PullRequest{Number: 1, HeadSHA: headSHA('8'), HeadRepositoryID: 701, AuthorID: ownerAuthor, BaseRef: "main"}, nativeConfig)
	f.poll(t)
	runs := f.active(t, 501)
	got := map[string]string{}
	for _, run := range runs {
		got[run.SHA] = run.Profile
		job := f.job(t, run.JobID)
		if job.Principal != "github:501" || job.Request.Repo != app || job.Request.Context.PullRequest == 0 {
			t.Fatalf("job identity: %+v", job)
		}
		if err := f.p.checkDispatch(context.Background(), job); err != nil {
			t.Fatalf("admitted head %s refused at dispatch: %v", run.SHA, err)
		}
	}
	// The first template the file admits: a native file skips the Flutter
	// template listed first; a Flutter file selects it.
	if len(got) != 2 || got[headSHA('1')] != nativeBuild || got[headSHA('5')] != flutterBuild {
		t.Fatalf("admitted heads: %v", got)
	}
	if len(f.active(t, 601)) != 0 || len(f.active(t, 701)) != 0 {
		t.Fatal("a repository of another owner was admitted")
	}
	f.remote.mu.Lock()
	for _, check := range f.remote.checks {
		if check.HeadSHA != headSHA('1') && check.HeadSHA != headSHA('5') {
			t.Errorf("check published for an ineligible head: %+v", check)
		}
	}
	reads := f.remote.fileGets
	f.remote.mu.Unlock()
	// An unchanged head's selection is not re-read.
	f.poll(t)
	f.remote.mu.Lock()
	if f.remote.fileGets != reads {
		t.Errorf(".macserve.json re-read for unchanged heads: %d then %d", reads, f.remote.fileGets)
	}
	f.remote.mu.Unlock()
	run, err := f.s.GitHubByJob(context.Background(), runs[0].JobID)
	if err != nil {
		t.Fatal(err)
	}
	approval, err := f.p.Approval(context.Background(), f.job(t, runs[0].JobID))
	if err != nil || approval.Intake != "github_pull" || !strings.HasPrefix(approval.Identity, "repository:501/policy:1/run:"+run.Key) {
		t.Fatalf("approval: %+v %v", approval, err)
	}
}

// Owner identity is the pinned account ID, not the login: after the login is
// renamed and re-registered by another account, its repositories are no
// longer governed, unfinished jobs are cancelled and nothing new is admitted.
func TestOwnerPolicyRefusesOwnerIDMismatchAfterLoginRename(t *testing.T) {
	f, err := newOwnerFixture(t, ownerPolicy("themartianapp", martianID))
	if err != nil {
		t.Fatal(err)
	}
	const app = "themartianapp/app"
	f.remote.install(app, 501, martianID, "themartianapp")
	f.pull(app, githubapi.PullRequest{Number: 1, HeadSHA: headSHA('1'), HeadRepositoryID: 501, AuthorID: ownerAuthor, BaseRef: "main"}, nativeConfig)
	f.poll(t)
	runs := f.active(t, 501)
	if len(runs) != 1 {
		t.Fatalf("runs: %+v", runs)
	}
	job := f.job(t, runs[0].JobID)
	// Another account (ID 901) now holds the login and a repository of the
	// same name; it is a new repository ID.
	f.remote.install(app, 502, 901, "themartianapp")
	f.pull(app, githubapi.PullRequest{Number: 2, HeadSHA: headSHA('2'), HeadRepositoryID: 502, AuthorID: ownerAuthor, BaseRef: "main"}, nativeConfig)
	f.poll(t)
	if len(f.active(t, 502)) != 0 {
		t.Fatal("repository of a re-registered login admitted")
	}
	if job = f.job(t, job.ID); !job.State.Terminal() && !job.CancelRequested {
		t.Fatalf("job of the departed repository still runs: %s", job.State)
	}
	// The same repository ID under an owner account ID that changed is refused
	// at dispatch too.
	g, err := newOwnerFixture(t, ownerPolicy("themartianapp", martianID))
	if err != nil {
		t.Fatal(err)
	}
	g.remote.install(app, 501, martianID, "themartianapp")
	g.pull(app, githubapi.PullRequest{Number: 1, HeadSHA: headSHA('1'), HeadRepositoryID: 501, AuthorID: ownerAuthor, BaseRef: "main"}, nativeConfig)
	g.poll(t)
	runs = g.active(t, 501)
	if len(runs) != 1 {
		t.Fatalf("runs: %+v", runs)
	}
	g.remote.mu.Lock()
	r := g.remote.repos[app]
	r.Owner.ID = 901
	g.remote.repos[app] = r
	g.remote.mu.Unlock()
	if err := g.p.checkDispatch(context.Background(), g.job(t, runs[0].JobID)); !errors.Is(err, ErrIneligible) {
		t.Fatalf("owner ID mismatch dispatched: %v", err)
	}
}

// Runs are keyed by repository ID and owner identity: a transfer to another
// owner-policy owner keeps building under the new name and ends the old
// name's job; a transfer to an unlisted owner ends the repository's jobs.
func TestOwnerPolicyTransfers(t *testing.T) {
	f, err := newOwnerFixture(t, ownerPolicy("jerryfane", jerryID), ownerPolicy("themartianapp", martianID))
	if err != nil {
		t.Fatal(err)
	}
	f.remote.install("jerryfane/app", 501, jerryID, "jerryfane")
	f.pull("jerryfane/app", githubapi.PullRequest{Number: 1, HeadSHA: headSHA('1'), HeadRepositoryID: 501, AuthorID: ownerAuthor, BaseRef: "main"}, nativeConfig)
	f.poll(t)
	before := f.active(t, 501)
	if len(before) != 1 || before[0].Repository != "jerryfane/app" {
		t.Fatalf("runs before transfer: %+v", before)
	}
	f.remote.install("themartianapp/app", 501, martianID, "themartianapp")
	f.remote.mu.Lock()
	f.remote.pulls["themartianapp/app"] = f.remote.pulls["jerryfane/app"]
	f.remote.files["themartianapp/app@"+headSHA('1')] = nativeConfig
	f.remote.mu.Unlock()
	f.poll(t)
	after := f.active(t, 501)
	if len(after) != 1 || after[0].Repository != "themartianapp/app" || after[0].Key == before[0].Key {
		t.Fatalf("runs after transfer: %+v", after)
	}
	if old := f.job(t, before[0].JobID); !old.State.Terminal() && !old.CancelRequested {
		t.Fatalf("old-name job still runs: %s", old.State)
	}
	if err := f.p.checkDispatch(context.Background(), f.job(t, after[0].JobID)); err != nil {
		t.Fatalf("transferred repository refused: %v", err)
	}
	f.remote.install("outsider/app", 501, 4242, "")
	f.poll(t)
	if left := f.job(t, after[0].JobID); !left.State.Terminal() && !left.CancelRequested {
		t.Fatalf("job of a repository transferred out still runs: %s", left.State)
	}
	if len(f.active(t, 501)) != 0 {
		t.Fatal("repository transferred out still has active runs")
	}
}

// A repository a repository-form policy pins is governed by that policy
// alone, never by the owner policy of its owner.
func TestOwnerPolicyLeavesPinnedRepositories(t *testing.T) {
	pinned := githubwire.Policy{RepositoryID: 1447740988, Repository: "themartianapp/tandem", AuthorIDs: []int64{ownerAuthor}, BaseBranches: []string{"release"}, Profiles: []string{nativeBuild}, PolicyRevision: 2}
	f, err := newOwnerFixture(t, pinned, ownerPolicy("themartianapp", martianID))
	if err != nil {
		t.Fatal(err)
	}
	f.remote.install("themartianapp/tandem", 1447740988, martianID, "themartianapp")
	f.pull("themartianapp/tandem", githubapi.PullRequest{Number: 1, HeadSHA: headSHA('1'), HeadRepositoryID: 1447740988, AuthorID: ownerAuthor, BaseRef: "main"}, nativeConfig)
	f.poll(t)
	f.remote.mu.Lock()
	reads := f.remote.fileGets
	f.remote.mu.Unlock()
	if reads != 0 {
		t.Fatalf("owner policy read a pinned repository's .macserve.json %d times", reads)
	}
	for _, run := range f.active(t, 1447740988) {
		t.Fatalf("PR into a base the pinned policy disallows ran: %+v", run)
	}
}

// New refuses a policy naming both forms and owner policies the pull mode
// cannot serve.
func TestOwnerPolicyValidation(t *testing.T) {
	both := ownerPolicy("themartianapp", martianID)
	both.Repository, both.RepositoryID = "themartianapp/app", 501
	if _, err := newOwnerFixture(t, both); !errors.Is(err, githubwire.ErrPolicyForm) {
		t.Fatalf("both-forms policy: %v", err)
	}
	for name, edit := range map[string]func(*githubwire.Policy){
		"no owner id":         func(p *githubwire.Policy) { p.OwnerID = 0 },
		"non-canonical owner": func(p *githubwire.Policy) { p.Owner = "TheMartianApp" },
		"no base":             func(p *githubwire.Policy) { p.DefaultBranch, p.BaseBranches = false, nil },
		"comment intake":      func(p *githubwire.Policy) { p.ActionsBotID = 55 },
		"unknown template":    func(p *githubwire.Policy) { p.Profiles = []string{"org-unknown-v1"} },
		"other owner":         func(p *githubwire.Policy) { p.Owner = "someone-else" },
		"duplicate profile":   func(p *githubwire.Policy) { p.Profiles = []string{nativeBuild, nativeBuild} },
		"no author":           func(p *githubwire.Policy) { p.AuthorIDs = nil },
	} {
		policy := ownerPolicy("themartianapp", martianID)
		edit(&policy)
		if _, err := newOwnerFixture(t, policy); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := newOwnerFixture(t, ownerPolicy("themartianapp", martianID), ownerPolicy("themartianapp", martianID)); err == nil {
		t.Error("duplicate owner policy accepted")
	}
}

// Departures are reconciled from durable runs: a repository admitted before
// a controller restart and gone from a complete listing after it still loses
// its unfinished job and current runs.
func TestOwnerPolicyDepartureAfterRestart(t *testing.T) {
	f, err := newOwnerFixture(t, ownerPolicy("themartianapp", martianID))
	if err != nil {
		t.Fatal(err)
	}
	const app = "themartianapp/app"
	f.remote.install(app, 501, martianID, "themartianapp")
	f.pull(app, githubapi.PullRequest{Number: 1, HeadSHA: headSHA('1'), HeadRepositoryID: 501, AuthorID: ownerAuthor, BaseRef: "main"}, nativeConfig)
	f.poll(t)
	runs := f.active(t, 501)
	if len(runs) != 1 {
		t.Fatalf("runs: %+v", runs)
	}
	f.restart(t)
	f.remote.install("outsider/app", 501, 4242, "")
	f.poll(t)
	if job := f.job(t, runs[0].JobID); !job.State.Terminal() && !job.CancelRequested {
		t.Fatalf("job of a repository that left the listing across a restart: state=%s", job.State)
	}
	if active := f.active(t, 501); len(active) != 0 {
		t.Fatalf("active runs after departure: %+v", active)
	}
	tracked, err := f.s.GitHubTrackedRepositories(context.Background())
	if err != nil || len(tracked) != 0 {
		t.Fatalf("tracked after retirement: %v %v", tracked, err)
	}
	// A repository-form policy's pinned repository is never retired by an
	// owner policy's listing, also after a restart.
	pinned := githubwire.Policy{RepositoryID: 1447740988, Repository: "themartianapp/tandem", AuthorIDs: []int64{ownerAuthor}, BaseBranches: []string{"main"}, Profiles: []string{nativeBuild}, PolicyRevision: 2}
	g, err := newOwnerFixture(t, pinned, ownerPolicy("themartianapp", martianID))
	if err != nil {
		t.Fatal(err)
	}
	g.remote.install("themartianapp/tandem", 1447740988, martianID, "")
	g.pull("themartianapp/tandem", githubapi.PullRequest{Number: 1, HeadSHA: headSHA('1'), HeadRepositoryID: 1447740988, AuthorID: ownerAuthor, BaseRef: "main"}, nativeConfig)
	g.poll(t)
	pinnedRuns := g.active(t, 1447740988)
	if len(pinnedRuns) != 1 {
		t.Fatalf("pinned runs: %+v", pinnedRuns)
	}
	g.restart(t)
	g.poll(t)
	if job := g.job(t, pinnedRuns[0].JobID); job.State.Terminal() || job.CancelRequested {
		t.Fatalf("pinned repository job retired by an owner listing: %s", job.State)
	}
}

// The template is selected against the policy governing the repository now:
// a transfer between owners with different template lists re-evaluates a
// head the old owner's templates did not admit.
func TestOwnerPolicyTransferReevaluatesTemplateSelection(t *testing.T) {
	flutterOnly := ownerPolicy("jerryfane", jerryID)
	flutterOnly.Profiles = []string{flutterBuild}
	f, err := newOwnerFixture(t, flutterOnly, ownerPolicy("themartianapp", martianID))
	if err != nil {
		t.Fatal(err)
	}
	f.remote.install("jerryfane/app", 501, jerryID, "jerryfane")
	f.pull("jerryfane/app", githubapi.PullRequest{Number: 1, HeadSHA: headSHA('1'), HeadRepositoryID: 501, AuthorID: ownerAuthor, BaseRef: "main"}, nativeConfig)
	f.poll(t)
	if runs := f.active(t, 501); len(runs) != 0 {
		t.Fatalf("native head admitted by a Flutter-only policy: %+v", runs)
	}
	f.remote.install("themartianapp/app", 501, martianID, "themartianapp")
	f.remote.mu.Lock()
	f.remote.pulls["themartianapp/app"] = f.remote.pulls["jerryfane/app"]
	f.remote.files["themartianapp/app@"+headSHA('1')] = nativeConfig
	reads := f.remote.fileGets
	f.remote.mu.Unlock()
	f.poll(t)
	runs := f.active(t, 501)
	if len(runs) != 1 || runs[0].Profile != nativeBuild || runs[0].Repository != "themartianapp/app" {
		t.Fatalf("transferred head not re-evaluated: %+v", runs)
	}
	f.remote.mu.Lock()
	defer f.remote.mu.Unlock()
	if f.remote.fileGets != reads {
		t.Fatalf("immutable .macserve.json re-read after transfer: %d then %d", reads, f.remote.fileGets)
	}
}

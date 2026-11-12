package githubpull

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/controllerk/store"
	"github.com/jerryfane/macserve/internal/githubapi"
	"github.com/jerryfane/macserve/internal/githubwire"
	"github.com/jerryfane/macserve/internal/model"
)

const (
	matrixRepo   = "themartianapp/app"
	matrixRepoID = int64(501)
	uiTemplate   = "org-uitest-v1"
	scriptTmpl   = "org-script-v1"
	matrixConfig = `{"version":1,"work_dir":".","project":"App.xcodeproj","scheme":"App",
 "ui_test":{"shards":{"chat":["AppUITests/ChatTests"],"gram":["AppUITests/GramTests","AppUITests/GramColumnTests"]}},
 "script":{"shards":{"duo-column":{"run":"Tools/ci/duo-column.sh"}}}}`
)

var (
	iPhone = model.Simulator{Runtime: "com.apple.CoreSimulator.SimRuntime.iOS-27-0", RuntimeBuild: "24A434", DeviceType: "com.apple.CoreSimulator.SimDeviceType.iPhone-18-Pro"}
	duo    = model.Simulator{Runtime: "com.apple.CoreSimulator.SimRuntime.iOS-27-1", RuntimeBuild: "24A94425", DeviceType: "com.apple.CoreSimulator.SimDeviceType.iPhone-Duo"}
	iPad   = model.Simulator{Runtime: "com.apple.CoreSimulator.SimRuntime.iOS-27-0", RuntimeBuild: "24A434", DeviceType: "com.apple.CoreSimulator.SimDeviceType.iPad-Pro-13-inch-M5-12GB"}
)

// matrixTemplates adds a UI test template pinning iPhone and Duo and a script
// template pinning iPhone to the org build templates.
func matrixTemplates() []model.Template {
	templates := orgTemplates()
	ui := templates[0]
	ui.ID, ui.Kind, ui.Simulators = uiTemplate, model.SimulatorUITest, []model.Simulator{iPhone, duo}
	script := ui
	script.ID, script.Kind, script.Simulators = scriptTmpl, model.SimulatorScript, []model.Simulator{iPhone}
	return append(templates, ui, script)
}

func matrixPolicy() githubwire.Policy {
	return githubwire.Policy{RepositoryID: matrixRepoID, Repository: matrixRepo, AuthorIDs: []int64{ownerAuthor}, BaseBranches: []string{"main"}, PolicyRevision: 1,
		Profiles: []string{nativeBuild, uiTemplate, scriptTmpl},
		Matrix: []githubwire.MatrixEntry{
			{Profile: uiTemplate, Shard: "chat", Simulator: iPhone},
			{Profile: uiTemplate, Shard: "gram", Simulator: duo},
			{Profile: scriptTmpl, Shard: "duo-column", Simulator: iPhone},
		}}
}

func newMatrixFixture(t *testing.T, policy githubwire.Policy) *ownerFixture {
	t.Helper()
	f, err := newOrgFixture(t, matrixTemplates(), policy)
	if err != nil {
		t.Fatal(err)
	}
	f.remote.install(matrixRepo, matrixRepoID, martianID, "")
	return f
}

// runsByCheck maps each run of the matrix repository's current snapshot, by
// its check name, to the run and its job (zero for a jobless run).
func (f *ownerFixture) runsByCheck(t *testing.T, sha string) map[string]store.GitHubRun {
	t.Helper()
	all, err := f.s.GitHubRuns(context.Background(), matrixRepoID)
	if err != nil {
		t.Fatal(err)
	}
	runs := make(map[string]store.GitHubRun)
	for _, run := range all {
		if run.SHA == sha {
			runs[githubwire.CheckName(run.Profile, run.Shard)] = run
		}
	}
	return runs
}

// checksOf maps each published check of sha by name.
func (f *ownerFixture) checksOf(sha string) map[string]githubapi.Check {
	f.remote.mu.Lock()
	defer f.remote.mu.Unlock()
	checks := make(map[string]githubapi.Check)
	for _, check := range f.remote.checks {
		if check.HeadSHA == sha {
			checks[check.Name] = check
		}
	}
	return checks
}

func (f *ownerFixture) setPull(repo string, update func(*githubapi.PullRequest)) {
	f.remote.mu.Lock()
	defer f.remote.mu.Unlock()
	update(&f.remote.pulls[repo][0])
}

// The poller accepts a repository policy matrix only of its own simulator
// test or script templates, each pinning the entry's simulator, with unique
// (profile, shard) pairs; every such template profile needs entries.
func TestMatrixPolicyValidation(t *testing.T) {
	if _, err := newOrgFixture(t, matrixTemplates(), matrixPolicy()); err != nil {
		t.Fatalf("valid matrix refused: %v", err)
	}
	for name, mutate := range map[string]func(*githubwire.Policy){
		"profile not in profiles":     func(p *githubwire.Policy) { p.Profiles = []string{nativeBuild, uiTemplate} },
		"duplicate profile and shard": func(p *githubwire.Policy) { p.Matrix[1].Shard = "chat" },
		"invalid shard name":          func(p *githubwire.Policy) { p.Matrix[0].Shard = "Chat" },
		"empty shard":                 func(p *githubwire.Policy) { p.Matrix[0].Shard = "" },
		"incomplete simulator":        func(p *githubwire.Policy) { p.Matrix[0].Simulator.RuntimeBuild = "" },
		"simulator not pinned":        func(p *githubwire.Policy) { p.Matrix[0].Simulator = iPad },
		"simulator of another entry":  func(p *githubwire.Policy) { p.Matrix[2].Simulator = duo },
		"build profile entry":         func(p *githubwire.Policy) { p.Matrix[0].Profile = nativeBuild },
		"template without entries":    func(p *githubwire.Policy) { p.Matrix = p.Matrix[:2] },
		"skip drafts without a matrix": func(p *githubwire.Policy) {
			p.Profiles, p.Matrix, p.MatrixSkipDrafts = []string{nativeBuild}, nil, true
		},
	} {
		policy := matrixPolicy()
		policy.Matrix = slices.Clone(policy.Matrix)
		mutate(&policy)
		if _, err := newOrgFixture(t, matrixTemplates(), policy); err == nil || !strings.Contains(err.Error(), "matrix") {
			t.Errorf("%s: matrix accepted or wrong error: %v", name, err)
		}
	}
	owner := ownerPolicy("themartianapp", martianID)
	owner.Matrix = []githubwire.MatrixEntry{{Profile: nativeBuild, Shard: "chat", Simulator: iPhone}}
	if _, err := newOrgFixture(t, matrixTemplates(), owner); err == nil || !strings.Contains(err.Error(), "matrix") {
		t.Errorf("owner policy matrix accepted or wrong error: %v", err)
	}
	owner.Matrix, owner.MatrixSkipDrafts = nil, true
	if _, err := newOrgFixture(t, matrixTemplates(), owner); err == nil || !strings.Contains(err.Error(), "matrix") {
		t.Errorf("owner policy matrix_skip_drafts accepted or wrong error: %v", err)
	}
}

// A build-only repository policy behaves exactly as before policy matrices:
// the same run key (so an upgrade continues existing runs instead of
// re-admitting every open head), request, profile snapshot and check name.
// The golden values are those 589a4c33 (v0.1.48) produces.
func TestBuildOnlyPolicyRunUnchanged(t *testing.T) {
	policy := githubwire.Policy{RepositoryID: matrixRepoID, Repository: matrixRepo, AuthorIDs: []int64{ownerAuthor}, BaseBranches: []string{"main"}, Profiles: []string{nativeBuild}, PolicyRevision: 3}
	f, err := newOwnerFixture(t, policy)
	if err != nil {
		t.Fatal(err)
	}
	f.remote.install(matrixRepo, matrixRepoID, martianID, "")
	f.pull(matrixRepo, githubapi.PullRequest{Number: 4, HeadSHA: headSHA('1'), HeadRepositoryID: matrixRepoID, AuthorID: ownerAuthor, BaseRef: "main"}, nativeConfig)
	f.poll(t)
	runs := f.active(t, matrixRepoID)
	if len(runs) != 1 {
		t.Fatalf("runs %+v", runs)
	}
	job := f.job(t, runs[0].JobID)
	f.remote.mu.Lock()
	check, checks := f.remote.checks[runs[0].CheckID], len(f.remote.checks)
	f.remote.mu.Unlock()
	if runs[0].Key != "204d2f3d48a2bac42f923f25126272fea730c594f1bb77bee15b99dbf2aa7889" ||
		job.RequestDigest != "725c771985c80fb954d5abec95f563ff4d37e3b422368a595676db2dd31e71b6" ||
		job.ProfileDigest != "022905d4b969de933db5959d96ea5010a71e3aab0bc801968c40da24e28984d0" ||
		checks != 1 || check.Name != "mac-evidence/"+nativeBuild || check.Status != "queued" || check.ExternalID != job.ID {
		t.Fatalf("build-only run changed: key %s request %s profile %s check %+v (%d checks)", runs[0].Key, job.RequestDigest, job.ProfileDigest, check, checks)
	}
}

// One eligible head admits the build profile and one job per matrix entry,
// each with the entry's shard and simulator, each published to its own check;
// a new head supersedes every one of the old head's jobs.
func TestMatrixAdmitsEntriesAndSupersedesThemTogether(t *testing.T) {
	f := newMatrixFixture(t, matrixPolicy())
	f.pull(matrixRepo, githubapi.PullRequest{Number: 1, HeadSHA: headSHA('1'), HeadRepositoryID: matrixRepoID, AuthorID: ownerAuthor, BaseRef: "main"}, matrixConfig)
	f.poll(t)
	want := map[string]struct {
		kind      model.Kind
		shard     string
		simulator *model.Simulator
	}{
		"mac-evidence/" + nativeBuild:                {model.Build, "", nil},
		"mac-evidence/" + uiTemplate + "/chat":       {model.SimulatorUITest, "chat", &iPhone},
		"mac-evidence/" + uiTemplate + "/gram":       {model.SimulatorUITest, "gram", &duo},
		"mac-evidence/" + scriptTmpl + "/duo-column": {model.SimulatorScript, "duo-column", &iPhone},
	}
	first := f.runsByCheck(t, headSHA('1'))
	checks := f.checksOf(headSHA('1'))
	if len(first) != len(want) || len(checks) != len(want) {
		t.Fatalf("runs %v, checks %v", first, checks)
	}
	for name, w := range want {
		run, ok := first[name]
		if !ok || run.JobID == "" || run.Blocked != "" {
			t.Fatalf("%s: run %+v", name, run)
		}
		job := f.job(t, run.JobID)
		if job.State != model.Queued || job.Request.Kind != w.kind || job.Request.Shard != w.shard || (job.Request.Simulator == nil) != (w.simulator == nil) || w.simulator != nil && *job.Request.Simulator != *w.simulator {
			t.Fatalf("%s: job request %+v", name, job.Request)
		}
		if check := checks[name]; check.ExternalID != run.JobID || check.Status != "queued" || run.CheckID != check.ID {
			t.Fatalf("%s: check %+v run %+v", name, check, run)
		}
	}
	// Polling again joins the same runs; nothing new is admitted.
	f.poll(t)
	if again := f.runsByCheck(t, headSHA('1')); len(again) != len(want) || again["mac-evidence/"+uiTemplate+"/gram"].JobID != first["mac-evidence/"+uiTemplate+"/gram"].JobID {
		t.Fatalf("repoll changed runs: %v", again)
	}

	f.setPull(matrixRepo, func(p *githubapi.PullRequest) { p.HeadSHA = headSHA('2') })
	f.remote.mu.Lock()
	f.remote.files[matrixRepo+"@"+headSHA('2')] = matrixConfig
	f.remote.mu.Unlock()
	f.poll(t)
	for name, run := range first {
		job := f.job(t, run.JobID)
		if job.State != model.Cancelled || job.CancelReason == nil || job.CancelReason.Source != model.CancelGitHub {
			t.Fatalf("%s: superseded job %s state %s reason %+v", name, job.ID, job.State, job.CancelReason)
		}
	}
	if second := f.runsByCheck(t, headSHA('2')); len(second) != len(want) || len(f.active(t, matrixRepoID)) != len(want) {
		t.Fatalf("new head runs %v", second)
	}
}

// A head whose .macserve.json does not declare an entry's shard for the
// template's kind gets an action_required check for that entry and no job;
// the other entries and the build run normally. Without the file every entry
// is refused that way.
func TestMatrixMissingShardRequiresAction(t *testing.T) {
	f := newMatrixFixture(t, matrixPolicy())
	noGram := strings.Replace(matrixConfig, `"gram":`, `"other":`, 1)
	f.pull(matrixRepo, githubapi.PullRequest{Number: 1, HeadSHA: headSHA('1'), HeadRepositoryID: matrixRepoID, AuthorID: ownerAuthor, BaseRef: "main"}, noGram)
	f.pull(matrixRepo, githubapi.PullRequest{Number: 2, HeadSHA: headSHA('2'), HeadRepositoryID: matrixRepoID, AuthorID: ownerAuthor, BaseRef: "main"}, "")
	f.poll(t)
	gram := "mac-evidence/" + uiTemplate + "/gram"
	runs, checks := f.runsByCheck(t, headSHA('1')), f.checksOf(headSHA('1'))
	if run := runs[gram]; run.JobID != "" || !strings.Contains(run.Blocked, `ui_test shard "gram"`) {
		t.Fatalf("gram run %+v", run)
	}
	if check := checks[gram]; check.Status != "completed" || check.Conclusion != "action_required" {
		t.Fatalf("gram check %+v", check)
	}
	for _, name := range []string{"mac-evidence/" + nativeBuild, "mac-evidence/" + uiTemplate + "/chat", "mac-evidence/" + scriptTmpl + "/duo-column"} {
		if run := runs[name]; run.JobID == "" || run.Blocked != "" || checks[name].Status != "queued" {
			t.Fatalf("%s: run %+v check %+v", name, run, checks[name])
		}
	}
	runs, checks = f.runsByCheck(t, headSHA('2')), f.checksOf(headSHA('2'))
	if len(runs) != 4 || runs["mac-evidence/"+nativeBuild].JobID == "" {
		t.Fatalf("head without .macserve.json: %v", runs)
	}
	for _, entry := range matrixPolicy().Matrix {
		name := githubwire.CheckName(entry.Profile, entry.Shard)
		if runs[name].JobID != "" || checks[name].Conclusion != "action_required" {
			t.Fatalf("%s without .macserve.json: run %+v check %+v", name, runs[name], checks[name])
		}
	}
}

// With matrix_skip_drafts a draft head runs only the build; marking it ready
// admits its matrix, and converting it back to a draft cancels nothing.
func TestMatrixSkipsDraftsUntilReady(t *testing.T) {
	policy := matrixPolicy()
	policy.MatrixSkipDrafts = true
	f := newMatrixFixture(t, policy)
	f.pull(matrixRepo, githubapi.PullRequest{Number: 1, Draft: true, HeadSHA: headSHA('1'), HeadRepositoryID: matrixRepoID, AuthorID: ownerAuthor, BaseRef: "main"}, matrixConfig)
	f.poll(t)
	runs, checks := f.runsByCheck(t, headSHA('1')), f.checksOf(headSHA('1'))
	build := "mac-evidence/" + nativeBuild
	if len(runs) != 1 || runs[build].JobID == "" || len(checks) != 1 || checks[build].Status != "queued" {
		t.Fatalf("draft head: runs %v checks %v", runs, checks)
	}

	f.setPull(matrixRepo, func(p *githubapi.PullRequest) { p.Draft = false })
	f.poll(t)
	ready := f.runsByCheck(t, headSHA('1'))
	if len(ready) != 4 || len(f.checksOf(headSHA('1'))) != 4 || ready[build].JobID != runs[build].JobID {
		t.Fatalf("ready head: runs %v", ready)
	}

	f.setPull(matrixRepo, func(p *githubapi.PullRequest) { p.Draft = true })
	f.poll(t)
	f.poll(t)
	for name, run := range ready {
		if job := f.job(t, run.JobID); job.State != model.Queued {
			t.Fatalf("%s: back-to-draft job %s", name, job.State)
		}
	}
	if active := f.active(t, matrixRepoID); len(active) != 4 {
		t.Fatalf("active runs after back to draft: %v", active)
	}
	// The kept matrix jobs still pass the dispatch recheck.
	job := f.job(t, ready["mac-evidence/"+uiTemplate+"/chat"].JobID)
	if err := f.p.checkDispatch(context.Background(), job); err != nil {
		t.Fatalf("dispatch of a kept matrix job: %v", err)
	}
}

// A matrix run is rerun through the owner API by its shard; the response's
// run names the shard and keeps its check.
func TestMatrixOwnerRerunNamesShard(t *testing.T) {
	ctx := context.Background()
	f := newMatrixFixture(t, matrixPolicy())
	f.pull(matrixRepo, githubapi.PullRequest{Number: 1, HeadSHA: headSHA('1'), HeadRepositoryID: matrixRepoID, AuthorID: ownerAuthor, BaseRef: "main"}, matrixConfig)
	f.poll(t)
	chat := f.runsByCheck(t, headSHA('1'))["mac-evidence/"+uiTemplate+"/chat"]
	if _, err := f.s.Cancel(ctx, chat.JobID, "client", model.CancelReason{Source: model.CancelGitHub}, f.options.Now()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.p.Rerun(ctx, matrixRepoID, "", headSHA('1'), uiTemplate, "", f.options.Now()); err == nil {
		t.Fatal("rerun of a matrix template without its shard accepted")
	}
	run, started, err := f.p.Rerun(ctx, matrixRepoID, "", headSHA('1'), uiTemplate, "chat", f.options.Now())
	if err != nil || !started || run.Key != chat.Key || run.Shard != "chat" || run.JobID == chat.JobID {
		t.Fatalf("rerun: %+v %v %v", run, started, err)
	}
	if job := f.job(t, run.JobID); job.Request.Shard != "chat" || *job.Request.Simulator != iPhone {
		t.Fatalf("rerun job request %+v", job.Request)
	}
	f.poll(t)
	if check := f.checksOf(headSHA('1'))["mac-evidence/"+uiTemplate+"/chat"]; check.ID != chat.CheckID || check.ExternalID != run.JobID {
		t.Fatalf("rerun check %+v (first %d)", check, chat.CheckID)
	}
}

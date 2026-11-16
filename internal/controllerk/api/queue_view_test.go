package api

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/controllerconfig"
	"github.com/jerryfane/macserve/internal/controllerk/controller"
	"github.com/jerryfane/macserve/internal/githubapi"
	"github.com/jerryfane/macserve/internal/health"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
)

type listPage struct {
	Items []struct {
		ID      string         `json:"id"`
		State   model.State    `json:"state"`
		Waiting map[string]any `json:"waiting"`
	} `json:"items"`
	NextCursor string `json:"next_cursor"`
}

func getList(t *testing.T, h http.Handler, token, query string) listPage {
	t.Helper()
	w := perform(h, "GET", "/v1/jobs"+query, token, "", "")
	var page listPage
	if err := json.Unmarshal(w.Body.Bytes(), &page); w.Code != 200 || err != nil {
		t.Fatalf("GET /v1/jobs%s %d: %s", query, w.Code, w.Body.String())
	}
	return page
}

func (p listPage) ids() []string {
	var ids []string
	for _, item := range p.Items {
		ids = append(ids, item.ID)
	}
	return ids
}

// listAll follows next_cursor from query, a page of limit 1 at a time.
func listAll(t *testing.T, h http.Handler, query string) []string {
	t.Helper()
	var ids []string
	page := getList(t, h, testToken, "?limit=1"+query)
	for {
		ids = append(ids, page.ids()...)
		if page.NextCursor == "" {
			return ids
		}
		page = getList(t, h, testToken, "?limit=1&cursor="+page.NextCursor+query)
	}
}

// A client lists its newest jobs first by default, filters by state and
// aliases, pages either order with cursors that keep their order, and gets a
// 400 for an unknown state or order.
func TestListFiltersStatesAndPagesNewestFirst(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	running := f.submit(t, "one")
	if claimed, err := f.db.Claim(ctx, "epoch", testTime, 2, false); err != nil || claimed.ID != running.ID {
		t.Fatalf("claim: %+v %v", claimed, err)
	}
	cancelled := f.submit(t, "two")
	if _, err := f.db.Cancel(ctx, cancelled.ID, "stop", model.CancelReason{Source: model.CancelClient, Principal: f.owner.ID}, testTime); err != nil {
		t.Fatal(err)
	}
	third, fourth := f.submit(t, "three"), f.submit(t, "four")
	all := []string{running.ID, cancelled.ID, third.ID, fourth.ID}
	newest := slices.Clone(all)
	slices.Reverse(newest)

	cases := map[string][]string{
		"":                                  newest,
		"&order=newest":                     newest,
		"&order=oldest":                     all,
		"&state=queued":                     {fourth.ID, third.ID},
		"&state=active":                     {running.ID},
		"&state=preparing":                  {running.ID},
		"&state=running":                    nil,
		"&state=terminal":                   {cancelled.ID},
		"&state=cancelled,queued":           {fourth.ID, third.ID, cancelled.ID},
		"&state=queued,active&order=oldest": {running.ID, third.ID, fourth.ID},
		"&state=queued,queued":              {fourth.ID, third.ID},
	}
	for query, want := range cases {
		if got := listAll(t, f.handler, query); !slices.Equal(got, want) {
			t.Errorf("%q: %v, want %v", query, got, want)
		}
		if got := getList(t, f.handler, testToken, "?limit=1000"+query).ids(); !slices.Equal(got, want) {
			t.Errorf("%q one page: %v, want %v", query, got, want)
		}
	}
	// A cursor keeps its order and refuses the other one.
	page := getList(t, f.handler, testToken, "?limit=2")
	if !slices.Equal(page.ids(), newest[:2]) || page.NextCursor == "" {
		t.Fatalf("newest page: %+v", page)
	}
	if w := perform(f.handler, "GET", "/v1/jobs?order=oldest&cursor="+page.NextCursor, testToken, "", ""); w.Code != 400 {
		t.Fatalf("newest cursor with order=oldest: %d", w.Code)
	}
	if got := getList(t, f.handler, testToken, "?order=newest&cursor="+page.NextCursor).ids(); !slices.Equal(got, newest[2:]) {
		t.Fatalf("newest cursor: %v", got)
	}
	for _, query := range []string{"state=bogus", "state=", "state=queued,", "state=Queued", "state=queued&state=active", "order=sideways", "order=", "order=newest&order=oldest"} {
		if w := perform(f.handler, "GET", "/v1/jobs?"+query, testToken, "", ""); w.Code != 400 {
			t.Errorf("%s: %d %s", query, w.Code, w.Body.String())
		}
	}
}

// With every lane busy, a queued job's waiting reports the lanes and its
// place in the scheduler's fair order; the job it reports next in line is the
// one the scheduler claims; and a principal limited to its repository sees
// counts only, never another repository's jobs.
func TestWaitingFollowsFairOrderWithoutLeakingOtherRepositories(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	const lanes = 6
	f.options.Status = func(ctx context.Context) (controller.Status, error) {
		s, err := f.db.ServiceState(ctx)
		return controller.Status{Service: s, WorkerReady: true, MaxConcurrentJobs: lanes, Gate: health.GateState{Ready: true, Blockers: []string{}, FreeBytes: 1 << 40}}, err
	}
	h, err := New(f.options)
	if err != nil {
		t.Fatal(err)
	}
	// Another repository's jobs, submitted by a principal that may see them.
	const otherRepo = "example-org/other-app"
	otherSHA := strings.Repeat("c", 40)
	profile := f.options.Profiles.List()[0]
	profile.ID, profile.Repo = "other-build-v1", otherRepo
	otherProfiles, err := profiles.New([]model.Profile{profile}, nil)
	if err != nil {
		t.Fatal(err)
	}
	otherToken := strings.Repeat("y", 64)
	other := principal(otherToken, "other", otherRepo, "jobs:read")
	if err := f.db.ReplacePrincipals(ctx, []controllerconfig.Principal{f.owner, other}); err != nil {
		t.Fatal(err)
	}
	submitOther := func(key string) model.Job {
		t.Helper()
		admission, err := otherProfiles.Resolve(model.Request{Repo: otherRepo, SHA: otherSHA, Kind: profile.Kind, Profile: profile.ID, Xcode: profile.Xcode})
		if err != nil {
			t.Fatal(err)
		}
		job, _, err := f.db.Enqueue(ctx, other.ID, key, admission, testTime)
		if err != nil {
			t.Fatal(err)
		}
		return job
	}
	var claimed []model.Job
	for i := range lanes {
		f.submit(t, "lane-"+string(rune('a'+i)))
		job, err := f.db.Claim(ctx, "epoch", testTime, lanes, false)
		if err != nil {
			t.Fatal(err)
		}
		claimed = append(claimed, job)
	}
	o1 := submitOther("o1")
	a7 := f.submit(t, "a7")
	o2 := submitOther("o2")
	a8 := f.submit(t, "a8")

	waiting := func(token string, job model.Job) map[string]any {
		t.Helper()
		w := perform(h, "GET", "/v1/jobs/"+job.ID, token, "", "")
		if w.Code != 200 {
			t.Fatalf("GET %s: %d %s", job.ID, w.Code, w.Body.String())
		}
		if token == testToken {
			for _, foreign := range []string{o1.ID, o2.ID, otherRepo, otherSHA} {
				if strings.Contains(w.Body.String(), foreign) {
					t.Fatalf("job view leaks %s: %s", foreign, w.Body.String())
				}
			}
		}
		waiting, _ := decodeView(t, w.Body.Bytes())["waiting"].(map[string]any)
		return waiting
	}
	expect := func(token string, job model.Job, reason string, busy, position, ahead int) {
		t.Helper()
		want := map[string]any{"reason": reason, "lanes_busy": float64(busy), "lanes": float64(lanes), "position_in_repository": float64(position), "queued_ahead_overall": float64(ahead)}
		if got := waiting(token, job); !mapsEqual(got, want) {
			t.Fatalf("%s waiting %v, want %v", job.ID, got, want)
		}
	}
	// The other repository has never been claimed, so its jobs go first.
	expect(testToken, a7, "all lanes busy", 6, 1, 2)
	expect(testToken, a8, "all lanes busy", 6, 2, 3)
	expect(otherToken, o1, "all lanes busy", 6, 1, 0)
	expect(otherToken, o2, "all lanes busy", 6, 2, 1)

	// The owner's list and capabilities carry the same counts, never the
	// other repository's jobs.
	for _, path := range []string{"/v1/jobs", "/v1/jobs?state=queued", "/v1/capabilities"} {
		w := perform(h, "GET", path, testToken, "", "")
		for _, foreign := range []string{o1.ID, o2.ID, otherRepo, otherSHA} {
			if w.Code != 200 || strings.Contains(w.Body.String(), foreign) {
				t.Fatalf("%s %d leaks %s: %s", path, w.Code, foreign, w.Body.String())
			}
		}
	}
	page := getList(t, h, testToken, "?state=queued")
	if !slices.Equal(page.ids(), []string{a8.ID, a7.ID}) || page.Items[1].Waiting["queued_ahead_overall"] != float64(2) || page.Items[0].Waiting["position_in_repository"] != float64(2) {
		t.Fatalf("queued list: %+v", page)
	}
	w := perform(h, "GET", "/v1/capabilities", testToken, "", "")
	var capabilities struct {
		LanesBusy int `json:"lanes_busy"`
		Queued    int `json:"queued"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &capabilities); err != nil || capabilities.LanesBusy != 6 || capabilities.Queued != 4 {
		t.Fatalf("capabilities: %s", w.Body.String())
	}

	if _, err := f.db.Pause(ctx, "maintenance", "drain", f.owner.ID, testTime); err != nil {
		t.Fatal(err)
	}
	expect(testToken, a7, "service paused", 6, 1, 2)
	if _, err := f.db.Resume(ctx); err != nil {
		t.Fatal(err)
	}

	// A lane frees: the fair head is next in line, and is what the
	// scheduler claims.
	if err := f.db.FailPreparation(ctx, claimed[0].ID, claimed[0].LeaseToken, model.Interrupted, true, "test", testTime); err != nil {
		t.Fatal(err)
	}
	expect(otherToken, o1, "next in line", 5, 1, 0)
	expect(testToken, a7, "jobs ahead are starting", 5, 1, 2)
	if job, err := f.db.Claim(ctx, "epoch", testTime.Add(time.Second), lanes, false); err != nil || job.ID != o1.ID {
		t.Fatalf("claim: %+v %v", job, err)
	}
	// The other repository was claimed last, so this repository goes first.
	expect(testToken, a7, "all lanes busy", 6, 1, 0)
	expect(testToken, a8, "all lanes busy", 6, 2, 1)
	expect(otherToken, o2, "all lanes busy", 6, 1, 2)
	if err := f.db.FailPreparation(ctx, claimed[1].ID, claimed[1].LeaseToken, model.Interrupted, true, "test", testTime); err != nil {
		t.Fatal(err)
	}
	expect(testToken, a7, "next in line", 5, 1, 0)
	if job, err := f.db.Claim(ctx, "epoch", testTime.Add(2*time.Second), lanes, false); err != nil || job.ID != a7.ID {
		t.Fatalf("claim: %+v %v", job, err)
	}
	if got := waiting(testToken, a7); got != nil {
		t.Fatalf("claimed job still waiting: %v", got)
	}
}

func mapsEqual(a, b map[string]any) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if b[key] != value {
			return false
		}
	}
	return true
}

// Dispatch checks the disk reservation for one more lane (Controller.next)
// before it asks Store.Claim, which checks for an active exclusive job; a
// queued job reports whichever holds it first.
func TestWaitingReportsDiskBeforeActiveExclusiveJob(t *testing.T) {
	heads := &fakeHeads{head: githubapi.BranchHead{RepositoryID: 77, Branch: "main", SHA: strings.Repeat("c", 40)}}
	f, archive := archiveSetup(t, heads, "jobs:submit", "jobs:read", "release:archive")
	var free int64
	f.options.Status = func(ctx context.Context) (controller.Status, error) {
		s, err := f.db.ServiceState(ctx)
		return controller.Status{Service: s, WorkerReady: true, MaxConcurrentJobs: 2, Gate: health.GateState{Ready: true, Blockers: []string{}, FreeBytes: free}}, err
	}
	h, err := New(f.options)
	if err != nil {
		t.Fatal(err)
	}
	f.handler = h
	if code, body := submitArchive(t, f, "archive", archive); code != 202 {
		t.Fatalf("archive: %d %s", code, body)
	}
	if claimed, err := f.db.Claim(context.Background(), "epoch", testTime, 2, false); err != nil || claimed.Request.Kind != model.IOSArchive {
		t.Fatalf("claim: %+v %v", claimed, err)
	}
	build := model.Request{Repo: archive.Repo, SHA: archive.SHA, Kind: model.Build, Profile: "org-build-v1", Xcode: archive.Xcode}
	if code, body := submitArchive(t, f, "build", build); code != 202 {
		t.Fatalf("build: %d %s", code, body)
	}
	queued, err := f.db.Lookup(context.Background(), "releaser", "build")
	if err != nil || queued.State != model.Queued {
		t.Fatalf("queued build: %+v %v", queued, err)
	}
	// A second lane needs the 120 GiB floor and two 30 GiB reservations.
	for gib, want := range map[int64]string{170: "disk budget", 1 << 10: "an exclusive job is running"} {
		free = gib << 30
		w := perform(h, "GET", "/v1/jobs/"+queued.ID, archiveToken, "", "")
		waiting, _ := decodeView(t, w.Body.Bytes())["waiting"].(map[string]any)
		if w.Code != 200 || waiting["reason"] != want || waiting["lanes_busy"] != float64(1) || waiting["lanes"] != float64(2) {
			t.Fatalf("%d GiB free: %d %v, want %q", gib, w.Code, waiting, want)
		}
	}
}

// A principal granted "owner/*" lists that owner's jobs without repo=, as
// it reads them one by one, and no other owner's.
func TestListShowsJobsOfWildcardGrantedRepositories(t *testing.T) {
	heads := &fakeHeads{head: githubapi.BranchHead{RepositoryID: 77, Branch: "main", SHA: strings.Repeat("c", 40)}}
	f, archive := archiveSetup(t, heads, "jobs:submit", "jobs:read")
	// The owner's exact repository, through setup's own profile registry.
	admission, err := setup(t).options.Profiles.Resolve(f.request)
	if err != nil {
		t.Fatal(err)
	}
	foreign, _, err := f.db.Enqueue(context.Background(), f.owner.ID, "foreign", admission, testTime)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, key := range []string{"first", "second"} {
		build := model.Request{Repo: archive.Repo, SHA: archive.SHA, Kind: model.Build, Profile: "org-build-v1", Xcode: archive.Xcode}
		if code, body := submitArchive(t, f, key, build); code != 202 {
			t.Fatalf("build: %d %s", code, body)
		}
		job, err := f.db.Lookup(context.Background(), "releaser", key)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, job.ID)
	}
	if got := getList(t, f.handler, archiveToken, "?order=oldest").ids(); !slices.Equal(got, ids) {
		t.Fatalf("wildcard list: %v, want %v", got, ids)
	}
	if got := getList(t, f.handler, archiveToken, "?repo=themartianapp/app&state=queued").ids(); !slices.Equal(got, []string{ids[1], ids[0]}) {
		t.Fatalf("wildcard list of one repository: %v", got)
	}
	if got := getList(t, f.handler, testToken, "").ids(); !slices.Equal(got, []string{foreign.ID}) {
		t.Fatalf("exact list: %v", got)
	}
}

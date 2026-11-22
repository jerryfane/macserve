package githubpull

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/controllerk/store"
	"github.com/jerryfane/macserve/internal/githubapi"
	"github.com/jerryfane/macserve/internal/githubwire"
	"github.com/jerryfane/macserve/internal/model"
)

// tieredConfig adds herdrup's smoke shard to the matrix fixture's config.
var tieredConfig = strings.Replace(matrixConfig, `"ui_test":{"shards":{`, `"ui_test":{"shards":{"smoke":["HerdrUITests/SmokeTests"],`, 1)

// tieredPolicy is herdrup's tiered policy: a fast smoke shard and the four
// full shards, drafts held back, ready-to-merge as the full-tier label.
func tieredPolicy() githubwire.Policy {
	policy := matrixPolicy()
	policy.MatrixSkipDrafts, policy.MatrixFullLabel = true, "ready-to-merge"
	policy.Matrix = []githubwire.MatrixEntry{{Profile: uiTemplate, Shard: "smoke", Tier: githubwire.TierFast, Simulator: iPhone}}
	for _, entry := range matrixPolicy().Matrix {
		entry.Tier = githubwire.TierFull
		policy.Matrix = append(policy.Matrix, entry)
	}
	return policy
}

const fastSmoke = "mac-evidence/fast/smoke"

var fullChecks = []string{"mac-evidence/full/iphone-terminal", "mac-evidence/full/iphone-app", "mac-evidence/full/ipad", "mac-evidence/full/ipad-script"}

func checkNames(checks map[string]githubapi.Check) []string {
	var names []string
	for name := range checks {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func sorted(names ...string) []string {
	slices.Sort(names)
	return names
}

// A draft head of a tiered policy runs the build and the fast tier; the
// ready-to-merge label adds the full tier under its mac-evidence/full/<shard>
// names; removing the label or the draft state cancels nothing; a new push
// leaves the new head without full checks until it is labelled or ready.
func TestTiersDraftRunsFastAndLabelAddsFull(t *testing.T) {
	f := newMatrixFixture(t, tieredPolicy())
	pull := matrixPull(1, headSHA('1'))
	pull.Draft = true
	f.pull(matrixRepo, pull, tieredConfig)
	f.poll(t)
	build := "mac-evidence/org-build-v1"
	base := sorted(build, fastSmoke)
	runs, checks := f.runsByCheck(t, headSHA('1')), f.checksOf(headSHA('1'))
	if !slices.Equal(checkNames(checks), base) || runs[fastSmoke].JobID == "" || runs[build].JobID == "" {
		t.Fatalf("draft head: checks %v runs %v", checkNames(checks), runs)
	}
	if job := f.job(t, runs[fastSmoke].JobID); job.Request.Shard != "smoke" || *job.Request.Simulator != iPhone {
		t.Fatalf("smoke job request %+v", job.Request)
	}

	f.setPull(matrixRepo, func(p *githubapi.PullRequest) { p.Labels = []string{"ui", "Ready-To-Merge"} })
	f.poll(t)
	labelled := f.runsByCheck(t, headSHA('1'))
	all := sorted(append(slices.Clone(base), fullChecks...)...)
	if !slices.Equal(checkNames(f.checksOf(headSHA('1'))), all) || labelled[fastSmoke].JobID != runs[fastSmoke].JobID {
		t.Fatalf("labelled head: checks %v", checkNames(f.checksOf(headSHA('1'))))
	}
	for _, name := range fullChecks {
		if labelled[name].JobID == "" {
			t.Fatalf("%s not admitted: %+v", name, labelled[name])
		}
	}

	f.setPull(matrixRepo, func(p *githubapi.PullRequest) { p.Labels = nil })
	f.poll(t)
	f.poll(t)
	for _, name := range fullChecks {
		if job := f.job(t, labelled[name].JobID); job.State != model.Queued {
			t.Fatalf("%s: unlabelled job %s", name, job.State)
		}
	}
	if active := f.active(t, matrixRepoID); len(active) != 6 {
		t.Fatalf("active runs after removing the label: %v", active)
	}

	f.setPull(matrixRepo, func(p *githubapi.PullRequest) { p.HeadSHA = headSHA('2') })
	f.remote.mu.Lock()
	f.remote.files[matrixRepo+"@"+headSHA('2')] = tieredConfig
	f.remote.mu.Unlock()
	f.poll(t)
	if got := checkNames(f.checksOf(headSHA('2'))); !slices.Equal(got, base) {
		t.Fatalf("new draft head: checks %v", got)
	}
	f.setPull(matrixRepo, func(p *githubapi.PullRequest) { p.Draft = false })
	f.poll(t)
	if got := checkNames(f.checksOf(headSHA('2'))); !slices.Equal(got, all) {
		t.Fatalf("ready head: checks %v", got)
	}
}

// An untiered policy with matrix_skip_drafts still holds its whole matrix
// back on a draft, whatever labels it has.
func TestUntieredDraftIgnoresLabels(t *testing.T) {
	policy := matrixPolicy()
	policy.MatrixSkipDrafts = true
	f := newMatrixFixture(t, policy)
	pull := matrixPull(1, headSHA('1'))
	pull.Draft, pull.Labels = true, []string{"ready-to-merge"}
	f.pull(matrixRepo, pull, matrixConfig)
	f.poll(t)
	if got := checkNames(f.checksOf(headSHA('1'))); !slices.Equal(got, []string{"mac-evidence/org-build-v1"}) {
		t.Fatalf("draft head: checks %v", got)
	}
}

// The owner rerun follows the tier triggers: a fast run of a draft head
// reruns, a full run gets no attempt until the head is labelled, and the
// reply names the tiered check.
func TestTiersOwnerRerunFollowsTriggers(t *testing.T) {
	ctx := context.Background()
	f := newMatrixFixture(t, tieredPolicy())
	pull := matrixPull(1, headSHA('1'))
	pull.Labels = []string{"ready-to-merge"}
	pull.Draft = true
	f.pull(matrixRepo, pull, tieredConfig)
	f.poll(t)
	runs := f.runsByCheck(t, headSHA('1'))
	for _, name := range []string{fastSmoke, "mac-evidence/full/ipad"} {
		if _, err := f.s.Cancel(ctx, runs[name].JobID, "client", model.CancelReason{Source: model.CancelGitHub}, f.options.Now()); err != nil {
			t.Fatal(err)
		}
	}
	f.setPull(matrixRepo, func(p *githubapi.PullRequest) { p.Labels = nil })
	f.poll(t)
	if _, started, err := f.p.Rerun(ctx, matrixRepoID, "", headSHA('1'), uiTemplate, "ipad", f.options.Now()); !errors.Is(err, ErrIneligible) || started {
		t.Fatalf("full rerun of an unlabelled draft: %v %v", started, err)
	}
	run, started, err := f.p.Rerun(ctx, matrixRepoID, "", headSHA('1'), uiTemplate, "smoke", f.options.Now())
	if err != nil || !started || f.p.CheckName(run) != fastSmoke {
		t.Fatalf("fast rerun of a draft: %+v %v %v", run, started, err)
	}
	f.setPull(matrixRepo, func(p *githubapi.PullRequest) { p.Labels = []string{"ready-to-merge"} })
	f.poll(t)
	run, started, err = f.p.Rerun(ctx, matrixRepoID, "", headSHA('1'), uiTemplate, "ipad", f.options.Now())
	if err != nil || !started || f.p.CheckName(run) != "mac-evidence/full/ipad" {
		t.Fatalf("full rerun of a labelled draft: %+v %v %v", run, started, err)
	}
}

// tierQueue polls the tiered policy's pull requests 1..n in turn, one poll
// each: pull 1 ready for review (its build, its smoke and its four full
// shards queue), every later one a draft (its build and its smoke).
func (f *ownerFixture) tierQueue(t *testing.T, from, to int) {
	t.Helper()
	for n := from; n <= to; n++ {
		pull := matrixPull(n, headSHA(byte('0'+n)))
		pull.Draft = n > 1
		f.pull(matrixRepo, pull, tieredConfig)
		f.poll(t)
	}
}

// apiJob submits a private API build of the matrix repository, as a
// principal of the API would: no GitHub run.
func (f *ownerFixture) apiJob(t *testing.T) model.Job {
	t.Helper()
	admission, err := f.p.admission(tieredPolicy(), matrixPull(9, headSHA('9')), nativeBuild, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	job, _, err := f.s.Enqueue(context.Background(), "api", "api-build", admission.Admission, f.options.Now())
	if err != nil {
		t.Fatal(err)
	}
	return job
}

// claimAll claims and ends every queued job one at a time and names each
// in claim order: "<pull>:<check without mac-evidence/>" for the runs of
// pulls 1..pulls, "api" for the API job api.
func (f *ownerFixture) claimAll(t *testing.T, pulls int, api string) []string {
	t.Helper()
	ctx := context.Background()
	labels := map[string]string{api: "api"}
	for n := 1; n <= pulls; n++ {
		for check, run := range f.runsByCheck(t, headSHA(byte('0'+n))) {
			labels[run.JobID] = fmt.Sprintf("%d:%s", n, strings.TrimPrefix(check, "mac-evidence/"))
		}
	}
	var order []string
	for {
		job, err := f.s.Claim(ctx, "worker-epoch", f.options.Now(), 1, false)
		if errors.Is(err, store.ErrNoJob) {
			return order
		}
		if err != nil {
			t.Fatal(err)
		}
		order = append(order, labels[job.ID])
		if err = f.s.Transition(ctx, job.ID, job.LeaseToken, model.Preparing, model.Finalizing, "test execution finished", f.options.Now()); err != nil {
			t.Fatal(err)
		}
		if err = f.s.Finish(ctx, job.ID, job.LeaseToken, model.Succeeded, json.RawMessage(`{"exit_code":0}`), true, "test terminal", f.options.Now()); err != nil {
			t.Fatal(err)
		}
	}
}

// A draft push's build and fast smoke shard are claimed ahead of another
// pull request's full-tier shards queued before them (#193); each tier
// keeps submission order.
func TestTiersClaimFastAheadOfQueuedFull(t *testing.T) {
	f := newMatrixFixture(t, tieredPolicy())
	f.tierQueue(t, 1, 2)
	want := []string{"1:org-build-v1", "1:fast/smoke", "2:org-build-v1", "2:fast/smoke",
		"1:full/iphone-terminal", "1:full/iphone-app", "1:full/ipad", "1:full/ipad-script"}
	if got := f.claimAll(t, 2, ""); !slices.Equal(got, want) {
		t.Fatalf("claim order\n got %v\nwant %v", got, want)
	}
}

// Fast-tier jobs pass a waiting full-tier shard at most
// store.MaxTierPasses times; then the oldest full shard is claimed and
// the count starts afresh.
func TestTiersBoundFastPassesOfAFullShard(t *testing.T) {
	f := newMatrixFixture(t, tieredPolicy())
	f.tierQueue(t, 1, 3)
	want := []string{"1:org-build-v1", "1:fast/smoke", "2:org-build-v1", "2:fast/smoke", "3:org-build-v1",
		"1:full/iphone-terminal", "3:fast/smoke", "1:full/iphone-app", "1:full/ipad", "1:full/ipad-script"}
	if got := f.claimAll(t, 3, ""); !slices.Equal(got, want) {
		t.Fatalf("claim order\n got %v\nwant %v", got, want)
	}
}

// An API job keeps its place relative to every job: tiered jobs queued
// after it do not pass it, nor do those before it move behind it.
func TestTiersLeaveAPIJobsInPlace(t *testing.T) {
	f := newMatrixFixture(t, tieredPolicy())
	f.tierQueue(t, 1, 2)
	api := f.apiJob(t)
	f.tierQueue(t, 3, 3)
	want := []string{"1:org-build-v1", "1:fast/smoke", "2:org-build-v1", "2:fast/smoke",
		"1:full/iphone-terminal", "1:full/iphone-app", "1:full/ipad", "1:full/ipad-script", "api", "3:org-build-v1", "3:fast/smoke"}
	if got := f.claimAll(t, 3, api.ID); !slices.Equal(got, want) {
		t.Fatalf("claim order\n got %v\nwant %v", got, want)
	}
}

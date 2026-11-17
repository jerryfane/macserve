package githubpull

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

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

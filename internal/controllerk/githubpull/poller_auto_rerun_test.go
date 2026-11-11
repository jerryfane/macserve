package githubpull

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/controllerk/store"
	"github.com/jerryfane/macserve/internal/githubapi"
	"github.com/jerryfane/macserve/internal/model"
)

// #119: in pull mode (owner policies read no comments) a head whose attempt
// the service cancelled gets one new attempt on the next poll, published to
// the same check; the owner API's requested rerun starts one more after a
// terminal attempt, bounded at two per hour.
func TestOwnerPullModeRerunsServiceCancelledHeadOnSameCheck(t *testing.T) {
	ctx := context.Background()
	f, err := newOwnerFixture(t, ownerPolicy("themartianapp", martianID))
	if err != nil {
		t.Fatal(err)
	}
	const app = "themartianapp/app"
	f.remote.install(app, 501, martianID, "themartianapp")
	f.pull(app, githubapi.PullRequest{Number: 1, HeadSHA: headSHA('1'), HeadRepositoryID: 501, AuthorID: ownerAuthor, BaseRef: "main"}, nativeConfig)
	f.poll(t)
	runs := f.active(t, 501)
	if len(runs) != 1 || runs[0].CheckID == 0 {
		t.Fatalf("runs = %+v", runs)
	}
	first := runs[0]
	if _, err := f.s.Cancel(ctx, first.JobID, "host not ready", model.CancelReason{Source: model.CancelHostReadiness, Blockers: []string{"disk"}}, f.options.Now()); err != nil {
		t.Fatal(err)
	}
	f.poll(t) // publishes the cancellation, then the next poll admits the rerun
	f.poll(t)
	runs = f.active(t, 501)
	if len(runs) != 1 || runs[0].JobID == first.JobID || runs[0].CheckID != first.CheckID || runs[0].Key != first.Key {
		t.Fatalf("service-cancelled head not rerun on the same check: %+v (first %+v)", runs, first)
	}
	f.remote.mu.Lock()
	check := f.remote.checks[first.CheckID]
	checks := len(f.remote.checks)
	f.remote.mu.Unlock()
	if checks != 1 || check.Name != "mac-evidence/"+nativeBuild || check.ExternalID != runs[0].JobID || check.Status != "queued" {
		t.Fatalf("check = %+v (%d checks)", check, checks)
	}

	// Owner API rerun: refused while the attempt is active, then one new
	// attempt after a terminal one, bounded at two per hour.
	rerun := func() (store.GitHubRun, bool, error) {
		return f.p.Rerun(ctx, 0, app, headSHA('1'), nativeBuild, f.options.Now())
	}
	if run, started, err := rerun(); err != nil || started || run.JobID != runs[0].JobID {
		t.Fatalf("rerun of a queued attempt: %+v %v %v", run, started, err)
	}
	current := runs[0].JobID
	for i := range 2 {
		if _, err := f.s.Cancel(ctx, current, "client", model.CancelReason{Source: model.CancelGitHub}, f.options.Now()); err != nil {
			t.Fatal(err)
		}
		run, started, err := rerun()
		if err != nil || !started || run.JobID == current || run.CheckID != first.CheckID {
			t.Fatalf("owner rerun %d: %+v %v %v", i+1, run, started, err)
		}
		current = run.JobID
		f.poll(t)
	}
	if _, err := f.s.Cancel(ctx, current, "client", model.CancelReason{Source: model.CancelGitHub}, f.options.Now()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := rerun(); !errors.Is(err, store.ErrRerunLimit) {
		t.Fatalf("third owner rerun within the hour: %v", err)
	}
	f.remote.mu.Lock()
	f.remote.now = f.remote.now.Add(time.Hour + time.Second)
	f.remote.mu.Unlock()
	if _, started, err := f.p.Rerun(ctx, 501, "", headSHA('1'), nativeBuild, f.options.Now()); err != nil || !started {
		t.Fatalf("owner rerun by repository ID after the hour: %v %v", started, err)
	}
	if _, _, err := rerun(); err != nil {
		t.Fatalf("rerun of the queued attempt: %v", err)
	}
	if _, _, err := f.p.Rerun(ctx, 0, app, headSHA('2'), nativeBuild, f.options.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown head: %v", err)
	}
	// A head no longer open is not rerun.
	f.remote.mu.Lock()
	f.remote.pulls[app][0].State = "closed"
	f.remote.mu.Unlock()
	if _, _, err := rerun(); !errors.Is(err, ErrIneligible) {
		t.Fatalf("closed pull request: %v", err)
	}
}

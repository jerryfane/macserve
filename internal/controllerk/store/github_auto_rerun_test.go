package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
)

// cancelQueued cancels the run's queued current attempt for cause.
func cancelQueued(t *testing.T, s *Store, run GitHubRun, cause model.CancelReason, now time.Time) {
	t.Helper()
	job, err := s.Cancel(context.Background(), run.JobID, "cancelled", cause, now)
	if err != nil || job.State != model.Cancelled {
		t.Fatalf("cancel: %+v %v", job, err)
	}
}

// #119: pull mode's ensure admission starts one new attempt when the latest
// attempt was ended by the service or an operator, never when GitHub
// superseded it, its own principal cancelled it or its own budget ended it.
func TestGitHubEnsureRerunsOnlyServiceCancelledAttempts(t *testing.T) {
	for name, tc := range map[string]struct {
		cause model.CancelReason
		rerun bool
	}{
		"host readiness":       {model.CancelReason{Source: model.CancelHostReadiness, Blockers: []string{"disk"}}, true},
		"gate error":           {model.CancelReason{Source: model.CancelGateError}, true},
		"controller shutdown":  {model.CancelReason{Source: model.CancelShutdown}, true},
		"admin pause":          {model.CancelReason{Source: model.CancelAdminPause, Principal: "owner"}, true},
		"operator cancel":      {model.CancelReason{Source: model.CancelClient, Principal: "owner"}, true},
		"github supersede":     {model.CancelReason{Source: model.CancelGitHub, Detail: "superseded"}, false},
		"own principal cancel": {model.CancelReason{Source: model.CancelClient, Principal: "github:123"}, false},
		"deadline":             {model.CancelReason{Source: model.CancelDeadline}, false},
		"log limit":            {model.CancelReason{Source: model.CancelLogLimit}, false},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s, _ := githubStore(t)
			first, err := s.AdmitGitHub(ctx, githubFixture(), testNow)
			if err != nil {
				t.Fatal(err)
			}
			cancelQueued(t, s, first, tc.cause, testNow)
			// The cancellation's own publication completes first.
			publication, err := s.NextGitHubPublication(ctx, testNow)
			if err != nil {
				t.Fatal(err)
			}
			if err = s.FinishGitHubPublication(ctx, publication, 71, time.Time{}); err != nil {
				t.Fatal(err)
			}
			run, err := s.AdmitGitHub(ctx, githubFixture(), testNow.Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			if (run.JobID != first.JobID) != tc.rerun {
				t.Fatalf("rerun = %v, want %v (%+v)", run.JobID != first.JobID, tc.rerun, run)
			}
			if !tc.rerun {
				return
			}
			// One new attempt, queued, published to the same run and check.
			job := getJob(t, s, run.JobID)
			if job.State != model.Queued || run.AttemptID == first.AttemptID || run.CheckID != 71 || run.Key != first.Key {
				t.Fatalf("automatic rerun %+v job %+v", run, job)
			}
			publication, err = s.NextGitHubPublication(ctx, testNow.Add(time.Minute))
			if err != nil || publication.Run.JobID != run.JobID || publication.Run.CheckID != 71 {
				t.Fatalf("automatic rerun not published: %+v %v", publication, err)
			}
			// The old attempt keeps its own provenance.
			if old, err := s.GitHubByJob(ctx, first.JobID); err != nil || old.AttemptID != first.AttemptID {
				t.Fatalf("old attempt rewritten: %+v %v", old, err)
			}
			joined, err := s.AdmitGitHub(ctx, githubFixture(), testNow.Add(2*time.Minute))
			if err != nil || joined.JobID != run.JobID {
				t.Fatalf("ensure duplicated the automatic rerun: %+v %v", joined, err)
			}
		})
	}
}

// An interrupted attempt whose cancel reason is the controller's shutdown is
// rerun; one interrupted without a cancel request (a lost worker) or that
// failed is not.
func TestGitHubEnsureRerunsShutdownInterruptedAttempt(t *testing.T) {
	for name, tc := range map[string]struct {
		end   func(t *testing.T, s *Store, job model.Job)
		rerun bool
	}{
		"shutdown": {func(t *testing.T, s *Store, job model.Job) {
			if _, err := s.Cancel(context.Background(), job.ID, "controller shutdown", model.CancelReason{Source: model.CancelShutdown}, testNow); err != nil {
				t.Fatal(err)
			}
			if err := s.Fail(context.Background(), job.ID, job.LeaseToken, model.Interrupted, false, "controller shutdown", testNow); err != nil {
				t.Fatal(err)
			}
		}, true},
		"lost worker": {func(t *testing.T, s *Store, job model.Job) {
			if err := s.Fail(context.Background(), job.ID, job.LeaseToken, model.Interrupted, false, "worker heartbeat lost", testNow); err != nil {
				t.Fatal(err)
			}
		}, false},
		"failed": {func(t *testing.T, s *Store, job model.Job) { finishJob(t, s, job, model.Failed, true, testNow) }, false},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s, _ := githubStore(t)
			first, err := s.AdmitGitHub(ctx, githubFixture(), testNow)
			if err != nil {
				t.Fatal(err)
			}
			tc.end(t, s, claimJob(t, s, "epoch", testNow))
			run, err := s.AdmitGitHub(ctx, githubFixture(), testNow.Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			if (run.JobID != first.JobID) != tc.rerun {
				t.Fatalf("rerun = %v, want %v (job %+v)", run.JobID != first.JobID, tc.rerun, getJob(t, s, first.JobID))
			}
		})
	}
}

// Automatic reruns are bounded at two per run in any hour, independently of
// requested reruns; over the bound the cancelled attempt stays current and
// ensure does not fail. An operator's cancel of an automatic rerun keeps the
// head cancelled.
func TestGitHubAutomaticRerunBounds(t *testing.T) {
	ctx := context.Background()
	s, _ := githubStore(t)
	run, err := s.AdmitGitHub(ctx, githubFixture(), testNow)
	if err != nil {
		t.Fatal(err)
	}
	readiness := model.CancelReason{Source: model.CancelHostReadiness}
	jobs := map[string]bool{run.JobID: true}
	for i := range 2 {
		cancelQueued(t, s, run, readiness, testNow)
		if run, err = s.AdmitGitHub(ctx, githubFixture(), testNow.Add(time.Duration(i)*time.Minute)); err != nil || jobs[run.JobID] {
			t.Fatalf("automatic rerun %d: %+v %v", i+1, run, err)
		}
		jobs[run.JobID] = true
	}
	cancelQueued(t, s, run, readiness, testNow)
	third, err := s.AdmitGitHub(ctx, githubFixture(), testNow.Add(30*time.Minute))
	if err != nil || third.JobID != run.JobID {
		t.Fatalf("third automatic rerun within the hour: %+v %v", third, err)
	}
	// A requested rerun has its own bound.
	requested := githubFixture()
	requested.Mode = "rerun"
	if run, err = s.AdmitGitHub(ctx, requested, testNow.Add(30*time.Minute)); err != nil || jobs[run.JobID] {
		t.Fatalf("requested rerun after the automatic bound: %+v %v", run, err)
	}
	jobs[run.JobID] = true
	cancelQueued(t, s, run, readiness, testNow.Add(30*time.Minute))
	if again, err := s.AdmitGitHub(ctx, githubFixture(), testNow.Add(59*time.Minute)); err != nil || again.JobID != run.JobID {
		t.Fatalf("automatic bound reset by a requested rerun: %+v %v", again, err)
	}
	// The window reopens an hour after the first automatic rerun.
	if run, err = s.AdmitGitHub(ctx, githubFixture(), testNow.Add(time.Hour+time.Second)); err != nil || jobs[run.JobID] {
		t.Fatalf("automatic rerun window never reopened: %+v %v", run, err)
	}
	// The operator cancels the automatic rerun: the head stays cancelled.
	cancelQueued(t, s, run, model.CancelReason{Source: model.CancelClient, Principal: "owner"}, testNow.Add(time.Hour+time.Second))
	if kept, err := s.AdmitGitHub(ctx, githubFixture(), testNow.Add(3*time.Hour)); err != nil || kept.JobID != run.JobID {
		t.Fatalf("operator-cancelled automatic rerun was rerun: %+v %v", kept, err)
	}
	var automatic int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM github_attempts WHERE rerun=2").Scan(&automatic); err != nil || automatic != 3 {
		t.Fatalf("automatic attempts = %d %v", automatic, err)
	}
}

// A publication in flight defers the automatic rerun to a later poll without
// failing ensure.
func TestGitHubAutomaticRerunWaitsForPublication(t *testing.T) {
	ctx := context.Background()
	s, _ := githubStore(t)
	first, err := s.AdmitGitHub(ctx, githubFixture(), testNow)
	if err != nil {
		t.Fatal(err)
	}
	cancelQueued(t, s, first, model.CancelReason{Source: model.CancelShutdown}, testNow)
	publication, err := s.NextGitHubPublication(ctx, testNow)
	if err != nil {
		t.Fatal(err)
	}
	run, err := s.AdmitGitHub(ctx, githubFixture(), testNow)
	if err != nil || run.JobID != first.JobID {
		t.Fatalf("automatic rerun replaced an in-flight publication: %+v %v", run, err)
	}
	if err = s.FinishGitHubPublication(ctx, publication, 5, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if run, err = s.AdmitGitHub(ctx, githubFixture(), testNow); err != nil || run.JobID == first.JobID {
		t.Fatalf("automatic rerun after publication: %+v %v", run, err)
	}
}

func TestGitHubRunsByHead(t *testing.T) {
	ctx := context.Background()
	s, _ := githubStore(t)
	input := githubFixture()
	run, err := s.AdmitGitHub(ctx, input, testNow)
	if err != nil {
		t.Fatal(err)
	}
	for _, by := range []struct {
		id   int64
		name string
	}{{123, ""}, {0, input.Run.Repository}, {123, input.Run.Repository}} {
		runs, err := s.GitHubRunsByHead(ctx, by.id, by.name, input.Run.SHA, input.Run.Profile, "")
		if err != nil || len(runs) != 1 || runs[0].Key != run.Key || runs[0].JobID != run.JobID || len(runs[0].PullRequests) != 1 || runs[0].PullRequests[0] != 7 {
			t.Fatalf("by %v: %+v %v", by, runs, err)
		}
	}
	for _, by := range []struct {
		id   int64
		name string
	}{{124, ""}, {0, "other/repo"}, {123, "other/repo"}} {
		if runs, err := s.GitHubRunsByHead(ctx, by.id, by.name, input.Run.SHA, input.Run.Profile, ""); err != nil || len(runs) != 0 {
			t.Fatalf("by %v: %+v %v", by, runs, err)
		}
	}
	if _, err := s.GitHubRunsByHead(ctx, 0, "", input.Run.SHA, input.Run.Profile, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unnamed repository: %v", err)
	}
}

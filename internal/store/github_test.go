package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
)

func githubFixture() GitHubAdmission {
	a := admissionFixture()
	a.Request.Context.PullRequest = 7
	return GitHubAdmission{Run: GitHubRun{Key: strings.Repeat("b", 64), RepositoryID: 123, Repository: a.Request.Repo, SHA: a.Request.SHA, Profile: a.Request.Profile, PolicyRevision: 1}, Admission: a, PullRequest: 7, Mode: "ensure"}
}
func githubStore(t *testing.T) (*Store, string) {
	t.Helper()
	s, path := newStore(t, Options{})
	if err := s.InitializeGitHub(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s, path
}

func TestGitHubAdmissionRollbackNeverExposesUnlinkedJob(t *testing.T) {
	ctx := context.Background()
	s, path := githubStore(t)
	if _, err := s.db.ExecContext(ctx, `CREATE TRIGGER reject_attempt BEFORE INSERT ON github_attempts BEGIN SELECT RAISE(ABORT,'injected crash boundary'); END;`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AdmitGitHub(ctx, githubFixture(), testNow); err == nil {
		t.Fatal("injected provenance failure admitted work")
	}
	other := openStore(t, path, Options{})
	if _, err := other.Claim(ctx, "epoch", testNow); !errors.Is(err, ErrNoJob) {
		t.Fatalf("partial admission became claimable: %v", err)
	}
	var count int
	if err := other.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM github_runs").Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial logical run count=%d err=%v", count, err)
	}
	if _, err := s.db.ExecContext(ctx, "DROP TRIGGER reject_attempt"); err != nil {
		t.Fatal(err)
	}
	run, err := s.AdmitGitHub(ctx, githubFixture(), testNow)
	if err != nil {
		t.Fatal(err)
	}
	job, err := other.Claim(ctx, "epoch", testNow)
	if err != nil {
		t.Fatal(err)
	}
	provenance, err := other.GitHubByJob(ctx, job.ID)
	if err != nil || provenance.AttemptID != run.AttemptID || provenance.JobID != job.ID || provenance.RepositoryID != 123 {
		t.Fatalf("claim lacked durable provenance: %+v %v", provenance, err)
	}
	publication, err := other.NextGitHubPublication(ctx, testNow)
	if err != nil || publication.Run.JobID != job.ID {
		t.Fatalf("claim lacked durable outbox: %+v %v", publication, err)
	}
}

func TestGitHubConcurrentEnsureAndImmutableCommentsSurviveReopen(t *testing.T) {
	ctx := context.Background()
	s, path := githubStore(t)
	other := openStore(t, path, Options{})
	start := make(chan struct{})
	results := make(chan GitHubRun, 2)
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for i, handle := range []*Store{s, other} {
		wg.Add(1)
		go func(i int, handle *Store) {
			defer wg.Done()
			<-start
			input := githubFixture()
			input.Request = &GitHubRequest{CommentID: int64(i + 1), RequestID: fmt.Sprintf("actions:8:%d", i+1), BodySHA256: strings.Repeat("c", 64)}
			run, err := handle.AdmitGitHub(ctx, input, testNow)
			results <- run
			errs <- err
		}(i, handle)
	}
	close(start)
	wg.Wait()
	a, b := <-results, <-results
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if a.JobID != b.JobID || a.AttemptID != b.AttemptID {
		t.Fatalf("concurrent ensure duplicated execution: %+v %+v", a, b)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openStore(t, path, Options{})
	requests, err := reopened.GitHubRequests(ctx, a.JobID)
	if err != nil || len(requests) != 2 {
		t.Fatalf("lost request audit trail: %+v %v", requests, err)
	}
	input := githubFixture()
	input.Request = &requests[0]
	input.Request.BodySHA256 = strings.Repeat("d", 64)
	if _, err = reopened.AdmitGitHub(ctx, input, testNow); !errors.Is(err, ErrConflict) {
		t.Fatalf("edited immutable comment accepted: %v", err)
	}
}

func TestGitHubRerunPublicationFenceAndHourlyLimit(t *testing.T) {
	ctx := context.Background()
	s, _ := githubStore(t)
	input := githubFixture()
	first, err := s.AdmitGitHub(ctx, input, testNow)
	if err != nil {
		t.Fatal(err)
	}
	job := claimJob(t, s, "epoch", testNow)
	finishJob(t, s, job, model.Failed, true, testNow)
	publication, err := s.NextGitHubPublication(ctx, testNow)
	if err != nil {
		t.Fatal(err)
	}
	input.Mode = "rerun"
	input.Request = &GitHubRequest{CommentID: 1, RequestID: "actions:9:1", BodySHA256: strings.Repeat("e", 64)}
	if _, err = s.AdmitGitHub(ctx, input, testNow); !errors.Is(err, ErrFull) {
		t.Fatalf("rerun replaced an in-flight publication: %v", err)
	}
	if err = s.FinishGitHubPublication(ctx, publication, 71, time.Time{}); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 2; i++ {
		input.Request = &GitHubRequest{CommentID: int64(i), RequestID: fmt.Sprintf("actions:9:%d", i), BodySHA256: strings.Repeat("e", 64)}
		run, err := s.AdmitGitHub(ctx, input, testNow)
		if err != nil {
			t.Fatal(err)
		}
		if run.JobID == first.JobID || run.CheckID != 71 {
			t.Fatalf("rerun identity/check mismatch: %+v", run)
		}
		joined, err := s.AdmitGitHub(ctx, input, testNow)
		if err != nil || joined.JobID != run.JobID {
			t.Fatalf("request replay forked rerun: %+v %v", joined, err)
		}
		input.Request = &GitHubRequest{CommentID: int64(10 + i), RequestID: fmt.Sprintf("actions:10:%d", i), BodySHA256: strings.Repeat("e", 64)}
		joined, err = s.AdmitGitHub(ctx, input, testNow)
		if err != nil || joined.JobID != run.JobID {
			t.Fatalf("active rerun was duplicated: %+v %v", joined, err)
		}
		job = claimJob(t, s, "epoch", testNow)
		finishJob(t, s, job, model.Failed, true, testNow)
	}
	input.Request = &GitHubRequest{CommentID: 30, RequestID: "actions:9:3", BodySHA256: strings.Repeat("f", 64)}
	if _, err = s.AdmitGitHub(ctx, input, testNow); !errors.Is(err, ErrRerunLimit) {
		t.Fatalf("third hourly rerun admitted: %v", err)
	}
	if _, err = s.AdmitGitHub(ctx, input, testNow.Add(time.Hour)); err != nil {
		t.Fatalf("rerun window never reopened: %v", err)
	}
	provenance, err := s.GitHubByJob(ctx, first.JobID)
	if err != nil || provenance.AttemptID != first.AttemptID {
		t.Fatalf("rerun rewrote old approval: %+v %v", provenance, err)
	}
}

func TestGitHubOutboxGenerationAndCrashLease(t *testing.T) {
	ctx := context.Background()
	s, path := githubStore(t)
	run, err := s.AdmitGitHub(ctx, githubFixture(), testNow)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := s.NextGitHubPublication(ctx, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Cancel(ctx, run.JobID, "superseded", testNow); err != nil {
		t.Fatal(err)
	}
	if err = s.FinishGitHubPublication(ctx, publication, 90, time.Time{}); err != nil {
		t.Fatal(err)
	}
	newer, err := s.NextGitHubPublication(ctx, testNow)
	if err != nil || newer.Generation <= publication.Generation {
		t.Fatalf("completion update was lost behind outbox ack: %+v %v", newer, err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openStore(t, path, Options{})
	if _, err = reopened.NextGitHubPublication(ctx, testNow); !errors.Is(err, ErrNotFound) {
		t.Fatalf("live publication lease duplicated: %v", err)
	}
	recovered, err := reopened.NextGitHubPublication(ctx, testNow.Add(10*time.Minute))
	if err != nil || recovered.Run.JobID != run.JobID || recovered.Run.CheckID != 90 {
		t.Fatalf("crashed outbox reservation did not recover: %+v %v", recovered, err)
	}
	if err = reopened.FinishGitHubPublication(ctx, newer, 91, time.Time{}); !errors.Is(err, ErrLease) {
		t.Fatalf("old publisher overwrote recovered owner: %v", err)
	}
}

func TestGitHubCorrelationBoundDoesNotDiscardAcceptedRequests(t *testing.T) {
	ctx := context.Background()
	s, _ := githubStore(t)
	input := githubFixture()
	var run GitHubRun
	for i := 1; i <= 128; i++ {
		input.Request = &GitHubRequest{CommentID: int64(i), RequestID: fmt.Sprintf("actions:42:%d", i), BodySHA256: strings.Repeat("a", 64)}
		var err error
		run, err = s.AdmitGitHub(ctx, input, testNow)
		if err != nil {
			t.Fatal(err)
		}
	}
	input.Request = &GitHubRequest{CommentID: 129, RequestID: "actions:42:129", BodySHA256: strings.Repeat("a", 64)}
	if _, err := s.AdmitGitHub(ctx, input, testNow); !errors.Is(err, ErrCorrelationLimit) {
		t.Fatalf("excess correlation admitted: %v", err)
	}
	requests, err := s.GitHubRequests(ctx, run.JobID)
	if err != nil || len(requests) != 128 || requests[0].CommentID != 1 || requests[127].CommentID != 128 {
		t.Fatalf("accepted correlations discarded: %+v %v", requests, err)
	}
}

func TestGitHubPublicationRetryDeadlineSurvivesUpdatesAndReopen(t *testing.T) {
	ctx := context.Background()
	s, path := githubStore(t)
	input := githubFixture()
	run, err := s.AdmitGitHub(ctx, input, testNow)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := s.NextGitHubPublication(ctx, testNow)
	if err != nil {
		t.Fatal(err)
	}
	retry := testNow.Add(time.Hour)
	if err = s.FinishGitHubPublication(ctx, publication, 0, retry); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Cancel(ctx, run.JobID, "superseded", testNow); err != nil {
		t.Fatal(err)
	}
	input.Request = &GitHubRequest{CommentID: 1, RequestID: "actions:42:1", BodySHA256: strings.Repeat("a", 64)}
	if _, err = s.AdmitGitHub(ctx, input, testNow); err != nil {
		t.Fatal(err)
	}
	if err = s.ReconcileGitHubPublications(ctx, 123); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openStore(t, path, Options{})
	if _, err = reopened.NextGitHubPublication(ctx, retry.Add(-time.Second)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("updates discarded durable retry deadline: %v", err)
	}
	next, err := reopened.NextGitHubPublication(ctx, retry)
	if err != nil || next.Run.JobID != run.JobID || next.Generation <= publication.Generation {
		t.Fatalf("retry lost new terminal/correlation generation: %+v %v", next, err)
	}
}

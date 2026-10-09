package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
)

func TestGitHubCurrentReconciliationRetiresHistoryWithoutLosingProvenance(t *testing.T) {
	ctx := context.Background()
	s, _ := githubStore(t)
	input := githubFixture()
	input.Request = &GitHubRequest{CommentID: 1, RequestID: "actions:1:1", BodySHA256: fmt.Sprintf("%064x", 1)}
	current, err := s.AdmitGitHub(ctx, input, testNow)
	if err != nil {
		t.Fatal(err)
	}
	job := claimJob(t, s, "epoch", testNow)
	finishJob(t, s, job, model.Failed, true, testNow)
	publication, err := s.NextGitHubPublication(ctx, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.FinishGitHubPublication(ctx, publication, 71, time.Time{}); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 200; i++ {
		run := input.Run
		run.Key, run.SHA = fmt.Sprintf("%064x", i), fmt.Sprintf("%040x", i)
		if err = s.BlockGitHub(ctx, run, "fork", testNow); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.MaintainGitHub(ctx, 123, map[string]bool{current.Key: true}, testNow); err != nil {
		t.Fatal(err)
	}
	if err = s.ReconcileGitHubPublications(ctx, 123); err != nil {
		t.Fatal(err)
	}
	repair, err := s.NextGitHubPublication(ctx, testNow)
	if err != nil || repair.Run.Key != current.Key || repair.Run.CheckID != 71 {
		t.Fatalf("current terminal check was not reconciled: %+v %v", repair, err)
	}
	if err = s.FinishGitHubPublication(ctx, repair, 72, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.NextGitHubPublication(ctx, testNow); !errors.Is(err, ErrNotFound) {
		t.Fatalf("historical fork checks remained publishable: %v", err)
	}
	if err = s.MaintainGitHub(ctx, 123, nil, testNow.Add(25*time.Hour)); err != nil {
		t.Fatal(err)
	}
	provenance, err := s.GitHubByJob(ctx, current.JobID)
	if err != nil || provenance.AttemptID != current.AttemptID {
		t.Fatalf("obsolete head lost retained provenance: %+v %v", provenance, err)
	}
	requests, err := s.GitHubRequests(ctx, current.JobID)
	if err != nil || len(requests) != 1 || requests[0].RequestID != "actions:1:1" {
		t.Fatalf("obsolete head lost immutable correlation: %+v %v", requests, err)
	}
	if err = s.ReconcileGitHubPublications(ctx, 123); err != nil {
		t.Fatal(err)
	}
	if _, err = s.NextGitHubPublication(ctx, testNow.Add(25*time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("historical terminal check was dirtied again: %v", err)
	}
	prunedAt := testNow.Add(s.options.Retention + time.Hour)
	if err = s.Prune(ctx, prunedAt); err != nil {
		t.Fatal(err)
	}
	if err = s.MaintainGitHub(ctx, 123, nil, prunedAt); err != nil {
		t.Fatal(err)
	}
	runs, err := s.GitHubRuns(ctx, 123)
	if err != nil || len(runs) != 0 {
		t.Fatalf("unreferenced history was retained forever: %+v %v", runs, err)
	}
}

func TestGitHubRetirementPreservesActiveJobsAndPublisherLease(t *testing.T) {
	ctx := context.Background()
	s, _ := githubStore(t)
	input := githubFixture()
	run, err := s.AdmitGitHub(ctx, input, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.MaintainGitHub(ctx, 123, nil, testNow.Add(25*time.Hour)); err != nil {
		t.Fatal(err)
	}
	active, err := s.GitHubActiveRuns(ctx, 123)
	if err != nil || len(active) != 1 || active[0].JobID != run.JobID {
		t.Fatalf("retirement discarded active work: %+v %v", active, err)
	}
	publication, err := s.NextGitHubPublication(ctx, testNow.Add(25*time.Hour))
	if err != nil || publication.Run.JobID != run.JobID {
		t.Fatalf("retirement discarded active outbox: %+v %v", publication, err)
	}
	if _, err = s.Cancel(ctx, run.JobID, "obsolete", testNow); err != nil {
		t.Fatal(err)
	}
	if err = s.MaintainGitHub(ctx, 123, nil, testNow.Add(25*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err = s.FinishGitHubPublication(ctx, publication, 71, time.Time{}); err != nil {
		t.Fatalf("retirement broke live publisher fence: %v", err)
	}
	newer, err := s.NextGitHubPublication(ctx, testNow.Add(25*time.Hour))
	if err != nil || newer.Generation <= publication.Generation {
		t.Fatalf("terminal update lost behind live publication: %+v %v", newer, err)
	}
	if err = s.FinishGitHubPublication(ctx, newer, 71, testNow.Add(48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err = s.MaintainGitHub(ctx, 123, nil, testNow.Add(25*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.NextGitHubPublication(ctx, testNow.Add(48*time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("obsolete failed publication retried forever: %v", err)
	}
}

func TestGitHubBlockedRetirementWaitsForPublisherLease(t *testing.T) {
	ctx := context.Background()
	s, _ := githubStore(t)
	run := githubFixture().Run
	if err := s.BlockGitHub(ctx, run, "fork", testNow); err != nil {
		t.Fatal(err)
	}
	publication, err := s.NextGitHubPublication(ctx, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.MaintainGitHub(ctx, 123, nil, testNow); err != nil {
		t.Fatal(err)
	}
	if err = s.FinishGitHubPublication(ctx, publication, 71, time.Time{}); err != nil {
		t.Fatalf("retirement invalidated live blocked publisher: %v", err)
	}
	if err = s.MaintainGitHub(ctx, 123, nil, testNow); err != nil {
		t.Fatal(err)
	}
	runs, err := s.GitHubRuns(ctx, 123)
	if err != nil || len(runs) != 0 {
		t.Fatalf("obsolete blocked metadata survived publication: %+v %v", runs, err)
	}
}

func TestGitHubCurrentForksAreNotPeriodicallyRepublished(t *testing.T) {
	ctx := context.Background()
	s, _ := githubStore(t)
	heads := make(map[string]bool)
	for i := 1; i <= 300; i++ {
		run := githubFixture().Run
		run.Key, run.SHA = fmt.Sprintf("%064x", i), fmt.Sprintf("%040x", i)
		heads[run.Key] = false
		if err := s.BlockGitHub(ctx, run, "fork", testNow); err != nil {
			t.Fatal(err)
		}
		publication, err := s.NextGitHubPublication(ctx, testNow)
		if err != nil || publication.Run.Key != run.Key {
			t.Fatalf("missing initial policy rejection: %+v %v", publication, err)
		}
		if err = s.FinishGitHubPublication(ctx, publication, int64(i), time.Time{}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.MaintainGitHub(ctx, 123, heads, testNow); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := s.ReconcileGitHubPublications(ctx, 123); err != nil {
			t.Fatal(err)
		}
		if _, err := s.NextGitHubPublication(ctx, testNow.Add(time.Hour)); !errors.Is(err, ErrNotFound) {
			t.Fatalf("full reconciliation republished open forks: %v", err)
		}
	}
}

func TestGitHubJobPublicationsPrecedeForkChurnWithoutBypassingRetry(t *testing.T) {
	ctx := context.Background()
	s, _ := githubStore(t)
	run, err := s.AdmitGitHub(ctx, githubFixture(), testNow)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 20; i++ {
		blocked := githubFixture().Run
		blocked.Key, blocked.SHA = fmt.Sprintf("%064x", i), fmt.Sprintf("%040x", i)
		if err = s.BlockGitHub(ctx, blocked, "fork", testNow); err != nil {
			t.Fatal(err)
		}
	}
	first, err := s.NextGitHubPublication(ctx, testNow)
	if err != nil || first.Run.JobID != run.JobID {
		t.Fatalf("fork churn starved admitted evidence: %+v %v", first, err)
	}
	second, err := s.NextGitHubPublication(ctx, testNow)
	if err != nil || second.Run.JobID != "" {
		t.Fatalf("priority bypassed live publication lease: %+v %v", second, err)
	}
	retry := testNow.Add(time.Hour)
	if err = s.FinishGitHubPublication(ctx, first, 0, retry); err != nil {
		t.Fatal(err)
	}
	third, err := s.NextGitHubPublication(ctx, retry.Add(-time.Second))
	if err != nil || third.Run.JobID != "" {
		t.Fatalf("priority bypassed durable retry deadline: %+v %v", third, err)
	}
	due, err := s.NextGitHubPublication(ctx, retry)
	if err != nil || due.Run.JobID != run.JobID {
		t.Fatalf("due admitted evidence remained behind fork churn: %+v %v", due, err)
	}
}

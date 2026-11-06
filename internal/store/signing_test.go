package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/model"
)

// A succeeded ios_archive job signs once at a time: BeginSigning starts it
// only without a record or after a failure, FinishSigning records the
// outcome, and the job's own state never changes.
func TestSigningSubStatusIsIdempotentAndLeavesJobState(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t, Options{})
	job, _, err := s.Enqueue(ctx, "principal", "archive", archiveAdmission(t), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.BeginSigning(ctx, job.ID, testNow); err != ErrTransition {
		t.Fatalf("queued job signing: %v", err)
	}
	finishJob(t, s, claimJob(t, s, "epoch", testNow), model.Succeeded, true, testNow)
	if _, err := s.GetSigning(ctx, job.ID); err != ErrNotFound {
		t.Fatalf("unsigned job record: %v", err)
	}
	record, started, err := s.BeginSigning(ctx, job.ID, testNow)
	if err != nil || !started || record.Status != Signing {
		t.Fatalf("begin: %+v %v %v", record, started, err)
	}
	again, started, err := s.BeginSigning(ctx, job.ID, testNow.Add(time.Second))
	if err != nil || started || again.Status != Signing {
		t.Fatalf("begin while signing: %+v %v %v", again, started, err)
	}
	requireError(t, s.FinishSigning(ctx, job.ID, SignFailed, "profile expired", nil, testNow), nil)
	record, started, err = s.BeginSigning(ctx, job.ID, testNow.Add(2*time.Second))
	if err != nil || !started {
		t.Fatalf("retry after failure: %+v %v %v", record, started, err)
	}
	artifacts := []evidence.Artifact{{ID: strings.Repeat("a", 64), Name: "App.ipa", MediaType: "application/octet-stream", SizeBytes: 9, SHA256: strings.Repeat("a", 64), ExpiresAt: testNow.Add(time.Hour)}}
	requireError(t, s.FinishSigning(ctx, job.ID, Signed, "", nil, testNow), ErrInvalid)
	requireError(t, s.FinishSigning(ctx, job.ID, Signed, "", artifacts, testNow), nil)
	requireError(t, s.FinishSigning(ctx, job.ID, SignFailed, "late", nil, testNow), ErrTransition)
	record, started, err = s.BeginSigning(ctx, job.ID, testNow.Add(3*time.Second))
	if err != nil || started || record.Status != Signed || len(record.Artifacts) != 1 || record.Artifacts[0].Name != "App.ipa" {
		t.Fatalf("begin after signed: %+v %v %v", record, started, err)
	}
	if got := getJob(t, s, job.ID); got.State != model.Succeeded {
		t.Fatalf("job state %s", got.State)
	}
	plain := enqueueJob(t, s, "principal", "plain", testNow)
	finishJob(t, s, claimJob(t, s, "epoch", testNow), model.Succeeded, true, testNow)
	if _, _, err := s.BeginSigning(ctx, plain.ID, testNow); err != ErrTransition {
		t.Fatalf("build job signing: %v", err)
	}
}

// A controller restart fails every signing left in progress.
func TestInterruptSigningsFailsInProgress(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t, Options{})
	job, _, err := s.Enqueue(ctx, "principal", "archive", archiveAdmission(t), testNow)
	if err != nil {
		t.Fatal(err)
	}
	finishJob(t, s, claimJob(t, s, "epoch", testNow), model.Succeeded, true, testNow)
	if _, _, err := s.BeginSigning(ctx, job.ID, testNow); err != nil {
		t.Fatal(err)
	}
	requireError(t, s.InterruptSignings(ctx, testNow), nil)
	record, err := s.GetSigning(ctx, job.ID)
	if err != nil || record.Status != SignFailed || !strings.Contains(record.Reason, "restart") {
		t.Fatalf("interrupted: %+v %v", record, err)
	}
}

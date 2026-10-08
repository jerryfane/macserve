package store

import (
	"context"
	"github.com/jerryfane/macserve/internal/model"
	"testing"
)

func TestRegistrationBindsClaimsAndFencesEarlierEpochs(t *testing.T) {
	ctx := context.Background()
	s, path := newStore(t, Options{})
	if err := s.RegisterWorker(ctx, "registered"); err != nil {
		t.Fatal(err)
	}
	enqueueJob(t, s, "principal", "registered", testNow)
	_, err := s.Claim(ctx, "unregistered", testNow)
	requireError(t, err, ErrLease)
	job := claimJob(t, s, "registered", testNow)
	if err := s.RegisterWorker(ctx, "registered"); err != nil {
		t.Fatalf("active delivery reconnect rejected: %v", err)
	}
	requireError(t, s.RegisterWorker(ctx, "replacement"), ErrTransition)
	finishJob(t, s, job, model.Succeeded, true, testNow)
	if err := s.RegisterWorker(ctx, "replacement"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openStore(t, path, Options{})
	requireError(t, s.RegisterWorker(ctx, "registered"), ErrLease)
	enqueueJob(t, s, "principal", "replacement", testNow)
	_, err = s.Claim(ctx, "unregistered", testNow)
	requireError(t, err, ErrLease)
	claimJob(t, s, "replacement", testNow)
}

func TestRegistrationRetiresLegacyEpochWithoutReopeningIt(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t, Options{})
	if _, err := s.db.ExecContext(ctx, "CREATE TABLE worker_runtime(singleton INTEGER PRIMARY KEY,epoch TEXT NOT NULL); INSERT INTO worker_runtime VALUES(1,'legacy-epoch')"); err != nil {
		t.Fatal(err)
	}
	if err := s.RegisterWorker(ctx, "new-epoch"); err != nil {
		t.Fatal(err)
	}
	requireError(t, s.RegisterWorker(ctx, "legacy-epoch"), ErrLease)
	if err := s.RegisterWorker(ctx, "new-epoch"); err != nil {
		t.Fatal(err)
	}
	enqueueJob(t, s, "principal", "new", testNow)
	claimJob(t, s, "new-epoch", testNow)
}

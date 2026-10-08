package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
)

func TestSourceDebtSurvivesPruningReopenAndWorkerAcknowledgment(t *testing.T) {
	ctx := context.Background()
	s, path := newStore(t, Options{Retention: time.Hour})
	enqueueJob(t, s, "owner", "source", testNow)
	job := claimJob(t, s, "epoch-a", testNow)
	requireError(t, s.RequireSourceCleanup(ctx, job.ID), nil)
	state, err := s.ServiceState(ctx)
	if err != nil || state.Quarantined {
		t.Fatalf("active source intent quarantined dispatch: %+v %v", state, err)
	}
	pending, err := s.PendingSourceCleanup(ctx)
	if err != nil || len(pending) != 0 {
		t.Fatalf("active source was eligible for removal: %v %v", pending, err)
	}
	finishJob(t, s, job, model.Succeeded, true, testNow)
	requireError(t, s.RegisterWorker(ctx, "epoch-b"), nil)
	requireError(t, s.AcknowledgeQuiescent(ctx, "epoch-b"), nil)
	requireError(t, s.Prune(ctx, testNow.Add(2*time.Hour)), nil)
	_, err = s.Get(ctx, job.ID)
	requireError(t, err, ErrNotFound)
	requireError(t, s.Close(), nil)
	s = openStore(t, path, Options{Retention: time.Hour})
	state, err = s.ServiceState(ctx)
	if err != nil || !state.Quarantined {
		t.Fatalf("pruning/restart/registration lost source quarantine: %+v %v", state, err)
	}
	pending, err = s.PendingSourceCleanup(ctx)
	if err != nil || len(pending) != 1 || pending[0] != job.ID {
		t.Fatalf("pruning lost source cleanup ID: %v %v", pending, err)
	}
	queued := enqueueJob(t, s, "owner", "waiting", testNow.Add(2*time.Hour))
	_, err = s.Claim(ctx, "epoch-b", testNow.Add(2*time.Hour))
	requireError(t, err, ErrNoJob)
	requireError(t, s.ConfirmSourceCleanup(ctx, job.ID), nil)
	claimed := claimJob(t, s, "epoch-b", testNow.Add(2*time.Hour))
	if claimed.ID != queued.ID {
		t.Fatalf("successful source retry did not release queue: %+v", claimed)
	}
}

func TestSourceDebtRecoveryPreservesIndependentWorkerFence(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t, Options{})
	enqueueJob(t, s, "owner", "source", testNow)
	job := claimJob(t, s, "epoch-a", testNow)
	requireError(t, s.RequireSourceCleanup(ctx, job.ID), nil)
	requireError(t, s.Recover(ctx, testNow.Add(time.Second)), nil)
	pending, err := s.PendingSourceCleanup(ctx)
	if err != nil || len(pending) != 1 || pending[0] != job.ID {
		t.Fatalf("recovery lost export obligation: %v %v", pending, err)
	}
	requireError(t, s.ConfirmSourceCleanup(ctx, job.ID), nil)
	state, err := s.ServiceState(ctx)
	if err != nil || !state.Quarantined {
		t.Fatalf("source removal acknowledged unknown worker: %+v %v", state, err)
	}
	requireError(t, s.RegisterWorker(ctx, "epoch-a"), ErrLease)
	requireError(t, s.RegisterWorker(ctx, "epoch-b"), nil)
	state, err = s.ServiceState(ctx)
	if err != nil || state.Quarantined {
		t.Fatalf("independent worker acknowledgment failed: %+v %v", state, err)
	}
}

func TestSourceDebtMigrationRecoversPreviouslyUncertainExports(t *testing.T) {
	ctx := context.Background()
	s, path := newStore(t, Options{})
	enqueueJob(t, s, "owner", "legacy-source", testNow)
	job := claimJob(t, s, "epoch-a", testNow)
	finishJob(t, s, job, model.Failed, false, testNow)
	// Emulate the pre-ledger database, including worker registration having
	// already cleared its overloaded quarantine bit.
	requireError(t, s.RegisterWorker(ctx, "epoch-b"), nil)
	_, err := s.db.ExecContext(ctx, "DROP TABLE source_cleanup; PRAGMA user_version=2;")
	requireError(t, err, nil)
	requireError(t, s.Close(), nil)
	s = openStore(t, path, Options{})
	pending, err := s.PendingSourceCleanup(ctx)
	if err != nil || len(pending) != 1 || pending[0] != job.ID {
		t.Fatalf("migration forgot uncertain source: %v %v", pending, err)
	}
	state, err := s.ServiceState(ctx)
	if err != nil || !state.Quarantined {
		t.Fatalf("migration reopened uncertain source admission: %+v %v", state, err)
	}
	if err := s.RegisterWorker(ctx, "epoch-a"); !errors.Is(err, ErrLease) {
		t.Fatalf("migration revived retired epoch: %v", err)
	}
}

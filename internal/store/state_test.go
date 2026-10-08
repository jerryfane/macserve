package store

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
)

func TestLeaseAndStateMachineBoundaries(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t, Options{})
	queued := enqueueJob(t, s, "principal", "key", testNow)
	requireError(t, s.Transition(ctx, queued.ID, "", model.Queued, model.Preparing, "", testNow), ErrTransition)
	requireError(t, s.Finish(ctx, queued.ID, "", model.Succeeded, nil, true, "", testNow), ErrLease)
	job := claimJob(t, s, "epoch", testNow)
	requireError(t, s.Transition(ctx, job.ID, "wrong", model.Preparing, model.Running, "", testNow), ErrLease)
	requireError(t, s.Transition(ctx, job.ID, job.LeaseToken, model.Running, model.Finalizing, "", testNow), ErrTransition)
	requireError(t, s.Transition(ctx, job.ID, job.LeaseToken, model.Preparing, model.Succeeded, "", testNow), ErrTransition)
	requireError(t, s.Finish(ctx, job.ID, job.LeaseToken, model.Succeeded, nil, true, "", testNow), ErrTransition)
	if err := s.Transition(ctx, job.ID, job.LeaseToken, model.Preparing, model.Running, "executing", testNow.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	requireError(t, s.Transition(ctx, job.ID, job.LeaseToken, model.Preparing, model.Running, "", testNow), ErrTransition)
	if err := s.Transition(ctx, job.ID, job.LeaseToken, model.Running, model.Finalizing, "exporting", testNow.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	requireError(t, s.Transition(ctx, job.ID, job.LeaseToken, model.Finalizing, model.Succeeded, "", testNow), ErrTransition)
	requireError(t, s.Finish(ctx, job.ID, job.LeaseToken, model.Expired, nil, true, "", testNow), ErrTransition)
	requireError(t, s.Finish(ctx, job.ID, job.LeaseToken, model.Failed, json.RawMessage(`{"broken":`), true, "", testNow), ErrInvalid)
	if got := getJob(t, s, job.ID); got.State != model.Finalizing || got.Result != nil || got.FinishedAt != nil {
		t.Fatal("invalid finish partially committed")
	}
	result := json.RawMessage(`{"exit_code":17,"signal":null}`)
	end := testNow.Add(3 * time.Second)
	if err := s.Finish(ctx, job.ID, job.LeaseToken, model.Failed, result, true, "command failed", end); err != nil {
		t.Fatal(err)
	}
	terminal := getJob(t, s, job.ID)
	if terminal.State != model.Failed || !terminal.CleanupOK || string(terminal.Result) != string(result) || terminal.FinishedAt == nil || !terminal.FinishedAt.Equal(end) || !terminal.UpdatedAt.Equal(end) {
		t.Fatalf("terminal result not atomic: %+v", terminal)
	}
	requireError(t, s.Finish(ctx, job.ID, job.LeaseToken, model.Succeeded, nil, true, "rewrite", end), ErrTransition)
	requireError(t, s.Transition(ctx, job.ID, job.LeaseToken, model.Finalizing, model.Cancelling, "rewrite", end), ErrTransition)
	cancelled, err := s.Cancel(ctx, job.ID, "late cancellation", end.Add(time.Hour))
	if err != nil || !reflect.DeepEqual(cancelled, terminal) {
		t.Fatalf("terminal cancellation mutated result: %+v %v", cancelled, err)
	}
}

func TestCancellationAtEveryNonterminalStage(t *testing.T) {
	for _, stage := range []model.State{model.Queued, model.Preparing, model.Running, model.Cancelling, model.Finalizing} {
		t.Run(string(stage), func(t *testing.T) {
			ctx := context.Background()
			s, _ := newStore(t, Options{})
			job := enqueueJob(t, s, "principal", "key", testNow)
			if stage != model.Queued {
				job = claimJob(t, s, "epoch", testNow)
				if stage != model.Preparing {
					if err := s.Transition(ctx, job.ID, job.LeaseToken, model.Preparing, stage, "stage", testNow); err != nil {
						t.Fatal(err)
					}
				}
			}
			cancelled, err := s.Cancel(ctx, job.ID, "owner request", testNow.Add(time.Second))
			if err != nil {
				t.Fatal(err)
			}
			want := model.Cancelling
			if stage == model.Queued {
				want = model.Cancelled
			}
			if stage == model.Finalizing {
				want = model.Finalizing
			}
			if cancelled.State != want || !cancelled.CancelRequested {
				t.Fatalf("cancelled from %s: %+v", stage, cancelled)
			}
			again, err := s.Cancel(ctx, job.ID, "repeated cancellation", testNow.Add(2*time.Second))
			if err != nil || !reflect.DeepEqual(again, cancelled) {
				t.Fatalf("cancel was not idempotent: %+v %v", again, err)
			}
			if stage == model.Queued {
				if cancelled.FinishedAt == nil {
					t.Fatal("queued cancellation lacks finish timestamp")
				}
				_, err := s.Claim(ctx, "epoch", testNow.Add(3*time.Second))
				requireError(t, err, ErrNoJob)
				return
			}
			if cancelled.State != model.Finalizing {
				if err := s.Transition(ctx, job.ID, job.LeaseToken, model.Cancelling, model.Finalizing, "cleanup", testNow.Add(3*time.Second)); err != nil {
					t.Fatal(err)
				}
			}
			requireError(t, s.Finish(ctx, job.ID, job.LeaseToken, model.Succeeded, nil, true, "", testNow), ErrTransition)
			if err := s.Finish(ctx, job.ID, job.LeaseToken, model.Cancelled, nil, true, "cancelled", testNow.Add(4*time.Second)); err != nil {
				t.Fatal(err)
			}
			if got := getJob(t, s, job.ID); got.State != model.Cancelled || !got.CancelRequested {
				t.Fatalf("lost cancellation: %+v", got)
			}
		})
	}
}

func TestPauseDrainAndCancelActive(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t, Options{})
	enqueueJob(t, s, "principal", "one", testNow)
	second := enqueueJob(t, s, "principal", "two", testNow)
	active := claimJob(t, s, "epoch", testNow)
	paused, err := s.Pause(ctx, "owner activity", "drain", testNow)
	if err != nil || !paused.Paused || paused.PauseMode != "drain" || paused.Generation != 1 {
		t.Fatalf("pause: %+v %v", paused, err)
	}
	if got := getJob(t, s, active.ID); got.State != model.Preparing || got.CancelRequested {
		t.Fatal("drain cancelled active work")
	}
	finishJob(t, s, active, model.Succeeded, true, testNow.Add(time.Second))
	_, err = s.Claim(ctx, "epoch", testNow.Add(2*time.Second))
	requireError(t, err, ErrNoJob)
	state, err := s.Resume(ctx)
	if err != nil || state.Paused || state.PauseReason != "" || state.PauseMode != "" || state.Generation <= paused.Generation {
		t.Fatalf("resume: %+v %v", state, err)
	}
	active = claimJob(t, s, "epoch", testNow.Add(3*time.Second))
	if active.ID != second.ID {
		t.Fatal("resume did not release queue")
	}
	paused, err = s.Pause(ctx, "owner needs quiescence", "cancel_active", testNow.Add(4*time.Second))
	if err != nil || !paused.Paused || paused.Generation <= state.Generation {
		t.Fatalf("cancel_active pause: %+v %v", paused, err)
	}
	active = getJob(t, s, active.ID)
	if active.State != model.Cancelling || !active.CancelRequested {
		t.Fatal("cancel_active did not atomically cancel")
	}
	finishJob(t, s, active, model.Cancelled, true, testNow.Add(5*time.Second))
	_, err = s.Pause(ctx, "", "freeze", testNow)
	requireError(t, err, ErrInvalid)
}

func TestCancelActivePauseDuringFinalization(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t, Options{})
	enqueueJob(t, s, "principal", "one", testNow)
	job := claimJob(t, s, "epoch", testNow)
	if err := s.Transition(ctx, job.ID, job.LeaseToken, model.Preparing, model.Finalizing, "exporting", testNow); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pause(ctx, "owner request", "cancel_active", testNow); err != nil {
		t.Fatal(err)
	}
	got := getJob(t, s, job.ID)
	if got.State != model.Finalizing || !got.CancelRequested {
		t.Fatal("pause broke finalization")
	}
	requireError(t, s.Finish(ctx, job.ID, job.LeaseToken, model.Succeeded, nil, true, "", testNow), ErrTransition)
}

func TestCleanupFailureQuarantineSurvivesReopen(t *testing.T) {
	ctx := context.Background()
	s, path := newStore(t, Options{})
	enqueueJob(t, s, "principal", "one", testNow)
	second := enqueueJob(t, s, "principal", "two", testNow)
	job := claimJob(t, s, "old-epoch", testNow)
	requireError(t, s.AcknowledgeQuiescent(ctx, "new-epoch"), ErrTransition)
	finishJob(t, s, job, model.Failed, false, testNow.Add(time.Second))
	if _, err := s.Pause(ctx, "manual pause", "drain", testNow); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openStore(t, path, Options{})
	if err := s.Recover(ctx, testNow.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	state, err := s.Resume(ctx)
	if err != nil || state.Paused || !state.Quarantined {
		t.Fatalf("resume cleared quarantine: %+v %v", state, err)
	}
	_, err = s.Claim(ctx, "new-epoch", testNow.Add(3*time.Second))
	requireError(t, err, ErrNoJob)
	requireError(t, s.AcknowledgeQuiescent(ctx, "old-epoch"), ErrLease)
	if err := s.AcknowledgeQuiescent(ctx, "new-epoch"); err != nil {
		t.Fatal(err)
	}
	_, err = s.Claim(ctx, "old-epoch", testNow.Add(4*time.Second))
	requireError(t, err, ErrLease)
	if got := claimJob(t, s, "new-epoch", testNow.Add(4*time.Second)); got.ID != second.ID {
		t.Fatal("quiescence did not restore dispatch")
	}
	finished := getJob(t, s, job.ID)
	if finished.State != model.Failed || finished.CleanupOK {
		t.Fatal("quarantine rewrote terminal result")
	}
}

func TestRecoveryInterruptsEveryActiveStageAndRetainsEvidence(t *testing.T) {
	for _, stage := range []model.State{model.Preparing, model.Running, model.Cancelling, model.Finalizing} {
		t.Run(string(stage), func(t *testing.T) {
			ctx := context.Background()
			s, path := newStore(t, Options{Retention: time.Hour})
			enqueueJob(t, s, "principal", "active", testNow)
			queued := enqueueJob(t, s, "principal", "queued", testNow)
			job := claimJob(t, s, "lost-epoch", testNow)
			if stage != model.Preparing {
				if err := s.Transition(ctx, job.ID, job.LeaseToken, model.Preparing, stage, "partial stage", testNow); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.AppendLog(ctx, job.ID, job.LeaseToken, "stderr", "partial evidence\n", testNow); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			s = openStore(t, path, Options{Retention: time.Hour})
			when := testNow.Add(time.Minute)
			if err := s.Recover(ctx, when); err != nil {
				t.Fatal(err)
			}
			interrupted := getJob(t, s, job.ID)
			if interrupted.State != model.Interrupted || interrupted.CleanupOK || interrupted.WorkerEpoch != job.WorkerEpoch || interrupted.LeaseToken != job.LeaseToken || !reflect.DeepEqual(interrupted.Profile, job.Profile) || !interrupted.FinishedAt.Equal(when) {
				t.Fatalf("bad recovery: %+v", interrupted)
			}
			logs, next, truncated, err := s.Logs(ctx, job.ID, 0, 0)
			if err != nil || len(logs) != 1 || logs[0].Text != "partial evidence\n" || next != 1 || truncated {
				t.Fatal("recovery lost partial evidence")
			}
			if got := getJob(t, s, queued.ID); got.State != model.Queued {
				t.Fatal("recovery changed queued work")
			}
			requireError(t, s.Transition(ctx, job.ID, job.LeaseToken, stage, model.Finalizing, "stale worker", when), ErrTransition)
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			s = openStore(t, path, Options{Retention: time.Hour})
			if err := s.Recover(ctx, when.Add(time.Minute)); err != nil {
				t.Fatal(err)
			}
			state, err := s.ServiceState(ctx)
			if err != nil || !state.Quarantined {
				t.Fatal("repeated recovery cleared quarantine")
			}
			requireError(t, s.AcknowledgeQuiescent(ctx, "lost-epoch"), ErrLease)
			if err := s.Prune(ctx, when.Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Get(ctx, job.ID); err != ErrNotFound {
				t.Fatalf("interrupted retention: %v", err)
			}
			requireError(t, s.AcknowledgeQuiescent(ctx, "lost-epoch"), ErrLease)
			if err := s.AcknowledgeQuiescent(ctx, "fresh-epoch"); err != nil {
				t.Fatal(err)
			}
			if got := claimJob(t, s, "fresh-epoch", when.Add(time.Hour)); got.ID != queued.ID {
				t.Fatal("recovery did not resume queued work")
			}
		})
	}
}

func TestSuccessRequiresVerifiedCleanup(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t, Options{})
	enqueueJob(t, s, "principal", "cleanup", testNow)
	job := claimJob(t, s, "epoch", testNow)
	if err := s.Transition(ctx, job.ID, job.LeaseToken, model.Preparing, model.Finalizing, "", testNow); err != nil {
		t.Fatal(err)
	}
	requireError(t, s.Finish(ctx, job.ID, job.LeaseToken, model.Succeeded, nil, false, "", testNow), ErrTransition)
	if got := getJob(t, s, job.ID); got.State != model.Finalizing {
		t.Fatalf("incomplete cleanup published %q", got.State)
	}
	requireError(t, s.Finish(ctx, job.ID, job.LeaseToken, model.Failed, nil, false, "cleanup failed", testNow), nil)
	state, err := s.ServiceState(ctx)
	if err != nil || !state.Quarantined {
		t.Fatalf("cleanup failure did not quarantine: %+v, %v", state, err)
	}
}

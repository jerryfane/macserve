package controller

import (
	"context"
	"errors"
	"testing"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/protocol"
)

func TestDispatchRefusalDoesNotPrepareSourceOrLeaveCleanupDebt(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		name := "ineligible"
		if deadline {
			name = "deadline"
		}
		t.Run(name, func(t *testing.T) {
			f := newRuntime(t)
			f.source.started = make(chan struct{})
			f.controller.options.BeforeDispatch = func(context.Context, model.Job) error {
				if deadline {
					return context.DeadlineExceeded
				}
				return errors.New("permanent policy rejection")
			}
			job := f.enqueue(t, "rejected", model.Build)
			ctx := context.Background()
			if err := f.controller.register(ctx, protocol.Registration{Epoch: "epoch-a", Quiescent: true}); err != nil {
				t.Fatal(err)
			}
			if lease, err := f.controller.next(ctx, "epoch-a"); err != nil || lease != nil {
				t.Fatalf("unexpected rejected lease: %+v %v", lease, err)
			}
			f.controller.prep.Wait()
			select {
			case <-f.source.started:
				t.Fatal("source prepared before successful authorization")
			default:
			}
			finished, err := f.db.Get(ctx, job.ID)
			want := model.Cancelled
			if deadline {
				want = model.TimedOut
			}
			if err != nil || finished.State != want || !finished.CleanupOK {
				t.Fatalf("wrong dispatch refusal outcome: %+v %v", finished, err)
			}
			pending, err := f.db.PendingSourceCleanup(ctx)
			if err != nil || len(pending) != 0 {
				t.Fatalf("authorization refusal created source debt: %v %v", pending, err)
			}
			// A rejected job must not quarantine otherwise healthy admission.
			f.controller.options.BeforeDispatch = nil
			f.enqueue(t, "next", model.Build)
			if _, err = f.controller.next(ctx, "epoch-a"); err != nil {
				t.Fatal(err)
			}
			f.controller.prep.Wait()
			lease, err := f.controller.next(ctx, "epoch-a")
			if err != nil || lease == nil {
				t.Fatalf("refusal wedged later eligible work: %+v %v", lease, err)
			}
		})
	}
}

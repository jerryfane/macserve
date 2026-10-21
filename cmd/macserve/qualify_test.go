package main

import (
	"context"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/worker"
)

func TestQualificationSnapshotCommandDeadline(t *testing.T) {
	for _, command := range []string{"begin", "collect", "approve", "reapprove", "activation-check"} {
		t.Run(command, func(t *testing.T) {
			start := time.Now()
			ctx, cancel := qualificationCommandContext(context.Background(), command)
			defer cancel()
			deadline, ok := ctx.Deadline()
			if !ok || deadline.Before(start.Add(540*time.Second)) || deadline.After(time.Now().Add(540*time.Second)) {
				t.Fatalf("full qualification command needs its fixed 540s deadline: %v present=%t", deadline, ok)
			}
			if !deadline.After(start.Add(worker.PersistenceFullScanTimeout)) {
				t.Fatal("qualification outer deadline leaves no collector publication headroom")
			}
			cancel()
			if ctx.Err() != context.Canceled {
				t.Fatalf("qualification ignores cancellation: %v", ctx.Err())
			}
			expired, expire := context.WithDeadline(context.Background(), start.Add(-time.Second))
			defer expire()
			ctx, cancel = qualificationCommandContext(expired, command)
			defer cancel()
			if ctx.Err() != context.DeadlineExceeded {
				t.Fatalf("qualification extended an expired caller deadline: %v", ctx.Err())
			}
		})
	}
}

func TestQualificationOrdinaryCommandDeadlineUnchanged(t *testing.T) {
	for _, command := range []string{"plan", "probe", "canary", "coexistence-before", "coexistence-after"} {
		t.Run(command, func(t *testing.T) {
			ctx, cancel := qualificationCommandContext(context.Background(), command)
			defer cancel()
			if deadline, ok := ctx.Deadline(); ok {
				t.Fatalf("ordinary command acquired an unrelated full-scan deadline: %v", deadline)
			}
			deadline := time.Now().Add(3 * time.Second)
			parent, stop := context.WithDeadline(context.Background(), deadline)
			defer stop()
			ctx, cancel = qualificationCommandContext(parent, command)
			defer cancel()
			if got, ok := ctx.Deadline(); !ok || !got.Equal(deadline) {
				t.Fatalf("caller deadline changed: got=%v present=%t want=%v", got, ok, deadline)
			}
			stop()
			if ctx.Err() != context.Canceled {
				t.Fatalf("caller cancellation ignored: %v", ctx.Err())
			}
		})
	}
}

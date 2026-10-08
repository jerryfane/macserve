package worker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
)

func TestFinalizationSharesOneBudgetAcrossWriterBarriers(t *testing.T) {
	var ran atomic.Bool
	runner := &fakeRunner{hook: func(_ context.Context, command Command, _, _ io.Writer) (bool, ProcessResult, error) {
		if len(command.Args) > 0 && command.Args[0] == "build" {
			ran.Store(true)
		}
		return false, ProcessResult{}, nil
	}, quiesce: func(ctx context.Context) error {
		if !ran.Load() {
			return nil
		}
		timer := time.NewTimer(20 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
			return ctx.Err()
		case <-ctx.Done():
			return ctx.Err()
		}
	}}
	engine := engineFixture(t, runner)
	engine.options.CleanupTimeout = 30 * time.Millisecond
	job := fixtureJob(t, model.Build)
	source, data := sourceFixture(t)
	result, err := engine.Execute(context.Background(), job, source, bytes.NewReader(data), nil)
	if !ran.Load() || !errors.Is(err, context.DeadlineExceeded) || result.State != model.TimedOut || result.CleanupOK {
		t.Fatalf("separate stages extended finalization budget: result=%+v err=%v ran=%v", result, err, ran.Load())
	}
	if _, err := engine.Execute(context.Background(), job, source, bytes.NewReader(data), nil); !errors.Is(err, ErrRecovery) {
		t.Fatalf("uncertain cleanup did not fence subsequent execution: %v", err)
	}
}

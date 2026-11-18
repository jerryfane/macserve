package worker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Studio 2026-11-18 09:50Z (#194): at load 53 a SIGKILLed xcodebuild group
// was still listed when the 1.5 s window closed, and cleanup went unconfirmed.
// After the window the protected cleanup keeps listing with backoff for
// cleanupConfirm, SIGKILLing what is still listed, and confirms cleanup once
// the group is gone. A member that outlives the bound is still contamination,
// judged only after it.
func TestProtectedCleanupConfirmsGroupGoneAfterTheWindow(t *testing.T) {
	for name, c := range map[string]struct {
		lingers, confirm time.Duration
		confirmed        bool
	}{
		"gone within the bound": {lingers: 400 * time.Millisecond, confirm: 5 * time.Second, confirmed: true},
		"outlives the bound":    {lingers: time.Hour, confirm: 300 * time.Millisecond},
	} {
		t.Run(name, func(t *testing.T) {
			runner, command := helperRunner(t, "success")
			var started *exec.Cmd
			launch := runner.command
			runner.command = func(c Command) *exec.Cmd { started = launch(c); return started }
			runner.termGrace, runner.killGrace, runner.pollInterval = 10*time.Millisecond, 20*time.Millisecond, time.Millisecond
			runner.cleanupConfirm = c.confirm
			runner.scope = scopeFixture()
			var mu sync.Mutex
			var killed time.Time
			kills := 0
			runner.scope.sample = func(context.Context) ([]processSample, error) {
				mu.Lock()
				defer mu.Unlock()
				if !killed.IsZero() && time.Since(killed) >= c.lingers {
					return nil, nil
				}
				return []processSample{{pid: 2147483646, group: started.Process.Pid, uid: runner.uid, start: "xcodebuild"}}, nil
			}
			runner.signalProcess = func(_ context.Context, _ processSample, sig syscall.Signal) error {
				mu.Lock()
				defer mu.Unlock()
				if sig == syscall.SIGKILL {
					kills++
					if killed.IsZero() {
						killed = time.Now()
					}
				}
				return nil
			}
			begun := time.Now()
			result, err := runner.Run(context.Background(), command, io.Discard, io.Discard)
			mu.Lock()
			defer mu.Unlock()
			if c.confirmed {
				if err != nil || !result.CleanupOK {
					t.Fatalf("group gone %v after SIGKILL left cleanup unconfirmed: %+v, %v", c.lingers, result, err)
				}
				if kills < 2 {
					t.Fatalf("SIGKILL sent %d times; a member still listed after the window is signalled again", kills)
				}
				return
			}
			if result.CleanupOK || !errors.Is(err, ErrCleanup) || !errors.Is(err, ErrContamination) {
				t.Fatalf("member outliving the bound accepted: %+v, %v", result, err)
			}
			if elapsed := time.Since(begun); elapsed < c.confirm {
				t.Fatalf("survivor judged after %v, before the %v bound", elapsed, c.confirm)
			}
		})
	}
}

// One _job-signal helper run that failed only on time (its output did not
// close within the WaitDelay) is retried; any other failure is returned at
// once, and the caller's context ends the retries.
func TestSignalWithRetryRetriesOnlyTimingFailures(t *testing.T) {
	waitDelay := fmt.Errorf("signal job process pid=40294 signal=15: %w", exec.ErrWaitDelay)
	calls := 0
	if err := signalWithRetry(context.Background(), func(context.Context) error {
		calls++
		if calls == 1 {
			return waitDelay
		}
		return nil
	}); err != nil || calls != 2 {
		t.Fatalf("WaitDelay once: %v after %d runs", err, calls)
	}
	changed := errors.New("signal target identity changed")
	calls = 0
	if err := signalWithRetry(context.Background(), func(context.Context) error { calls++; return changed }); !errors.Is(err, changed) || calls != 1 {
		t.Fatalf("identity change: %v after %d runs", err, calls)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	calls = 0
	if err := signalWithRetry(ctx, func(context.Context) error { calls++; return waitDelay }); !errors.Is(err, exec.ErrWaitDelay) || calls != 1 {
		t.Fatalf("cancelled caller: %v after %d runs", err, calls)
	}
}

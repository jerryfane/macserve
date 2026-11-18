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

// loadedGroup runs a command that exits at once under a protected runner
// whose listing shows one more member of its group until a signal reaches
// it, and returns the runner, the command and the signals that reached it.
// signal decides each signal call: deliver reports whether it reached the
// member; err is the helper's result.
func loadedGroup(t *testing.T, signal func(ctx context.Context, call int) (deliver bool, err error)) (*nativeRunner, Command, func() []syscall.Signal) {
	t.Helper()
	runner, command := helperRunner(t, "success")
	var started *exec.Cmd
	launch := runner.command
	runner.command = func(c Command) *exec.Cmd { started = launch(c); return started }
	// A 300 ms signalling window: SIGTERM for 100 ms, then SIGKILL.
	runner.termGrace, runner.killGrace, runner.pollInterval = 100*time.Millisecond, 200*time.Millisecond, time.Millisecond
	runner.scope = scopeFixture()
	var mu sync.Mutex
	var reached []syscall.Signal
	calls := 0
	runner.scope.sample = func(context.Context) ([]processSample, error) {
		mu.Lock()
		defer mu.Unlock()
		if len(reached) > 0 {
			return nil, nil
		}
		return []processSample{{pid: 2147483646, group: started.Process.Pid, uid: runner.uid, start: "xcodebuild"}}, nil
	}
	runner.signalProcess = func(ctx context.Context, _ processSample, sig syscall.Signal) error {
		mu.Lock()
		calls++
		call := calls
		mu.Unlock()
		deliver, err := signal(ctx, call)
		if deliver {
			mu.Lock()
			reached = append(reached, sig)
			mu.Unlock()
		}
		return err
	}
	return runner, command, func() []syscall.Signal {
		mu.Lock()
		defer mu.Unlock()
		return append([]syscall.Signal(nil), reached...)
	}
}

// Studio 2026-11-18 09:50Z (#194), load 53 on 36 cores: the readiness gate
// cancelled three jobs, and signalling xcodebuild's group failed with "signal
// job process pid=40294 … signal=15: exec: WaitDelay expired before I/O
// complete", then "job group still live after the cleanup window", so the
// worker quarantined and needed an owner restart. A signal helper that is
// slow or fails on time once must not decide cleanup: the signal is retried
// and, once the group is gone, cleanup is confirmed.
func TestProtectedCleanupSlowSignalHelperOnceConfirms(t *testing.T) {
	waitDelay := fmt.Errorf("signal job process pid=40294 start=%q signal=15: %w; helper stderr=%q", "xcodebuild", exec.ErrWaitDelay, "")
	for name, signal := range map[string]func(context.Context, int) (bool, error){
		// The helper's output did not close in time; the signal never ran.
		"WaitDelay expired once": func(_ context.Context, call int) (bool, error) {
			if call == 1 {
				return false, waitDelay
			}
			return true, nil
		},
		// The helper took twice the window to start under load and was
		// killed at the deadline it was given before it could signal.
		"slower than the window once": func(ctx context.Context, call int) (bool, error) {
			if call == 1 {
				select {
				case <-ctx.Done():
					return false, fmt.Errorf("signal job process pid=40294: signal: killed: %w", ctx.Err())
				case <-time.After(600 * time.Millisecond):
				}
			}
			return true, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			runner, command, reached := loadedGroup(t, signal)
			result, err := runner.Run(context.Background(), command, io.Discard, io.Discard)
			if err != nil || !result.CleanupOK || result.ExitCode != 0 {
				t.Fatalf("one slow signal left cleanup unconfirmed: %+v, %v", result, err)
			}
			if len(reached()) == 0 {
				t.Fatal("cleanup confirmed without signalling the group")
			}
		})
	}
}

// Guard (passes before #194 by design): a member that every signal misses,
// or that survives every signal, still ends cleanup unconfirmed (ErrCleanup,
// CleanupOK false) and a surviving one is contamination.
func TestProtectedCleanupSurvivorStaysUnconfirmed(t *testing.T) {
	for name, signal := range map[string]func(context.Context, int) (bool, error){
		"every signal fails": func(context.Context, int) (bool, error) {
			return false, fmt.Errorf("signal job process: %w", exec.ErrWaitDelay)
		},
		"survives every signal": func(context.Context, int) (bool, error) { return false, nil },
	} {
		t.Run(name, func(t *testing.T) {
			runner, command, _ := loadedGroup(t, signal)
			result, err := runner.Run(context.Background(), command, io.Discard, io.Discard)
			if result.CleanupOK || !errors.Is(err, ErrCleanup) {
				t.Fatalf("surviving member accepted: %+v, %v", result, err)
			}
			if name == "survives every signal" && !errors.Is(err, ErrContamination) {
				t.Fatalf("surviving member is not contamination: %v", err)
			}
		})
	}
}

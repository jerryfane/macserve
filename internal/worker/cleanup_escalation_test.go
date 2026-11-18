package worker

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// #195 review F1: a slow SIGTERM round must not use up the cleanup before any
// SIGKILL. Every SIGTERM helper run here hangs until its deadline, and the
// member dies only of SIGKILL. A round that could last the whole bound sent
// only SIGTERM and the member was judged contamination without a SIGKILL;
// rounds end with the bound and choose the signal per member, and a member
// no SIGKILL has reached gets one when the bound closes.
func TestProtectedCleanupSlowTermStillSIGKILLs(t *testing.T) {
	for name, confirm := range map[string]time.Duration{"with a confirmation phase": 200 * time.Millisecond, "window only": 0} {
		t.Run(name, func(t *testing.T) {
			runner, command := helperRunner(t, "success")
			var started *exec.Cmd
			launch := runner.command
			runner.command = func(c Command) *exec.Cmd { started = launch(c); return started }
			runner.termGrace, runner.killGrace, runner.pollInterval = 10*time.Millisecond, 20*time.Millisecond, time.Millisecond
			runner.cleanupConfirm, runner.signalTimeout = confirm, 50*time.Millisecond
			runner.scope = scopeFixture()
			var mu sync.Mutex
			alive, terms, kills := true, 0, 0
			runner.scope.sample = func(context.Context) ([]processSample, error) {
				mu.Lock()
				defer mu.Unlock()
				if !alive {
					return nil, nil
				}
				return []processSample{{pid: 2147483646, group: started.Process.Pid, uid: runner.uid, start: "xcodebuild"}}, nil
			}
			runner.signalProcess = func(ctx context.Context, _ processSample, sig syscall.Signal) error {
				if sig == syscall.SIGTERM {
					mu.Lock()
					terms++
					mu.Unlock()
					<-ctx.Done()
					return ctx.Err()
				}
				mu.Lock()
				defer mu.Unlock()
				kills++
				alive = false
				return nil
			}
			result, err := runner.Run(context.Background(), command, io.Discard, io.Discard)
			mu.Lock()
			defer mu.Unlock()
			if err != nil || !result.CleanupOK || kills == 0 {
				t.Fatalf("slow SIGTERM held back SIGKILL: %d SIGTERM, %d SIGKILL: %+v, %v", terms, kills, result, err)
			}
		})
	}
}

// #195 review F3: a finalization's budget covers every command cleanup it
// can wait for beyond its windows. A cancelled job waits for its recipe
// command's cleanup before the finalizer, then for the evidence command
// still running when the cleanup budget ends; the verification window
// follows.
func TestFinalizationTimeoutCoversCancelledRecipeAndEvidenceCleanups(t *testing.T) {
	cancelled := processCleanupBound + DefaultCleanupTimeout + processCleanupBound + finalVerificationWindow
	if FinalizationTimeout < cancelled {
		t.Fatalf("FinalizationTimeout %v < a cancelled job's recipe cleanup, cleanup budget, evidence cleanup and verification window %v", FinalizationTimeout, cancelled)
	}
}

// #195 review F2: the account quiesce judges a survivor by completed
// escalation, not by time spent before a slow SIGTERM. The first signal
// helper run fails on time and is retried after a pause (signalWithRetry),
// three graces in all; the process ignores SIGTERM and dies of SIGKILL.
func TestQuiesceSlowSIGTERMIsNotASurvivor(t *testing.T) {
	s, agents, rows := devtoolWorld(t)
	s.grace = 50 * time.Millisecond
	agents.procs[200] = agentProcess{start: "30:0", uid: testJobUID, ppid: 1, executable: "/bin/sleep", platform: true}
	stubborn := sample(200, "30:0")
	alive := true
	s.sample = func(context.Context) ([]processSample, error) {
		live := append([]processSample(nil), rows...)
		if alive {
			live = append(live, stubborn)
		}
		return live, nil
	}
	var sent []syscall.Signal
	s.signal = func(_ context.Context, p processSample, sig syscall.Signal) error {
		if p.pid != 200 {
			return nil
		}
		sent = append(sent, sig)
		if sig == syscall.SIGTERM {
			time.Sleep(3 * s.grace)
			return nil
		}
		alive = false
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.quiesce(ctx); err != nil {
		t.Fatalf("slow SIGTERM judged a survivor before SIGKILL (sent %v): %v", sent, err)
	}
	if len(sent) == 0 || sent[len(sent)-1] != syscall.SIGKILL {
		t.Fatalf("signals %v, want escalation to SIGKILL", sent)
	}
	// Guard: one that also survives SIGKILL is still contamination.
	alive = true
	s.signal = func(context.Context, processSample, syscall.Signal) error { return nil }
	if err := s.quiesce(ctx); !errors.Is(err, ErrContamination) || !strings.Contains(err.Error(), "remain after termination") {
		t.Fatalf("SIGKILL survivor: %v", err)
	}
}

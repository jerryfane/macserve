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
// still running when the cleanup budget ends, then for the Metal toolchain
// unmount (/sbin/umount through the protected runner) still running when the
// verification window ends.
func TestFinalizationTimeoutCoversEveryCommandWindow(t *testing.T) {
	cancelled := processCleanupBound + DefaultCleanupTimeout + processCleanupBound + finalVerificationWindow + processCleanupBound
	if FinalizationTimeout < cancelled {
		t.Fatalf("FinalizationTimeout %v < a cancelled job's recipe cleanup, cleanup budget, evidence cleanup, verification window and unmount cleanup %v", FinalizationTimeout, cancelled)
	}
}

// #195 review P3: processCleanupBound is the protected cleanup's own timing
// at the runner's defaults, so a changed default cannot silently invalidate
// the finalization budget and the controller leases derived from it.
func TestProcessCleanupBoundFollowsRunnerDefaults(t *testing.T) {
	r := newProcessRunner()
	want := r.termGrace + r.killGrace + DefaultProcessCleanupTimeout + inspectWaitDelay + // window, confirmation, last helper output wait
		r.sampleTimeout + r.signalTimeout + inspectWaitDelay + r.killGrace + // listing, SIGKILL round and settle after the bound
		r.sampleTimeout // final listing
	if processCleanupBound != want {
		t.Fatalf("processCleanupBound %v, the runner's defaults give %v", processCleanupBound, want)
	}
}

// #195 review F1 (round 2): the cleanup bound is hard, so with several slow
// helpers the last round can end before SIGKILL reaches every member. Members
// still listed that no SIGKILL reached are not evidence: cleanup is
// unconfirmed (ErrCleanup), not contamination. Here each helper run takes
// 25 ms, SIGTERM is ignored and SIGKILL kills.
func TestProtectedCleanupUnescalatedMembersAreUnconfirmed(t *testing.T) {
	runner, command := helperRunner(t, "success")
	var started *exec.Cmd
	launch := runner.command
	runner.command = func(c Command) *exec.Cmd { started = launch(c); return started }
	runner.termGrace, runner.killGrace, runner.pollInterval = 10*time.Millisecond, 20*time.Millisecond, time.Millisecond
	runner.cleanupConfirm, runner.signalTimeout = 0, 60*time.Millisecond
	runner.scope = scopeFixture()
	var mu sync.Mutex
	alive := map[int]bool{}
	for pid := 2147483640; pid < 2147483645; pid++ {
		alive[pid] = true
	}
	kills := 0
	runner.scope.sample = func(context.Context) ([]processSample, error) {
		mu.Lock()
		defer mu.Unlock()
		var out []processSample
		for pid := range alive {
			out = append(out, processSample{pid: pid, group: started.Process.Pid, uid: runner.uid, start: "xcodebuild"})
		}
		return out, nil
	}
	runner.signalProcess = func(_ context.Context, p processSample, sig syscall.Signal) error {
		time.Sleep(25 * time.Millisecond)
		mu.Lock()
		defer mu.Unlock()
		if sig == syscall.SIGKILL {
			kills++
			delete(alive, p.pid)
		}
		return nil
	}
	result, err := runner.Run(context.Background(), command, io.Discard, io.Discard)
	mu.Lock()
	defer mu.Unlock()
	if len(alive) == 0 {
		t.Fatalf("every member was SIGKILLed in time (%d kills); the bound did not bind", kills)
	}
	if result.CleanupOK || !errors.Is(err, ErrCleanup) || errors.Is(err, ErrContamination) {
		t.Fatalf("%d members left without SIGKILL (%d delivered): %+v, %v; want unconfirmed, not contamination", len(alive), kills, result, err)
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

// #195 review round 3: the final listing gets the same foreign-UID and
// GUI-baseline checks as every other listing before its members are split
// into SIGKILL survivors and unescalated ones. A GUI baseline PID first seen
// in the job's group there is contamination, not unconfirmed cleanup, which
// the full-account quiesce (excluding baseline PIDs) would never report.
func TestProtectedCleanupBaselinePIDInFinalListingIsContamination(t *testing.T) {
	r := newProcessRunner()
	r.termGrace, r.killGrace, r.pollInterval, r.cleanupConfirm = 5*time.Millisecond, 5*time.Millisecond, time.Millisecond, 0
	r.scope = scopeFixture()
	const group = 201
	until := time.Now().Add(r.termGrace + r.killGrace)
	var mu sync.Mutex
	after := 0
	r.scope.sample = func(context.Context) ([]processSample, error) {
		mu.Lock()
		defer mu.Unlock()
		if time.Now().Before(until) {
			return nil, nil
		}
		// The listing after the bound sees the group empty; the final
		// listing finds the audited GUI process (PID 100) in it.
		if after++; after < 2 {
			return nil, nil
		}
		baseline := trustedGUI()
		baseline.group = group
		return []processSample{baseline}, nil
	}
	r.signalProcess = func(context.Context, processSample, syscall.Signal) error { return nil }
	err := r.cleanupProtectedGroup(processInstance{pid: group}, testJobUID, func() {}, func() bool { return false })
	if !errors.Is(err, ErrContamination) || !strings.Contains(err.Error(), "GUI baseline PID") {
		t.Fatalf("baseline PID in the final listing: %v; want contamination", err)
	}
}

//go:build darwin || linux

package worker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
)

// The only subprocess executed by the tests is this harmless Go helper (plus
// numeric-only process inspection). Apple scheduling/build/simulator commands
// are never invoked; the unexported launcher is replaced for these tests.
func TestNativeRunnerHelper(t *testing.T) {
	mode := os.Getenv("MACSERVE_RUNNER_HELPER")
	if mode == "" {
		return
	}
	switch mode {
	case "exit":
		fmt.Fprint(os.Stdout, "standard output\n")
		fmt.Fprint(os.Stderr, "standard error\n")
		os.Exit(7)
	case "success":
		fmt.Fprint(os.Stdout, "complete\n")
		os.Exit(0)
	case "linger":
		time.Sleep(500 * time.Millisecond)
		os.Exit(0)
	case "environment":
		dir, err := os.Getwd()
		if err != nil {
			os.Exit(91)
		}
		fmt.Fprintf(os.Stdout, "%s\n%s\n%s\n", dir, os.Getenv("VISIBLE"), os.Getenv("MACSERVE_PARENT_SECRET"))
		os.Exit(0)
	case "descendant":
		child := exec.Command(os.Args[0], "-test.run=^TestNativeRunnerHelper$")
		child.Env = []string{"MACSERVE_RUNNER_HELPER=hang"}
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if err := child.Start(); err != nil {
			os.Exit(92)
		}
		fmt.Fprintf(os.Stdout, "child=%d\n", child.Process.Pid)
		os.Exit(0)
	case "ignore-term":
		signal.Ignore(syscall.SIGTERM)
		fmt.Fprint(os.Stdout, "ready\n")
	case "hang":
		fmt.Fprint(os.Stdout, "ready\n")
	case "signal":
		_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
	case "already-shutdown", "shutdown-timeout":
		message := "Unable to shutdown device in current state: Shutdown"
		if mode == "shutdown-timeout" {
			message = "Operation timed out"
		}
		fmt.Fprintf(os.Stderr, "An error was encountered processing the command (domain=com.apple.CoreSimulator.SimError, code=405):\n%s\n", message)
		os.Exit(164)
	default:
		os.Exit(93)
	}
	for {
		time.Sleep(time.Hour)
	}
}

func helperRunner(t *testing.T, mode string) (*nativeRunner, Command) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	runner := newProcessRunner()
	runner.command = func(command Command) *exec.Cmd {
		return exec.Command(command.Executable, command.Args...)
	}
	runner.pollInterval = 10 * time.Millisecond
	runner.sampleInterval = 25 * time.Millisecond
	runner.termGrace = 50 * time.Millisecond
	runner.killGrace = time.Second
	runner.drainTimeout = 100 * time.Millisecond
	return runner, Command{
		Executable: executable,
		Args:       []string{"-test.run=^TestNativeRunnerHelper$"},
		Dir:        t.TempDir(),
		Env:        []string{"MACSERVE_RUNNER_HELPER=" + mode},
	}
}

// The boot retry tears down the device that failed to boot. When that device
// is already shut down, the production runner reports `simctl shutdown` as an
// ordinary non-zero exit error with CoreSimulator's state refusal; teardown
// accepts exactly that (delete and the absence proof still run) and the job
// retries on a fresh device. Any other shutdown failure is not retried.
func TestSimulatorRetryTeardownAcceptsAlreadyShutdownFromNativeRunner(t *testing.T) {
	for _, tc := range []struct {
		mode    string
		creates int
		succeed bool
	}{
		{mode: "already-shutdown", creates: 2, succeed: true},
		{mode: "shutdown-timeout", creates: 1},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			native, helper := helperRunner(t, tc.mode)
			runner := &fakeRunner{}
			var mu sync.Mutex
			booted, shutdowns := false, 0
			runner.hook = func(ctx context.Context, c Command, stdout, stderr io.Writer) (bool, ProcessResult, error) {
				mu.Lock()
				defer mu.Unlock()
				if len(c.Args) < 2 || c.Args[0] != "simctl" {
					return false, ProcessResult{}, nil
				}
				if c.Args[1] == "boot" && !booted {
					booted = true
					return true, ProcessResult{ExitCode: 164, CleanupOK: true}, nil
				}
				if c.Args[1] == "shutdown" {
					if shutdowns++; shutdowns == 1 {
						result, err := native.Run(ctx, helper, stdout, stderr)
						return true, result, err
					}
				}
				return false, ProcessResult{}, nil
			}
			engine := engineFixture(t, runner)
			source, data := sourceFixture(t)
			result, err := engine.Execute(context.Background(), fixtureJob(t, model.SimulatorUITest), source, bytes.NewReader(data), nil)
			if tc.succeed != (err == nil && result.State == model.Succeeded) || !result.CleanupOK {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			if got := len(simctl(runner, "create")); got != tc.creates {
				t.Fatalf("created %d devices, want %d", got, tc.creates)
			}
			if tc.succeed && len(simctl(runner, "delete")) != 2 {
				t.Fatalf("both devices must be deleted: %+v", simctl(runner, "delete"))
			}
		})
	}
}

func TestNativeRunnerExitAndOutput(t *testing.T) {
	runner, command := helperRunner(t, "exit")
	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := runner.Run(ctx, command, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "status 7") {
		t.Fatalf("nonzero exit was not reported: %v", err)
	}
	if result.ExitCode != 7 || result.Signal != "" || !result.CleanupOK {
		t.Fatalf("incorrect process status: %+v", result)
	}
	if stdout.String() != "standard output\n" || stderr.String() != "standard error\n" {
		t.Fatalf("lost output: stdout=%q stderr=%q", &stdout, &stderr)
	}
}

func TestNativeRunnerExplicitEnvironmentAndDirectory(t *testing.T) {
	t.Setenv("MACSERVE_PARENT_SECRET", "must-not-be-inherited")
	runner, command := helperRunner(t, "environment")
	command.Env = append(command.Env, "VISIBLE=approved")
	var stdout bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := runner.Run(ctx, command, &stdout, io.Discard)
	if err != nil || result.ExitCode != 0 || !result.CleanupOK {
		t.Fatalf("run: %+v, %v", result, err)
	}
	// Getwd can resolve the platform's temporary-directory symlink.
	lines := strings.Split(stdout.String(), "\n")
	if len(lines) != 4 || lines[1] != "approved" || lines[2] != "" {
		t.Fatalf("unexpected environment: %q", stdout.String())
	}
	actual, err := os.Stat(lines[0])
	if err != nil {
		t.Fatal(err)
	}
	wanted, err := os.Stat(command.Dir)
	if err != nil || !os.SameFile(actual, wanted) {
		t.Fatalf("working directory differs: %q, %v", lines[0], err)
	}
}

func TestNativeRunnerCleansInheritedPipesOnNormalExit(t *testing.T) {
	runner, command := helperRunner(t, "descendant")
	var stdout bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := runner.Run(ctx, command, &stdout, io.Discard)
	if err != nil || result.ExitCode != 0 || !result.CleanupOK {
		t.Fatalf("run: %+v, %v", result, err)
	}
	var child int
	for _, line := range strings.Split(stdout.String(), "\n") {
		if strings.HasPrefix(line, "child=") {
			child, err = strconv.Atoi(strings.TrimPrefix(line, "child="))
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if child == 0 {
		t.Fatalf("helper did not report descendant: %q", &stdout)
	}
	processes, err := sampleProcesses(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range processes {
		if p.pid == child && !p.zombie {
			t.Fatalf("descendant %d survived cleanup", child)
		}
	}
}

type readyWriter struct {
	once  sync.Once
	ready func()
}

func (w *readyWriter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("ready")) {
		w.once.Do(w.ready)
	}
	return len(p), nil
}

func TestNativeRunnerCancellationEscalatesToKill(t *testing.T) {
	runner, command := helperRunner(t, "ignore-term")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	writer := &readyWriter{ready: cancel}
	result, err := runner.Run(ctx, command, writer, io.Discard)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("missing cancellation: %v", err)
	}
	if result.Signal != syscall.SIGKILL.String() || result.ExitCode != -1 || !result.CleanupOK {
		t.Fatalf("TERM-resistant child not killed and reaped: %+v, %v", result, err)
	}
}

func TestNativeRunnerDeadline(t *testing.T) {
	runner, command := helperRunner(t, "hang")
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	result, err := runner.Run(ctx, command, io.Discard, io.Discard)
	if !errors.Is(err, context.DeadlineExceeded) || !result.CleanupOK || result.Signal == "" {
		t.Fatalf("deadline did not terminate child: %+v, %v", result, err)
	}
}

func TestNativeRunnerReportsSignal(t *testing.T) {
	runner, command := helperRunner(t, "signal")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := runner.Run(ctx, command, io.Discard, io.Discard)
	if err == nil || result.Signal != syscall.SIGTERM.String() || result.ExitCode != -1 || !result.CleanupOK {
		t.Fatalf("wrong signal status: %+v, %v", result, err)
	}
}

func TestNativeRunnerMemoryIncludesOtherWorkerUIDGroups(t *testing.T) {
	runner, command := helperRunner(t, "hang")
	command.MemoryLimitMiB = 150
	runner.sample = func(context.Context) ([]processSample, error) {
		return []processSample{
			{pid: 10, group: 10, uid: os.Geteuid(), footprintKiB: 80 * 1024},
			{pid: 11, group: 11, uid: os.Geteuid(), footprintKiB: 80 * 1024},
			{pid: 12, group: 12, uid: os.Geteuid() + 1, footprintKiB: 1000 * 1024},
		}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := runner.Run(ctx, command, io.Discard, io.Discard)
	if !errors.Is(err, ErrMemoryLimit) || !result.CleanupOK || result.PeakMemoryMiB < 160 || result.PeakMemoryMiB >= 1000 {
		t.Fatalf("wrong worker-UID budget enforcement: %+v, %v", result, err)
	}
}

func TestNativeRunnerMemoryIgnoresOtherUIDAndZombies(t *testing.T) {
	runner, command := helperRunner(t, "linger")
	command.MemoryLimitMiB = 2
	runner.sample = func(context.Context) ([]processSample, error) {
		return []processSample{
			{uid: os.Geteuid(), footprintKiB: 2 * 1024},
			{uid: os.Geteuid(), footprintKiB: 100 * 1024, zombie: true},
			{uid: os.Geteuid() + 1, footprintKiB: 100 * 1024},
		}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := runner.Run(ctx, command, io.Discard, io.Discard)
	if err != nil || result.ExitCode != 0 || !result.CleanupOK {
		t.Fatalf("unexpected budget failure: %+v, %v", result, err)
	}
}

// A booting simulator starts hundreds of worker-UID processes that each map
// the same shared pages; their summed RSS charges those pages once per
// process. The budget charges each process's footprint instead.
func TestNativeRunnerMemoryChargesFootprintNotSharedRSS(t *testing.T) {
	runner, command := helperRunner(t, "linger")
	command.MemoryLimitMiB = 1024
	rows := make([]processSample, 100)
	for i := range rows {
		rows[i] = processSample{pid: 100 + i, group: 100, uid: os.Geteuid(), rssKiB: 300 * 1024, footprintKiB: 4 * 1024}
	}
	runner.sample = func(context.Context) ([]processSample, error) { return rows, nil }
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := runner.Run(ctx, command, io.Discard, io.Discard)
	if err != nil || result.ExitCode != 0 || !result.CleanupOK || result.PeakMemoryMiB < 400 || result.PeakMemoryMiB >= 1024 {
		t.Fatalf("shared resident pages were charged to the budget: %+v, %v", result, err)
	}
}

func TestNativeRunnerMemorySampleTimeoutDoesNotStopChild(t *testing.T) {
	runner, command := helperRunner(t, "linger")
	var calls atomic.Int32
	runner.sample = func(context.Context) ([]processSample, error) {
		if calls.Add(1) == 1 {
			// The production ps sample was killed at its deadline while a
			// simulator booted.
			time.Sleep(200 * time.Millisecond)
			return nil, errors.New("read process RSS: signal: killed")
		}
		return []processSample{{uid: os.Geteuid()}}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := runner.Run(ctx, command, io.Discard, io.Discard)
	if err != nil || result.ExitCode != 0 || result.Signal != "" || !result.CleanupOK || calls.Load() < 2 {
		t.Fatalf("one slow sample stopped the command: %+v, %v, %d samples", result, err, calls.Load())
	}
}

func TestNativeRunnerMemorySampleFailureStopsChild(t *testing.T) {
	runner, command := helperRunner(t, "hang")
	// Memory goes unobserved for sampleFailureTimeouts of these; cleanup's
	// group inspection keeps an unhurried ps.
	runner.sampleTimeout = 20 * time.Millisecond
	runner.inspect = func(context.Context) ([]processSample, error) { return sampleProcesses(context.Background()) }
	sampleErr := errors.New("sampler unavailable")
	var calls atomic.Int32
	runner.sample = func(context.Context) ([]processSample, error) {
		calls.Add(1)
		return nil, sampleErr
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := runner.Run(ctx, command, io.Discard, io.Discard)
	if !errors.Is(err, sampleErr) || errors.Is(err, ErrMemoryLimit) || !result.CleanupOK || result.Signal == "" || calls.Load() < 2 {
		t.Fatalf("persistent sampling failure was not fail-closed after retries: %+v, %v, %d samples", result, err, calls.Load())
	}
}

type brokenWriter struct{ err error }

func (w brokenWriter) Write([]byte) (int, error) { return 0, w.err }

func TestNativeRunnerOutputFailureStopsChild(t *testing.T) {
	runner, command := helperRunner(t, "hang")
	writeErr := errors.New("log stream disconnected")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := runner.Run(ctx, command, brokenWriter{err: writeErr}, io.Discard)
	if !errors.Is(err, writeErr) || !result.CleanupOK || result.Signal == "" {
		t.Fatalf("output failure was not propagated: %+v, %v", result, err)
	}
}

func TestNativeRunnerStartFailureHasNoCleanupDebt(t *testing.T) {
	runner, command := helperRunner(t, "hang")
	command.Executable = command.Dir + "/missing-command"
	result, err := runner.Run(context.Background(), command, io.Discard, io.Discard)
	if !errors.Is(err, fs.ErrNotExist) || !result.CleanupOK || result.ExitCode != -1 {
		t.Fatalf("incorrect start failure: %+v, %v", result, err)
	}
}

func TestNativeRunnerUnverifiableCleanupFails(t *testing.T) {
	runner, command := helperRunner(t, "hang")
	runner.termGrace = 10 * time.Millisecond
	runner.killGrace = 30 * time.Millisecond
	runner.sampleTimeout = 10 * time.Millisecond
	inspectErr := errors.New("cannot inspect process ownership")
	runner.inspect = func(context.Context) ([]processSample, error) { return nil, inspectErr }
	runner.sample = func(context.Context) ([]processSample, error) { return nil, inspectErr }
	result, err := runner.Run(context.Background(), command, io.Discard, io.Discard)
	if !errors.Is(err, ErrCleanup) || !errors.Is(err, inspectErr) || result.CleanupOK {
		t.Fatalf("unverified cleanup was accepted: %+v, %v", result, err)
	}
}

func TestNativeRunnerRefusesOwnerGroup(t *testing.T) {
	runner, _ := helperRunner(t, "hang")
	err := runner.cleanupGroup(syscall.Getpgrp(), os.Geteuid(), func() {}, func() bool { return true }, func() bool { return false })
	if !errors.Is(err, ErrCleanup) {
		t.Fatalf("owner group not rejected: %v", err)
	}
}

func TestNativeRunnerRejectsForeignUIDGroup(t *testing.T) {
	runner, command := helperRunner(t, "hang")
	other := exec.Command(command.Executable, command.Args...)
	other.Env = command.Env
	other.Dir = command.Dir
	other.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := other.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = other.Process.Kill()
		_ = other.Wait()
	})
	runner.termGrace = 10 * time.Millisecond
	runner.killGrace = 10 * time.Millisecond
	runner.inspect = func(context.Context) ([]processSample, error) {
		return []processSample{
			{pid: other.Process.Pid, group: other.Process.Pid, uid: os.Geteuid() + 1},
		}, nil
	}
	err := runner.cleanupGroup(other.Process.Pid, os.Geteuid(), func() {}, func() bool { return true }, func() bool { return false })
	if !errors.Is(err, ErrCleanup) {
		t.Fatalf("foreign group was accepted: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	processes, err := sampleProcesses(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range processes {
		if p.pid == other.Process.Pid && !p.zombie {
			return
		}
	}
	t.Fatal("a process reported under another UID was signalled")
}

func TestNativeRunnerProcessSnapshotValidation(t *testing.T) {
	for _, text := range []string{"", "1 2 3\n", "1 2 3 -1 S\n", "1 2 x 5 S\n"} {
		if _, err := parseProcesses(text); err == nil {
			t.Fatalf("accepted invalid process snapshot %q", text)
		}
	}
	processes, err := parseProcesses("10 10 200 4096 S\n11 10 200 0 Z+\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(processes) != 2 || processes[0].rssKiB != 4096 || !processes[1].zombie {
		t.Fatalf("incorrect process accounting snapshot: %+v", processes)
	}
}

func TestProcessSnapshotNormalizesSignedDarwinUID(t *testing.T) {
	processes, err := parseProcesses("40 40 -2 128 Ss\n41 41 501 256 S\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(processes) != 2 || processes[0].uid != int(uint32(4294967294)) || processes[1].uid != 501 {
		t.Fatalf("incorrect signed UID normalization: %+v", processes)
	}
}

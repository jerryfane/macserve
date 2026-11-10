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
	"path/filepath"
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
	runner.sample = afterBaseline(nil, func(context.Context) ([]processSample, error) {
		return []processSample{
			{pid: 10, group: 10, uid: os.Geteuid(), footprintKiB: 80 * 1024},
			{pid: 11, group: 11, uid: os.Geteuid(), footprintKiB: 80 * 1024},
			{pid: 12, group: 12, uid: os.Geteuid() + 1, footprintKiB: 1000 * 1024},
		}, nil
	})
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
	runner.sample = afterBaseline(nil, func(context.Context) ([]processSample, error) {
		return []processSample{
			{uid: os.Geteuid(), footprintKiB: 2 * 1024},
			{uid: os.Geteuid(), footprintKiB: 100 * 1024, zombie: true},
			{uid: os.Geteuid() + 1, footprintKiB: 100 * 1024},
		}, nil
	})
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
	runner.sample = afterBaseline(nil, func(context.Context) ([]processSample, error) { return rows, nil })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := runner.Run(ctx, command, io.Discard, io.Discard)
	if err != nil || result.ExitCode != 0 || !result.CleanupOK || result.PeakMemoryMiB < 400 || result.PeakMemoryMiB >= 1024 {
		t.Fatalf("shared resident pages were charged to the budget: %+v, %v", result, err)
	}
}

// afterBaseline answers the sample taken before the command starts with
// baseline and every later sample with next.
func afterBaseline(baseline []processSample, next processSampler) processSampler {
	var started atomic.Bool
	return func(ctx context.Context) ([]processSample, error) {
		if !started.Swap(true) {
			return baseline, nil
		}
		return next(ctx)
	}
}

// gigabytesOfJobUID is one job-UID process with gib GiB plus extraMiB MiB of
// footprint.
func gigabytesOfJobUID(gib, extraMiB int64) []processSample {
	return []processSample{{pid: 10, group: 10, uid: os.Geteuid(), footprintKiB: gib<<20 + extraMiB<<10}}
}

// The job UID's GUI session is always logged in; on the Studio a long-running
// desktop session's footprint (which counts compressed and swapped memory)
// was 2.5x its RSS. Only what the command adds is charged.
func TestNativeRunnerMemoryChargesOnlyAboveBaseline(t *testing.T) {
	runner, command := helperRunner(t, "linger")
	command.MemoryLimitMiB = 1024
	runner.sample = afterBaseline(gigabytesOfJobUID(40, 0), func(context.Context) ([]processSample, error) { return gigabytesOfJobUID(40, 100), nil })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := runner.Run(ctx, command, io.Discard, io.Discard)
	if err != nil || result.ExitCode != 0 || !result.CleanupOK || result.PeakMemoryMiB != 100 {
		t.Fatalf("pre-existing job-UID footprint was charged to the command: %+v, %v", result, err)
	}
}

func TestNativeRunnerMemoryIncreaseOverBudgetFails(t *testing.T) {
	runner, command := helperRunner(t, "hang")
	command.MemoryLimitMiB = 1024
	runner.sample = afterBaseline(gigabytesOfJobUID(40, 0), func(context.Context) ([]processSample, error) { return gigabytesOfJobUID(42, 0), nil })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := runner.Run(ctx, command, io.Discard, io.Discard)
	if !errors.Is(err, ErrMemoryLimit) || !result.CleanupOK || result.Signal == "" || result.PeakMemoryMiB != 2048 {
		t.Fatalf("command increase over budget was not charged and stopped: %+v, %v", result, err)
	}
}

// A job boots its simulator in one command and tests in a later one; the
// simulator it left running is still the job's memory, so every command of a
// job is charged above the footprint that preceded the job's first command.
func TestNativeRunnerMemoryJobBaselineSpansCommands(t *testing.T) {
	runner, command := helperRunner(t, "success")
	command.MemoryLimitMiB = 1024
	command.MemoryBaseline = &MemoryBaseline{}
	footprint := gigabytesOfJobUID(40, 0)
	runner.sample = func(context.Context) ([]processSample, error) { return footprint, nil }
	var log bytes.Buffer
	runner.diagnostics = &log
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if result, err := runner.Run(ctx, command, io.Discard, io.Discard); err != nil || result.PeakMemoryMiB != 0 {
		t.Fatalf("first job command: %+v, %v", result, err)
	}
	// The first command's simulator is still running when the next starts.
	footprint = gigabytesOfJobUID(42, 0)
	command.Env = []string{"MACSERVE_RUNNER_HELPER=hang"}
	result, err := runner.Run(ctx, command, io.Discard, io.Discard)
	if !errors.Is(err, ErrMemoryLimit) || !strings.Contains(err.Error(), "above the 40960 MiB job-UID baseline") || result.PeakMemoryMiB != 2048 || !result.CleanupOK {
		t.Fatalf("memory a job left running escaped its budget: %+v, %v", result, err)
	}
	if got := log.String(); got != "macserve worker: job memory baseline: job-UID footprint 40960 MiB\n" {
		t.Fatalf("job memory baseline not logged once at job start: %q", got)
	}
}

func TestNativeRunnerMemoryBaselineFailureRefusesCommand(t *testing.T) {
	runner, command := helperRunner(t, "success")
	launch := runner.command
	var launched atomic.Int32
	runner.command = func(command Command) *exec.Cmd {
		launched.Add(1)
		return launch(command)
	}
	sampleErr := errors.New("sampler unavailable")
	var calls atomic.Int32
	runner.sample = func(context.Context) ([]processSample, error) {
		if calls.Add(1) == 1 {
			return nil, sampleErr
		}
		return gigabytesOfJobUID(0, 1), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := runner.Run(ctx, command, io.Discard, io.Discard)
	if !errors.Is(err, sampleErr) || launched.Load() != 0 || !result.CleanupOK || result.ExitCode != -1 {
		t.Fatalf("command started without a memory baseline: %+v, %v, %d launches", result, err, launched.Load())
	}
}

func TestNativeRunnerMemorySampleTimeoutDoesNotStopChild(t *testing.T) {
	runner, command := helperRunner(t, "linger")
	var calls atomic.Int32
	runner.sample = func(context.Context) ([]processSample, error) {
		if calls.Add(1) == 2 {
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
	if err != nil || result.ExitCode != 0 || result.Signal != "" || !result.CleanupOK || calls.Load() < 3 {
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
	runner.sample = afterBaseline(nil, func(context.Context) ([]processSample, error) {
		calls.Add(1)
		return nil, sampleErr
	})
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
	runner.sample = afterBaseline(nil, func(context.Context) ([]processSample, error) { return nil, inspectErr })
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

// flakyInspector fails (slowly) on its first call, then defers to next.
func flakyInspector(delay time.Duration, err error, next processSampler) processSampler {
	var calls atomic.Int32
	return func(ctx context.Context) ([]processSample, error) {
		if calls.Add(1) == 1 {
			time.Sleep(delay)
			return nil, err
		}
		return next(ctx)
	}
}

func TestNativeRunnerCleanupRetriesTransientInspection(t *testing.T) {
	runner, command := helperRunner(t, "hang")
	runner.inspect = flakyInspector(20*time.Millisecond, context.DeadlineExceeded, runner.inspect)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	result, err := runner.Run(ctx, command, io.Discard, io.Discard)
	if errors.Is(err, ErrCleanup) || !result.CleanupOK {
		t.Fatalf("one failed inspection left cleanup unconfirmed: %+v, %v", result, err)
	}
}

func TestProtectedCleanupRetriesTransientListing(t *testing.T) {
	r := newProcessRunner()
	r.termGrace, r.killGrace, r.pollInterval = 20*time.Millisecond, 20*time.Millisecond, time.Millisecond
	r.scope = scopeFixture()
	var calls atomic.Int32
	r.scope.sample = func(context.Context) ([]processSample, error) {
		if calls.Add(1) == 1 {
			return nil, context.DeadlineExceeded
		}
		return []processSample{trustedGUI()}, nil
	}
	r.signalProcess = func(context.Context, processSample, syscall.Signal) error { return nil }
	if err := r.cleanupProtectedGroup(201, testJobUID, func() {}, func() bool { return true }); err != nil {
		t.Fatalf("one failed listing left cleanup unconfirmed: %v", err)
	}
}

func TestProtectedCleanupPersistentListingFailureFails(t *testing.T) {
	r := newProcessRunner()
	r.termGrace, r.killGrace, r.pollInterval, r.sampleTimeout = 10*time.Millisecond, 10*time.Millisecond, time.Millisecond, 10*time.Millisecond
	r.scope = scopeFixture()
	listErr := errors.New("cannot list processes")
	r.scope.sample = func(context.Context) ([]processSample, error) { return nil, listErr }
	r.signalProcess = func(context.Context, processSample, syscall.Signal) error {
		t.Fatal("signalled without a listing")
		return nil
	}
	if err := r.cleanupProtectedGroup(201, testJobUID, func() {}, func() bool { return true }); !errors.Is(err, ErrCleanup) || !errors.Is(err, listErr) || !strings.Contains(err.Error(), "protected cleanup: final listing: ") {
		t.Fatalf("persistent listing failure accepted: %v", err)
	}
}

func TestProtectedCleanupGroupLiveAfterWindowIsContamination(t *testing.T) {
	runner, command := helperRunner(t, "success")
	var started *exec.Cmd
	launch := runner.command
	runner.command = func(c Command) *exec.Cmd { started = launch(c); return started }
	runner.termGrace, runner.killGrace = 10*time.Millisecond, 10*time.Millisecond
	runner.scope = scopeFixture()
	runner.scope.sample = func(context.Context) ([]processSample, error) {
		return []processSample{{pid: 2147483646, group: started.Process.Pid, uid: runner.uid, start: "stuck"}}, nil
	}
	runner.signalProcess = func(context.Context, processSample, syscall.Signal) error { return nil }
	var diagnostics bytes.Buffer
	runner.diagnostics = &diagnostics
	result, err := runner.Run(context.Background(), command, io.Discard, io.Discard)
	if !errors.Is(err, ErrCleanup) || !errors.Is(err, ErrContamination) || result.CleanupOK {
		t.Fatalf("live group after the window was accepted: %+v, %v", result, err)
	}
	prefix := filepath.Base(command.Executable) + ": worker process cleanup failed"
	phase := "protected cleanup: job group still live after the cleanup window"
	if !strings.Contains(err.Error(), prefix) || !strings.Contains(err.Error(), phase) || !strings.HasPrefix(diagnostics.String(), "macserve worker: "+prefix+"; ") || !strings.Contains(diagnostics.String(), phase) {
		t.Fatalf("cleanup failure does not name its command and phase: %q / %q", err, diagnostics.String())
	}
}

// A command of a job in lane mode is charged its own lane's processes, so it
// never samples the account-wide baseline: a failing baseline sample cannot
// refuse it. A command outside lane mode still needs that baseline.
func TestLaneCommandSkipsAccountBaseline(t *testing.T) {
	for _, lane := range []bool{true, false} {
		runner, command := helperRunner(t, "success")
		var calls atomic.Int32
		runner.sample = func(context.Context) ([]processSample, error) {
			if calls.Add(1) == 1 {
				return nil, errors.New("account sample unavailable")
			}
			return nil, nil
		}
		command.JobID = "job-a"
		if lane {
			runner.lanes = trackerFor(syscall.Getpid(), os.Geteuid(), map[int]processDescription{})
			runner.lanes.begin("job-a", time.Now())
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := runner.Run(ctx, command, io.Discard, io.Discard)
		cancel()
		refused := err != nil && strings.Contains(err.Error(), "sample worker memory baseline")
		if lane == refused {
			t.Fatalf("lane=%v: baseline refusal %v (err %v)", lane, refused, err)
		}
	}
}

// Darwin's killpg can return EPERM for a group whose member is exiting, after
// it delivered the signal (CI macOS, 2026-11-10). Cleanup is decided by the
// confirmation listing and reap, not by that return; a member that survives
// still fails cleanup.
func TestNativeRunnerCleanupToleratesExitingGroupEPERM(t *testing.T) {
	for _, delivered := range []bool{true, false} {
		runner, command := helperRunner(t, "hang")
		runner.termGrace, runner.killGrace = 200*time.Millisecond, 200*time.Millisecond
		var target atomic.Int64
		runner.kill = func(pid int, sig syscall.Signal) error {
			target.Store(int64(pid))
			if delivered {
				if err := syscall.Kill(pid, sig); err != nil {
					return err
				}
			}
			return syscall.EPERM
		}
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		result, err := runner.Run(ctx, command, io.Discard, io.Discard)
		cancel()
		if delivered && (errors.Is(err, ErrCleanup) || !result.CleanupOK) {
			t.Fatalf("delivered signal's EPERM left cleanup unconfirmed: %+v, %v", result, err)
		}
		if !delivered {
			syscall.Kill(int(target.Load()), syscall.SIGKILL)
			if result.CleanupOK || !errors.Is(err, ErrCleanup) {
				t.Fatalf("surviving member passed cleanup: %+v, %v", result, err)
			}
		}
	}
}

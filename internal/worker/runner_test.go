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
	"syscall"
	"testing"
	"time"
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
			{pid: 10, group: 10, uid: os.Geteuid(), rssKiB: 80 * 1024},
			{pid: 11, group: 11, uid: os.Geteuid(), rssKiB: 80 * 1024},
			{pid: 12, group: 12, uid: os.Geteuid() + 1, rssKiB: 1000 * 1024},
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
	runner, command := helperRunner(t, "success")
	command.MemoryLimitMiB = 2
	runner.sample = func(context.Context) ([]processSample, error) {
		return []processSample{
			{uid: os.Geteuid(), rssKiB: 2 * 1024},
			{uid: os.Geteuid(), rssKiB: 100 * 1024, zombie: true},
			{uid: os.Geteuid() + 1, rssKiB: 100 * 1024},
		}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := runner.Run(ctx, command, io.Discard, io.Discard)
	if err != nil || result.ExitCode != 0 || !result.CleanupOK {
		t.Fatalf("unexpected budget failure: %+v, %v", result, err)
	}
}

func TestNativeRunnerMemorySampleFailureStopsChild(t *testing.T) {
	runner, command := helperRunner(t, "hang")
	sampleErr := errors.New("sampler unavailable")
	runner.sample = func(context.Context) ([]processSample, error) { return nil, sampleErr }
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := runner.Run(ctx, command, io.Discard, io.Discard)
	if !errors.Is(err, sampleErr) || errors.Is(err, ErrMemoryLimit) || !result.CleanupOK || result.Signal == "" {
		t.Fatalf("sampling failure was not fail-closed: %+v, %v", result, err)
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

//go:build darwin || linux

package worker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	// ErrMemoryLimit means the sampled aggregate phys_footprint of the worker
	// UID's live processes exceeded the budget.
	ErrMemoryLimit = errors.New("worker memory budget exceeded")
	// ErrCleanup means the runner could not prove its process group was cleaned.
	ErrCleanup = errors.New("worker process cleanup failed")
)

// sampleFailureTimeouts bounds how long memory may go unobserved: the job
// fails closed once no sample has succeeded for this many sample timeouts
// (30 s at the production 5 s), never because one sample was slow or failed.
const sampleFailureTimeouts = 6

type processSample struct {
	pid    int
	group  int
	uid    int
	rssKiB int64
	// footprintKiB is the memory the platform charges the process: Darwin's
	// phys_footprint, which excludes shared clean pages; RSS on Linux.
	footprintKiB int64
	zombie       bool
	start        string
}

type processSampler func(context.Context) ([]processSample, error)

type nativeRunner struct {
	command         func(Command) *exec.Cmd
	sample          processSampler
	inspect         processSampler
	pollInterval    time.Duration
	sampleInterval  time.Duration
	sampleTimeout   time.Duration
	termGrace       time.Duration
	killGrace       time.Duration
	drainTimeout    time.Duration
	uid             int
	launchDir       string
	scope           *processScope
	signalProcess   func(context.Context, processSample, syscall.Signal) error
	baselinePath    string
	persistencePath string
	persistence     func(context.Context) error
	// console refuses admission unless the owner or the login window holds
	// /dev/console (hostguard.ConsoleAdmissible). Nil refuses.
	console func() error
	// diagnostics receives tolerated memory sampling failures; nil discards.
	diagnostics io.Writer
}

// newProcessRunner is the process/pipes implementation. Production construction
// is exclusively through NewNativeRunner, which binds the protected UID scope.
func newProcessRunner() *nativeRunner {
	r := &nativeRunner{
		uid:            os.Geteuid(),
		inspect:        sampleProcesses,
		pollInterval:   20 * time.Millisecond,
		sampleInterval: 250 * time.Millisecond,
		sampleTimeout:  5 * time.Second,
		termGrace:      500 * time.Millisecond,
		killGrace:      time.Second,
		drainTimeout:   250 * time.Millisecond,
	}
	r.sample = func(ctx context.Context) ([]processSample, error) { return memoryProcesses(ctx, r.uid) }
	return r
}

type pipeResult struct {
	stream string
	err    error
}

type synchronizedWriter struct {
	mu     *sync.Mutex
	writer io.Writer
}

func (w synchronizedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.writer.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	return n, err
}

// exitStatusError is a reaped command's ordinary non-zero exit, with no
// signal: the command's own verdict rather than a runner, output, deadline or
// cleanup failure.
type exitStatusError struct{ code int }

func (e *exitStatusError) Error() string {
	return fmt.Sprintf("worker command exited with status %d", e.code)
}

// onlyExitStatus reports whether err is exactly one ordinary non-zero exit
// with status code and nothing else joined to it.
func onlyExitStatus(err error, code int) bool {
	for {
		switch e := err.(type) {
		case *exitStatusError:
			return e.code == code
		case interface{ Unwrap() []error }:
			errs := e.Unwrap()
			if len(errs) != 1 {
				return false
			}
			err = errs[0]
		default:
			return false
		}
	}
}

// Run does not inherit the caller's environment or working directory. Writers
// must return from Write; as with other io.Writer consumers, a caller-provided
// writer that never returns cannot be interrupted by closing the child pipes.
func (r *nativeRunner) Run(ctx context.Context, command Command, stdout, stderr io.Writer) (result ProcessResult, runErr error) {
	result.ExitCode = -1
	result.CleanupOK = true // No child exists until Start succeeds.
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if r.command == nil {
		return result, errors.New("protected command launcher is required")
	}
	if !filepath.IsAbs(command.Executable) || !filepath.IsAbs(command.Dir) {
		return result, errors.New("worker command executable and directory must be absolute")
	}
	if command.MemoryLimitMiB < 0 {
		return result, errors.New("worker command memory budget must not be negative")
	}
	// The job UID's GUI session is always logged in, and its footprint
	// (including compressed and swapped memory) is outside the job's control.
	// A command is charged only for footprint above the job UID's footprint
	// sampled immediately before its job's first command; without that
	// baseline it must not start.
	baseline := command.MemoryBaseline
	if baseline == nil {
		baseline = &MemoryBaseline{}
	}
	if !baseline.sampled {
		baselineCtx, cancelBaseline := context.WithTimeout(ctx, r.sampleTimeout)
		samples, err := r.sample(baselineCtx)
		cancelBaseline()
		if err != nil {
			return result, fmt.Errorf("sample worker memory baseline: %w", err)
		}
		kib, err := footprintKiB(samples, r.uid)
		if err != nil {
			return result, fmt.Errorf("sample worker memory baseline: %w", err)
		}
		*baseline = MemoryBaseline{sampled: true, kib: kib}
	}
	baselineKiB := baseline.kib
	result.BaselineFootprintMiB = kibToMiB(baselineKiB)
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	outRead, outWrite, err := os.Pipe()
	if err != nil {
		return result, fmt.Errorf("open stdout pipe: %w", err)
	}
	defer outRead.Close()
	defer outWrite.Close()
	errRead, errWrite, err := os.Pipe()
	if err != nil {
		return result, fmt.Errorf("open stderr pipe: %w", err)
	}
	defer errRead.Close()
	defer errWrite.Close()

	cmd := r.command(command)
	cmd.Dir = command.Dir
	if r.launchDir != "" {
		cmd.Dir = r.launchDir
	}
	cmd.Env = append([]string{}, command.Env...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout, cmd.Stderr = outWrite, errWrite
	if err := cmd.Start(); err != nil {
		return result, fmt.Errorf("start worker command: %w", err)
	}
	result.CleanupOK = false
	_ = outWrite.Close()
	_ = errWrite.Close()
	pid := cmd.Process.Pid
	uid := r.uid
	defer cmd.Process.Release()

	pipes := make(chan pipeResult, 2)
	var outputMu sync.Mutex
	pump := func(stream string, reader *os.File, writer io.Writer) {
		_, err := io.Copy(synchronizedWriter{mu: &outputMu, writer: writer}, reader)
		_ = reader.Close()
		pipes <- pipeResult{stream: stream, err: err}
	}
	go pump("stdout", outRead, stdout)
	go pump("stderr", errRead, stderr)
	remainingPipes := 2
	pipeClosed := false
	recordPipe := func(p pipeResult) {
		remainingPipes--
		if p.err != nil && !(pipeClosed && errors.Is(p.err, os.ErrClosed)) {
			runErr = errors.Join(runErr, fmt.Errorf("worker %s output: %w", p.stream, p.err))
		}
	}

	// Wait4(WNOHANG) keeps wait bounded even if a child cannot be killed; no
	// waiter goroutine can be stranded on an uninterruptible child. We own the
	// pipes ourselves, so exec.Cmd has no copying goroutines to wait for.
	reaped := false
	waitFailed := false
	reap := func() {
		if reaped || waitFailed {
			return
		}
		var status syscall.WaitStatus
		waited, err := syscall.Wait4(pid, &status, syscall.WNOHANG, nil)
		if errors.Is(err, syscall.EINTR) {
			return
		}
		if err != nil {
			waitFailed = true
			runErr = errors.Join(runErr, fmt.Errorf("wait for worker command: %w", err))
			return
		}
		if waited == 0 {
			return
		}
		reaped = true
		result.ExitCode = status.ExitStatus()
		if status.Signaled() {
			result.Signal = status.Signal().String()
		}
	}
	observe := func(samples []processSample) error {
		totalKiB, err := footprintKiB(samples, uid)
		if err != nil {
			return err
		}
		charged := kibToMiB(max(0, totalKiB-baselineKiB))
		result.PeakMemoryMiB = max(result.PeakMemoryMiB, charged)
		if command.MemoryLimitMiB > 0 && charged > int64(command.MemoryLimitMiB) {
			return fmt.Errorf("%w: sampled %d MiB above the %d MiB job-UID baseline, budget %d MiB (monitored, not a hard cap)", ErrMemoryLimit, charged, result.BaselineFootprintMiB, command.MemoryLimitMiB)
		}
		return nil
	}

	poll := time.NewTicker(r.pollInterval)
	defer poll.Stop()
	memory := time.NewTicker(r.sampleInterval)
	defer memory.Stop()
	// Sampling runs beside the loop, so a slow sample never delays reaping,
	// output or cancellation. A failed or timed-out sample is reported and
	// tolerated; the job fails closed once no sample has succeeded for
	// sampleFailureTimeouts sample timeouts.
	type memorySample struct {
		samples []processSample
		err     error
	}
	sampled := make(chan memorySample, 1)
	sampling := false
	samplingCtx, stopSampling := context.WithCancel(context.Background())
	sampleMemory := func() {
		if sampling {
			return
		}
		sampling = true
		go func() {
			ctx, cancel := context.WithTimeout(samplingCtx, r.sampleTimeout)
			defer cancel()
			samples, err := r.sample(ctx)
			sampled <- memorySample{samples: samples, err: err}
		}()
	}
	observed := time.Now()
	failures := 0
	var lastFailure error
	recordSample := func(s memorySample) {
		sampling = false
		if s.err != nil {
			failures++
			lastFailure = s.err
			if r.diagnostics != nil {
				fmt.Fprintf(r.diagnostics, "macserve worker: memory sample failed (%d consecutive): %v\n", failures, s.err)
			}
			return
		}
		observed, failures, lastFailure = time.Now(), 0, nil
		runErr = errors.Join(runErr, observe(s.samples))
	}
	checkObserved := func() {
		unobserved := time.Since(observed)
		if unobserved <= sampleFailureTimeouts*r.sampleTimeout {
			return
		}
		if lastFailure == nil {
			lastFailure = errors.New("memory sample did not complete")
		}
		runErr = errors.Join(runErr, fmt.Errorf("sample worker memory: no sample succeeded for %s (%d failed): %w", unobserved.Round(time.Millisecond), failures, lastFailure))
	}
	sampleMemory()
	for runErr == nil {
		reap()
		if reaped || waitFailed {
			break
		}
		select {
		case <-ctx.Done():
			runErr = ctx.Err()
		case p := <-pipes:
			recordPipe(p)
		case <-poll.C:
		case s := <-sampled:
			recordSample(s)
		case <-memory.C:
			checkObserved()
			sampleMemory()
		}
	}
	// The command has finished or failed; a sample still in flight no longer
	// decides anything and must not outlive Run.
	stopSampling()
	if sampling {
		<-sampled
	}
	if ctx.Err() != nil {
		runErr = errors.Join(runErr, ctx.Err())
	}

	cleanupErr := r.cleanupGroup(pid, uid, reap, func() bool { return reaped }, func() bool { return waitFailed })
	result.CleanupOK = cleanupErr == nil
	if cleanupErr != nil {
		runErr = errors.Join(runErr, cleanupErr)
	}
	if reaped && (result.ExitCode != 0 || result.Signal != "") {
		if result.Signal != "" {
			runErr = errors.Join(runErr, fmt.Errorf("worker command terminated by signal %s", result.Signal))
		} else {
			runErr = errors.Join(runErr, &exitStatusError{code: result.ExitCode})
		}
	}

	// A descendant that escaped the group may retain a pipe. Such a pipe must
	// never keep Run waiting indefinitely after the tracked group is gone.
	drain := time.NewTimer(r.drainTimeout)
	defer drain.Stop()
	for remainingPipes != 0 {
		select {
		case p := <-pipes:
			recordPipe(p)
		case <-drain.C:
			pipeClosed = true
			_ = outRead.Close()
			_ = errRead.Close()
			runErr = errors.Join(runErr, errors.New("worker output drain deadline exceeded"))
		}
	}
	if err := ctx.Err(); err != nil && !errors.Is(runErr, err) {
		runErr = errors.Join(runErr, err)
	}
	return result, runErr
}

func (r *nativeRunner) snapshot(sample processSampler) ([]processSample, error) {
	ctx, cancel := context.WithTimeout(context.Background(), r.sampleTimeout)
	defer cancel()
	return sample(ctx)
}

func (r *nativeRunner) cleanupGroup(group, uid int, reap func(), reaped, waitFailed func() bool) error {
	if r.signalProcess != nil {
		return r.cleanupProtectedGroup(group, uid, reap, reaped)
	}
	if group <= 1 || group == syscall.Getpgrp() {
		return fmt.Errorf("%w: refusing to signal the owner process group", ErrCleanup)
	}
	var failures error
	foreignGroup := false
	inspect := func() (bool, bool) {
		samples, err := r.snapshot(r.inspect)
		if err != nil {
			failures = errors.Join(failures, fmt.Errorf("inspect process group: %w", err))
			return true, false
		}
		live, err := ownedGroup(samples, group, uid)
		if err != nil {
			failures = errors.Join(failures, err)
			foreignGroup = true
			return true, false
		}
		return live, true
	}
	signal := func(sig syscall.Signal) {
		live, owned := inspect()
		if !owned {
			// A still-unreaped direct child cannot have had its PID reused.
			// Never fall back to signalling an unverified process group.
			if !foreignGroup && !reaped() && !waitFailed() {
				if err := syscall.Kill(group, sig); err != nil && !errors.Is(err, syscall.ESRCH) {
					failures = errors.Join(failures, fmt.Errorf("signal direct child: %w", err))
				}
			}
			return
		}
		if live {
			if err := syscall.Kill(-group, sig); err != nil && !errors.Is(err, syscall.ESRCH) {
				failures = errors.Join(failures, fmt.Errorf("signal worker process group: %w", err))
			}
		}
	}
	wait := func(grace time.Duration) bool {
		deadline := time.Now().Add(grace)
		for {
			reap()
			live, inspected := inspect()
			if inspected && !live && reaped() {
				return true
			}
			if !time.Now().Before(deadline) {
				return false
			}
			time.Sleep(min(r.pollInterval, time.Until(deadline)))
		}
	}
	signal(syscall.SIGTERM)
	clean := wait(r.termGrace)
	if !clean {
		signal(syscall.SIGKILL)
		clean = wait(r.killGrace)
	}
	if !clean && failures == nil {
		if live, inspected := inspect(); inspected && live {
			return errors.Join(ErrCleanup, ErrContamination)
		}
	}
	if !clean || failures != nil {
		return errors.Join(ErrCleanup, failures)
	}
	return nil
}

// No root kill(2) operation is permitted, even after inspecting a group: a
// member can change UID or a PID can be reused between inspection and signal.
func (r *nativeRunner) cleanupProtectedGroup(group, uid int, reap func(), reaped func() bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), r.termGrace+r.killGrace)
	defer cancel()
	termUntil := time.Now().Add(r.termGrace)
	for {
		reap()
		samples, err := r.scope.sample(ctx)
		if err != nil {
			return errors.Join(ErrCleanup, err)
		}
		live := false
		for _, p := range samples {
			if p.group != group || p.zombie {
				continue
			}
			live = true
			if p.uid != uid {
				return errors.Join(ErrCleanup, ErrContamination, errors.New("job group contains a foreign UID"))
			}
			for _, trusted := range r.scope.baseline.Processes {
				if trusted.PID == p.pid {
					return errors.Join(ErrCleanup, ErrContamination, errors.New("refusing to signal a GUI baseline PID"))
				}
			}
			sig := syscall.SIGTERM
			if !time.Now().Before(termUntil) {
				sig = syscall.SIGKILL
			}
			if err := r.signalProcess(ctx, p, sig); err != nil {
				return errors.Join(ErrCleanup, err)
			}
		}
		if !live && reaped() {
			return nil
		}
		select {
		case <-ctx.Done():
			samples, err := r.snapshot(r.scope.sample)
			if err != nil {
				return errors.Join(ErrCleanup, err)
			}
			live, err := ownedGroup(samples, group, uid)
			if err != nil {
				return errors.Join(ErrCleanup, ErrContamination, err)
			}
			if live {
				return errors.Join(ErrCleanup, ErrContamination)
			}
			return errors.Join(ErrCleanup, ctx.Err())
		case <-time.After(r.pollInterval):
		}
	}
}

func ownedGroup(samples []processSample, group, uid int) (bool, error) {
	live := false
	for _, p := range samples {
		if p.group != group {
			continue
		}
		if p.uid != uid {
			return false, errors.New("refusing to signal a process group containing another UID")
		}
		// Zombies cannot execute, hold output pipes, or consume resident memory.
		if !p.zombie {
			live = true
		}
	}
	return live, nil
}

func kibToMiB(kib int64) int64 {
	mib := kib / 1024
	if kib%1024 != 0 {
		mib++
	}
	return mib
}

// footprintKiB sums the footprint of uid's live processes in samples.
func footprintKiB(samples []processSample, uid int) (int64, error) {
	var totalKiB int64
	for _, p := range samples {
		if p.uid != uid || p.zombie {
			continue
		}
		if p.footprintKiB < 0 || p.footprintKiB > (1<<63-1)-totalKiB {
			return 0, errors.New("invalid worker memory sample")
		}
		totalKiB += p.footprintKiB
	}
	return totalKiB, nil
}

// ps exposes only numeric identity, RSS and state; command lines, paths and
// environment data are deliberately neither requested nor retained.
func sampleProcesses(ctx context.Context) ([]processSample, error) {
	cmd := exec.CommandContext(ctx, "/bin/ps", "-axo", "pid=,pgid=,uid=,rss=,stat=")
	cmd.Env = []string{"LC_ALL=C"}
	cmd.Dir = "/"
	cmd.WaitDelay = 100 * time.Millisecond
	var output limitedProcessOutput
	cmd.Stdout = &output
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("read process RSS: %w", err)
	}
	return parseProcesses(output.String())
}

type limitedProcessOutput struct{ strings.Builder }

func (w *limitedProcessOutput) Write(p []byte) (int, error) {
	if len(p) > 16*1024*1024-w.Len() {
		return 0, errors.New("process snapshot too large")
	}
	return w.Builder.Write(p)
}

func parseProcesses(text string) ([]processSample, error) {
	var result []processSample
	for line := range strings.SplitSeq(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 5 {
			return nil, errors.New("invalid process snapshot fields")
		}
		values := [4]int64{}
		for i := range values {
			value, err := strconv.ParseInt(fields[i], 10, 64)
			if err != nil || i != 2 && value < 0 || i == 2 && (value < -1<<31 || value > 1<<32-1) {
				return nil, errors.New("invalid numeric process snapshot field")
			}
			// macOS ps prints some valid uid_t values (for example nobody)
			// as signed 32-bit integers. Normalize identity, not other fields.
			if i == 2 {
				value = int64(uint32(value))
			}
			values[i] = value
		}
		result = append(result, processSample{pid: int(values[0]), group: int(values[1]), uid: int(values[2]), rssKiB: values[3], zombie: strings.HasPrefix(fields[4], "Z")})
	}
	if len(result) == 0 {
		return nil, errors.New("empty process snapshot")
	}
	return result, nil
}

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
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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

// degradedAfterTimeouts is how long memory may go unobserved before the
// broker logs that a command's memory monitoring is degraded: no sample has
// completed for this many sample timeouts (30 s at the production 5 s).
// Degraded monitoring is never a failure: the command keeps running and its
// budget is enforced on the next sample that completes. Until v0.1.67 it
// failed the command: at three lanes with two parallel-testing clones each
// (Studio, 2026-11-17 15:52:36Z), three UI-test runs failed together with
// "no sample succeeded for 34.679s (0 failed)", and the cleanup of the test
// runs they killed quarantined the worker.
const degradedAfterTimeouts = 6

type processSample struct {
	pid    int
	parent int
	group  int
	uid    int
	rssKiB int64
	// footprintKiB is the memory the platform charges the process: Darwin's
	// phys_footprint, which excludes shared clean pages; RSS on Linux.
	footprintKiB int64
	zombie       bool
	start        string
}

// memoryCharge is one completed memory sample's charge to a command: charged
// is the footprint the budget judges (KiB), total the job UID's whole
// footprint (KiB, lane mode only), err why the sample has no charge.
type memoryCharge struct {
	charged, total int64
	err            error
}

type processSampler func(context.Context) ([]processSample, error)

type nativeRunner struct {
	command        func(Command) *exec.Cmd
	sample         processSampler
	inspect        processSampler
	pollInterval   time.Duration
	sampleInterval time.Duration
	sampleTimeout  time.Duration
	termGrace      time.Duration
	killGrace      time.Duration
	drainTimeout   time.Duration
	uid            int
	launchDir      string
	scope          *processScope
	signalProcess  func(context.Context, processSample, syscall.Signal) error
	// cleanupConfirm is how long a protected cleanup keeps re-listing and
	// SIGKILLing its group after the signalling window before its verdict
	// (cleanupProtectedGroup). NewNativeRunner sets it from
	// Options.ProcessCleanupTimeout; zero gives the window alone.
	cleanupConfirm time.Duration
	// signalTimeout is the least time one protected signalling round has
	// (signalMembers).
	signalTimeout   time.Duration
	baselinePath    string
	persistencePath string
	persistence     func(context.Context) error
	// console refuses admission unless the owner or the login window holds
	// /dev/console (hostguard.ConsoleAdmissible). Nil refuses.
	console func() error
	// diagnostics receives tolerated memory sampling failures; nil discards.
	diagnostics io.Writer
	// kill signals the unprotected cleanup's process group or direct child.
	kill func(int, syscall.Signal) error
	// Lane attribution (lanes.go): the tracker, its sampler, the workspace
	// root that holds every job's workspace and the reader of an
	// instance's executable and launchd_sim arguments.
	lanes          *laneTracker
	lanesOnce      sync.Once
	samplerMu      sync.Mutex
	samplerRunning bool
	workspaceRoot  string
	describe       func(int, bool) (processDescription, error)
	lineage        func(int, string) (uint64, uint64, error)
	// censusRefresh runs in every lane census before it judges (see
	// SetCensusRefresh).
	censusRefresh atomic.Pointer[func(context.Context)]
}

// newProcessRunner is the process/pipes implementation. Production construction
// is exclusively through NewNativeRunner, which binds the protected UID scope.
func newProcessRunner() *nativeRunner {
	r := &nativeRunner{
		uid:            os.Geteuid(),
		inspect:        inspectProcesses,
		pollInterval:   20 * time.Millisecond,
		sampleInterval: 250 * time.Millisecond,
		sampleTimeout:  defaultSampleTimeout,
		termGrace:      defaultTermGrace,
		killGrace:      defaultKillGrace,
		signalTimeout:  cleanupSignalTimeout,
		drainTimeout:   outputDrainTimeout,
		kill:           syscall.Kill,
	}
	r.sample = func(ctx context.Context) ([]processSample, error) { return memoryProcesses(ctx, r.uid) }
	return r
}

// outputDrainTimeout bounds how long Run waits, after the command's process
// group is gone, for its output pipes to reach end of file. Every chunk a
// job command writes is a controller log request (workerclient's remote
// sink, at most request_timeout_seconds, 10 s, each) before the next read,
// so the drain waits for the requests still in flight when the command
// exits. Until v0.1.60 it was 250 ms: at six lanes and load 20-35 that ran
// out after a successful `simctl boot` or `bootstatus` (j_a099efdf,
// j_4c485ddd and j_1f9cbf13, 2026-11-15) and failed the boot (#155), as the
// 100 ms inspection WaitDelay had failed admissions (#150: now 1 s; a
// command's fork/exec alone takes seconds at times under that load). It
// still bounds a pipe a descendant that escaped the group keeps open.
const outputDrainTimeout = 10 * time.Second

// DefaultProcessCleanupTimeout is Options.ProcessCleanupTimeout when unset,
// and its maximum: how long, after its 1.5 s signalling window, a protected
// cleanup keeps re-listing a command's process group with backoff and
// SIGKILLing what is left before it declares cleanup unconfirmed. A host at
// load 53 on 36 cores kept a SIGKILLed xcodebuild group listed past the
// window (Studio 2026-11-18 09:50Z, #194); a process that survives this long
// after SIGKILL is genuinely stuck.
const DefaultProcessCleanupTimeout = 3 * time.Minute

// cleanupSignalTimeout bounds one protected signalling round (signalMembers),
// and is the time the round after the bound closes has to SIGKILL members no
// SIGKILL has reached; the helper bounds each of its runs within it
// (jobSignalAttempts).
const cleanupSignalTimeout = 30 * time.Second

// cleanupBackoffMax caps the pause between a protected cleanup's listings
// after the signalling window: they start at pollInterval and double.
const cleanupBackoffMax = 5 * time.Second

// The runner's cleanup timing defaults (newProcessRunner), which
// processCleanupBound and so FinalizationTimeout are derived from.
const (
	// defaultTermGrace is how long members get SIGTERM before SIGKILL.
	defaultTermGrace = 500 * time.Millisecond
	// defaultKillGrace is the rest of the signalling window, and the settle
	// after the SIGKILL round at the end of a protected cleanup.
	defaultKillGrace = time.Second
	// defaultSampleTimeout bounds one process listing.
	defaultSampleTimeout = 5 * time.Second
)

// processCleanupBound bounds one protected cleanup (cleanupProtectedGroup) at
// the runner's defaults: the signalling window and the confirmation phase
// (every listing and round inside them ends with them, plus at most one
// helper's output wait), then the listing, the SIGKILL round (plus its
// output wait) and the settle after the bound, and the final listing.
// FinalizationTimeout counts it per command cleanup a finalization can wait
// for.
const processCleanupBound = defaultTermGrace + defaultKillGrace + DefaultProcessCleanupTimeout + inspectWaitDelay +
	defaultSampleTimeout + cleanupSignalTimeout + inspectWaitDelay + defaultKillGrace + defaultSampleTimeout

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
	label := commandLabel(command)
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
	// A command of a job in lane mode is charged its own lane's processes
	// (laneTracker) and samples no job-UID baseline.
	var tracker *laneTracker
	if command.JobID != "" && r.lanes != nil && r.lanes.has(command.JobID) {
		tracker = r.lanes
	}
	// Otherwise the job UID's GUI session is always logged in, and its
	// footprint (including compressed and swapped memory) is outside the
	// job's control. A command is charged only for footprint above the job
	// UID's footprint sampled immediately before its job's first command;
	// without that baseline it must not start.
	var baselineKiB int64
	if tracker == nil {
		baseline := command.MemoryBaseline
		if baseline == nil {
			baseline = &MemoryBaseline{}
		}
		if !baseline.sampled {
			baselineCtx, cancelBaseline := context.WithTimeout(ctx, r.sampleTimeout)
			samples, err := r.sample(baselineCtx)
			cancelBaseline()
			if err != nil {
				return result, fmt.Errorf("%s: sample worker memory baseline: %w", label, err)
			}
			kib, err := footprintKiB(samples, r.uid)
			if err != nil {
				return result, fmt.Errorf("%s: sample worker memory baseline: %w", label, err)
			}
			*baseline = MemoryBaseline{sampled: true, kib: kib}
			if command.MemoryBaseline != nil && r.diagnostics != nil {
				fmt.Fprintf(r.diagnostics, "macserve worker: job memory baseline: job-UID footprint %d MiB\n", kibToMiB(kib))
			}
		}
		baselineKiB = baseline.kib
	}
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
	if tracker != nil {
		// The root keeps this PID through launchctl asuser, _job-exec and
		// the tool's exec. It is forgotten once reaped: the PID may be reused.
		tracker.addRoot(command.JobID, pid)
		defer tracker.removeRoot(command.JobID, pid)
	}

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
	// enforce records a completed sample's charge (KiB) and judges it against
	// the budget: a measured charge over budget is the only memory verdict
	// that fails a command.
	enforce := func(c memoryCharge) error {
		charged := kibToMiB(c.charged)
		result.PeakMemoryMiB = max(result.PeakMemoryMiB, charged)
		if tracker != nil {
			result.HostPeakMemoryMiB = max(result.HostPeakMemoryMiB, kibToMiB(c.total))
		}
		if command.MemoryLimitMiB <= 0 || charged <= int64(command.MemoryLimitMiB) {
			return nil
		}
		if tracker != nil {
			return fmt.Errorf("%w: sampled %d MiB in the job's own processes, budget %d MiB (monitored, not a hard cap)", ErrMemoryLimit, charged, command.MemoryLimitMiB)
		}
		return fmt.Errorf("%w: sampled %d MiB above the %d MiB job-UID baseline, budget %d MiB (monitored, not a hard cap)", ErrMemoryLimit, charged, kibToMiB(baselineKiB), command.MemoryLimitMiB)
	}
	// measure samples memory and charges it: in lane mode the job's own
	// processes by the labels the lane sampler keeps current
	// (startLaneSampler), which it reads without relabelling; otherwise the
	// job UID's footprint above the baseline.
	measure := func(ctx context.Context) memoryCharge {
		samples, err := r.sample(ctx)
		if err != nil {
			return memoryCharge{err: err}
		}
		if tracker != nil {
			mine, total, err := tracker.footprint(samples, command.JobID)
			return memoryCharge{charged: mine, total: total, err: err}
		}
		total, err := footprintKiB(samples, uid)
		return memoryCharge{charged: max(0, total-baselineKiB), err: err}
	}

	poll := time.NewTicker(r.pollInterval)
	defer poll.Stop()
	memory := time.NewTicker(r.sampleInterval)
	defer memory.Stop()
	// Memory is sampled and charged beside the loop, one sample at a time:
	// the process table, the kernel memory reads and the lane labels (one
	// tracker, which every lane's commands, the lane sampler, the census and
	// the lane quiesce share) never delay reaping, output or cancellation.
	// Until v0.1.67 the charge ran in the loop, which then waited for the
	// tracker behind the other lanes' labelling. A sample has no deadline of
	// its own: its kernel reads cannot be interrupted, and a late sample is
	// still a measurement. A sample that fails, or none completing for
	// degradedAfterTimeouts sample timeouts, is logged, never a failure.
	charges := make(chan memoryCharge, 1)
	sampling := false
	samplingCtx, stopSampling := context.WithCancel(context.Background())
	sampleMemory := func() {
		if sampling {
			return
		}
		sampling = true
		go func() { charges <- measure(samplingCtx) }()
	}
	observed := time.Now()
	failures := 0
	var lastFailure error
	degraded := false
	recordCharge := func(c memoryCharge) {
		sampling = false
		if c.err != nil {
			failures++
			lastFailure = c.err
			if !degraded && r.diagnostics != nil {
				fmt.Fprintf(r.diagnostics, "macserve worker: %s: memory sample failed (%d consecutive): %v\n", label, failures, c.err)
			}
			return
		}
		if degraded && r.diagnostics != nil {
			fmt.Fprintf(r.diagnostics, "macserve worker: %s: memory monitoring restored after %s unobserved (%d failed)\n", label, time.Since(observed).Round(time.Millisecond), failures)
		}
		observed, failures, lastFailure, degraded = time.Now(), 0, nil, false
		runErr = errors.Join(runErr, enforce(c))
	}
	checkObserved := func() {
		unobserved := time.Since(observed)
		if degraded || unobserved <= degradedAfterTimeouts*r.sampleTimeout {
			return
		}
		degraded = true
		if r.diagnostics == nil {
			return
		}
		cause := "a sample is still running"
		if lastFailure != nil {
			cause = "last error: " + lastFailure.Error()
		}
		fmt.Fprintf(r.diagnostics, "macserve worker: %s: memory monitoring degraded: no sample completed for %s (%d failed; %s); the command keeps running and its budget is enforced on the next completed sample\n", label, unobserved.Round(time.Millisecond), failures, cause)
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
		case c := <-charges:
			recordCharge(c)
		case <-memory.C:
			checkObserved()
			sampleMemory()
		}
	}
	// The command has finished or failed; a sample still in flight no longer
	// decides anything. Run does not wait for it: it may be held in the kernel
	// or behind the lane tracker. It ends on its own into the buffered channel,
	// and its charge is dropped.
	stopSampling()
	if ctx.Err() != nil {
		runErr = errors.Join(runErr, ctx.Err())
	}

	cleanupErr := r.cleanupGroup(pid, uid, reap, func() bool { return reaped }, func() bool { return waitFailed })
	result.CleanupOK = cleanupErr == nil
	if cleanupErr != nil {
		cleanupErr = fmt.Errorf("%s: %w", label, cleanupErr)
		runErr = errors.Join(runErr, cleanupErr)
		if r.diagnostics != nil {
			fmt.Fprintf(r.diagnostics, "macserve worker: %s\n", strings.ReplaceAll(cleanupErr.Error(), "\n", "; "))
		}
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

// commandLabel names a command for diagnostics by its executable and leading
// subcommand words (e.g. "xcrun simctl bootstatus"); operands such as UDIDs,
// paths and flag values are never included.
func commandLabel(command Command) string {
	words := []string{filepath.Base(command.Executable)}
	for _, arg := range command.Args {
		if len(words) == 3 || !labelWord.MatchString(arg) {
			break
		}
		words = append(words, arg)
	}
	return strings.Join(words, " ")
}

var labelWord = regexp.MustCompile(`^[a-z][a-z-]{0,23}$`)

// cleanupFailure names the cleanup phase of a failure; Run prefixes the
// command, so a recurrence explains itself ("xcrun simctl boot: worker process
// cleanup failed; protected cleanup: final listing: …").
func cleanupFailure(phase string, errs ...error) error {
	return fmt.Errorf("%s: %w", phase, errors.Join(errs...))
}

func (r *nativeRunner) cleanupGroup(group, uid int, reap func(), reaped, waitFailed func() bool) error {
	if r.signalProcess != nil {
		return r.cleanupProtectedGroup(group, uid, reap, reaped)
	}
	if group <= 1 || group == syscall.Getpgrp() {
		return errors.Join(ErrCleanup, cleanupFailure("cleanup", errors.New("refusing to signal the owner process group")))
	}
	var failures, inspectErr error
	foreignGroup := false
	// A failed inspection is retried within the cleanup window; only one still
	// failing when the window closes leaves cleanup unconfirmed.
	inspect := func() (bool, bool) {
		samples, err := r.snapshot(r.inspect)
		if err != nil {
			inspectErr = cleanupFailure("cleanup: inspect process group", err)
			return true, false
		}
		inspectErr = nil
		live, err := ownedGroup(samples, group, uid)
		if err != nil {
			failures = errors.Join(failures, cleanupFailure("cleanup: ownership", err))
			foreignGroup = true
			return true, false
		}
		return live, true
	}
	signal := func(sig syscall.Signal, grace time.Duration) {
		deadline := time.Now().Add(grace)
		live, owned := inspect()
		for !owned && !foreignGroup && time.Now().Before(deadline) {
			time.Sleep(min(r.pollInterval, time.Until(deadline)))
			live, owned = inspect()
		}
		if !owned {
			// A still-unreaped direct child cannot have had its PID reused.
			// Never fall back to signalling an unverified process group.
			if !foreignGroup && !reaped() && !waitFailed() {
				if err := r.kill(group, sig); !signalSettled(err) {
					failures = errors.Join(failures, cleanupFailure("cleanup: signal direct child", err))
				}
			}
			return
		}
		if live {
			if err := r.kill(-group, sig); !signalSettled(err) {
				failures = errors.Join(failures, cleanupFailure("cleanup: signal process group", err))
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
	termUntil := time.Now().Add(r.termGrace)
	signal(syscall.SIGTERM, r.termGrace)
	clean := wait(time.Until(termUntil))
	if !clean {
		killUntil := time.Now().Add(r.killGrace)
		signal(syscall.SIGKILL, r.killGrace)
		clean = wait(time.Until(killUntil))
	}
	if !clean && failures == nil {
		if live, inspected := inspect(); inspected && live {
			return errors.Join(ErrCleanup, ErrContamination, cleanupFailure("cleanup", errors.New("process group still live after the cleanup window")))
		}
	}
	if !clean {
		failures = errors.Join(failures, inspectErr)
		if failures == nil {
			failures = cleanupFailure("cleanup", errors.New("direct child not reaped within the cleanup window"))
		}
	}
	if !clean || failures != nil {
		return errors.Join(ErrCleanup, failures)
	}
	return nil
}

// No root kill(2) operation is permitted, even after inspecting a group: a
// member can change UID or a PID can be reused between inspection and signal.
//
// The window (termGrace, then killGrace) bounds signalling: each listed
// member is sent SIGTERM within termGrace and SIGKILL after. Under load
// neither the signal helper nor the kernel keeps to it: at load 53 a helper
// run outlasted the 1.5 s window ("WaitDelay expired before I/O complete")
// and an xcodebuild group SIGKILLed in it was still listed when it closed,
// so cleanup went unconfirmed and the worker needed an owner restart
// (Studio 2026-11-18 09:50Z, #194). So after the window the listing is
// retried with backoff (up to cleanupBackoffMax) for cleanupConfirm,
// SIGKILLing every member still listed; a signal that fails is retried in
// the next round rather than ending cleanup. Each round chooses SIGTERM or
// SIGKILL per member as it reaches it and ends with the bound, so a slow
// SIGTERM round cannot hold back SIGKILL (#195 review F1). When the bound
// closes, every member still listed that no SIGKILL has reached gets one
// more round of cleanupSignalTimeout and killGrace to go. The bound is hard:
// a round that runs out before it reaches every member leaves the rest
// without a completed SIGKILL.
//
// Cleanup is confirmed exactly when a listing shows no live group member and
// the direct child is reaped. A foreign-UID member or a GUI baseline PID in the
// group is contamination at once. In the final listing, a member a SIGKILL
// was delivered to is a proven survivor, which is contamination; a member no
// SIGKILL reached within the bound (its signals kept failing or never ran)
// is not evidence of anything and leaves this command's cleanup unconfirmed
// (ErrCleanup without ErrContamination: no quarantine marker). The command
// fails; the job's finalization then tries to repair it, as for any failed
// command: its account or lane quiesce SIGKILLs and judges what is left by
// escalation. Only if the job's final cleanup is still unconfirmed does the
// job end with cleanup_ok false, which fences the epoch and drains to the
// idle check (#195 review F1). A listing that still fails is unconfirmed.
func (r *nativeRunner) cleanupProtectedGroup(group, uid int, reap func(), reaped func() bool) error {
	begun := time.Now()
	termUntil := begun.Add(r.termGrace)
	window := begun.Add(r.termGrace + r.killGrace)
	until := window.Add(r.cleanupConfirm)
	killed := map[processInstance]bool{}
	pause := r.pollInterval
	var listErr, signalErr error
	for time.Now().Before(until) {
		reap()
		members, err, refused := r.listGroup(min(time.Until(until), r.sampleTimeout), group, uid)
		if refused != nil {
			return refused
		}
		listErr = err
		if err == nil && len(members) == 0 && reaped() {
			return nil
		}
		if len(members) > 0 {
			signalErr = r.signalMembers(members, termUntil, min(time.Until(until), r.signalTimeout), killed)
		}
		if !time.Now().Before(window) {
			pause = min(2*pause, cleanupBackoffMax)
		}
		time.Sleep(max(0, min(pause, time.Until(until))))
	}
	reap()
	if members, err, refused := r.listGroup(r.sampleTimeout, group, uid); refused != nil {
		return refused
	} else if err == nil {
		var pending []processSample
		for _, p := range members {
			if !killed[processInstance{p.pid, p.start}] {
				pending = append(pending, p)
			}
		}
		if len(pending) > 0 {
			signalErr = r.signalMembers(pending, termUntil, r.signalTimeout, killed)
			for settle := time.Now().Add(r.killGrace); time.Now().Before(settle); time.Sleep(min(r.pollInterval, time.Until(settle))) {
				reap()
				if members, err, _ := r.listGroup(time.Until(settle), group, uid); err == nil && len(members) == 0 && reaped() {
					break
				}
			}
		}
	}
	reap()
	samples, err := r.snapshot(r.scope.sample)
	if err != nil {
		return errors.Join(ErrCleanup, cleanupFailure("protected cleanup: final listing", listErr, signalErr, err))
	}
	// The same foreign-UID and GUI-baseline checks as every listing, and a
	// zombie of another UID too, before members are split into survivors
	// and unescalated ones: a baseline PID first seen here is contamination
	// at once, never unconfirmed (#195 review round 3).
	members, refused := r.groupMembers(samples, group, uid, true)
	if refused != nil {
		return refused
	}
	survivors, unescalated := 0, 0
	for _, p := range members {
		if killed[processInstance{p.pid, p.start}] {
			survivors++
		} else {
			unescalated++
		}
	}
	if survivors > 0 {
		return errors.Join(ErrCleanup, ErrContamination, cleanupFailure("protected cleanup", fmt.Errorf("job group still live after the cleanup window: %d member(s) survived SIGKILL", survivors), signalErr))
	}
	if unescalated > 0 {
		return errors.Join(ErrCleanup, cleanupFailure("protected cleanup", fmt.Errorf("job group still live after the cleanup window: no SIGKILL reached %d member(s) within the bound", unescalated), signalErr))
	}
	if !reaped() {
		return errors.Join(ErrCleanup, cleanupFailure("protected cleanup", errors.New("direct child not reaped within the cleanup window"), signalErr))
	}
	return nil
}

// listGroup lists the live members of group within timeout (groupMembers).
func (r *nativeRunner) listGroup(timeout time.Duration, group, uid int) (members []processSample, err, refused error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	samples, err := r.scope.sample(ctx)
	members, refused = r.groupMembers(samples, group, uid, false)
	return members, err, refused
}

// groupMembers returns the live members of group in samples. refused is the
// contamination verdict for a member of another UID or a GUI baseline PID,
// and with zombies (the final listing) for a zombie of another UID too. It
// names every refused member (groupRefusal).
func (r *nativeRunner) groupMembers(samples []processSample, group, uid int, zombies bool) (members []processSample, refused error) {
	var foreign, baseline []processSample
	for _, p := range samples {
		if p.group != group || (p.zombie && !zombies) {
			continue
		}
		switch {
		case p.uid != uid:
			foreign = append(foreign, p)
		case p.zombie:
		case slices.ContainsFunc(r.scope.baseline.Processes, func(trusted ProcessIdentity) bool { return trusted.PID == p.pid }):
			baseline = append(baseline, p)
		default:
			members = append(members, p)
		}
	}
	if len(foreign) > 0 || len(baseline) > 0 {
		return nil, groupRefusal(foreign, baseline)
	}
	return members, nil
}

// signalMembers sends one protected cleanup round to members within timeout:
// SIGTERM to each member it reaches before termUntil, SIGKILL after, choosing
// as it goes so a slow SIGTERM does not hold back SIGKILL from the rest. It
// records each member a SIGKILL reached in killed and returns the last failed
// signal, which the next round retries.
func (r *nativeRunner) signalMembers(members []processSample, termUntil time.Time, timeout time.Duration, killed map[processInstance]bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var failed error
	for _, p := range members {
		if ctx.Err() != nil {
			break
		}
		sig := syscall.SIGTERM
		if !time.Now().Before(termUntil) {
			sig = syscall.SIGKILL
		}
		if err := r.signalProcess(ctx, p, sig); err != nil {
			failed = cleanupFailure("protected cleanup: signal", err)
		} else if sig == syscall.SIGKILL {
			killed[processInstance{p.pid, p.start}] = true
		}
	}
	return failed
}

// signalSettled reports whether a cleanup signal's result leaves the
// verdict to the confirmation listing. ESRCH: nothing left to signal. EPERM:
// Darwin's killpg refuses a group whose member is exiting (CI macOS
// 2026-11-10: "signal process group: operation not permitted" while the
// leader died of the same SIGTERM). ownedGroup already refused a foreign-UID
// member, and a member that survives is still found live by the listing and
// fails cleanup, so neither error can pass a live process.
func signalSettled(err error) bool {
	return err == nil || errors.Is(err, syscall.ESRCH) || errors.Is(err, syscall.EPERM)
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

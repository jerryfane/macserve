package worker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// protectedRunner is helperRunner with the root broker's protected cleanup
// for testJobUID: its listings come from sample, given the command's direct
// child (its process group), its job-UID signals are recorded only, and its
// memory samples are empty. A child Run leaves unreaped (a refused group) is
// killed after the test.
func protectedRunner(t *testing.T, mode string, sample func(ctx context.Context, child int) ([]processSample, error)) (*nativeRunner, Command) {
	t.Helper()
	runner, command := helperRunner(t, mode)
	runner.uid = testJobUID
	var started *exec.Cmd
	// child is the direct child's PID, kept from the first listing: Run
	// releases its process (Pid -1) before it returns.
	var child atomic.Int64
	launch := runner.command
	runner.command = func(c Command) *exec.Cmd {
		started = launch(c)
		return started
	}
	t.Cleanup(func() {
		pid := int(child.Load())
		if pid <= 1 {
			return
		}
		var status syscall.WaitStatus
		if waited, err := syscall.Wait4(pid, &status, syscall.WNOHANG, nil); err == nil && waited == 0 {
			_ = syscall.Kill(pid, syscall.SIGKILL) // still this test's unreaped child
			_, _ = syscall.Wait4(pid, &status, 0, nil)
		}
	})
	runner.scope = &processScope{uid: testJobUID, sample: func(ctx context.Context) ([]processSample, error) {
		child.CompareAndSwap(0, int64(started.Process.Pid))
		return sample(ctx, int(child.Load()))
	}}
	runner.signalProcess = func(context.Context, processSample, syscall.Signal) error { return nil }
	// Memory is not under test; a ps sample slowed by the host must not
	// refuse the command before it starts.
	runner.sample = func(context.Context) ([]processSample, error) { return nil, nil }
	return runner, command
}

// launchingGroup lists the command's process group as the kernel does, with
// its direct child still UID 0, as launchctl asuser and _job-exec are until
// the drop to the job UID.
func launchingGroup(ctx context.Context, child int) ([]processSample, error) {
	rows, err := identityProcesses(ctx)
	var group []processSample
	for _, p := range rows {
		if p.group != child {
			continue
		}
		p.uid = testJobUID
		if p.pid == child {
			p.uid = 0
		}
		group = append(group, p)
	}
	return group, err
}

// rootKills records the root kill(2) calls of runner's cleanup; with
// deliver, they then run.
func rootKills(runner *nativeRunner, deliver bool) func() []int {
	var mu sync.Mutex
	var pids []int
	kill := runner.kill
	runner.kill = func(pid int, sig syscall.Signal) error {
		mu.Lock()
		pids = append(pids, pid)
		mu.Unlock()
		if !deliver {
			return nil
		}
		return kill(pid, sig)
	}
	return func() []int {
		mu.Lock()
		defer mu.Unlock()
		return append([]int(nil), pids...)
	}
}

// A command cancelled while its launcher still runs as root (launchctl
// asuser or _job-exec before the drop) is cleaned up: the launcher, the
// unreaped direct child with the PID and start time recorded at spawn, UID
// 0 and leading its group, is the command's own process, signalled by its
// PID as root (SIGTERM, then SIGKILL) and reaped, and cleanup is confirmed.
// The job-UID signal helper cannot signal it (here, as in production, it
// refuses the target's identity). Before (#196), the cleanup refused the
// launcher as a foreign UID and quarantined the worker.
func TestProtectedCleanupSignalsItsOwnRootLauncher(t *testing.T) {
	var child int
	runner, command := protectedRunner(t, "hang", func(ctx context.Context, pid int) ([]processSample, error) {
		child = pid
		return launchingGroup(ctx, pid)
	})
	kills := rootKills(runner, true)
	runner.signalProcess = func(context.Context, processSample, syscall.Signal) error {
		return errors.New("signal target identity changed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	result, err := runner.Run(ctx, command, io.Discard, io.Discard)
	if errors.Is(err, ErrCleanup) || errors.Is(err, ErrContamination) || !result.CleanupOK {
		t.Fatalf("own launcher not cleaned up: %+v, %v", result, err)
	}
	if !errors.Is(err, context.DeadlineExceeded) || (result.Signal != "terminated" && result.Signal != "killed") {
		t.Fatalf("command not cancelled and signalled: %+v, %v", result, err)
	}
	if got := kills(); len(got) == 0 || slices.ContainsFunc(got, func(pid int) bool { return pid != child }) {
		t.Fatalf("root kills %v, want only the direct child %d", got, child)
	}
}

// Guards (pass before #196 by design): a member of another UID is the
// command's launcher only as UID 0 with the direct child's PID and recorded
// start time. One with the direct child's PID and another start time (its
// PID reused), one with its start time and another PID, and the direct
// child as another non-root UID are foreign UIDs: contamination at once,
// and no root kill(2) is sent (here none would be delivered).
func TestProtectedCleanupRefusesAnyOtherRootMember(t *testing.T) {
	self := kernelSelf(t)
	for name, members := range map[string]func(ctx context.Context, child int) ([]processSample, error){
		"direct child's PID, another start time": func(_ context.Context, child int) ([]processSample, error) {
			return []processSample{{pid: child, parent: self.pid, group: child, uid: 0, start: "1:0"}}, nil
		},
		"direct child's start time, another PID": func(ctx context.Context, child int) ([]processSample, error) {
			group, err := launchingGroup(ctx, child)
			var start string
			for i := range group {
				if group[i].pid == child {
					start = group[i].start
				}
				group[i].uid = testJobUID
			}
			return append(group, processSample{pid: self.pid, parent: self.parent, group: child, uid: 0, start: start}), err
		},
		"direct child as another non-root UID": func(ctx context.Context, child int) ([]processSample, error) {
			group, err := launchingGroup(ctx, child)
			for i := range group {
				if group[i].pid == child {
					group[i].uid = 999
				}
			}
			return group, err
		},
	} {
		t.Run(name, func(t *testing.T) {
			runner, command := protectedRunner(t, "hang", members)
			kills := rootKills(runner, false)
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			result, err := runner.Run(ctx, command, io.Discard, io.Discard)
			if !errors.Is(err, ErrContamination) || result.CleanupOK || !strings.Contains(err.Error(), "job group contains a foreign UID") {
				t.Fatalf("root member accepted: %+v, %v", result, err)
			}
			if got := kills(); len(got) != 0 {
				t.Fatalf("root kill(2) sent to %v", got)
			}
		})
	}
}

// kernelSelf is the test process's own kernel record.
func kernelSelf(t *testing.T) processSample {
	t.Helper()
	rows, err := identityProcesses(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range rows {
		if p.pid == os.Getpid() {
			return p
		}
	}
	t.Fatal("test process not listed")
	return processSample{}
}

// A protected cleanup refusal names every refused member of the command's
// process group by PID, UID, parent, group, start time and kernel command
// name, in the worker log and in the error the quarantine record keeps; the
// job's public reason keeps the refusals and their count only. Before
// (#196), "job group contains a foreign UID" named no process, and the
// member a herdrup smoke run's clone listing refused on 18 Nov 13:43Z
// could not be identified.
func TestProtectedCleanupRefusalNamesMembers(t *testing.T) {
	self := kernelSelf(t)
	const gone = 2147483646
	var group int
	runner, command := protectedRunner(t, "success", func(_ context.Context, child int) ([]processSample, error) {
		group = child
		return []processSample{
			// A live process of another UID reported in the group.
			{pid: self.pid, parent: self.parent, group: child, uid: 0, start: self.start},
			// A GUI baseline PID whose process is gone by the report.
			{pid: gone, parent: 1, group: child, uid: testJobUID, start: "1:0"},
		}, nil
	})
	runner.scope.baseline.Processes = []ProcessIdentity{{PID: gone, Start: "1:0"}}
	var log bytes.Buffer
	runner.diagnostics = &log
	result, err := runner.Run(context.Background(), command, io.Discard, io.Discard)
	if !errors.Is(err, ErrContamination) || result.CleanupOK {
		t.Fatalf("refused members accepted: %+v, %v", result, err)
	}
	comm := filepath.Base(os.Args[0])
	comm = comm[:min(len(comm), 15)]
	for _, want := range []string{
		"job group contains a foreign UID",
		"refusing to signal a GUI baseline PID",
		fmt.Sprintf("pid=%d uid=0 ppid=%d pgid=%d start=%s command=\"%s", self.pid, self.parent, group, self.start, comm),
		fmt.Sprintf("pid=%d uid=%d ppid=1 pgid=%d start=1:0 command=unavailable: GUI baseline PID", gone, testJobUID, group),
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal lacks %q:\n%v", want, err)
		}
		if !strings.Contains(log.String(), want) {
			t.Fatalf("worker log lacks %q:\n%s", want, log.String())
		}
	}
	if !strings.Contains(err.Error(), "\": foreign UID") {
		t.Fatalf("foreign member not marked: %v", err)
	}
	public := PublicReason(err)
	if strings.Contains(public, "pid=") || !strings.Contains(public, "job group contains a foreign UID") || !strings.Contains(public, "2 unexpected process(es)") {
		t.Fatalf("public reason %q", public)
	}
}

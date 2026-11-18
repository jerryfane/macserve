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
	"strings"
	"syscall"
	"testing"
)

// protectedRunner is helperRunner with the root broker's protected cleanup
// for testJobUID: its listings come from sample, given the command's direct
// child (its process group), and its signals are recorded only.
func protectedRunner(t *testing.T, mode string, sample func(ctx context.Context, child int) ([]processSample, error)) (*nativeRunner, Command) {
	t.Helper()
	runner, command := helperRunner(t, mode)
	runner.uid = testJobUID
	var started *exec.Cmd
	launch := runner.command
	runner.command = func(c Command) *exec.Cmd {
		started = launch(c)
		return started
	}
	runner.scope = &processScope{uid: testJobUID, sample: func(ctx context.Context) ([]processSample, error) {
		return sample(ctx, started.Process.Pid)
	}}
	runner.signalProcess = func(context.Context, processSample, syscall.Signal) error { return nil }
	return runner, command
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

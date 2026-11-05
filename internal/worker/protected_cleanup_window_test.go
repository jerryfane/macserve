package worker

import (
	"bytes"
	"context"
	"io"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// v0.1.32 Studio failure (org-ios-sim-uitest-v1): `simctl boot` exited 0, but a
// member of its group was still exiting when the 1.5 s protected cleanup window
// closed. The fresh listing taken then showed the group gone, yet cleanup
// returned "worker process cleanup failed\ncontext deadline exceeded", so
// bootstatus never ran and the boot retry was refused (CleanupOK false).
func TestProtectedCleanupConfirmsGroupGoneAtWindowClose(t *testing.T) {
	runner, command := helperRunner(t, "success")
	var started *exec.Cmd
	launch := runner.command
	runner.command = func(c Command) *exec.Cmd { started = launch(c); return started }
	runner.termGrace, runner.killGrace = 20*time.Millisecond, 20*time.Millisecond
	runner.scope = scopeFixture()
	// Every listing inside the window sees the member still exiting; the first
	// listing after the window (a fresh deadline) sees the group gone.
	var window time.Time
	runner.scope.sample = func(ctx context.Context) ([]processSample, error) {
		deadline, _ := ctx.Deadline()
		if window.IsZero() {
			window = deadline
		}
		if deadline.Equal(window) {
			return []processSample{{pid: 2147483646, group: started.Process.Pid, uid: runner.uid, start: "exiting"}}, nil
		}
		return nil, nil
	}
	runner.signalProcess = func(context.Context, processSample, syscall.Signal) error { return nil }
	var diagnostics bytes.Buffer
	runner.diagnostics = &diagnostics
	result, err := runner.Run(context.Background(), command, io.Discard, io.Discard)
	if err != nil || !result.CleanupOK || result.ExitCode != 0 {
		t.Fatalf("group gone at window close left cleanup unconfirmed: %+v, %q", result, err)
	}
	if diagnostics.Len() != 0 && strings.Contains(diagnostics.String(), "cleanup") {
		t.Fatalf("confirmed cleanup reported a failure: %q", diagnostics.String())
	}
}

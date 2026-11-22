package hostguard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestJobLoginListable(t *testing.T) {
	const fakeDSCL = `#!/bin/sh
set -eu
[ "$#" -eq 4 ]
[ "$1" = "." ]
[ "$2" = "-read" ]
[ "$3" = "/Users/test-job" ]
[ "$4" = "AuthenticationAuthority" ]
fixture=${0%/*}
printf 'validated\n' > "$fixture/invocation"
/bin/cat "$fixture/stdout"
/bin/cat "$fixture/stderr" >&2
exit "$(/bin/cat "$fixture/status")"
`
	for _, tc := range []struct {
		name    string
		stdout  string
		stderr  string
		status  string
		wantErr bool
	}{
		{name: "shadow hash", stdout: "AuthenticationAuthority: ;ShadowHash;\n"},
		{name: "native hash list", stdout: "AuthenticationAuthority: ;ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2>\n"},
		{name: "multiple authorities", stdout: "AuthenticationAuthority:\n ;Kerberosv5;;job@LOCAL;LOCAL;\n ;ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2>\n ;SecureToken;\n"},
		{name: "missing attribute", stderr: "sensitive missing attribute diagnostic", status: "1", wantErr: true},
		{name: "empty output", wantErr: true},
		{name: "empty attribute", stdout: "AuthenticationAuthority:\n", wantErr: true},
		{name: "other authority", stdout: "AuthenticationAuthority: ;Kerberosv5;;job@LOCAL;LOCAL;\n", wantErr: true},
		{name: "wrong case", stdout: "AuthenticationAuthority: ;shadowhash;\n", wantErr: true},
		{name: "missing leading delimiter", stdout: "AuthenticationAuthority: ShadowHash;\n", wantErr: true},
		{name: "missing trailing delimiter", stdout: "AuthenticationAuthority: ;ShadowHash\n", wantErr: true},
		{name: "different marker", stdout: "AuthenticationAuthority: ;ShadowHashOther;\n", wantErr: true},
		{name: "failed read", stderr: "sensitive directory diagnostic", status: "2", wantErr: true},
		{name: "partial successful-looking output", stdout: "AuthenticationAuthority: ;ShadowHash; sensitive directory output", stderr: "sensitive directory diagnostic", status: "2", wantErr: true},
		{name: "marker only on stderr", stderr: "AuthenticationAuthority: ;ShadowHash;\n", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			status := tc.status
			if status == "" {
				status = "0"
			}
			for name, data := range map[string]string{"stdout": tc.stdout, "stderr": tc.stderr, "status": status} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			executable := filepath.Join(dir, "dscl")
			if err := os.WriteFile(executable, []byte(fakeDSCL), 0700); err != nil {
				t.Fatal(err)
			}
			err := jobLoginListable(context.Background(), "test-job", executable)
			invocation, readErr := os.ReadFile(filepath.Join(dir, "invocation"))
			if readErr != nil || string(invocation) != "validated\n" {
				t.Fatalf("fake dscl did not validate the read arguments: invocation = %q, error = %v", invocation, readErr)
			}
			if (err != nil) != tc.wantErr {
				t.Fatalf("listability error = %v, wantError = %v", err, tc.wantErr)
			}
			if err != nil && err.Error() != "job user not listable at login window" {
				t.Fatalf("refusal must not disclose directory output or command diagnostics: %v", err)
			}
		})
	}
}

// #215: under job load the maintenance probe's dscl read was killed at its
// deadline and reported as "job user not listable", a finding that published
// invalid health and cancelled every running job (Studio 2026-11-22 20:26Z).
// A read cut short observed nothing: it is a deadline, which maintenance
// counts as a probe without evidence.
func TestJobLoginListableKilledReadIsADeadline(t *testing.T) {
	dir := t.TempDir()
	executable := filepath.Join(dir, "dscl")
	// The marker is printed, then the read blocks until killed.
	script := "#!/bin/sh\nprintf 'AuthenticationAuthority: ;ShadowHash; partial'\n: > \"${0%/*}/blocked\"\nexec /bin/sleep 5\n"
	if err := os.WriteFile(executable, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := jobLoginListable(ctx, "test-job", executable)
	if _, statErr := os.Stat(filepath.Join(dir, "blocked")); statErr != nil {
		t.Fatalf("the read never reached its blocking phase: %v", statErr)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("killed read: %v, want a deadline", err)
	}
	if strings.Contains(err.Error(), "ShadowHash") {
		t.Fatalf("error discloses directory output: %v", err)
	}
}

// Review of #219: a failed command and an ended context do not show that the
// context ended the command. One that ended on its own (an exit with any
// status, or a signal from anyone else), whether reaped before the context
// ended or still unreaped then, is a result, even while a descendant keeps
// its output open; only one the context kept from starting or terminated is
// cut short.
func TestCutShortOnlyWhenTheContextEndedTheCommand(t *testing.T) {
	for _, ending := range []string{"exit 42", "kill -TERM $$", "kill -KILL $$"} {
		for _, reaped := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s, reaped %v", ending, reaped), func(t *testing.T) {
				run := startWatched(t, "(read _ < \"$HOLD\") & "+ending)
				if reaped {
					run.wait()
					run.until("reaped", func() bool { return syscall.Kill(run.cmd.Process.Pid, 0) == syscall.ESRCH })
				} else {
					run.until("dead", func() bool {
						out, _ := exec.Command("/bin/ps", "-o", "stat=", "-p", strconv.Itoa(run.cmd.Process.Pid)).Output()
						return strings.HasPrefix(strings.TrimSpace(string(out)), "Z")
					})
				}
				run.cancel()
				if !reaped {
					run.awaitCancelCall()
					run.wait()
				}
				run.release()
				if err := run.result(); run.watch.cutShort(run.ctx, err) {
					t.Fatalf("%v: cut short, want a result", err)
				}
			})
		}
	}
	t.Run("terminated by the context", func(t *testing.T) {
		run := startWatched(t, "exec /bin/sleep 5")
		run.wait()
		run.cancel()
		if err := run.result(); !run.watch.cutShort(run.ctx, err) {
			t.Fatalf("%v: not cut short", err)
		}
	})
	done, stop := context.WithCancel(context.Background())
	stop()
	notStarted := exec.CommandContext(done, "/bin/sh", "-c", "exit 0")
	w := watchCancel(notStarted)
	if err := notStarted.Run(); !w.cutShort(done, err) {
		t.Fatalf("a command its done context kept from starting (%v) was not cut short", err)
	}
	failed := exec.Command("/bin/sh", "-c", "exit 1")
	if err := failed.Run(); (&cancelWatch{cmd: failed}).cutShort(context.Background(), err) {
		t.Fatalf("a failure with a live context (%v) was cut short", err)
	}
}

// watchedRun is one command started under watchCancel whose stdout a
// background descendant may hold open until release.
type watchedRun struct {
	t        *testing.T
	ctx      context.Context
	cancel   context.CancelFunc
	cmd      *exec.Cmd
	watch    *cancelWatch
	hold     string
	canceled chan struct{}
	done     chan error
}

func startWatched(t *testing.T, script string) *watchedRun {
	t.Helper()
	hold := filepath.Join(t.TempDir(), "hold")
	if err := syscall.Mkfifo(hold, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", script)
	cmd.Env = []string{"HOLD=" + hold}
	cmd.Stdout = &bytes.Buffer{} // copied by exec, so its drain can outlast the command
	cmd.WaitDelay = 10 * time.Second
	r := &watchedRun{t: t, ctx: ctx, cancel: cancel, cmd: cmd, watch: watchCancel(cmd), hold: hold, canceled: make(chan struct{})}
	signal := cmd.Cancel
	cmd.Cancel = func() error { defer close(r.canceled); return signal() }
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	return r
}

// wait reaps the command in the background.
func (r *watchedRun) wait() {
	r.done = make(chan error, 1)
	go func() { r.done <- r.cmd.Wait() }()
}

func (r *watchedRun) until(what string, cond func() bool) {
	r.t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			r.t.Fatalf("command never %s", what)
		}
	}
}

func (r *watchedRun) awaitCancelCall() {
	r.t.Helper()
	select {
	case <-r.canceled:
	case <-time.After(5 * time.Second):
		r.t.Fatal("the context's cancellation never reached the command")
	}
}

// release lets the descendant holding stdout exit.
func (r *watchedRun) release() {
	r.t.Helper()
	f, err := os.OpenFile(r.hold, os.O_WRONLY, 0)
	if err != nil {
		r.t.Fatal(err)
	}
	f.Close()
}

func (r *watchedRun) result() error {
	r.t.Helper()
	select {
	case err := <-r.done:
		if err == nil {
			r.t.Fatal("the command succeeded")
		}
		return err
	case <-time.After(10 * time.Second):
		r.t.Fatal("the command was never reaped")
		return nil
	}
}

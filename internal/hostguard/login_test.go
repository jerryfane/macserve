package hostguard

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
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
// context ended the command. One that ended on its own (any exit status, or
// any signal from anyone, including SIGUSR2 and SIGKILL) before the deadline,
// even if it was not yet reaped then and a descendant still holds its
// output, is a result; only one still running at the deadline, or never
// started, is cut short.
func TestRunToDeadlineCutsShortOnlyARunningCommand(t *testing.T) {
	for _, ending := range []string{"exit 42", "kill -TERM $$", "kill -USR2 $$", "kill -KILL $$"} {
		t.Run(ending, func(t *testing.T) {
			f := newHeldCommand(t, ending)
			f.awaitRunningCheck()
			f.proceed()
			f.untilZombie()
			f.cancel()
			if r := f.result(); r.cut || r.err == nil {
				t.Fatalf("ended with %q before the deadline: cut short %v, error %v; want a failed result", ending, r.cut, r.err)
			}
		})
	}
	t.Run("running at the deadline", func(t *testing.T) {
		f := newHeldCommand(t, "exec /bin/sleep 5")
		f.awaitRunningCheck()
		f.proceed()
		f.cancel()
		if r := f.result(); !r.cut || !errors.Is(r.err, context.Canceled) {
			t.Fatalf("cut short %v, error %v; want cut short by the context", r.cut, r.err)
		}
	})
	t.Run("never started", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err, cut := runToDeadline(ctx, exec.Command("/bin/sh", "-c", "exit 0")); !cut || !errors.Is(err, context.Canceled) {
			t.Fatalf("cut short %v, error %v", cut, err)
		}
	})
	t.Run("success with output", func(t *testing.T) {
		out, err, cut := runToDeadline(context.Background(), exec.Command("/bin/sh", "-c", "printf ok"))
		if cut || err != nil || string(out) != "ok" {
			t.Fatalf("out %q, error %v, cut short %v", out, err, cut)
		}
	})
}

// heldCommand runs a script under runToDeadline in the background, which
// checks it only when the test's context ends after the first check. The
// script records its PID in $PIDFILE, then waits for proceed (fd 4) before
// its ending; a descendant holds its stdout until cleanup (fd 3).
type heldCommand struct {
	t       *testing.T
	cancel  context.CancelFunc
	pidFile string
	goW     *os.File
	checked chan struct{}
	done    chan heldResult
}

type heldResult struct {
	err error
	cut bool
}

func newHeldCommand(t *testing.T, ending string) *heldCommand {
	t.Helper()
	pipe := func() (*os.File, *os.File) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { w.Close(); r.Close() })
		return r, w
	}
	holdR, _ := pipe()
	goR, goW := pipe()
	f := &heldCommand{t: t, pidFile: filepath.Join(t.TempDir(), "pid"), goW: goW, checked: make(chan struct{}, 1), done: make(chan heldResult, 1)}
	poll, hook := reapPoll, checkedRunning
	reapPoll = time.Hour
	checkedRunning = func() {
		select {
		case f.checked <- struct{}{}:
		default:
		}
	}
	t.Cleanup(func() { reapPoll, checkedRunning = poll, hook })
	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel
	t.Cleanup(cancel)
	cmd := exec.Command("/bin/sh", "-c", "(read _ <&3) & echo $$ > \"$PIDFILE\"; read _ <&4; "+ending)
	cmd.Env = []string{"PIDFILE=" + f.pidFile}
	cmd.ExtraFiles = []*os.File{holdR, goR}
	go func() {
		_, err, cut := runToDeadline(ctx, cmd)
		f.done <- heldResult{err, cut}
	}()
	return f
}

// awaitRunningCheck waits until runToDeadline found the command running; it
// then waits for the context only.
func (f *heldCommand) awaitRunningCheck() {
	f.t.Helper()
	select {
	case <-f.checked:
	case <-time.After(5 * time.Second):
		f.t.Fatal("runToDeadline never checked the running command")
	}
}

// proceed lets the script run its ending.
func (f *heldCommand) proceed() { f.goW.Close() }

func (f *heldCommand) pid() int {
	data, err := os.ReadFile(f.pidFile)
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(string(bytes.TrimSpace(data)))
	return pid
}

func (f *heldCommand) until(what string, cond func() bool) {
	f.t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			f.t.Fatalf("command never %s", what)
		}
	}
}

// untilZombie waits until the command has ended but is not reaped.
func (f *heldCommand) untilZombie() {
	f.until("ended", func() bool {
		pid := f.pid()
		if pid == 0 {
			return false
		}
		out, _ := exec.Command("/bin/ps", "-o", "stat=", "-p", strconv.Itoa(pid)).Output()
		return strings.HasPrefix(strings.TrimSpace(string(out)), "Z")
	})
}

func (f *heldCommand) result() heldResult {
	f.t.Helper()
	select {
	case r := <-f.done:
		return r
	case <-time.After(10 * time.Second):
		f.t.Fatal("runToDeadline never returned")
		return heldResult{}
	}
}

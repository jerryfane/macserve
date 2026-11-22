package hostguard

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
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

// Review of #219: a failed command and an expired context do not show that
// the deadline ended the command. Its exit, whatever the status, is a result:
// only a command ctx kept from starting or killed is cut short.
func TestCutShortOnlyWhenTheContextEndedTheCommand(t *testing.T) {
	done, cancel := context.WithCancel(context.Background())
	cancel()
	exited := exec.Command("/bin/sh", "-c", "exit 42")
	err := exited.Run()
	if err == nil || cutShort(done, exited, err) {
		t.Fatalf("a command that exited 42 (%v) before its context ended was cut short", err)
	}
	notStarted := exec.CommandContext(done, "/bin/sh", "-c", "exit 0")
	if err := notStarted.Run(); err == nil || !cutShort(done, notStarted, err) {
		t.Fatalf("a command its done context kept from starting (%v) was not cut short", err)
	}
	live, stop := context.WithCancel(context.Background())
	killed := exec.CommandContext(live, "/bin/sleep", "5")
	if err := killed.Start(); err != nil {
		t.Fatal(err)
	}
	stop()
	if err := killed.Wait(); err == nil || !cutShort(live, killed, err) {
		t.Fatalf("a command its context killed (%v) was not cut short", err)
	}
	running := exec.Command("/bin/sh", "-c", "exit 1")
	if err := running.Run(); err == nil || cutShort(context.Background(), running, err) {
		t.Fatalf("a failure with a live context (%v) was cut short", err)
	}
}

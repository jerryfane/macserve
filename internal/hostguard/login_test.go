package hostguard

import (
	"context"
	"os"
	"path/filepath"
	"testing"
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

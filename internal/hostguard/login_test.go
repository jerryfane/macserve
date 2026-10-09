package hostguard

import (
	"context"
	"errors"
	"testing"
)

func TestJobLoginAuthority(t *testing.T) {
	for _, tc := range []struct {
		name    string
		data    string
		readErr error
		wantErr bool
	}{
		{name: "shadow hash", data: "AuthenticationAuthority: ;ShadowHash;\n"},
		{name: "native hash list", data: "AuthenticationAuthority: ;ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2>\n"},
		{name: "multiple authorities", data: "AuthenticationAuthority:\n ;Kerberosv5;;job@LOCAL;LOCAL;\n ;ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2>\n ;SecureToken;\n"},
		{name: "missing attribute", wantErr: true},
		{name: "empty attribute", data: "AuthenticationAuthority:\n", wantErr: true},
		{name: "other authority", data: "AuthenticationAuthority: ;Kerberosv5;;job@LOCAL;LOCAL;\n", wantErr: true},
		{name: "wrong case", data: "AuthenticationAuthority: ;shadowhash;\n", wantErr: true},
		{name: "missing leading delimiter", data: "AuthenticationAuthority: ShadowHash;\n", wantErr: true},
		{name: "missing trailing delimiter", data: "AuthenticationAuthority: ;ShadowHash\n", wantErr: true},
		{name: "different marker", data: "AuthenticationAuthority: ;ShadowHashOther;\n", wantErr: true},
		{name: "failed read", readErr: errors.New("sensitive directory diagnostic"), wantErr: true},
		{name: "partial successful-looking output", data: "AuthenticationAuthority: ;ShadowHash; sensitive directory output", readErr: errors.New("sensitive directory diagnostic"), wantErr: true},
		{name: "deadline", data: "AuthenticationAuthority: ;ShadowHash;", readErr: context.DeadlineExceeded, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := jobLoginAuthority([]byte(tc.data), tc.readErr)
			if (err != nil) != tc.wantErr {
				t.Fatalf("listability error = %v, wantError = %v", err, tc.wantErr)
			}
			if err != nil && err.Error() != "job user not listable at login window" {
				t.Fatalf("refusal must not disclose directory output or command diagnostics: %v", err)
			}
		})
	}
}

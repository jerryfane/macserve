package hostguard

import (
	"context"
	"errors"
	"testing"
)

func TestOwnedServiceACLRejectsEvenDenyEntries(t *testing.T) {
	plain := "-rw-r--r--  1 root wheel 12 Oct 11 00:00 service.plist\n"
	if err := checkProtectedACL([]byte(plain), false); err != nil {
		t.Fatal(err)
	}
	deny := plain + " 0: group:everyone deny delete\n"
	if err := checkProtectedACL([]byte(deny), true); err != nil {
		t.Fatal("existing deny-only policy changed")
	}
	if err := checkProtectedACL([]byte(deny), false); err == nil {
		t.Fatal("strict service policy accepted an ACL")
	}
	for _, text := range []string{"", plain + " 0: user:fixture allow write\n", plain + "unknown extra output\n"} {
		if err := checkProtectedACL([]byte(text), false); err == nil {
			t.Fatal("unavailable or ACL-bearing result accepted")
		}
	}
}

func TestProtectedPathCanceledObservationDoesNotInspect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, allowDeny := range []bool{true, false} {
		if err := checkProtectedPathACL(ctx, "must-not-inspect", false, allowDeny); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled protected-path observation inspected input: %v", err)
		}
	}
}

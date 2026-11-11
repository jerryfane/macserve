package hostguard

import (
	"context"
	"errors"
	"os/exec"
	"testing"
	"time"
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

// An ACL inspection killed at its deadline (Studio, 2026-11-10 08:45:12Z:
// "cannot inspect protected input ACL: signal: killed", which cancelled a job,
// #108) is a deadline, not a finding; a command that fails on its own is not.
func TestACLInspectionKilledAtDeadlineIsADeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := exec.CommandContext(ctx, "/bin/sleep", "5").Output()
	if err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("exec no longer reports a killed command as its exit: %v", err)
	}
	if got := aclCommandError(ctx, err); !errors.Is(got, context.DeadlineExceeded) || got.Error() != "cannot inspect protected input ACL: signal: killed: context deadline exceeded" {
		t.Fatalf("killed at deadline: %v", got)
	}
	_, err = exec.CommandContext(context.Background(), "/bin/sh", "-c", "exit 1").Output()
	if got := aclCommandError(context.Background(), err); got == nil || errors.Is(got, context.DeadlineExceeded) {
		t.Fatalf("failed command: %v", got)
	}
	if aclCommandError(context.Background(), nil) != nil {
		t.Fatal("successful command reported an error")
	}
}

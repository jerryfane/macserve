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
// #108) is a deadline, not a finding, and marked as cut short (#148: it
// quarantined the service at a job's admission); a command that fails on its
// own is neither.
func TestACLInspectionKilledAtDeadlineIsADeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := exec.CommandContext(ctx, "/bin/sleep", "5").Output()
	if err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("exec no longer reports a killed command as its exit: %v", err)
	}
	if got := aclCommandError(ctx, err); !errors.Is(got, context.DeadlineExceeded) || !errors.Is(got, ErrACLInspectionCut) || got.Error() != "cannot inspect protected input ACL: signal: killed: context deadline exceeded" {
		t.Fatalf("killed at deadline: %v", got)
	}
	if got := CheckProtectedPathContext(ctx, "/", true); !errors.Is(got, ErrACLInspectionCut) {
		t.Fatalf("inspection after its deadline: %v", got)
	}
	_, err = exec.CommandContext(context.Background(), "/bin/sh", "-c", "exit 1").Output()
	if got := aclCommandError(context.Background(), err); got == nil || errors.Is(got, context.DeadlineExceeded) || errors.Is(got, ErrACLInspectionCut) {
		t.Fatalf("failed command: %v", got)
	}
	if aclCommandError(context.Background(), nil) != nil {
		t.Fatal("successful command reported an error")
	}
}

// An ACL listing its own five seconds cut short observed nothing and runs
// once more within the caller's deadline; one cut short twice is
// ErrACLInspectionCut, and a listing that shows an ACL is never retried
// (Studio v0.1.56, six lanes at load 20-35, #150).
func TestACLListingCutByItsOwnDeadlineRunsOnceMore(t *testing.T) {
	timeout, command := aclCommandTimeout, aclCommand
	t.Cleanup(func() { aclCommandTimeout, aclCommand = timeout, command })
	aclCommandTimeout = 20 * time.Millisecond
	listing := func(path, acl string) []byte {
		return []byte("drwxr-xr-x  20 root  wheel  640 Oct 11 00:00 " + path + "\n" + acl)
	}
	for name, c := range map[string]struct {
		cut   int
		acl   string
		calls int
		want  func(error) bool
	}{
		"cut once":         {cut: 1, calls: 2, want: func(err error) bool { return err == nil }},
		"cut twice":        {cut: 2, calls: 2, want: func(err error) bool { return errors.Is(err, ErrACLInspectionCut) }},
		"ACL is a finding": {acl: " 0: user:job allow write\n", calls: 1, want: func(err error) bool { return err != nil && !errors.Is(err, ErrACLInspectionCut) }},
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			aclCommand = func(ctx context.Context, path string) ([]byte, error) {
				if calls++; calls <= c.cut {
					<-ctx.Done()
					return nil, errors.New("signal: killed")
				}
				return listing(path, c.acl), nil
			}
			if err := CheckProtectedPathContext(context.Background(), "/", true); !c.want(err) || calls != c.calls {
				t.Fatalf("calls=%d err=%v", calls, err)
			}
		})
	}
}

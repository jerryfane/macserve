//go:build darwin

package worker

import (
	"context"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// TestInspectProcessesKernelListing is the darwin smoke harness for cleanup
// inspection: the in-process kern.proc.all listing must report a fresh
// process group leader's PID, parent, group and UID without any subprocess.
func TestInspectProcessesKernelListing(t *testing.T) {
	child := exec.Command("/bin/sleep", "30")
	child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	started := time.Now()
	rows, err := inspectProcesses(ctx)
	elapsed := time.Since(started)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("listed %d processes in %s", len(rows), elapsed)
	pid := child.Process.Pid
	for _, p := range rows {
		if p.pid != pid {
			continue
		}
		if p.parent != os.Getpid() || p.group != pid || p.uid != os.Geteuid() || p.zombie || p.start == "" {
			t.Fatalf("kernel listing misreported the child: %+v (parent=%d uid=%d)", p, os.Getpid(), os.Geteuid())
		}
		owned, err := ownedGroup(rows, pid, os.Geteuid())
		if err != nil || !owned {
			t.Fatalf("live owned group not confirmed: %v %v", owned, err)
		}
		return
	}
	t.Fatalf("child %d missing from %d listed processes", pid, len(rows))
}

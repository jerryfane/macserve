//go:build darwin

package worker

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
)

// TestMemoryProcessesHelper maps the named file shared and read-only, touches
// every page of it and of a private allocation, then waits to be killed.
func TestMemoryProcessesHelper(t *testing.T) {
	path := os.Getenv("MACSERVE_MEMORY_HELPER")
	if path == "" {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		os.Exit(90)
	}
	info, err := f.Stat()
	if err != nil {
		os.Exit(91)
	}
	shared, err := syscall.Mmap(int(f.Fd()), 0, int(info.Size()), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		os.Exit(92)
	}
	private := make([]byte, 32<<20)
	var sum byte
	for i := 0; i < len(shared); i += os.Getpagesize() {
		sum += shared[i]
	}
	for i := 0; i < len(private); i += os.Getpagesize() {
		private[i] = 1
	}
	fmt.Printf("ready %d\n", sum)
	time.Sleep(time.Hour)
	runtime.KeepAlive(private)
}

// A booting simulator starts hundreds of job-UID processes that all map the
// same shared pages; summing their RSS charged those pages once per process.
// phys_footprint charges a process its private memory and not shared clean
// file pages.
func TestMemoryProcessesChargeFootprintNotSharedPages(t *testing.T) {
	const sharedSize = 64 << 20
	path := filepath.Join(t.TempDir(), "shared")
	if err := os.WriteFile(path, bytes.Repeat([]byte{1}, sharedSize), 0o600); err != nil {
		t.Fatal(err)
	}
	var pids []int
	for range 3 {
		child := exec.Command(os.Args[0], "-test.run=^TestMemoryProcessesHelper$")
		child.Env = []string{"MACSERVE_MEMORY_HELPER=" + path}
		stdout, err := child.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := child.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = child.Process.Kill()
			_ = child.Wait()
		})
		line, err := bufio.NewReader(stdout).ReadString('\n')
		if err != nil || !bytes.HasPrefix([]byte(line), []byte("ready ")) {
			t.Fatalf("helper not ready: %q, %v", line, err)
		}
		pids = append(pids, child.Process.Pid)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	samples, err := memoryProcesses(ctx, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	for _, pid := range pids {
		found := false
		for _, p := range samples {
			if p.pid != pid {
				continue
			}
			found = true
			if p.uid != os.Geteuid() || p.zombie {
				t.Fatalf("wrong identity for helper %d: %+v", pid, p)
			}
			if p.footprintKiB < 32<<10 {
				t.Fatalf("helper %d private memory not charged: %+v", pid, p)
			}
			if p.rssKiB < p.footprintKiB+48<<10 {
				t.Fatalf("helper %d shared mapping charged or not resident: %+v", pid, p)
			}
		}
		if !found {
			t.Fatalf("helper %d missing from memory sample", pid)
		}
	}
}

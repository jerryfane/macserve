//go:build macserve_realhost && darwin

package maintenance

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/controller"
)

// TestRealHostHealthSampler (v0.1.16 real-host harness) runs the maintenance
// observation that needs no root over the harness's workspace root while the
// worker harness builds: accountBytes (the production census, allocated bytes
// for regular files) and memoryPressure, and the controller's
// accounted-bytes gate. For comparison it also sums the same tree under the
// v0.1.15 rule (max(logical, allocated) per node) and logical sizes. The
// production census also covers /Library/macserve/var and the job home; the
// numbers here are the workspace's contribution.
func TestRealHostHealthSampler(t *testing.T) {
	control, out := os.Getenv("MACSERVE_RH_CONTROL"), os.Getenv("MACSERVE_RH_OUT")
	if control == "" || out == "" {
		t.Skip("MACSERVE_RH_CONTROL or MACSERVE_RH_OUT unset")
	}
	f, err := os.OpenFile(filepath.Join(out, "health.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	admission := controller.ServiceBudgetBytes - controller.JobReservationBytes
	gate := func(n int64) string {
		switch {
		case n < 0 || n > controller.ServiceBudgetBytes:
			return "service_disk_budget_exceeded (cancels active job)"
		case n > admission:
			return "service_disk_reservation_unavailable (blocks admission)"
		}
		return "ok"
	}
	for {
		if _, err := os.Stat(control + ".stop"); err == nil {
			return
		}
		data, _ := os.ReadFile(control)
		if root := strings.TrimSpace(string(data)); root != "" {
			begun := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			accounted, accountErr := accountBytes(ctx, []string{root}, "", 0)
			cancel()
			elapsed := time.Since(begun)
			logical, legacy, entries, walkErr := legacyCensus(root)
			pressure, pressureErr := memoryPressure()
			rec := map[string]any{"t": time.Now().UTC(), "root": root, "accounted_bytes": accounted, "account_ms": elapsed.Milliseconds(), "legacy_v0115_bytes": legacy, "logical_bytes": logical, "entries": entries, "memory_pressure": pressure, "gate": gate(accounted), "gate_v0115": gate(legacy), "admission_headroom_bytes": admission - accounted, "cancel_headroom_bytes": controller.ServiceBudgetBytes - accounted, "admission_headroom_v0115_bytes": admission - legacy}
			if accountErr != nil {
				rec["account_error"] = accountErr.Error()
			}
			if walkErr != nil {
				rec["legacy_error"] = walkErr.Error()
			}
			if pressureErr != nil {
				rec["memory_error"] = pressureErr.Error()
			}
			b, _ := json.Marshal(rec)
			f.Write(append(b, '\n'))
		}
		time.Sleep(2 * time.Second)
	}
}

// legacyCensus is the v0.1.15 charge (max(logical, allocated) per node, each
// inode once, same device only) and the plain logical sum of regular files.
func legacyCensus(root string) (logical, legacy int64, entries int, err error) {
	var top syscall.Stat_t
	if err = syscall.Lstat(root, &top); err != nil {
		return
	}
	seen := map[[2]uint64]bool{}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if os.IsNotExist(walkErr) {
				return nil
			}
			return walkErr
		}
		var st syscall.Stat_t
		if err := syscall.Lstat(path, &st); err != nil {
			return nil
		}
		if st.Dev != top.Dev {
			return fs.SkipDir
		}
		entries++
		key := [2]uint64{uint64(st.Dev), st.Ino}
		if seen[key] {
			return nil
		}
		seen[key] = true
		if st.Mode&syscall.S_IFMT == syscall.S_IFREG {
			logical += st.Size
		}
		legacy += max(st.Size, st.Blocks*512)
		return nil
	})
	return
}

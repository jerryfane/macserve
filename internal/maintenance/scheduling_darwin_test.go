//go:build darwin

package maintenance

import (
	"testing"

	"golang.org/x/sys/unix"
)

// launchd starts the observer with ProcessType=Background. The observer must
// leave that band, or its census is I/O-throttled behind builds and misses the
// probe deadline, which cancels the running job.
func TestLeaveBackgroundSchedulingClearsDarwinBackground(t *testing.T) {
	if err := unix.Setpriority(prioDarwinProcess, 0, prioDarwinBG); err != nil {
		t.Fatalf("enter background band: %v", err)
	}
	t.Cleanup(func() { _ = unix.Setpriority(prioDarwinProcess, 0, 0) })
	if got, err := unix.Getpriority(prioDarwinProcess, 0); err != nil || got == 0 {
		t.Fatalf("fixture not in background band: %d %v", got, err)
	}
	if err := leaveBackgroundScheduling(); err != nil {
		t.Fatal(err)
	}
	if got, err := unix.Getpriority(prioDarwinProcess, 0); err != nil || got != 0 {
		t.Fatalf("still in background band after leaveBackgroundScheduling: %d %v", got, err)
	}
}

package worker

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// A job can attach a disk image under ~/Library/LaunchAgents; reset must refuse
// and leave the mounted filesystem untouched.
func TestResetLaunchAgentsNeverEntersRealMount(t *testing.T) {
	home := t.TempDir()
	mountPoint := filepath.Join(home, "Library", "LaunchAgents", "volume")
	if err := os.MkdirAll(mountPoint, 0700); err != nil {
		t.Fatal(err)
	}
	image := filepath.Join(t.TempDir(), "agents.dmg")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "/usr/bin/hdiutil", "create", "-quiet", "-megabytes", "4", "-fs", "HFS+", "-volname", "agents", image).CombinedOutput(); err != nil {
		t.Skipf("hdiutil create unavailable: %v %s", err, out)
	}
	if out, err := exec.CommandContext(ctx, "/usr/bin/hdiutil", "attach", "-quiet", "-nobrowse", "-noautoopen", "-mountpoint", mountPoint, image).CombinedOutput(); err != nil {
		t.Skipf("hdiutil attach unavailable: %v %s", err, out)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if out, err := exec.CommandContext(ctx, "/usr/bin/hdiutil", "detach", "-quiet", "-force", mountPoint).CombinedOutput(); err != nil {
			t.Errorf("hdiutil detach: %v %s", err, out)
		}
	})
	inside := filepath.Join(mountPoint, "job.plist")
	if err := os.WriteFile(inside, []byte("mounted"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := resetLaunchAgents(context.Background(), home); !errors.Is(err, ErrContamination) {
		t.Fatalf("reset with a mounted image: %v", err)
	}
	if data, err := os.ReadFile(inside); err != nil || string(data) != "mounted" {
		t.Fatalf("reset changed the mounted filesystem: %q %v", data, err)
	}
	t.Log("ran: real hdiutil mount under LaunchAgents refused")
}

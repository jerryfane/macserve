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

// Jobs run with HOME at <workspace>/home, so CoreDevice could mount its devicefs
// there. Cleanup must refuse, never delete inside a mounted filesystem.
func TestWorkspaceCleanupNeverEntersNestedMount(t *testing.T) {
	workspaces, control := t.TempDir(), t.TempDir()
	mountPoint := filepath.Join(workspaces, "job", "home", "Library/Developer/CoreDevice/DeviceFS")
	if err := os.MkdirAll(mountPoint, 0700); err != nil {
		t.Fatal(err)
	}
	image := filepath.Join(t.TempDir(), "device.dmg")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "/usr/bin/hdiutil", "create", "-quiet", "-megabytes", "4", "-fs", "HFS+", "-volname", "device", image).CombinedOutput(); err != nil {
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
	device := filepath.Join(mountPoint, "device-node-stand-in")
	if err := os.WriteFile(device, []byte("mounted"), 0600); err != nil {
		t.Fatal(err)
	}
	wsRoot, err := os.OpenRoot(workspaces)
	if err != nil {
		t.Fatal(err)
	}
	defer wsRoot.Close()
	controlRoot, err := os.OpenRoot(control)
	if err != nil {
		t.Fatal(err)
	}
	defer controlRoot.Close()
	e := &Engine{options: Options{CleanupTimeout: time.Minute}, root: controlRoot, workspaces: wsRoot}
	if err := e.cleanup(context.Background(), &manifest{JobID: "job"}); !errors.Is(err, ErrContamination) {
		t.Fatalf("cleanup with a nested mount: %v", err)
	}
	if data, err := os.ReadFile(device); err != nil || string(data) != "mounted" {
		t.Fatalf("cleanup changed the mounted filesystem: %q %v", data, err)
	}
}

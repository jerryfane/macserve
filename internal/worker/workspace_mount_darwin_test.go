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

// attachImage mounts a fresh 4 MB HFS+ image at mountPoint, as any user can
// at a directory it owns, and detaches it when the test ends.
func attachImage(t *testing.T, mountPoint string) {
	t.Helper()
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
}

// Jobs run with HOME at <workspace>/home, so CoreDevice could mount its devicefs
// there. Cleanup must refuse, never delete inside a mounted filesystem.
func TestWorkspaceCleanupNeverEntersNestedMount(t *testing.T) {
	workspaces, control := t.TempDir(), t.TempDir()
	mountPoint := filepath.Join(workspaces, "job", "home", "Library/Developer/CoreDevice/DeviceFS")
	if err := os.MkdirAll(mountPoint, 0700); err != nil {
		t.Fatal(err)
	}
	attachImage(t, mountPoint)
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

// The live budget and the lockfile digests run while job code runs and
// never descend a real mount in the workspace: its bytes are not on the
// workspace device, and a lockfile inside it is not the checkout's.
func TestWorkspaceBudgetAndLockfilesRefuseRealMount(t *testing.T) {
	workspace := t.TempDir()
	mountPoint := filepath.Join(workspace, "checkout", "ios", "Packages")
	if err := os.MkdirAll(mountPoint, 0700); err != nil {
		t.Fatal(err)
	}
	attachImage(t, mountPoint)
	if err := os.WriteFile(filepath.Join(mountPoint, "Package.resolved"), []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(workspace)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := workspaceBudget(root, 1<<40); !errors.Is(err, errWorkspaceMount) {
		t.Fatalf("budget walk with a nested mount: %v", err)
	}
	if digests, err := lockfiles(context.Background(), root, uint32(os.Geteuid())); !errors.Is(err, errWorkspaceMount) {
		t.Fatalf("lockfile walk with a nested mount: %v %v", digests, err)
	}
}

// Review F1 (round 1): a real mount exactly at a job's workspace directory is
// refused as contamination; nothing inside it is removed.
func TestWorkspaceCleanupRefusesRealMountAtJobRoot(t *testing.T) {
	workspaces, control := t.TempDir(), t.TempDir()
	jobDir := filepath.Join(workspaces, "job")
	if err := os.Mkdir(jobDir, 0700); err != nil {
		t.Fatal(err)
	}
	attachImage(t, jobDir)
	kept := filepath.Join(jobDir, "kept")
	if err := os.WriteFile(kept, []byte("mounted"), 0600); err != nil {
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
	if err := e.cleanup(context.Background(), &manifest{JobID: "job"}); !errors.Is(err, ErrContamination) || !errors.Is(err, errWorkspaceMount) {
		t.Fatalf("cleanup with a mount at the job root: %v", err)
	}
	if data, err := os.ReadFile(kept); err != nil || string(data) != "mounted" {
		t.Fatalf("cleanup changed the mounted filesystem: %q %v", data, err)
	}
}

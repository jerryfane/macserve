package maintenance

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestMountEntryFromStudioStatfs(t *testing.T) {
	if mountNoDev != unix.MNT_NODEV || mountNoSUID != unix.MNT_NOSUID {
		t.Fatal("mount flag constants differ from <sys/mount.h>")
	}
	raw := studioProbe(t, "studio-devicefs-statfs.hex")
	var s unix.Statfs_t
	if len(raw) != int(unsafe.Sizeof(s)) {
		t.Skipf("probe bytes are darwin/arm64 struct statfs; this platform's is %d bytes", unsafe.Sizeof(s))
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&s)), unsafe.Sizeof(s)), raw)
	if got, want := mountEntryFromStatfs(&s), darwinStatfsRecord(t, raw); got != want {
		t.Fatalf("production decoder read %+v, want %+v", got, want)
	}
}

// attachImage mounts a fresh disk image at mountPoint as the current user, the
// way a job could try to hide data at the CoreDevice mount point.
func attachImage(t *testing.T, mountPoint string) {
	t.Helper()
	image := filepath.Join(t.TempDir(), "hide.dmg")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "/usr/bin/hdiutil", "create", "-quiet", "-megabytes", "4", "-fs", "HFS+", "-volname", "hide", image).CombinedOutput(); err != nil {
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

func TestMutableAccountingRefusesRealImageAtCoreDevicePath(t *testing.T) {
	home := censusFixtureDir(t)
	mountPoint := filepath.Join(home, coreDeviceMountPoint)
	if err := os.MkdirAll(mountPoint, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, coreDeviceData), 0700); err != nil {
		t.Fatal(err)
	}
	attachImage(t, mountPoint)
	n, err := accountBytes(context.Background(), []string{home}, home, uint32(os.Geteuid()))
	if n != -1 || err == nil || !strings.Contains(err.Error(), `"Library/Developer/CoreDevice/DeviceFS": mutable mount crossing: "hfs" mount is not the job CoreDevice devicefs`) {
		t.Fatalf("disk image at the CoreDevice path was not refused: bytes=%d err=%v", n, err)
	}
}

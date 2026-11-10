package worker

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/mounttable"
	"golang.org/x/sys/unix"
)

// A real read-only APFS image attached by this (non-root) user at the Metal
// toolchain mount point in a job HOME has the shape Xcode's fallback produced
// on the build host (apfs on a /dev/disk slice, rdonly+nodev+nosuid, owned by
// the attaching user). The evidence pass skips it, cleanup unmounts it with a
// real /sbin/umount run as that user, and the workspace is removed.
func TestCleanupUnmountsRealImageAtMetalToolchainMountPoint(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a root attach is not a job-user mount")
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{}
	engine, err := New(Options{Root: filepath.Join(base, "worker"), ExportRoot: filepath.Join(base, "exports"), WorkspaceRoot: filepath.Join(base, "workspaces"), Runner: runner, JobUID: uint32(os.Getuid())})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	workspace := filepath.Join(engine.options.WorkspaceRoot, "job")
	point := metalPoint(workspace)
	if err := os.MkdirAll(point, 0700); err != nil {
		t.Fatal(err)
	}
	image := filepath.Join(t.TempDir(), "MetalToolchain.dmg")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "/usr/bin/hdiutil", "create", "-quiet", "-megabytes", "16", "-fs", "APFS", "-volname", "MetalToolchain", image).CombinedOutput(); err != nil {
		t.Skipf("hdiutil create unavailable: %v %s", err, out)
	}
	out, err := exec.CommandContext(ctx, "/usr/bin/hdiutil", "attach", "-readonly", "-nobrowse", "-noautoopen", "-mountpoint", point, image).CombinedOutput()
	if err != nil {
		t.Skipf("hdiutil attach unavailable: %v %s", err, out)
	}
	// hdiutil prints the whole disk first; detaching it detaches the image.
	device := strings.Fields(string(out))[0]
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if out, err := exec.CommandContext(ctx, "/usr/bin/hdiutil", "detach", "-quiet", "-force", device).CombinedOutput(); err != nil {
			t.Errorf("hdiutil detach %s: %v %s", device, err, out)
		}
	})
	var st unix.Stat_t
	if err := unix.Lstat(point, &st); err != nil {
		t.Fatal(err)
	}
	table, err := mounttable.Read()
	if err != nil {
		t.Fatal(err)
	}
	record, ok := mounttable.Unique(table, uint64(st.Dev))
	if !ok || !MetalToolchainMount(record, engine.options.WorkspaceRoot, engine.options.JobUID) {
		t.Fatalf("attached image record %+v (unique %v) is not a MetalToolchainMount", record, ok)
	}
	if err := engine.workspacePass(context.Background(), "job", false, false); err != nil {
		t.Fatalf("evidence pass with the image: %v", err)
	}
	runner.hook = func(ctx context.Context, c Command, out, stderr io.Writer) (bool, ProcessResult, error) {
		if c.Executable != "/sbin/umount" {
			return false, ProcessResult{}, nil
		}
		cmd := exec.CommandContext(ctx, c.Executable, c.Args...)
		cmd.Dir, cmd.Env, cmd.Stdout, cmd.Stderr = c.Dir, c.Env, out, stderr
		err := cmd.Run()
		if cmd.ProcessState == nil {
			return true, ProcessResult{ExitCode: -1, CleanupOK: true}, err
		}
		return true, ProcessResult{ExitCode: cmd.ProcessState.ExitCode(), CleanupOK: true}, err
	}
	if err := engine.cleanup(context.Background(), &manifest{JobID: "job"}); err != nil {
		t.Fatalf("cleanup with the image: %v", err)
	}
	if _, err := os.Lstat(workspace); !os.IsNotExist(err) {
		t.Fatalf("workspace not removed: %v", err)
	}
}

package worker

import (
	"context"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
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
	device := attachReadOnlyImage(t, ctx, image, point)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if out, err := exec.CommandContext(ctx, "/usr/sbin/diskutil", "eject", device).CombinedOutput(); err != nil {
			t.Errorf("diskutil eject %s: %v %s", device, err, out)
		}
	})
	requireMountShape(t, ctx, point)
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

// wholeDisk is the first device row of an attach report: the image's whole
// disk, which ejecting detaches with every disk synthesized from it.
var wholeDisk = regexp.MustCompile(`(?m)^(/dev/disk[0-9]+)\s`)

// attachReadOnlyImage attaches image read-only, unbrowsable, at point and
// returns its whole disk. It uses `diskutil image attach` (macOS 27, where
// `hdiutil attach -mountpoint` prints a deprecation warning) and falls back
// to hdiutil where diskutil has no image verb. Only stdout is parsed. A
// failed attach skips; an attach whose report names no device fails, after
// ejecting whatever is mounted at point.
func attachReadOnlyImage(t *testing.T, ctx context.Context, image, point string) string {
	t.Helper()
	argv := []string{"/usr/sbin/diskutil", "image", "attach", "--readOnly", "--nobrowse", "--mountPoint", point, image}
	if err := exec.CommandContext(ctx, "/usr/sbin/diskutil", "image", "attach", "--help").Run(); err != nil {
		argv = []string{"/usr/bin/hdiutil", "attach", "-readonly", "-nobrowse", "-noautoopen", "-mountpoint", point, image}
	}
	var stdout, stderr strings.Builder
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Skipf("%s unavailable: %v\nstdout: %s\nstderr: %s", strings.Join(argv[:2], " "), err, stdout.String(), stderr.String())
	}
	match := wholeDisk.FindStringSubmatch(stdout.String())
	if match == nil {
		out, err := exec.CommandContext(ctx, "/usr/sbin/diskutil", "eject", point).CombinedOutput()
		t.Fatalf("%s reported no /dev/disk device (eject by mount point: %v %s)\nstdout: %s\nstderr: %s", strings.Join(argv[:2], " "), err, out, stdout.String(), stderr.String())
	}
	t.Logf("%s attached %s at %s", strings.Join(argv[:2], " "), match[1], point)
	return match[1]
}

// requireMountShape requires mount(8)'s line for point to show the shape of
// Xcode's Metal toolchain fallback mount on the build host: apfs, nodev,
// nosuid, read-only, mounted by the current user.
func requireMountShape(t *testing.T, ctx context.Context, point string) {
	t.Helper()
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.CommandContext(ctx, "/sbin/mount").Output()
	if err != nil {
		t.Fatalf("mount: %v", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		_, rest, ok := strings.Cut(line, " on "+point+" (")
		if !ok {
			continue
		}
		options := map[string]bool{}
		for _, option := range strings.Split(strings.TrimSuffix(rest, ")"), ", ") {
			options[option] = true
		}
		for _, want := range []string{"apfs", "nodev", "nosuid", "read-only", "mounted by " + account.Username} {
			if !options[want] {
				t.Fatalf("mount line %q lacks %q", line, want)
			}
		}
		return
	}
	t.Fatalf("no mount line for %s:\n%s", point, out)
}

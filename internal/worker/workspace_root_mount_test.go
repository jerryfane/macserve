package worker

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// presentMountAt makes fstatFD report another device for the directory at
// path, as a mount over it would, and counts how often it was asked.
func presentMountAt(t *testing.T, path string) *int {
	t.Helper()
	var target unix.Stat_t
	if err := unix.Lstat(path, &target); err != nil {
		t.Fatal(err)
	}
	calls := 0
	saved := fstatFD
	fstatFD = func(fd int, st *unix.Stat_t) error {
		if err := unix.Fstat(fd, st); err != nil {
			return err
		}
		if st.Dev == target.Dev && st.Ino == target.Ino {
			calls++
			st.Dev++
		}
		return nil
	}
	t.Cleanup(func() { fstatFD = saved })
	return &calls
}

// Review F1 (round 1): a mount exactly at a job's workspace directory is
// entered when the directory is opened by name, so walkWorkspace compared it
// with itself. Cleanup now refuses it as contamination, the engine
// quarantines, and the next Recover refuses without walking it again.
func TestWorkspaceRootMountIsQuarantinedNotRetried(t *testing.T) {
	engine := engineFixture(t, &fakeRunner{})
	if err := engine.saveManifest(manifest{JobID: "job", DeveloperDir: "/Applications/Xcode.app/Contents/Developer"}); err != nil {
		t.Fatal(err)
	}
	jobDir := filepath.Join(engine.options.WorkspaceRoot, "job")
	if err := os.MkdirAll(filepath.Join(jobDir, "home"), 0700); err != nil {
		t.Fatal(err)
	}
	kept := filepath.Join(jobDir, "home", "kept")
	if err := os.WriteFile(kept, []byte("mounted"), 0600); err != nil {
		t.Fatal(err)
	}
	calls := presentMountAt(t, jobDir)
	err := engine.Recover(context.Background())
	if !errors.Is(err, ErrContamination) || !errors.Is(err, errWorkspaceMount) {
		t.Fatalf("recover with a mount at the workspace root: %v", err)
	}
	seen := *calls
	if err := engine.Recover(context.Background()); !errors.Is(err, ErrRecovery) || !strings.Contains(err.Error(), "administrator reset required") {
		t.Fatalf("second recover = %v, want quarantine refusal", err)
	}
	if *calls != seen {
		t.Fatalf("quarantined workspace was walked again (%d -> %d)", seen, *calls)
	}
	if data, err := os.ReadFile(kept); err != nil || string(data) != "mounted" {
		t.Fatalf("cleanup changed the mounted filesystem: %q %v", data, err)
	}
}

// Review F2 (round 1): a directory whose name stats on the workspace device
// but whose opened descriptor is on another one (a mount placed between
// fstatat and openat) is refused by the post-open check, never walked.
func TestWorkspaceWalksRefuseMountAfterOpen(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "checkout", "ios")
	if err := os.MkdirAll(sub, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "Package.resolved"), []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	presentMountAt(t, sub)
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := workspaceBudget(root, 1<<40); !errors.Is(err, errWorkspaceMount) {
		t.Fatalf("budget walk = %v, want post-open mount refusal", err)
	}
	if digests, err := lockfiles(context.Background(), root, uint32(os.Geteuid())); !errors.Is(err, errWorkspaceMount) {
		t.Fatalf("lockfile walk = %v %v, want post-open mount refusal", digests, err)
	}
}

// Review F3 (round 1): the budget charges an inode once, however many links
// name it.
func TestWorkspaceBudgetChargesHardlinkedInodeOnce(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "payload"), bytes.Repeat([]byte{0xa5}, 128<<10), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(dir, "payload"), filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	charged := allocatedBytes(t, root, "payload")
	if err := workspaceBudget(root, charged); err != nil {
		t.Fatalf("hard link charged twice: %v", err)
	}
	if err := workspaceBudget(root, charged-1); err == nil {
		t.Fatal("hardlinked inode not charged")
	}
}

// Review F4 (round 1): one residual instance that survives termination is
// contamination two graces after it was first listed, not only at the
// quiesce's settle bound.
func TestQuiesceSurvivorIsContaminationAfterTwoGraces(t *testing.T) {
	s, agents, rows := devtoolWorld(t)
	s.grace = 50 * time.Millisecond
	agents.procs[200] = agentProcess{start: "30:0", uid: testJobUID, ppid: 1, executable: "/bin/sleep", platform: true}
	live := append(rows, sample(200, "30:0"))
	s.sample = func(context.Context) ([]processSample, error) { return append([]processSample(nil), live...), nil }
	s.signal = func(context.Context, processSample, syscall.Signal) error { return nil }
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	started := time.Now()
	err := s.quiesce(ctx)
	elapsed := time.Since(started)
	if !errors.Is(err, ErrContamination) || !strings.Contains(err.Error(), "remain after termination") {
		t.Fatalf("surviving job process: %v", err)
	}
	if elapsed < 2*s.grace || elapsed >= quiesceSettleGraces*s.grace/2 {
		t.Fatalf("survivor judged after %v, want about two graces (%v)", elapsed, 2*s.grace)
	}
}

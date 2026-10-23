package worker

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// v0.1.15 tool evidence (entmoot, Mac Studio): 5 s into `xcodebuild build`
// derived-data/CompilationCache.noindex/generic/v1.1 held data.v1, index.v1
// and actions.v1 at 24, 12 and 1 GiB logical, about 1 MiB allocated each.
// The budget summed logical sizes, 37 GiB > 30 GiB, and stopped the build.
func TestWorkspaceBudgetChargesSparseFilesAllocatedBytes(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(dir, "derived-data/CompilationCache.noindex/generic/v1.1")
	if err := os.MkdirAll(cache, 0700); err != nil {
		t.Fatal(err)
	}
	var allocated int64
	for _, f := range []struct {
		name string
		size int64
	}{{"data.v1", 24 << 30}, {"index.v1", 12 << 30}, {"actions.v1", 1 << 30}} {
		path := filepath.Join(cache, f.name)
		if err := os.WriteFile(path, bytes.Repeat([]byte{0xa5}, 64<<10), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Truncate(path, f.size); err != nil {
			t.Fatal(err)
		}
		var st unix.Stat_t
		if err := unix.Lstat(path, &st); err != nil {
			t.Fatal(err)
		}
		if st.Blocks*512 >= 1<<30 {
			t.Skipf("filesystem does not keep sparse files: %d bytes allocated", st.Blocks*512)
		}
		allocated += st.Blocks * 512
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := workspaceBudget(root, 30<<30); err != nil {
		t.Fatalf("sparse compilation cache exceeded the 30 GiB budget: %v", err)
	}
	if err := workspaceBudget(root, allocated-1); err == nil {
		t.Fatal("allocated bytes of the sparse files were not charged")
	}
}

// A mount point inside the workspace is never descended by the budget or the
// lockfile walk; both refuse it (errWorkspaceMount).
func TestWorkspaceWalksRefuseMountPoint(t *testing.T) {
	dir := t.TempDir()
	mountPoint := filepath.Join(dir, "checkout/ios/mounted")
	if err := os.MkdirAll(mountPoint, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mountPoint, "Package.resolved"), []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var mounted unix.Stat_t
	if err := unix.Lstat(mountPoint, &mounted); err != nil {
		t.Fatal(err)
	}
	statat := func(fd int, name string, st *unix.Stat_t, flags int) error {
		var parent unix.Stat_t
		if err := unix.Fstat(fd, &parent); err != nil {
			return err
		}
		if parent.Dev == mounted.Dev && parent.Ino == mounted.Ino {
			t.Errorf("walk descended into the mount point: stat %q", name)
		}
		if err := unix.Fstatat(fd, name, st, flags); err != nil {
			return err
		}
		if st.Dev == mounted.Dev && st.Ino == mounted.Ino {
			st.Dev++
		}
		return nil
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := workspaceBudgetWith(root, 1<<40, statat); !errors.Is(err, errWorkspaceMount) || !strings.Contains(err.Error(), `"checkout/ios/mounted"`) {
		t.Fatalf("budget walk = %v, want mount refusal", err)
	}
	digests, err := lockfilesWith(context.Background(), root, uint32(os.Geteuid()), statat)
	if !errors.Is(err, errWorkspaceMount) || len(digests) != 0 {
		t.Fatalf("lockfile walk = %v %v, want mount refusal", digests, err)
	}
}

// v0.1.15 tool evidence, Mac Studio 16:34:42: quiesce's SIGKILL round killed
// fskit_agent, a tolerated launch. launchd tore its pid domain down with a
// SIGTERM and a 5 s cleanup delay, and the DeviceFS extension instance it had
// started 0.3 s earlier stayed. With no live owner that instance is residual,
// first listed 1.3 s into the quiesce, after the fixed 2-grace deadline, so
// quiesce reported contamination without ever signalling it. Each residual
// instance now has two graces from its own first snapshot, SIGKILL when
// first seen past the first grace.
func TestQuiesceKillsResidualFirstSeenLate(t *testing.T) {
	s, agents, rows := devtoolWorld(t)
	s.grace = 50 * time.Millisecond
	orphan := 900
	facts := agents.procs[deviceFSPID]
	facts.start = "70:0"
	agents.procs[orphan] = facts
	live := slices.Clone(rows)
	begun := time.Now()
	calls := 0
	s.sample = func(context.Context) ([]processSample, error) {
		if calls++; calls == 2 {
			time.Sleep(time.Until(begun.Add(3 * s.grace)))
			live = append(live, sample(orphan, "70:0"))
		}
		return slices.Clone(live), nil
	}
	var signals []syscall.Signal
	s.signal = func(_ context.Context, p processSample, sig syscall.Signal) error {
		if p.pid == orphan {
			signals = append(signals, sig)
			if sig == syscall.SIGKILL {
				live = slices.DeleteFunc(live, func(row processSample) bool { return row.pid == orphan })
			}
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.quiesce(ctx); err != nil {
		t.Fatalf("late orphan of a killed owner failed cleanup: %v", err)
	}
	if !slices.Equal(signals, []syscall.Signal{syscall.SIGKILL}) {
		t.Fatalf("orphan signals %v, want one SIGKILL at first sight", signals)
	}
}

// A job that keeps starting residual processes is contamination once the
// quiesce reaches quiesceSettleGraces, however recent each instance is.
func TestQuiesceBoundsProcessesThatKeepAppearing(t *testing.T) {
	s, agents, rows := devtoolWorld(t)
	s.grace = 20 * time.Millisecond
	next := 900
	spawn := func() processSample {
		next++
		p := sample(next, "80:"+strconv.Itoa(next))
		agents.procs[p.pid] = agentProcess{start: p.start, uid: testJobUID, ppid: 1, executable: "/bin/sleep", platform: true}
		return p
	}
	live := append(slices.Clone(rows), spawn())
	s.sample = func(context.Context) ([]processSample, error) { return slices.Clone(live), nil }
	s.signal = func(_ context.Context, p processSample, sig syscall.Signal) error {
		if p.pid > 900 {
			live = append(slices.DeleteFunc(live, func(row processSample) bool { return row.pid == p.pid }), spawn())
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	started := time.Now()
	err := s.quiesce(ctx)
	if !errors.Is(err, ErrContamination) || !strings.Contains(err.Error(), "keep appearing") {
		t.Fatalf("respawning job processes: %v", err)
	}
	if elapsed := time.Since(started); elapsed < quiesceSettleGraces*s.grace || elapsed > time.Second {
		t.Fatalf("bound reached after %v", elapsed)
	}
}

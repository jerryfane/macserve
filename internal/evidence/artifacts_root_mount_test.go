package evidence

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
	"golang.org/x/sys/unix"
)

// Review F1 (round 1): an artifact root is opened by name, so a mount exactly
// at it would be entered. Collect refuses a root on another device than its
// parent.
func TestCollectRefusesMountAtRoot(t *testing.T) {
	root, dest := t.TempDir(), filepath.Join(t.TempDir(), "export")
	if err := os.WriteFile(filepath.Join(root, "build.txt"), []byte("mounted"), 0600); err != nil {
		t.Fatal(err)
	}
	var target unix.Stat_t
	if err := unix.Lstat(root, &target); err != nil {
		t.Fatal(err)
	}
	saved := fstatFD
	fstatFD = func(fd int, st *unix.Stat_t) error {
		if err := unix.Fstat(fd, st); err != nil {
			return err
		}
		if st.Dev == target.Dev && st.Ino == target.Ino {
			st.Dev++
		}
		return nil
	}
	t.Cleanup(func() { fstatFD = saved })
	artifacts, err := Collect(context.Background(), root, []model.ArtifactRule{{Path: "*.txt", Required: true}}, dest, Limits{}, time.Now())
	if !errors.Is(err, ErrArtifact) || len(artifacts) != 0 {
		t.Fatalf("collected from a root mount: %v %v", artifacts, err)
	}
}

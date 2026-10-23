package evidence

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
)

// Artifact collection never collects from or descends a mount point beneath
// the artifact root: any user can attach an image at a directory it owns.
func TestCollectRefusesRealMount(t *testing.T) {
	root, dest := t.TempDir(), filepath.Join(t.TempDir(), "export")
	mountPoint := filepath.Join(root, "logs")
	if err := os.Mkdir(mountPoint, 0700); err != nil {
		t.Fatal(err)
	}
	image := filepath.Join(t.TempDir(), "logs.dmg")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "/usr/bin/hdiutil", "create", "-quiet", "-megabytes", "4", "-fs", "HFS+", "-volname", "logs", image).CombinedOutput(); err != nil {
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
	if err := os.WriteFile(filepath.Join(mountPoint, "build.txt"), []byte("mounted"), 0600); err != nil {
		t.Fatal(err)
	}
	artifacts, err := Collect(context.Background(), root, []model.ArtifactRule{{Path: "logs/*.txt", Required: true}}, dest, Limits{}, time.Now())
	if !errors.Is(err, ErrArtifact) || len(artifacts) != 0 {
		t.Fatalf("collected through a mount point: %v %v", artifacts, err)
	}
}

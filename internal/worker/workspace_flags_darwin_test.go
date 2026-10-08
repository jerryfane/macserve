//go:build darwin

package worker

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestWorkspaceCleanupClearsOnlyConfinedUserFlags(t *testing.T) {
	root, outside := t.TempDir(), filepath.Join(t.TempDir(), "outside")
	directory := filepath.Join(root, "readonly")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(directory, "output")
	for _, name := range []string{file, outside} {
		if err := os.WriteFile(name, []byte("evidence"), 0400); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(root, "outside-link")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Chflags(directory, 0); _ = unix.Chflags(file, 0); _ = unix.Chflags(outside, 0) })
	for _, name := range []string{file, directory, outside} {
		if err := unix.Chflags(name, unix.UF_IMMUTABLE|unix.UF_APPEND|unix.UF_NODUMP); err != nil {
			t.Fatal(err)
		}
	}
	dir, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	if err := walkWorkspace(context.Background(), dir, uint32(os.Geteuid()), false, uint32(os.Getegid()), true); err != nil {
		t.Fatal(err)
	}
	var repaired, untouched unix.Stat_t
	if err := unix.Lstat(file, &repaired); err != nil {
		t.Fatal(err)
	}
	if err := unix.Lstat(outside, &untouched); err != nil {
		t.Fatal(err)
	}
	if repaired.Flags != unix.UF_NODUMP || untouched.Flags != unix.UF_IMMUTABLE|unix.UF_APPEND|unix.UF_NODUMP {
		t.Fatalf("wrong flags after confined repair: file=%x outside=%x", repaired.Flags, untouched.Flags)
	}
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("workspace survived cleanup: %v", err)
	}
}

func TestWorkspaceImmutableHardlinkDoesNotModifyExternalInode(t *testing.T) {
	root, outside := t.TempDir(), filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("outside evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(root, "hardlink")
	if err := os.Link(outside, linked); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Chflags(outside, 0) })
	if err := unix.Chflags(outside, unix.UF_IMMUTABLE); err != nil {
		t.Fatal(err)
	}
	dir, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	if err := walkWorkspace(context.Background(), dir, uint32(os.Geteuid()), false, uint32(os.Getegid()), true); err == nil {
		t.Fatal("modified immutable external hardlink instead of refusing cleanup")
	}
	var stat unix.Stat_t
	if err := unix.Lstat(outside, &stat); err != nil {
		t.Fatal(err)
	}
	if stat.Flags != unix.UF_IMMUTABLE || stat.Nlink != 2 {
		t.Fatalf("external inode changed: flags=%x links=%d", stat.Flags, stat.Nlink)
	}
}

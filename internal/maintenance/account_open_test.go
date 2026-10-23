package maintenance

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// Review F2 (round 1): a directory that stats on the census device but opens
// on another (a mount placed between fstatat and openat) is a mount crossing.
func TestMutableAccountingRefusesMountAfterOpen(t *testing.T) {
	root := censusFixtureDir(t)
	sub := filepath.Join(root, "Library")
	if err := os.Mkdir(sub, 0700); err != nil {
		t.Fatal(err)
	}
	var target unix.Stat_t
	if err := unix.Lstat(sub, &target); err != nil {
		t.Fatal(err)
	}
	fstat := func(fd int, st *unix.Stat_t) error {
		if err := unix.Fstat(fd, st); err != nil {
			return err
		}
		if st.Dev == target.Dev && st.Ino == target.Ino {
			st.Dev++
		}
		return nil
	}
	n, err := census{base: "/", statat: unix.Fstatat, fstat: fstat}.account(context.Background(), []string{root})
	if err == nil || n != -1 || !strings.Contains(err.Error(), "mount crossing") {
		t.Fatalf("post-open mount accounted: bytes=%d err=%v", n, err)
	}
}

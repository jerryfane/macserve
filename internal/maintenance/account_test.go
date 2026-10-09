package maintenance

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func censusFixtureDir(t *testing.T) string {
	t.Helper()
	path, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func censusFixtureFile(t *testing.T, path string, size int64) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
}

func censusFixtureBytes(t *testing.T, path string) int64 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		t.Fatal(err)
	}
	return max(st.Size, st.Blocks*512)
}

func TestMutableAccountingEntryChurn(t *testing.T) {
	for _, change := range []string{"unlink before stat", "unlink before open", "replace with file", "replace with symlink", "replace with directory", "create within directory"} {
		t.Run(change, func(t *testing.T) {
			base := censusFixtureDir(t)
			root, outside := filepath.Join(base, "root"), filepath.Join(base, "outside")
			entry := filepath.Join(root, "changing")
			for _, path := range []string{root, outside, entry} {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			budget := filepath.Join(root, "budget")
			censusFixtureFile(t, budget, 64*1024)
			censusFixtureFile(t, filepath.Join(outside, "not-accounted"), 1024*1024)
			want := censusFixtureBytes(t, root) + censusFixtureBytes(t, budget)
			changed := false
			statat := func(fd int, name string, st *unix.Stat_t, flags int) error {
				if name != "changing" || changed {
					return unix.Fstatat(fd, name, st, flags)
				}
				changed = true
				if change == "unlink before stat" {
					if err := os.Remove(entry); err != nil {
						t.Fatal(err)
					}
					return unix.Fstatat(fd, name, st, flags)
				}
				if err := unix.Fstatat(fd, name, st, flags); err != nil {
					return err
				}
				if change == "unlink before open" {
					if err := os.Remove(entry); err != nil {
						t.Fatal(err)
					}
				} else if change != "create within directory" {
					// Keep the old inode alive so replacement cannot reuse its identity.
					if err := os.Rename(entry, filepath.Join(base, "retired")); err != nil {
						t.Fatal(err)
					}
				}
				switch change {
				case "replace with file":
					censusFixtureFile(t, entry, 1024*1024)
				case "replace with symlink":
					if err := os.Symlink(outside, entry); err != nil {
						t.Fatal(err)
					}
				case "replace with directory", "create within directory":
					if change == "replace with directory" {
						if err := os.Mkdir(entry, 0700); err != nil {
							t.Fatal(err)
						}
					}
					payload := filepath.Join(entry, "payload")
					censusFixtureFile(t, payload, 32*1024)
					want += censusFixtureBytes(t, entry) + censusFixtureBytes(t, payload)
				}
				return nil
			}
			n, err := accountBytesWithStat(context.Background(), []string{root}, statat)
			if !changed || err != nil || n != want || n <= 32*1024 {
				t.Fatalf("churn lost budget observation: changed=%v bytes=%d want=%d err=%v", changed, n, want, err)
			}
		})
	}
}

func TestMutableAccountingDirectoryMetadataChurn(t *testing.T) {
	root := censusFixtureDir(t)
	payload := filepath.Join(root, "payload")
	censusFixtureFile(t, payload, 64*1024)
	want := censusFixtureBytes(t, root) + censusFixtureBytes(t, payload)
	statat := func(fd int, name string, st *unix.Stat_t, flags int) error {
		err := unix.Fstatat(fd, name, st, flags)
		if err == nil && name == "payload" {
			created, renamed := filepath.Join(root, "created"), filepath.Join(root, "renamed")
			censusFixtureFile(t, created, 4096)
			if err := os.Rename(created, renamed); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(renamed); err != nil {
				t.Fatal(err)
			}
			// Ensure a distinct timestamp without relying on filesystem clock resolution.
			if err := os.Chtimes(root, time.Unix(1, 0), time.Unix(1, 0)); err != nil {
				t.Fatal(err)
			}
		}
		return err
	}
	n, err := accountBytesWithStat(context.Background(), []string{root}, statat)
	if err != nil || n != want {
		t.Fatalf("metadata churn invalidated observation: bytes=%d want=%d err=%v", n, want, err)
	}
}

func TestMutableAccountingOpenedDirectoryUnlinked(t *testing.T) {
	base := censusFixtureDir(t)
	root := filepath.Join(base, "root")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	censusFixtureFile(t, filepath.Join(root, "removed"), 4096)
	want := censusFixtureBytes(t, root)
	statat := func(fd int, name string, st *unix.Stat_t, flags int) error {
		if name == "removed" {
			if err := os.RemoveAll(root); err != nil {
				t.Fatal(err)
			}
		}
		return unix.Fstatat(fd, name, st, flags)
	}
	n, err := accountBytesWithStat(context.Background(), []string{root}, statat)
	if err != nil || n != want {
		t.Fatalf("unlinked open directory invalidated observation: bytes=%d want=%d err=%v", n, want, err)
	}
}

func TestMutableAccountingUsesOpenedParentAfterRename(t *testing.T) {
	base := censusFixtureDir(t)
	root, outside := filepath.Join(base, "root"), filepath.Join(base, "outside")
	entry := filepath.Join(root, "changing")
	for _, path := range []string{root, outside, entry} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	payload := filepath.Join(entry, "payload")
	censusFixtureFile(t, payload, 64*1024)
	censusFixtureFile(t, filepath.Join(outside, "not-accounted"), 1024*1024)
	want := censusFixtureBytes(t, root) + censusFixtureBytes(t, entry) + censusFixtureBytes(t, payload)
	statat := func(fd int, name string, st *unix.Stat_t, flags int) error {
		err := unix.Fstatat(fd, name, st, flags)
		if err == nil && name == "changing" {
			if err := os.Rename(root, filepath.Join(base, "moved")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, root); err != nil {
				t.Fatal(err)
			}
		}
		return err
	}
	n, err := accountBytesWithStat(context.Background(), []string{root}, statat)
	if err != nil || n != want {
		t.Fatalf("renamed parent escaped descriptor confinement: bytes=%d want=%d err=%v", n, want, err)
	}
}

func TestMutableAccountingReplacementAlreadyCounted(t *testing.T) {
	base := censusFixtureDir(t)
	first, second := filepath.Join(base, "first"), filepath.Join(base, "second")
	for _, path := range []string{first, second} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	payload := filepath.Join(first, "payload")
	censusFixtureFile(t, payload, 64*1024)
	want := censusFixtureBytes(t, first) + censusFixtureBytes(t, payload)
	stats := 0
	statat := func(fd int, name string, st *unix.Stat_t, flags int) error {
		err := unix.Fstatat(fd, name, st, flags)
		if err == nil && name == "second" {
			stats++
			if stats == 2 {
				if err := os.Rename(second, filepath.Join(base, "retired")); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(first, second); err != nil {
					t.Fatal(err)
				}
			}
		}
		return err
	}
	n, err := accountBytesWithStat(context.Background(), []string{first, second}, statat)
	if err != nil || n != want {
		t.Fatalf("opened replacement counted twice: bytes=%d want=%d err=%v", n, want, err)
	}
}

func TestMutableAccountingFileGrowthUsesLiveObservations(t *testing.T) {
	root := censusFixtureDir(t)
	payload := filepath.Join(root, "growing")
	censusFixtureFile(t, payload, 4096)
	before := censusFixtureBytes(t, root) + censusFixtureBytes(t, payload)
	statat := func(fd int, name string, st *unix.Stat_t, flags int) error {
		err := unix.Fstatat(fd, name, st, flags)
		if err == nil && name == "growing" {
			if err := os.Truncate(payload, 64*1024); err != nil {
				t.Fatal(err)
			}
		}
		return err
	}
	n, err := accountBytesWithStat(context.Background(), []string{root}, statat)
	if err != nil || n != before {
		t.Fatalf("live file write invalidated observation: bytes=%d want=%d err=%v", n, before, err)
	}
	after := censusFixtureBytes(t, root) + censusFixtureBytes(t, payload)
	n, err = accountBytes(context.Background(), []string{root})
	if err != nil || n != after || n <= 32*1024 {
		t.Fatalf("next observation lost budget excess: bytes=%d want=%d err=%v", n, after, err)
	}
}

func TestMutableAccountingRetainsFailures(t *testing.T) {
	for _, failure := range []string{"permission", "io", "mount", "negative size", "negative blocks", "block overflow", "total overflow"} {
		t.Run(failure, func(t *testing.T) {
			root := censusFixtureDir(t)
			censusFixtureFile(t, filepath.Join(root, "payload"), 4096)
			statat := func(fd int, name string, st *unix.Stat_t, flags int) error {
				err := unix.Fstatat(fd, name, st, flags)
				if err != nil || name != "payload" {
					return err
				}
				switch failure {
				case "permission":
					return unix.EACCES
				case "io":
					return unix.EIO
				case "mount":
					st.Dev++
				case "negative size":
					st.Size = -1
				case "negative blocks":
					st.Blocks = -1
				case "block overflow":
					st.Blocks = math.MaxInt64/512 + 1
				case "total overflow":
					st.Size = math.MaxInt64
				}
				return nil
			}
			n, err := accountBytesWithStat(context.Background(), []string{root}, statat)
			if err == nil || n != -1 {
				t.Fatalf("real failure published budget: bytes=%d err=%v", n, err)
			}
			if failure == "permission" && !errors.Is(err, unix.EACCES) || failure == "io" && !errors.Is(err, unix.EIO) {
				t.Fatalf("lost underlying error: %v", err)
			}
		})
	}
}

func TestMutableAccountingHardlinksAndAncestorSymlinks(t *testing.T) {
	base := censusFixtureDir(t)
	root := filepath.Join(base, "root")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	payload := filepath.Join(root, "payload")
	censusFixtureFile(t, payload, 64*1024)
	if err := os.Link(payload, filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	want := censusFixtureBytes(t, root) + censusFixtureBytes(t, payload)
	n, err := accountBytes(context.Background(), []string{root})
	if err != nil || n != want {
		t.Fatalf("hardlink counted twice: bytes=%d want=%d err=%v", n, want, err)
	}
	if err := os.Symlink(base, filepath.Join(base, "linked-parent")); err != nil {
		t.Fatal(err)
	}
	n, err = accountBytes(context.Background(), []string{filepath.Join(base, "linked-parent", "root")})
	if err == nil || n != -1 {
		t.Fatalf("followed ancestor symlink: bytes=%d err=%v", n, err)
	}
}

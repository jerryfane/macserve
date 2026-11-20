package maintenance

import (
	"bytes"
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
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

// censusFixtureFile writes size bytes of data: the census charges a regular
// file its allocated blocks, so a fixture must occupy what it claims.
func censusFixtureFile(t *testing.T, path string, size int64) {
	t.Helper()
	if err := os.WriteFile(path, bytes.Repeat([]byte{0xa5}, int(size)), 0600); err != nil {
		t.Fatal(err)
	}
}

// censusFixtureBytes is what the census charges path: allocated bytes for a
// regular file, max(logical, allocated) for anything else.
func censusFixtureBytes(t *testing.T, path string) int64 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		t.Fatal(err)
	}
	if st.Mode&unix.S_IFMT == unix.S_IFREG {
		return st.Blocks * 512
	}
	return max(st.Size, st.Blocks*512)
}

// Xcode 27 preallocates derived-data/CompilationCache.noindex sparse: 24, 12
// and 1 GiB logical, about 1 MiB each on disk (v0.1.15 tool evidence). The
// census charges what a file occupies, not its logical size.
func TestMutableAccountingChargesSparseFilesAllocatedBytes(t *testing.T) {
	root := censusFixtureDir(t)
	cache := filepath.Join(root, "CompilationCache.noindex")
	if err := os.Mkdir(cache, 0700); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(cache, "data.v1")
	censusFixtureFile(t, data, 64*1024)
	if err := os.Truncate(data, 24<<30); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Lstat(data, &st); err != nil {
		t.Fatal(err)
	}
	if st.Blocks*512 >= 1<<30 {
		t.Skipf("filesystem does not keep sparse files: %d bytes allocated", st.Blocks*512)
	}
	want := censusFixtureBytes(t, root) + censusFixtureBytes(t, cache) + st.Blocks*512
	n, _, err := accountBytes(context.Background(), []string{root}, "", 0)
	if err != nil || n != want || n >= 1<<30 {
		t.Fatalf("sparse file charged by logical size: bytes=%d want=%d err=%v", n, want, err)
	}
}

// A signal interrupting a stat or a directory open (EINTR, seen on the Mac
// Studio opening Library/Containers/*/Data during a build) is transient. It must
// be retried, not published as an invalid census that cancels the running job.
func TestMutableAccountingRetriesInterruptedCalls(t *testing.T) {
	for _, call := range []string{"statat", "openat"} {
		t.Run(call, func(t *testing.T) {
			root := censusFixtureDir(t)
			data := filepath.Join(root, "Data")
			if err := os.Mkdir(data, 0700); err != nil {
				t.Fatal(err)
			}
			censusFixtureFile(t, filepath.Join(data, "payload"), 4096)
			want, _, err := census{base: "/", statat: unix.Fstatat}.account(context.Background(), []string{root})
			if err != nil {
				t.Fatal(err)
			}
			interrupted := map[string]bool{}
			interrupt := func(name string) bool {
				if interrupted[name] {
					return false
				}
				interrupted[name] = true
				return true
			}
			c := census{base: "/", statat: unix.Fstatat}
			switch call {
			case "statat":
				c.statat = func(fd int, name string, st *unix.Stat_t, flags int) error {
					if interrupt(name) {
						return unix.EINTR
					}
					return unix.Fstatat(fd, name, st, flags)
				}
			case "openat":
				c.openat = func(fd int, name string, flags int, mode uint32) (int, error) {
					if interrupt(name) {
						return -1, unix.EINTR
					}
					return unix.Openat(fd, name, flags, mode)
				}
			}
			n, _, err := c.account(context.Background(), []string{root})
			if err != nil || n != want {
				t.Fatalf("interrupted %s not retried: bytes=%d want=%d err=%v", call, n, want, err)
			}
			if !interrupted["Data"] || !interrupted["payload"] && call == "statat" {
				t.Fatalf("fixture did not interrupt the expected calls: %v", interrupted)
			}
		})
	}
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
			n, _, err := census{base: "/", statat: statat}.account(context.Background(), []string{root})
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
	n, _, err := census{base: "/", statat: statat}.account(context.Background(), []string{root})
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
	n, _, err := census{base: "/", statat: statat}.account(context.Background(), []string{root})
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
	n, _, err := census{base: "/", statat: statat}.account(context.Background(), []string{root})
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
	n, _, err := census{base: "/", statat: statat}.account(context.Background(), []string{first, second})
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
			if err := os.WriteFile(payload, bytes.Repeat([]byte{0xa5}, 64*1024), 0600); err != nil {
				t.Fatal(err)
			}
		}
		return err
	}
	n, _, err := census{base: "/", statat: statat}.account(context.Background(), []string{root})
	if err != nil || n != before {
		t.Fatalf("live file write invalidated observation: bytes=%d want=%d err=%v", n, before, err)
	}
	after := censusFixtureBytes(t, root) + censusFixtureBytes(t, payload)
	n, _, err = accountBytes(context.Background(), []string{root}, "", 0)
	if err != nil || n != after || n <= 32*1024 {
		t.Fatalf("next observation lost budget excess: bytes=%d want=%d err=%v", n, after, err)
	}
}

func TestMutableAccountingRetainsFailures(t *testing.T) {
	for _, failure := range []string{"permission", "io", "mount", "negative size", "negative blocks", "block overflow", "total overflow"} {
		t.Run(failure, func(t *testing.T) {
			root := censusFixtureDir(t)
			censusFixtureFile(t, filepath.Join(root, "payload"), 4096)
			// Two near-maximum files overflow the total whatever the
			// filesystem charges the directory itself.
			censusFixtureFile(t, filepath.Join(root, "payload-2"), 4096)
			statat := func(fd int, name string, st *unix.Stat_t, flags int) error {
				err := unix.Fstatat(fd, name, st, flags)
				if err == nil && failure == "total overflow" && name == "payload-2" {
					st.Blocks = math.MaxInt64 / 512
				}
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
					st.Blocks = math.MaxInt64 / 512
				}
				return nil
			}
			n, _, err := census{base: "/", statat: statat}.account(context.Background(), []string{root})
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
	n, _, err := accountBytes(context.Background(), []string{root}, "", 0)
	if err != nil || n != want {
		t.Fatalf("hardlink counted twice: bytes=%d want=%d err=%v", n, want, err)
	}
	if err := os.Symlink(base, filepath.Join(base, "linked-parent")); err != nil {
		t.Fatal(err)
	}
	n, _, err = accountBytes(context.Background(), []string{filepath.Join(base, "linked-parent", "root")}, "", 0)
	if err == nil || n != -1 {
		t.Fatalf("followed ancestor symlink: bytes=%d err=%v", n, err)
	}
}

func TestMutableAccountingErrorsNameRelativePath(t *testing.T) {
	for _, tc := range []struct {
		failure, name, want string
		cause               error
	}{
		{"tcc denial", "Mail", `"Library/Mail": operation not permitted`, unix.EPERM},
		{"mount", "DeviceFS", `"Library/Developer/CoreDevice/DeviceFS": mutable mount crossing`, nil},
	} {
		t.Run(tc.failure, func(t *testing.T) {
			root := filepath.Join(censusFixtureDir(t), "home")
			for _, dir := range []string{"Library/Mail", "Library/Developer/CoreDevice/DeviceFS"} {
				if err := os.MkdirAll(filepath.Join(root, dir), 0700); err != nil {
					t.Fatal(err)
				}
			}
			statat := func(fd int, name string, st *unix.Stat_t, flags int) error {
				if name != tc.name {
					return unix.Fstatat(fd, name, st, flags)
				}
				if tc.cause != nil {
					return tc.cause
				}
				if err := unix.Fstatat(fd, name, st, flags); err != nil {
					return err
				}
				st.Dev++
				return nil
			}
			n, _, err := census{base: "/", statat: statat}.account(context.Background(), []string{root})
			if n != -1 || err == nil || !strings.Contains(err.Error(), root+": "+tc.want) {
				t.Fatalf("census error does not name the failing path: bytes=%d err=%v", n, err)
			}
			if tc.cause != nil && !errors.Is(err, tc.cause) {
				t.Fatalf("lost underlying error: %v", err)
			}
		})
	}
}

// The census reports the products pool's bytes (the directory and what it
// holds) apart, as part of its total, from the same walk (#204). A census
// whose roots do not hold the pool reports none, which the budget counts
// as accounted.
func TestMutableAccountingReportsProductsPoolApart(t *testing.T) {
	root := censusFixtureDir(t)
	controller := filepath.Join(root, "controller")
	pool := filepath.Join(controller, "products")
	if err := os.MkdirAll(pool, 0700); err != nil {
		t.Fatal(err)
	}
	product := filepath.Join(pool, strings.Repeat("a", 64)+".tar")
	censusFixtureFile(t, product, 96*1024)
	evidence := filepath.Join(controller, "evidence.bin")
	censusFixtureFile(t, evidence, 32*1024)
	wantPool := censusFixtureBytes(t, pool) + censusFixtureBytes(t, product)
	wantTotal := censusFixtureBytes(t, root) + censusFixtureBytes(t, controller) + censusFixtureBytes(t, evidence) + wantPool
	for _, roots := range [][]string{{root}, {controller}, {pool}} {
		total, products, err := census{base: "/", statat: unix.Fstatat, products: pool}.account(context.Background(), roots)
		if err != nil || products != wantPool || total < products {
			t.Fatalf("roots %v: total=%d products=%d err=%v; want products=%d", roots, total, products, err, wantPool)
		}
		if roots[0] == root && total != wantTotal {
			t.Fatalf("total=%d want %d", total, wantTotal)
		}
	}
	total, products, err := census{base: "/", statat: unix.Fstatat, products: filepath.Join(root, "elsewhere")}.account(context.Background(), []string{root})
	if err != nil || products != 0 || total != wantTotal {
		t.Fatalf("pool outside the roots: total=%d products=%d err=%v", total, products, err)
	}
	// Only the exact directory is the pool, not a sibling sharing its prefix.
	sibling := filepath.Join(controller, "products-old")
	if err := os.Mkdir(sibling, 0700); err != nil {
		t.Fatal(err)
	}
	censusFixtureFile(t, filepath.Join(sibling, "x"), 8*1024)
	_, products, err = census{base: "/", statat: unix.Fstatat, products: pool}.account(context.Background(), []string{root})
	if err != nil || products != wantPool {
		t.Fatalf("sibling counted as pool: products=%d err=%v; want %d", products, err, wantPool)
	}
}

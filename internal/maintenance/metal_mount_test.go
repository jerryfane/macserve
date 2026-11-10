package maintenance

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/mounttable"
	"golang.org/x/sys/unix"
)

// The v0.1.40/v0.1.42 after-reboot rounds: a job's first xcodebuild attached
// Xcode's Metal toolchain image in its workspace HOME (read-only, nodev,
// nosuid apfs, mounted by the job user). While that job runs, the census of
// /Library/macserve/var records it without descending or charging it, like
// the CoreDevice devicefs; every variation stays a mount crossing.
func TestMutableAccountingSkipsJobMetalToolchainImage(t *testing.T) {
	const (
		jobUID = 6202
		asset  = "389a215aea89fda945178f9fb8bcdc6aa0e20570"
		rel    = "workspaces/job/home/Library/Developer/DVTDownloads/MetalToolchain/mounts/" + asset
	)
	studio := mounttable.Entry{FSID: 0x1d000014, Owner: jobUID, Flags: mounttable.ReadOnly | mounttable.NoSUID | mounttable.NoDev | 0x1000 | 0x200000 | 0x800000, FSType: "apfs", On: "/Library/macserve/var/" + rel, From: "/dev/disk12s1"}
	changed := func(f func(*mounttable.Entry)) mounttable.Entry {
		m := studio
		f(&m)
		return m
	}
	for name, tc := range map[string]struct {
		mountAt string // var-relative path that presents the mounted root
		record  mounttable.Entry
		want    string
	}{
		"studio image":         {mountAt: rel, record: studio},
		"writable image":       {mountAt: rel, record: changed(func(m *mounttable.Entry) { m.Flags &^= mounttable.ReadOnly }), want: "mutable mount crossing"},
		"setuid image":         {mountAt: rel, record: changed(func(m *mounttable.Entry) { m.Flags &^= mounttable.NoSUID }), want: "mutable mount crossing"},
		"device nodes allowed": {mountAt: rel, record: changed(func(m *mounttable.Entry) { m.Flags &^= mounttable.NoDev }), want: "mutable mount crossing"},
		"another user's image": {mountAt: rel, record: changed(func(m *mounttable.Entry) { m.Owner = 501 }), want: "mutable mount crossing"},
		"not apfs":             {mountAt: rel, record: changed(func(m *mounttable.Entry) { m.FSType = "hfs" }), want: "mutable mount crossing"},
		"not a disk slice":     {mountAt: rel, record: changed(func(m *mounttable.Entry) { m.From = "//host/share" }), want: "mutable mount crossing"},
		"record for elsewhere": {mountAt: rel, record: changed(func(m *mounttable.Entry) { m.On = "/Volumes/Metal" }), want: "mutable mount crossing"},
		"outside a workspace": {mountAt: "broker/home/Library/Developer/DVTDownloads/MetalToolchain/mounts/" + asset, record: changed(func(m *mounttable.Entry) {
			m.On = "/Library/macserve/var/broker/home/Library/Developer/DVTDownloads/MetalToolchain/mounts/" + asset
		}), want: "mutable mount crossing"},
		"not an asset mount": {mountAt: "workspaces/job/home/Library/Caches", record: changed(func(m *mounttable.Entry) { m.On = "/Library/macserve/var/workspaces/job/home/Library/Caches" }), want: "mutable mount crossing"},
	} {
		t.Run(name, func(t *testing.T) {
			base := censusFixtureDir(t)
			mountPoint := filepath.Join(base, "Library/macserve/var", tc.mountAt)
			home := filepath.Join(base, "Library/macserve/var/workspaces/job/home")
			for _, dir := range []string{mountPoint, home} {
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			censusFixtureFile(t, filepath.Join(mountPoint, "shadowed"), 16*1024)
			censusFixtureFile(t, filepath.Join(home, "build.log"), 8*1024)
			roots := []string{"/Library/macserve/var"}
			plain, err := census{base: base, statat: unix.Fstatat}.account(context.Background(), roots)
			if err != nil {
				t.Fatal(err)
			}
			want := plain - censusFixtureBytes(t, mountPoint) - censusFixtureBytes(t, filepath.Join(mountPoint, "shadowed"))
			var mounted unix.Stat_t
			if err := unix.Lstat(mountPoint, &mounted); err != nil {
				t.Fatal(err)
			}
			statat := func(fd int, name string, st *unix.Stat_t, flags int) error {
				var dir unix.Stat_t
				if err := unix.Fstat(fd, &dir); err != nil {
					return err
				}
				if dir.Dev == mounted.Dev && dir.Ino == mounted.Ino {
					t.Errorf("census descended into the mount point: stat %q", name)
				}
				if err := unix.Fstatat(fd, name, st, flags); err != nil {
					return err
				}
				if st.Dev == mounted.Dev && st.Ino == mounted.Ino {
					setStat(st, "Dev", tc.record.FSID)
				}
				return nil
			}
			calls := 0
			c := census{base: base, statat: statat, jobHome: "/Users/macservejob", workspaces: workspaceRoot, jobUID: jobUID, mounts: func() ([]mounttable.Entry, error) {
				calls++
				return []mounttable.Entry{{FSID: 1, FSType: "apfs", On: "/"}, tc.record}, nil
			}}
			n, err := c.account(context.Background(), roots)
			if tc.want == "" {
				if err != nil || n != want || calls != 2 {
					t.Fatalf("job Metal toolchain image not skipped: bytes=%d want=%d calls=%d err=%v", n, want, calls, err)
				}
				return
			}
			if n != -1 || err == nil || !strings.Contains(err.Error(), strconv.Quote(tc.mountAt)+": "+tc.want) || errors.Is(err, errAcceptedMountChanged) {
				t.Fatalf("nested mount was not refused: bytes=%d err=%v", n, err)
			}
		})
	}
}

// The worker unmounting the image while a census runs makes that census
// inconclusive, never a finding.
func TestMutableAccountingMetalToolchainUnmountedDuringCensus(t *testing.T) {
	const rel = "workspaces/job/home/Library/Developer/DVTDownloads/MetalToolchain/mounts/389a215aea89fda945178f9fb8bcdc6aa0e20570"
	base := censusFixtureDir(t)
	mountPoint := filepath.Join(base, "Library/macserve/var", rel)
	if err := os.MkdirAll(mountPoint, 0700); err != nil {
		t.Fatal(err)
	}
	var mounted unix.Stat_t
	if err := unix.Lstat(mountPoint, &mounted); err != nil {
		t.Fatal(err)
	}
	record := mounttable.Entry{FSID: 77, Owner: 6202, Flags: mounttable.ReadOnly | mounttable.NoSUID | mounttable.NoDev, FSType: "apfs", On: "/Library/macserve/var/" + rel, From: "/dev/disk12s1"}
	statat := func(fd int, name string, st *unix.Stat_t, flags int) error {
		if err := unix.Fstatat(fd, name, st, flags); err != nil {
			return err
		}
		if st.Dev == mounted.Dev && st.Ino == mounted.Ino {
			setStat(st, "Dev", record.FSID)
		}
		return nil
	}
	calls := 0
	c := census{base: base, statat: statat, workspaces: workspaceRoot, jobUID: 6202, mounts: func() ([]mounttable.Entry, error) {
		if calls++; calls > 1 {
			return nil, nil
		}
		return []mounttable.Entry{record}, nil
	}}
	_, err := c.account(context.Background(), []string{"/Library/macserve/var"})
	if !errors.Is(err, errAcceptedMountChanged) || !strings.Contains(err.Error(), "mutable census /Library/macserve/var: "+strconv.Quote(rel)) {
		t.Fatalf("census = %v, want inconclusive naming the image", err)
	}
}

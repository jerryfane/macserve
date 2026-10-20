package maintenance

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// The testdata hex files are verbatim bytes from a read-only probe on the macOS
// 27.0 (26A428) build host after a real xcodebuild by the job user:
//   - studio-devicefs-statfs.hex: the job user's getfsstat(MNT_NOWAIT) record
//     for /Users/macservejob/Library/Developer/CoreDevice/DeviceFS (darwin/arm64
//     struct statfs, 2168 bytes).
//   - studio-devicefs-root-lstat.hex: lstat of an identical CoreDevice DeviceFS
//     mount root on the same host (darwin/arm64 struct stat, 144 bytes). Its
//     st_dev equaled that mount's f_fsid.val[0]; the fixture applies that same
//     identity to the job record.
const (
	deviceFS     = "Library/Developer/CoreDevice/DeviceFS"
	coreDataDir  = "Library/Containers/com.apple.CoreDevice.CoreDeviceService/Data"
	statfsNoSUID = 0x8  // MNT_NOSUID
	statfsNoDev  = 0x10 // MNT_NODEV
)

func studioProbe(t *testing.T, name string) []byte {
	t.Helper()
	text, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	data, err := hex.DecodeString(strings.TrimSpace(string(text)))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// darwinStatfsRecord decodes the darwin/arm64 struct statfs layout portably.
func darwinStatfsRecord(t *testing.T, b []byte) mountEntry {
	t.Helper()
	if len(b) != 2168 {
		t.Fatalf("statfs record size %d", len(b))
	}
	text := func(b []byte) string {
		if i := strings.IndexByte(string(b), 0); i >= 0 {
			return string(b[:i])
		}
		return string(b)
	}
	le := binary.LittleEndian
	return mountEntry{
		fsid:   uint64(int32(le.Uint32(b[48:]))),
		owner:  le.Uint32(b[56:]),
		flags:  uint64(le.Uint32(b[64:])),
		fstype: text(b[72:88]),
		on:     text(b[88:1112]),
		from:   text(b[1112:2136]),
	}
}

type devicefsRoot struct{ ino, mode, nlink, uid, gid, size, blocks uint64 }

// darwinStatRoot decodes the darwin/arm64 struct stat layout portably.
func darwinStatRoot(t *testing.T, b []byte) devicefsRoot {
	t.Helper()
	if len(b) != 144 {
		t.Fatalf("stat record size %d", len(b))
	}
	le := binary.LittleEndian
	return devicefsRoot{
		mode: uint64(le.Uint16(b[4:])), nlink: uint64(le.Uint16(b[6:])), ino: le.Uint64(b[8:]),
		uid: uint64(le.Uint32(b[16:])), gid: uint64(le.Uint32(b[20:])),
		size: le.Uint64(b[96:]), blocks: le.Uint64(b[104:]),
	}
}

func setStat(st *unix.Stat_t, field string, value uint64) {
	v := reflect.ValueOf(st).Elem().FieldByName(field)
	if v.CanInt() {
		v.SetInt(int64(value))
	} else {
		v.SetUint(value)
	}
}

func TestStudioDevicefsProbeBytes(t *testing.T) {
	m := darwinStatfsRecord(t, studioProbe(t, "studio-devicefs-statfs.hex"))
	want := mountEntry{fsid: 805306371, owner: 6202, flags: 0x10301418, fstype: "devicefs",
		on:   "/Users/macservejob/Library/Developer/CoreDevice/DeviceFS",
		from: "devices -- file:///Users/macservejob/Library/Containers/com.apple.CoreDevice.CoreDeviceService/Data/"}
	if m != want {
		t.Fatalf("probe record decoded as %+v", m)
	}
	root := darwinStatRoot(t, studioProbe(t, "studio-devicefs-root-lstat.hex"))
	if root.mode != unix.S_IFDIR|0555 || root.ino == 0 {
		t.Fatalf("probe root decoded as %+v", root)
	}
}

// devicefsHome lays out the production shape: a job home with the CoreDevice
// container data and the DeviceFS mount point, plus a service root, beneath base.
func devicefsHome(t *testing.T) (base string, shadow string) {
	t.Helper()
	base = censusFixtureDir(t)
	home := filepath.Join(base, "Users", "macservejob")
	for _, dir := range []string{deviceFS, coreDataDir, "Library/Caches", "Documents"} {
		if err := os.MkdirAll(filepath.Join(home, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(base, "Library/macserve/var", deviceFS), 0700); err != nil {
		t.Fatal(err)
	}
	censusFixtureFile(t, filepath.Join(home, coreDataDir, "device.db"), 96*1024)
	censusFixtureFile(t, filepath.Join(home, "Documents", "build.log"), 8*1024)
	censusFixtureFile(t, filepath.Join(home, "Library/Caches", "cache.db"), 8*1024)
	censusFixtureFile(t, filepath.Join(base, "Library/macserve/var", "queue"), 4*1024)
	// Bytes beneath the mount point on the home device are shadowed by the mount.
	shadow = filepath.Join(home, deviceFS, "shadowed")
	censusFixtureFile(t, shadow, 16*1024)
	return base, shadow
}

func TestMutableAccountingSkipsJobCoreDeviceMount(t *testing.T) {
	record := darwinStatfsRecord(t, studioProbe(t, "studio-devicefs-statfs.hex"))
	probeRoot := darwinStatRoot(t, studioProbe(t, "studio-devicefs-root-lstat.hex"))
	roots := []string{"/Library/macserve/var", "/Users/macservejob"}
	type scenario struct {
		mountAt   string // base-relative path that presents the mounted root
		table     func(call int) ([]mountEntry, error)
		remounted bool // the name resolves to another root after the decision
		want      string
	}
	same := func(m mountEntry) func(int) ([]mountEntry, error) {
		return func(int) ([]mountEntry, error) { return []mountEntry{m}, nil }
	}
	jobMount := "Users/macservejob/" + deviceFS
	changed := func(f func(*mountEntry)) mountEntry {
		m := record
		f(&m)
		return m
	}
	for name, tc := range map[string]scenario{
		"studio devicefs":           {mountAt: jobMount, table: same(record)},
		"disk image at mount point": {mountAt: jobMount, table: same(changed(func(m *mountEntry) { m.fstype = "apfs" })), want: "mutable mount crossing"},
		"devicefs at another path":  {mountAt: "Users/macservejob/Library/Caches", table: same(changed(func(m *mountEntry) { m.on = "/Users/macservejob/Library/Caches" })), want: "mutable mount crossing"},
		"devicefs in service root":  {mountAt: "Library/macserve/var/" + deviceFS, table: same(record), want: "mutable mount crossing"},
		"another user's devicefs":   {mountAt: jobMount, table: same(changed(func(m *mountEntry) { m.owner = 501 })), want: "mutable mount crossing"},
		"source outside job home":   {mountAt: jobMount, table: same(changed(func(m *mountEntry) { m.from = "devices -- file:///private/tmp/data/" })), want: "mutable mount crossing"},
		"setuid devicefs":           {mountAt: jobMount, table: same(changed(func(m *mountEntry) { m.flags &^= statfsNoSUID })), want: "mutable mount crossing"},
		"device nodes allowed":      {mountAt: jobMount, table: same(changed(func(m *mountEntry) { m.flags &^= statfsNoDev })), want: "mutable mount crossing"},
		"ambiguous mount record":    {mountAt: jobMount, table: func(int) ([]mountEntry, error) { return []mountEntry{record, record}, nil }, want: "mutable mount crossing"},
		"no mount record":           {mountAt: jobMount, table: func(int) ([]mountEntry, error) { return nil, nil }, want: "mutable mount crossing"},
		"mount table unavailable":   {mountAt: jobMount, table: func(int) ([]mountEntry, error) { return nil, unix.EIO }, want: "mutable mount crossing"},
		"remounted after decision":  {mountAt: jobMount, table: same(record), remounted: true, want: "mutable mount changed during census"},
		"unmounted during census":   {mountAt: jobMount, table: func(call int) ([]mountEntry, error) { return []mountEntry{record}[:2-call], nil }, want: "mutable mount table changed during census"},
		"replaced during census": {mountAt: jobMount, table: func(call int) ([]mountEntry, error) {
			if call == 1 {
				return []mountEntry{record}, nil
			}
			return []mountEntry{changed(func(m *mountEntry) { m.from = "devices -- file:///private/tmp/data/" })}, nil
		}, want: "mutable mount table changed during census"},
	} {
		t.Run(name, func(t *testing.T) {
			base, shadow := devicefsHome(t)
			plain, err := census{base: base, statat: unix.Fstatat}.account(context.Background(), roots)
			if err != nil {
				t.Fatal(err)
			}
			mountPoint := filepath.Join(base, tc.mountAt)
			want := plain - censusFixtureBytes(t, mountPoint)
			if tc.mountAt == jobMount {
				want -= censusFixtureBytes(t, shadow)
			}
			var mounted unix.Stat_t
			if err := unix.Lstat(mountPoint, &mounted); err != nil {
				t.Fatal(err)
			}
			presented := 0
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
				if st.Dev != mounted.Dev || st.Ino != mounted.Ino {
					return nil
				}
				presented++
				// Present the real probed devicefs root in place of the directory.
				setStat(st, "Dev", record.fsid)
				setStat(st, "Ino", probeRoot.ino)
				setStat(st, "Mode", probeRoot.mode)
				setStat(st, "Nlink", probeRoot.nlink)
				setStat(st, "Uid", probeRoot.uid)
				setStat(st, "Gid", probeRoot.gid)
				setStat(st, "Size", probeRoot.size)
				setStat(st, "Blocks", probeRoot.blocks)
				if tc.remounted && presented > 1 {
					setStat(st, "Ino", probeRoot.ino+1)
				}
				return nil
			}
			calls := 0
			c := census{base: base, statat: statat, jobHome: "/Users/macservejob", jobUID: 6202, mounts: func() ([]mountEntry, error) {
				calls++
				return tc.table(calls)
			}}
			n, err := c.account(context.Background(), roots)
			if tc.want == "" {
				if err != nil || n != want {
					t.Fatalf("job CoreDevice mount not skipped: bytes=%d want=%d err=%v", n, want, err)
				}
				if calls != 2 {
					t.Fatalf("mount table read %d times, want decision and final check", calls)
				}
				return
			}
			rel := strings.TrimPrefix(strings.TrimPrefix(tc.mountAt, "Users/macservejob/"), "Library/macserve/var/")
			if n != -1 || err == nil || !strings.Contains(err.Error(), strconv.Quote(rel)+": "+tc.want) {
				t.Fatalf("nested mount was not refused: bytes=%d err=%v", n, err)
			}
		})
	}
}

func TestMutableAccountingWithoutMountTableRefusesMounts(t *testing.T) {
	base, _ := devicefsHome(t)
	statat := func(fd int, name string, st *unix.Stat_t, flags int) error {
		if err := unix.Fstatat(fd, name, st, flags); err != nil {
			return err
		}
		if name == "DeviceFS" {
			st.Dev++
		}
		return nil
	}
	_, err := census{base: base, statat: statat, jobHome: "/Users/macservejob", jobUID: 6202}.account(context.Background(), []string{"/Users/macservejob"})
	if err == nil || !strings.Contains(err.Error(), "mutable mount crossing") {
		t.Fatalf("mount accepted without a mount table: %v", err)
	}
}

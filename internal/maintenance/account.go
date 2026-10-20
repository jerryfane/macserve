package maintenance

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// accountBytes uses descriptor-relative, no-follow traversal. Symlinks count as
// links, never as their targets; regular files use max(logical, allocated) bytes.
// Hardlinks and nested roots are counted once. This is an approximate live budget
// census, not a snapshot: concurrent changes can be missed or observed at different
// times. Mount crossings, special nodes (except local sockets), and traversal
// limits invalidate the census, with one exception: the CoreDevice devicefs that
// Xcode/CoreDeviceService mounts for the job user inside the job home (see
// coreDeviceMount) is not descended. Local sockets have metadata but no file payload.
// Errors name the census root and the quoted root-relative path that failed, so
// a TCC denial (EPERM without Full Disk Access) or a refusal is diagnosable.
func accountBytes(ctx context.Context, roots []string, jobHome string, jobUID uint32) (int64, error) {
	return census{base: "/", statat: unix.Fstatat, mounts: mountTable, jobHome: jobHome, jobUID: jobUID}.account(ctx, roots)
}

// census is the filesystem boundary of accountBytes. Roots are absolute paths
// resolved beneath base ("/" in production). The stat boundary permits
// deterministic coverage of changes before directory open; mounts reports the
// kernel mount table. jobHome and jobUID name the job-home root and its owner.
type census struct {
	base    string
	statat  func(int, string, *unix.Stat_t, int) error
	mounts  func() ([]mountEntry, error)
	jobHome string
	jobUID  uint32
}

// mountEntry is the portable subset of one getfsstat record. fsid is
// f_fsid.val[0], which equals st_dev of every node on that mount.
type mountEntry struct {
	fsid   uint64
	owner  uint32
	flags  uint64
	fstype string
	on     string
	from   string
}

const (
	// Root-relative mount point and backing directory of the CoreDevice devicefs.
	coreDeviceMountPoint = "Library/Developer/CoreDevice/DeviceFS"
	coreDeviceData       = "Library/Containers/com.apple.CoreDevice.CoreDeviceService/Data"
	// <sys/mount.h> MNT_NODEV and MNT_NOSUID; a darwin test pins them to x/sys.
	mountNoDev  = 0x10
	mountNoSUID = 0x8
)

// coreDeviceMount returns the single mount-table record for dev if, and only if,
// it is the job user's own CoreDevice devicefs at its fixed job-home path, backed
// by CoreDeviceService's container directory in that same home. The backing bytes
// are therefore already counted on the home device, and the FSKit server runs as
// the job user, so it cannot store anything the job could not write directly.
// Every other nested mount (disk images, other FSKit or network filesystems,
// devicefs elsewhere or owned by another user) stays a mount crossing.
func (c census) coreDeviceMount(dev uint64) (mountEntry, error) {
	if c.mounts == nil || c.jobHome == "" {
		return mountEntry{}, errors.New("mutable mount crossing")
	}
	table, err := c.mounts()
	if err != nil {
		return mountEntry{}, fmt.Errorf("mutable mount crossing: %w", err)
	}
	var match []mountEntry
	for _, m := range table {
		if m.fsid == dev {
			match = append(match, m)
		}
	}
	if len(match) != 1 {
		return mountEntry{}, errors.New("mutable mount crossing: no unique mount record")
	}
	m := match[0]
	if m.fstype != "devicefs" || m.on != c.jobHome+"/"+coreDeviceMountPoint || m.from != "devices -- file://"+c.jobHome+"/"+coreDeviceData+"/" || m.owner != c.jobUID || m.flags&(mountNoDev|mountNoSUID) != mountNoDev|mountNoSUID {
		return mountEntry{}, fmt.Errorf("mutable mount crossing: %s mount is not the job CoreDevice devicefs", strconv.Quote(m.fstype))
	}
	return m, nil
}

func (c census) account(ctx context.Context, roots []string) (int64, error) {
	statat := c.statat
	type inode struct {
		dev uint64
		ino uint64
	}
	seen := map[inode]bool{}
	var total int64
	entries := 0
	// The one accepted CoreDevice mount; it must be unchanged when the census ends.
	var skipped *mountEntry
	jobHome := false
	var walk func(int, string, string, uint64, int) error
	walk = func(parent int, name, rel string, device uint64, depth int) error {
		fail := func(err error) error {
			return fmt.Errorf("%s: %w", strconv.Quote(rel), err)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		entries++
		if entries > 1000000 || depth > 128 {
			return fail(errors.New("mutable census bound exceeded"))
		}
		var st unix.Stat_t
		if err := statat(parent, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			if errors.Is(err, unix.ENOENT) {
				return nil
			}
			return fail(err)
		}
		if uint64(st.Dev) != device {
			if !jobHome || rel != coreDeviceMountPoint || skipped != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR {
				return fail(errors.New("mutable mount crossing"))
			}
			m, err := c.coreDeviceMount(uint64(st.Dev))
			if err != nil {
				return fail(err)
			}
			// Never open or descend the mount. The name must still resolve to the
			// same mounted root after the decision.
			var again unix.Stat_t
			if err := statat(parent, name, &again, unix.AT_SYMLINK_NOFOLLOW); err != nil || again.Dev != st.Dev || again.Ino != st.Ino || again.Mode&unix.S_IFMT != unix.S_IFDIR {
				return fail(errors.New("mutable mount changed during census"))
			}
			skipped = &m
			return nil
		}
		key := inode{uint64(st.Dev), uint64(st.Ino)}
		if seen[key] {
			return nil
		}
		kind := st.Mode & unix.S_IFMT
		var f *os.File
		fd := -1
		if kind == unix.S_IFDIR {
			var err error
			fd, err = unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP) {
					return nil
				}
				return fail(err)
			}
			f = os.NewFile(uintptr(fd), name)
			defer f.Close()
			// Account the directory actually opened, not its possibly stale lstat.
			if err = unix.Fstat(fd, &st); err != nil {
				return fail(err)
			}
			if uint64(st.Dev) != device {
				return fail(errors.New("mutable mount crossing"))
			}
			key = inode{uint64(st.Dev), uint64(st.Ino)}
			if seen[key] {
				return nil
			}
		}
		seen[key] = true
		size := st.Size
		if st.Blocks < 0 || st.Blocks > math.MaxInt64/512 || size < 0 {
			return fail(errors.New("invalid mutable size"))
		}
		if allocated := st.Blocks * 512; allocated > size {
			size = allocated
		}
		if total > math.MaxInt64-size {
			return fail(errors.New("mutable size overflow"))
		}
		total += size
		if kind == unix.S_IFREG || kind == unix.S_IFLNK || kind == unix.S_IFSOCK {
			return nil
		}
		if kind != unix.S_IFDIR {
			return fail(errors.New("unsupported mutable special file"))
		}
		for {
			names, err := f.Readdirnames(128)
			if err != nil && err != io.EOF {
				if errors.Is(err, unix.ENOENT) {
					return nil
				}
				return fail(err)
			}
			for _, child := range names {
				if err := walk(fd, child, filepath.Join(rel, child), device, depth+1); err != nil {
					return err
				}
			}
			if err == io.EOF {
				break
			}
		}
		return nil
	}
	for _, root := range roots {
		if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
			return -1, errors.New("invalid mutable root")
		}
		// Open every ancestor without following a link, not just the final component.
		fd, err := unix.Open(c.base, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return -1, err
		}
		parts := strings.Split(strings.TrimPrefix(root, "/"), "/")
		for _, part := range parts[:len(parts)-1] {
			next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			unix.Close(fd)
			if e != nil {
				return -1, fmt.Errorf("mutable census %s: ancestor %s: %w", root, strconv.Quote(part), e)
			}
			fd = next
		}
		var st unix.Stat_t
		err = statat(fd, parts[len(parts)-1], &st, unix.AT_SYMLINK_NOFOLLOW)
		if err == nil && st.Mode&unix.S_IFMT != unix.S_IFDIR {
			err = errors.New("mutable root is not directory")
		}
		if err == nil {
			jobHome = c.jobHome != "" && root == c.jobHome
			err = walk(fd, parts[len(parts)-1], ".", uint64(st.Dev), 0)
		}
		unix.Close(fd)
		if err != nil {
			return -1, fmt.Errorf("mutable census %s: %w", root, err)
		}
	}
	if skipped != nil {
		// The skip is valid only if the same record still describes that mount.
		table, err := c.mounts()
		if err != nil {
			return -1, fmt.Errorf("mutable census %s: %s: %w", c.jobHome, strconv.Quote(coreDeviceMountPoint), err)
		}
		same := 0
		for _, m := range table {
			if m.fsid == skipped.fsid {
				same++
				if m != *skipped {
					same++
				}
			}
		}
		if same != 1 {
			return -1, fmt.Errorf("mutable census %s: %s: mutable mount table changed during census", c.jobHome, strconv.Quote(coreDeviceMountPoint))
		}
	}
	return total, ctx.Err()
}

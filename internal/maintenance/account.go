package maintenance

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/jerryfane/macserve/internal/mounttable"
	"github.com/jerryfane/macserve/internal/worker"
	"golang.org/x/sys/unix"
)

// accountBytes uses descriptor-relative, no-follow traversal. Symlinks count as
// links, never as their targets. A regular file is charged its allocated blocks,
// so a sparse file counts what it occupies (Xcode 27 preallocates
// derived-data/CompilationCache.noindex at 24 + 12 + 1 GiB logical, about 1 MiB
// each on disk); a clone is charged per inode, which over-counts shared blocks.
// Every other node is charged max(logical, allocated) bytes.
// Hardlinks and nested roots are counted once. This is an approximate live budget
// census, not a snapshot: concurrent changes can be missed or observed at different
// times. Mount crossings, special nodes (except local sockets), and traversal
// limits invalidate the census, with the exceptions acceptedMount names: the
// CoreDevice devicefs that Xcode/CoreDeviceService mounts for the job user
// inside the job home and Xcode's read-only Metal toolchain image in a job
// workspace are not descended. Local sockets have metadata but no file payload.
// Errors name the census root and the quoted root-relative path that failed, so
// a TCC denial (EPERM without Full Disk Access) or a refusal is diagnosable.
func accountBytes(ctx context.Context, roots []string, jobHome string, jobUID uint32) (int64, error) {
	return census{base: "/", statat: unix.Fstatat, mounts: mounttable.Read, jobHome: jobHome, workspaces: workspaceRoot, jobUID: jobUID}.account(ctx, roots)
}

// workspaceRoot is the worker's job workspace root, the only worker.json
// workspace_root Inspect accepts.
const workspaceRoot = "/Library/macserve/var/workspaces"

// census is the filesystem boundary of accountBytes. Roots are absolute paths
// resolved beneath base ("/" in production). The stat boundary permits
// deterministic coverage of changes before directory open; mounts reports the
// kernel mount table. jobHome and jobUID name the job-home root and its owner;
// workspaces is the worker's job workspace root.
type census struct {
	base   string
	statat func(int, string, *unix.Stat_t, int) error
	// fstat is unix.Fstat of an opened directory when nil.
	fstat func(int, *unix.Stat_t) error
	// openat is unix.Openat when nil.
	openat     func(int, string, int, uint32) (int, error)
	mounts     func() ([]mounttable.Entry, error)
	jobHome    string
	workspaces string
	jobUID     uint32
}

const (
	// Root-relative mount point and backing directory of the CoreDevice devicefs.
	coreDeviceMountPoint = "Library/Developer/CoreDevice/DeviceFS"
	coreDeviceData       = "Library/Containers/com.apple.CoreDevice.CoreDeviceService/Data"
)

// acceptedMount returns the single mount-table record for dev, the mounted
// root found at the absolute path at, if, and only if, it is one of:
//   - the job user's own CoreDevice devicefs at its fixed job-home path, backed
//     by CoreDeviceService's container directory in that same home. The backing
//     bytes are therefore already counted on the home device, and the FSKit
//     server runs as the job user, so it cannot store anything the job could
//     not write directly.
//   - Xcode's Metal toolchain image in a job workspace, mounted read-only,
//     nodev and nosuid by the job user (worker.MetalToolchainMount): Apple's
//     asset bytes, stored outside the workspace, that nothing can write. The
//     worker unmounts it when it removes the workspace.
//
// Every other nested mount (other disk images, FSKit or network filesystems,
// devicefs elsewhere or owned by another user) stays a mount crossing.
func (c census) acceptedMount(dev uint64, at string) (mounttable.Entry, error) {
	coreDevice := c.jobHome != "" && at == c.jobHome+"/"+coreDeviceMountPoint
	metal := c.workspaces != "" && worker.MetalToolchainMountPoint(c.workspaces, at)
	if c.mounts == nil || !coreDevice && !metal {
		return mounttable.Entry{}, errors.New("mutable mount crossing")
	}
	table, err := c.mounts()
	if err != nil {
		return mounttable.Entry{}, fmt.Errorf("mutable mount crossing: %w", err)
	}
	m, ok := mounttable.Unique(table, dev)
	if !ok {
		return mounttable.Entry{}, errors.New("mutable mount crossing: no unique mount record")
	}
	if coreDevice && (m.FSType != "devicefs" || m.On != at || m.From != "devices -- file://"+c.jobHome+"/"+coreDeviceData+"/" || m.Owner != c.jobUID || m.Flags&(mounttable.NoDev|mounttable.NoSUID) != mounttable.NoDev|mounttable.NoSUID) {
		return mounttable.Entry{}, fmt.Errorf("mutable mount crossing: %s mount is not the job CoreDevice devicefs", strconv.Quote(m.FSType))
	}
	if metal && (m.On != at || !worker.MetalToolchainMount(m, c.workspaces, c.jobUID)) {
		return mounttable.Entry{}, fmt.Errorf("mutable mount crossing: %s mount is not the job Xcode Metal toolchain image", strconv.Quote(m.FSType))
	}
	return m, nil
}

func (c census) account(ctx context.Context, roots []string) (int64, error) {
	// Raw x/sys calls, unlike package os, do not retry EINTR. On macOS opening a
	// sandboxed container directory can be interrupted by the Go runtime's
	// preemption signal; that is a transient condition, not a census failure.
	rawStatat, rawFstat, rawOpenat := c.statat, c.fstat, c.openat
	if rawFstat == nil {
		rawFstat = unix.Fstat
	}
	if rawOpenat == nil {
		rawOpenat = unix.Openat
	}
	statat := func(fd int, name string, st *unix.Stat_t, flags int) error {
		return ignoringEINTR(func() error { return rawStatat(fd, name, st, flags) })
	}
	fstat := func(fd int, st *unix.Stat_t) error {
		return ignoringEINTR(func() error { return rawFstat(fd, st) })
	}
	openat := func(fd int, name string, flags int, mode uint32) (int, error) {
		var opened int
		err := ignoringEINTR(func() error {
			var err error
			opened, err = rawOpenat(fd, name, flags, mode)
			return err
		})
		return opened, err
	}
	type inode struct {
		dev uint64
		ino uint64
	}
	seen := map[inode]bool{}
	var total int64
	entries := 0
	// The accepted mounts (acceptedMount), by device, with where each was
	// found; each must be unchanged when the census ends.
	type accepted struct {
		entry     mounttable.Entry
		root, rel string
	}
	var skipped []accepted
	rootPath := ""
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
			if st.Mode&unix.S_IFMT != unix.S_IFDIR {
				return fail(errors.New("mutable mount crossing"))
			}
			m, err := c.acceptedMount(uint64(st.Dev), filepath.Join(rootPath, rel))
			if err != nil {
				return fail(err)
			}
			// Never open or descend the mount. The name must still resolve to the
			// same mounted root after the decision. An accepted mount that is gone
			// or replaced by then (the worker unmounts the Metal toolchain image
			// as it removes a workspace; CoreDeviceService remounts its devicefs)
			// makes the census inconclusive, like a change the final check sees;
			// whatever is there now is decided by the next census. Any other
			// stat failure stays a failure.
			var again unix.Stat_t
			if err := statat(parent, name, &again, unix.AT_SYMLINK_NOFOLLOW); err != nil && !errors.Is(err, unix.ENOENT) {
				return fail(err)
			} else if err != nil || again.Dev != st.Dev || again.Ino != st.Ino || again.Mode&unix.S_IFMT != unix.S_IFDIR {
				return fail(errAcceptedMountChanged)
			}
			if !slices.ContainsFunc(skipped, func(s accepted) bool { return s.entry.FSID == m.FSID }) {
				skipped = append(skipped, accepted{m, rootPath, rel})
			}
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
			fd, err = openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP) {
					return nil
				}
				return fail(err)
			}
			f = os.NewFile(uintptr(fd), name)
			defer f.Close()
			// Account the directory actually opened, not its possibly stale lstat.
			if err = fstat(fd, &st); err != nil {
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
		if allocated := st.Blocks * 512; kind == unix.S_IFREG || allocated > size {
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
		fd, err := openat(unix.AT_FDCWD, c.base, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return -1, err
		}
		parts := strings.Split(strings.TrimPrefix(root, "/"), "/")
		for _, part := range parts[:len(parts)-1] {
			next, e := openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
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
			rootPath = root
			err = walk(fd, parts[len(parts)-1], ".", uint64(st.Dev), 0)
		}
		unix.Close(fd)
		if err != nil {
			return -1, fmt.Errorf("mutable census %s: %w", root, err)
		}
	}
	if skipped != nil {
		// A skip is valid only if the same record still describes that mount.
		table, err := c.mounts()
		for _, s := range skipped {
			if err != nil {
				return -1, fmt.Errorf("mutable census %s: %s: %w", s.root, strconv.Quote(s.rel), err)
			}
			if m, ok := mounttable.Unique(table, s.entry.FSID); !ok || m != s.entry {
				return -1, fmt.Errorf("mutable census %s: %s: %w", s.root, strconv.Quote(s.rel), errAcceptedMountChanged)
			}
		}
	}
	return total, ctx.Err()
}

// errAcceptedMountChanged reports that an accepted mount (acceptedMount)
// changed (remounted or unmounted) while the census ran. Xcode's
// CoreDeviceService does this on its own schedule, notably as a build
// finishes, and the worker unmounts the Metal toolchain image as it removes
// a workspace, so it makes that census inconclusive rather than a finding; a
// mount that is actually wrong is refused by the next census.
var errAcceptedMountChanged = errors.New("mutable mount table changed during census")

// ignoringEINTR retries a system call interrupted by a signal before it did any
// work, as package os does for its own calls.
func ignoringEINTR(call func() error) error {
	for {
		if err := call(); !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}

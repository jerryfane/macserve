package worker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"strconv"

	"golang.org/x/sys/unix"
)

// errWorkspaceMount is a mount point inside a job workspace. Any user can
// attach a disk image or an FSKit volume at a directory it owns, so a job can
// create one. The budget and lockfile walks never descend it: the nested
// filesystem's bytes are not on the workspace device and a job could hide or
// forge them there. walkWorkspace (evidence and cleanup) refuses it as
// contamination.
var errWorkspaceMount = errors.New("mount point in workspace")

// statAt is unix.Fstatat; tests replace it to present another device.
type statAt func(dirfd int, name string, stat *unix.Stat_t, flags int) error

// walkSameDevice visits every entry beneath dir with its lstat facts, the
// open parent directory and its slash-separated path below rel. It works on
// directory descriptors: no symlink is followed, and no entry or opened
// directory on a device other than device is visited or descended. A running
// job deletes and renames files, so an entry that vanishes between listing
// and stat or open is skipped; maxArchiveEntries bounds the walk.
func walkSameDevice(ctx context.Context, dir *os.File, rel string, device uint64, statat statAt, visit func(parent *os.File, name, rel string, stat *unix.Stat_t) error) error {
	mount := func(rel string) error { return fmt.Errorf("%w: %s", errWorkspaceMount, strconv.Quote(rel)) }
	var top unix.Stat_t
	if err := unix.Fstat(int(dir.Fd()), &top); err != nil {
		return err
	}
	if uint64(top.Dev) != device {
		return mount(rel)
	}
	entries := 0
	var walk func(*os.File, string) error
	walk = func(dir *os.File, prefix string) error {
		for {
			names, readErr := dir.Readdirnames(128)
			if readErr != nil && readErr != io.EOF {
				return readErr
			}
			for _, name := range names {
				if err := ctx.Err(); err != nil {
					return err
				}
				if entries++; entries > maxArchiveEntries {
					return errors.New("workspace entry limit exceeded")
				}
				rel := path.Join(prefix, name)
				var stat unix.Stat_t
				if err := statat(int(dir.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
					if errors.Is(err, unix.ENOENT) {
						continue
					}
					return err
				}
				if uint64(stat.Dev) != device {
					return mount(rel)
				}
				if err := visit(dir, name, rel, &stat); err != nil {
					return err
				}
				if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
					continue
				}
				fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
				if err != nil {
					if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP) {
						continue
					}
					return err
				}
				child := os.NewFile(uintptr(fd), name)
				// Only the directory actually opened is walked: the name may
				// have been renamed over or mounted on since the stat.
				var opened unix.Stat_t
				err = unix.Fstat(fd, &opened)
				if err == nil && uint64(opened.Dev) != device {
					err = mount(rel)
				}
				if err == nil {
					err = walk(child, rel)
				}
				child.Close()
				if err != nil {
					return err
				}
			}
			if readErr == io.EOF {
				return nil
			}
		}
	}
	return walk(dir, rel)
}

// chargedBytes is the disk use the workspace budget charges an inode: the
// allocated blocks of a regular file, the larger of logical and allocated
// size of anything else. A sparse file is charged what it occupies (Xcode 27
// preallocates derived-data/CompilationCache.noindex at 24 + 12 + 1 GiB
// logical, about 1 MiB each on disk); a clone is charged per inode, which
// over-counts shared blocks.
func chargedBytes(stat *unix.Stat_t) (int64, error) {
	if stat.Size < 0 || stat.Blocks < 0 || stat.Blocks > math.MaxInt64/512 {
		return 0, errors.New("invalid workspace entry size")
	}
	allocated := stat.Blocks * 512
	if stat.Mode&unix.S_IFMT == unix.S_IFREG {
		return allocated, nil
	}
	return max(stat.Size, allocated), nil
}

// walkWorkspace opens every component relative to an already open directory,
// never follows a symlink and never crosses a mount. It is used only before
// launching jobs or after proven UID quiescence, not as a concurrent chmod tool.
func walkWorkspace(ctx context.Context, directory *os.File, owner uint32, prepare bool, gid uint32, repair bool) error {
	var base unix.Stat_t
	if err := unix.Fstat(int(directory.Fd()), &base); err != nil {
		return err
	}
	count := 0
	var visit func(*os.File) error
	visit = func(dir *os.File) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		var stat unix.Stat_t
		if err := unix.Fstat(int(dir.Fd()), &stat); err != nil {
			return err
		}
		if stat.Dev != base.Dev || (stat.Uid != owner && stat.Uid != uint32(os.Geteuid())) {
			return fmt.Errorf("%w: workspace directory ownership or filesystem changed", ErrContamination)
		}
		if prepare {
			if err := dir.Chown(int(owner), int(gid)); err != nil {
				return err
			}
		}
		if repair {
			if err := repairDirectoryFlags(dir, &stat); err != nil {
				return err
			}
			if err := dir.Chmod(os.FileMode(stat.Mode&0777) | 0700); err != nil {
				return err
			}
		}
		for {
			names, readErr := dir.Readdirnames(128)
			if readErr != nil && readErr != io.EOF {
				return readErr
			}
			for _, name := range names {
				if err := ctx.Err(); err != nil {
					return err
				}
				count++
				if count > maxArchiveEntries {
					return errors.New("workspace entry limit exceeded")
				}
				var entry unix.Stat_t
				if err := unix.Fstatat(int(dir.Fd()), name, &entry, unix.AT_SYMLINK_NOFOLLOW); err != nil {
					return err
				}
				kind := entry.Mode & unix.S_IFMT
				// Unlink non-directories without changing their targets. On Darwin,
				// clear only user unlink-blocking flags on a confined single-link inode.
				if repair && kind != unix.S_IFDIR {
					if err := repairEntryFlags(dir, name, &entry, &base, owner); err != nil {
						return err
					}
					continue
				}
				if kind == unix.S_IFLNK {
					if prepare {
						return errors.New("symlink in prepared workspace")
					}
					continue // unlinking later removes only the link, never its target
				}
				if entry.Dev != base.Dev || (entry.Uid != owner && entry.Uid != uint32(os.Geteuid())) {
					return fmt.Errorf("%w: foreign workspace entry", ErrContamination)
				}
				if kind != unix.S_IFDIR && kind != unix.S_IFREG {
					return errors.New("special file in workspace")
				}
				if !prepare && !repair && entry.Uid != owner {
					return errors.New("artifact workspace entry is not job-owned")
				}
				if kind == unix.S_IFREG && entry.Nlink != 1 {
					return errors.New("hardlinked workspace file")
				}
				if kind == unix.S_IFREG && !prepare {
					continue
				}
				flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
				if kind == unix.S_IFDIR {
					flags |= unix.O_DIRECTORY
				}
				fd, err := unix.Openat(int(dir.Fd()), name, flags, 0)
				if err != nil {
					return fmt.Errorf("open workspace entry: %w", err)
				}
				file := os.NewFile(uintptr(fd), name)
				if kind == unix.S_IFDIR {
					err = visit(file)
				} else if prepare {
					err = file.Chown(int(owner), int(gid))
				}
				closeErr := file.Close()
				if err := errors.Join(err, closeErr); err != nil {
					return err
				}
			}
			if readErr == io.EOF {
				return nil
			}
		}
	}
	return visit(directory)
}

func (e *Engine) workspacePass(ctx context.Context, jobID string, prepare, repair bool) error {
	file, err := e.workspaces.OpenFile(jobID, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	owner, gid := e.options.JobUID, e.options.JobGID
	if _, native := e.options.Runner.(*nativeRunner); !native {
		// Injected runners never change machine identity. Their fixtures are owned
		// by the test process; production always uses the validated dedicated UID.
		owner, gid = uint32(os.Geteuid()), uint32(os.Getegid())
		prepare = false
	}
	return walkWorkspace(ctx, file, owner, prepare, gid, repair)
}

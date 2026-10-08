//go:build darwin

package worker

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

const workspaceUserFlags = unix.UF_IMMUTABLE | unix.UF_APPEND

func repairDirectoryFlags(dir *os.File, stat *unix.Stat_t) error {
	if stat.Flags&workspaceUserFlags == 0 {
		return nil
	}
	return unix.Fchflags(int(dir.Fd()), int(stat.Flags&^workspaceUserFlags))
}

// Event-only descriptors avoid reading file/FIFO data. DAC still applies; the
// protected root broker can open unreadable job files. O_SYMLINK opens only the
// symlink inode, never the target.
func repairEntryFlags(dir *os.File, name string, before, base *unix.Stat_t, owner uint32) error {
	if before.Flags&workspaceUserFlags == 0 {
		return nil
	}
	if before.Dev != base.Dev || (before.Uid != owner && before.Uid != uint32(os.Geteuid())) || before.Nlink != 1 {
		return errors.New("immutable workspace entry has foreign ownership, filesystem or hardlinks")
	}
	flags := unix.O_EVTONLY | unix.O_CLOEXEC | unix.O_NONBLOCK | unix.O_NOFOLLOW
	if before.Mode&unix.S_IFMT == unix.S_IFLNK {
		flags |= unix.O_SYMLINK
	}
	fd, err := unix.Openat(int(dir.Fd()), name, flags, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var current unix.Stat_t
	if err := unix.Fstat(fd, &current); err != nil {
		return err
	}
	if current.Dev != before.Dev || current.Ino != before.Ino || current.Uid != before.Uid || current.Nlink != 1 || current.Mode&unix.S_IFMT != before.Mode&unix.S_IFMT {
		return errors.New("immutable workspace entry changed before repair")
	}
	return unix.Fchflags(fd, int(current.Flags&^workspaceUserFlags))
}

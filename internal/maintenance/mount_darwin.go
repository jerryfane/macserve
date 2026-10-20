package maintenance

import (
	"errors"

	"golang.org/x/sys/unix"
)

// mountTable reads cached mount records (MNT_NOWAIT): it never asks a
// filesystem, including a user-space FSKit server, for fresh statistics.
func mountTable() ([]mountEntry, error) {
	for range 4 {
		n, err := unix.Getfsstat(nil, unix.MNT_NOWAIT)
		if err != nil {
			return nil, err
		}
		buf := make([]unix.Statfs_t, n+8)
		n, err = unix.Getfsstat(buf, unix.MNT_NOWAIT)
		if err != nil {
			return nil, err
		}
		if n == len(buf) {
			continue // The table may have grown past the buffer.
		}
		mounts := make([]mountEntry, n)
		for i := range mounts {
			mounts[i] = mountEntryFromStatfs(&buf[i])
		}
		return mounts, nil
	}
	return nil, errors.New("mount table changed while reading")
}

func mountEntryFromStatfs(s *unix.Statfs_t) mountEntry {
	return mountEntry{
		fsid:   uint64(s.Fsid.Val[0]),
		owner:  s.Owner,
		flags:  uint64(s.Flags),
		fstype: unix.ByteSliceToString(s.Fstypename[:]),
		on:     unix.ByteSliceToString(s.Mntonname[:]),
		from:   unix.ByteSliceToString(s.Mntfromname[:]),
	}
}

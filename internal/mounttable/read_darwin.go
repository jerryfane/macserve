package mounttable

import (
	"errors"

	"golang.org/x/sys/unix"
)

// Read returns the cached mount records (MNT_NOWAIT): it never asks a
// filesystem, including a user-space FSKit server, for fresh statistics.
func Read() ([]Entry, error) {
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
		mounts := make([]Entry, n)
		for i := range mounts {
			mounts[i] = FromStatfs(&buf[i])
		}
		return mounts, nil
	}
	return nil, errors.New("mount table changed while reading")
}

// FromStatfs is the Entry of one struct statfs.
func FromStatfs(s *unix.Statfs_t) Entry {
	return Entry{
		FSID:   uint64(s.Fsid.Val[0]),
		Owner:  s.Owner,
		Flags:  uint64(s.Flags),
		FSType: unix.ByteSliceToString(s.Fstypename[:]),
		On:     unix.ByteSliceToString(s.Mntonname[:]),
		From:   unix.ByteSliceToString(s.Mntfromname[:]),
	}
}

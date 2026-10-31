//go:build darwin

package worker

import (
	"errors"

	"golang.org/x/sys/unix"
)

// sipRestrictedExecutable requires a regular file (never a symlink) carrying
// SF_RESTRICTED, owned by root and not group or other writable.
func sipRestrictedExecutable(path string) error {
	return sipRestrictedNode(path, false)
}

func sipRestrictedDirectory(path string) error {
	return sipRestrictedNode(path, true)
}

func sipRestrictedNode(path string, directory bool) error {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return err
	}
	kind := uint16(unix.S_IFREG)
	if directory {
		kind = unix.S_IFDIR
	}
	if st.Mode&unix.S_IFMT != kind {
		return errors.New("not the required regular file or directory")
	}
	if st.Flags&unix.SF_RESTRICTED == 0 {
		return errors.New("not SIP-restricted (SF_RESTRICTED unset)")
	}
	if st.Uid != 0 || st.Mode&0o022 != 0 {
		return errors.New("not root-owned or writable by group/other")
	}
	return nil
}

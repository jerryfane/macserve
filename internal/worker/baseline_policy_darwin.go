//go:build darwin

package worker

import (
	"errors"

	"golang.org/x/sys/unix"
)

// sipRestrictedExecutable requires a regular file (never a symlink) carrying
// SF_RESTRICTED, owned by root and not group or other writable.
func sipRestrictedExecutable(path string) error {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("not a regular file")
	}
	if st.Flags&unix.SF_RESTRICTED == 0 {
		return errors.New("not SIP-restricted (SF_RESTRICTED unset)")
	}
	if st.Uid != 0 || st.Mode&0o022 != 0 {
		return errors.New("not root-owned or writable by group/other")
	}
	return nil
}

package mounttable

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestFlagsMatchSystem(t *testing.T) {
	if ReadOnly != unix.MNT_RDONLY || NoSUID != unix.MNT_NOSUID || NoDev != unix.MNT_NODEV {
		t.Fatal("mount flag constants differ from <sys/mount.h>")
	}
}

// Package mounttable reads the kernel's cached mount records. It is the one
// getfsstat boundary shared by the maintenance census and the worker's
// workspace walks, which recognize a few exact mounts Xcode makes for the job
// user and refuse every other nested mount.
package mounttable

// Entry is the portable subset of one getfsstat record. FSID is
// f_fsid.val[0], which equals st_dev of every node on that mount.
type Entry struct {
	FSID   uint64
	Owner  uint32
	Flags  uint64
	FSType string
	On     string
	From   string
}

// <sys/mount.h> mount flags; a darwin test pins them to x/sys.
const (
	ReadOnly = 0x1  // MNT_RDONLY
	NoSUID   = 0x8  // MNT_NOSUID
	NoDev    = 0x10 // MNT_NODEV
)

// Unique returns the record for the mount whose f_fsid.val[0] is fsid if, and
// only if, table has exactly one.
func Unique(table []Entry, fsid uint64) (Entry, bool) {
	var match Entry
	found := 0
	for _, m := range table {
		if m.FSID == fsid {
			match = m
			found++
		}
	}
	return match, found == 1
}

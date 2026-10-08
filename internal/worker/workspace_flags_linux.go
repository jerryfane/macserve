//go:build linux

package worker

import (
	"golang.org/x/sys/unix"
	"os"
)

// Linux has no Darwin user-settable st_flags. Its privileged filesystem flags
// are not cleared by the portable fixture runner; cleanup errors stay fatal.
func repairDirectoryFlags(*os.File, *unix.Stat_t) error                           { return nil }
func repairEntryFlags(*os.File, string, *unix.Stat_t, *unix.Stat_t, uint32) error { return nil }

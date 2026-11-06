package signer

import (
	"os"
	"syscall"
)

// ownedByMe reports whether info's owner is the current account.
func ownedByMe(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Getuid())
}

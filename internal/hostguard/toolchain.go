package hostguard

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

// ToolchainDirectory permits administrator-managed toolchains, including the
// normal root:admin group-writable /Applications, but never job-writable paths.
func ToolchainDirectory(path string, jobUID uint32) error {
	return toolchainPath(path, true, jobUID)
}

// ToolchainExecutable applies the same policy to a regular executable file.
// It is not a replacement for RootConfig's stricter secret/helper policy.
func ToolchainExecutable(path string, jobUID uint32) error {
	return toolchainPath(path, false, jobUID)
}

func toolchainPath(path string, directory bool, jobUID uint32) error {
	account, err := user.LookupId(strconv.FormatUint(uint64(jobUID), 10))
	if err != nil {
		return err
	}
	groups, err := account.GroupIds()
	if err != nil {
		return err
	}
	admin, err := user.LookupGroup("admin")
	if err != nil {
		return err
	}
	memberships := make(map[string]bool, len(groups)+1)
	memberships[account.Gid] = true
	for _, gid := range groups {
		memberships[gid] = true
	}
	return protectedToolchainPath(path, directory, jobUID, admin.Gid, memberships, os.Lstat)
}

func protectedToolchainPath(path string, directory bool, jobUID uint32, adminGID string, jobGroups map[string]bool, lstat func(string) (os.FileInfo, error)) error {
	if jobUID < 501 || adminGID == "" || jobGroups[adminGID] || jobGroups["0"] {
		return errors.New("toolchain requires a nonprivileged dedicated job account")
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("toolchain requires a clean absolute path")
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := lstat(current)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		validType := info.IsDir()
		if current == path && !directory {
			validType = info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0
		}
		if !ok || !validType || info.Mode()&os.ModeSymlink != 0 || stat.Uid != 0 || info.Mode().Perm()&0002 != 0 {
			return errors.New("toolchain and ancestors must be root-owned, non-symlink and not world writable")
		}
		gid := strconv.FormatUint(uint64(stat.Gid), 10)
		if info.Mode().Perm()&0020 != 0 && (!info.IsDir() || gid != adminGID || jobGroups[gid]) {
			return errors.New("only administrator-owned directories outside job groups may be group writable")
		}
		if current == filepath.Dir(current) {
			return nil
		}
	}
}

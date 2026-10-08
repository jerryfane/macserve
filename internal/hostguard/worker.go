// Package hostguard checks native service identity before execution is enabled.
package hostguard

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"
)

// Worker accepts only a root execution broker with protected configuration.
// The controller and job account are independently validated below.
func Worker(configPath string) error {
	if runtime.GOOS != "darwin" {
		return errors.New("native workers require macOS")
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return errors.New("worker execution broker must run as root")
	}
	return RootConfig(configPath)
}

func BrokerIdentity(jobUID, jobGID, controllerUID, ownerUID uint32) error {
	if runtime.GOOS != "darwin" || os.Getuid() != 0 || os.Geteuid() != 0 {
		return errors.New("protected execution requires a macOS root broker")
	}
	if err := DistinctJobIdentity(jobUID, jobGID, controllerUID, ownerUID); err != nil {
		return err
	}
	account, err := user.LookupId(strconv.FormatUint(uint64(jobUID), 10))
	if err != nil {
		return err
	}
	if account.Gid != strconv.FormatUint(uint64(jobGID), 10) {
		return errors.New("job GID must be the dedicated account primary group")
	}
	admin, err := user.LookupGroup("admin")
	if err != nil {
		return err
	}
	groups, err := account.GroupIds()
	if err != nil {
		return err
	}
	for _, gid := range append(groups, account.Gid) {
		if gid == admin.Gid || gid == "0" {
			return errors.New("job account must not belong to privileged groups")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// This only checks an existing domain. It never creates a GUI login.
	cmd := exec.CommandContext(ctx, "/bin/launchctl", "print", "gui/"+account.Uid)
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: jobUID, Gid: jobGID, Groups: []uint32{}}}
	cmd.WaitDelay = 100 * time.Millisecond
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("dedicated job GUI session unavailable: %w", err)
	}
	return nil
}

func DistinctJobIdentity(jobUID, jobGID, controllerUID, ownerUID uint32) error {
	if jobUID < 501 || jobGID == 0 || controllerUID == 0 || ownerUID == 0 || jobUID == controllerUID || jobUID == ownerUID || controllerUID == ownerUID {
		return errors.New("job, owner and controller UIDs must be distinct non-root identities; job UID must be a dedicated login account")
	}
	return nil
}

func RootDirectory(path string) error { return protectedPath(path, true) }

func RootConfig(path string) error { return protectedPath(path, false) }

func protectedPath(path string, directory bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("service configuration requires a clean absolute path")
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		validType := info.IsDir()
		if current == path && !directory {
			validType = info.Mode().IsRegular()
		}
		if !ok || !validType || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
			return errors.New("configuration and its parent directories must be root-owned, non-symlink and not group/world writable")
		}
		if current == filepath.Dir(current) {
			return nil
		}
	}
}

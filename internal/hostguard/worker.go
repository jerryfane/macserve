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
	"strings"
	"syscall"
	"time"
)

// Worker requires a standard macOS GUI account and an administrator-owned,
// non-writable configuration. It never creates users or changes permissions.
func Worker(configPath string) error {
	if runtime.GOOS != "darwin" {
		return errors.New("native workers require macOS")
	}
	if os.Geteuid() == 0 || os.Geteuid() != os.Getuid() {
		return errors.New("worker must run as a non-root account without elevated identity")
	}
	admin, err := user.LookupGroup("admin")
	if err != nil {
		return fmt.Errorf("lookup administrator group: %w", err)
	}
	adminID, err := strconv.Atoi(admin.Gid)
	if err != nil {
		return err
	}
	if os.Getgid() == adminID || os.Getegid() == adminID {
		return errors.New("worker must not use the administrator primary group")
	}
	groups, err := os.Getgroups()
	if err != nil {
		return err
	}
	for _, gid := range groups {
		if gid == adminID {
			return errors.New("worker must not belong to the administrator group")
		}
	}
	if err := RootConfig(configPath); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/launchctl", "managername")
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("worker GUI session unavailable: %w", err)
	}
	if strings.TrimSpace(string(output)) != "Aqua" {
		return errors.New("worker requires a logged-in Aqua GUI session")
	}
	return nil
}

func RootConfig(path string) error {
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
		if current == path {
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

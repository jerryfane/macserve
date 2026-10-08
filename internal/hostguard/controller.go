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

func standardAccount(role string) error {
	if runtime.GOOS != "darwin" {
		return errors.New("native services require macOS")
	}
	if os.Geteuid() == 0 || os.Geteuid() != os.Getuid() {
		return fmt.Errorf("%s requires a non-root account without elevated identity", role)
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
		return fmt.Errorf("%s must not use the administrator primary group", role)
	}
	groups, err := os.Getgroups()
	if err != nil {
		return err
	}
	for _, gid := range groups {
		if gid == adminID {
			return fmt.Errorf("%s must not belong to the administrator group", role)
		}
	}
	return nil
}

// Controller requires a dedicated non-login service account, never the owner.
func Controller(configPath string) error {
	if err := standardAccount("controller"); err != nil {
		return err
	}
	if err := RootConfig(configPath); err != nil {
		return err
	}
	current, err := user.Current()
	if err != nil {
		return err
	}
	if strings.ContainsAny(current.Username, "/\x00\r\n") {
		return errors.New("invalid controller account name")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/dscl", ".", "-read", "/Users/"+current.Username, "UserShell")
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}
	data, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("read controller account shell: %w", err)
	}
	shell := strings.Fields(string(data))
	if len(shell) != 2 || shell[0] != "UserShell:" || (shell[1] != "/usr/bin/false" && shell[1] != "/usr/sbin/nologin") {
		return errors.New("controller requires a non-login account")
	}
	return nil
}

// PrivateFile protects controller secrets independently of public root config.
func PrivateFile(path string) error { return privatePath(path, false) }

func PrivateDirectory(path string) error { return privatePath(path, true) }

func privatePath(path string, directory bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return errors.New("private storage requires an absolute non-root path")
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return errors.New("unsafe private storage ownership or ancestor")
		}
		if current == path {
			valid := info.Mode().IsRegular()
			if directory {
				valid = info.IsDir()
			}
			if !valid || info.Mode().Perm()&0077 != 0 {
				return errors.New("private storage has unsafe type or permissions")
			}
		} else if !info.IsDir() {
			return errors.New("unsafe private storage ancestor")
		}
		if current == "/" {
			return nil
		}
	}
}

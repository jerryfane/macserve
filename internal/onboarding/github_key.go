package onboarding

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// AppKeyName is the App key's file name in the controller secrets
// directory, the name the admin enrollment uses.
const AppKeyName = "github-app.pem"

// nofollow refuses a symlink as the final path component.
const nofollow = syscall.O_NOFOLLOW

// ErrKeyExists refuses to replace an installed App key. A key is never
// overwritten; deleting an old one is a separate, deliberate owner action.
var ErrKeyExists = errors.New("a GitHub App key is already installed; macserve never replaces it")

// KeyTarget is where the App key is installed: <Root>/var/controller/secrets.
// Root and Root/var must be owned by RootUID (0 outside tests) and not
// writable by group or other; var/controller and its secrets must be
// controller-owned 0700 directories, as deploy-install creates them.
type KeyTarget struct {
	Root                         string
	RootUID                      uint32
	ControllerUID, ControllerGID uint32
}

// Dir is the controller secrets directory.
func (t KeyTarget) Dir() string { return filepath.Join(t.Root, "var", "controller", "secrets") }

// Path is the installed key's path, the github.private_key_file value.
func (t KeyTarget) Path() string { return filepath.Join(t.Dir(), AppKeyName) }

func owner(info fs.FileInfo) (uid, gid uint32, nlink uint64, ok bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, 0, false
	}
	return st.Uid, st.Gid, uint64(st.Nlink), true
}

// checkTrustedDir requires a real directory (never a symlink) owned by
// uid and not writable by group or other, unless sticky above the root.
func checkTrustedDir(path string, uids []uint32, allowSticky bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%s is not a real directory", path)
	}
	uid, _, _, ok := owner(info)
	if !ok {
		return fmt.Errorf("cannot read the owner of %s", path)
	}
	trusted := false
	for _, u := range uids {
		trusted = trusted || uid == u
	}
	if !trusted {
		return fmt.Errorf("%s has an untrusted owner", path)
	}
	if info.Mode().Perm()&0o022 != 0 && !(allowSticky && info.Mode()&fs.ModeSticky != 0) {
		return fmt.Errorf("%s is writable by group or other", path)
	}
	return nil
}

func checkControllerDir(path string, uid, gid uint32) (fs.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("%s is not a real directory", path)
	}
	u, g, _, ok := owner(info)
	if !ok || u != uid || g != gid || info.Mode().Perm() != 0o700 || info.Mode()&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky) != 0 {
		return nil, fmt.Errorf("%s must be a controller-owned 0700 directory", path)
	}
	return info, nil
}

// checkTarget validates every directory from / to the secrets directory.
func (t KeyTarget) checkTarget() (fs.FileInfo, error) {
	if !filepath.IsAbs(t.Root) || filepath.Clean(t.Root) != t.Root || t.Root == "/" {
		return nil, errors.New("the install root must be a clean absolute path")
	}
	for p := filepath.Dir(t.Root); ; p = filepath.Dir(p) {
		if err := checkTrustedDir(p, []uint32{0, t.RootUID}, true); err != nil {
			return nil, err
		}
		if p == "/" {
			break
		}
	}
	for _, p := range []string{t.Root, filepath.Join(t.Root, "var")} {
		if err := checkTrustedDir(p, []uint32{t.RootUID}, false); err != nil {
			return nil, err
		}
	}
	if _, err := checkControllerDir(filepath.Dir(t.Dir()), t.ControllerUID, t.ControllerGID); err != nil {
		return nil, err
	}
	return checkControllerDir(t.Dir(), t.ControllerUID, t.ControllerGID)
}

// KeyInstalled reports whether any entry already holds the key's name.
func (t KeyTarget) KeyInstalled() (bool, error) {
	_, err := os.Lstat(t.Path())
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// InstallAppKey writes the App key as a controller-owned 0600 single-link
// regular file in the secrets directory, with the properties of the admin
// enrollment: exclusive create (never overwrite, never follow a symlink),
// no symlink or untrusted ancestor, owner, group, mode and link count
// verified on the open descriptor, and the bytes read back. A file this
// call created but could not validate is removed again.
func InstallAppKey(t KeyTarget, data []byte) (err error) {
	if _, err := ParseAppKey(data); err != nil {
		return err
	}
	dirInfo, err := t.checkTarget()
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(t.Dir())
	if err != nil {
		return err
	}
	defer root.Close()
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(opened, dirInfo) {
		return errors.New("the controller secrets directory changed during validation")
	}
	if _, err := root.Lstat(AppKeyName); err == nil {
		return ErrKeyExists
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	f, err := root.OpenFile(AppKeyName, os.O_WRONLY|os.O_CREATE|os.O_EXCL|nofollow, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return ErrKeyExists
	}
	if err != nil {
		return err
	}
	created, statErr := f.Stat()
	defer func() {
		if err != nil && statErr == nil {
			if current, e := root.Lstat(AppKeyName); e == nil && os.SameFile(current, created) {
				_ = root.Remove(AppKeyName)
			}
		}
	}()
	if statErr != nil {
		f.Close()
		return statErr
	}
	_, werr := f.Write(data)
	err = errors.Join(werr, f.Chown(int(t.ControllerUID), int(t.ControllerGID)), f.Chmod(0o600), f.Sync())
	info, serr := f.Stat()
	err = errors.Join(err, serr, f.Close())
	if err != nil {
		return fmt.Errorf("cannot write the GitHub App key: %w", err)
	}
	uid, gid, nlink, ok := owner(info)
	if !ok || uid != t.ControllerUID || gid != t.ControllerGID || info.Mode() != 0o600 || nlink != 1 || info.Size() != int64(len(data)) {
		return errors.New("the installed GitHub App key failed owner, mode or link validation")
	}
	back, err := root.Open(AppKeyName)
	if err != nil {
		return err
	}
	defer back.Close()
	again, err := back.Stat()
	if err != nil || !os.SameFile(again, info) {
		return errors.New("the installed GitHub App key changed during validation")
	}
	installed, err := io.ReadAll(io.LimitReader(back, int64(len(data))+1))
	if err != nil || subtle.ConstantTimeCompare(installed, data) != 1 {
		return errors.New("the installed GitHub App key does not read back")
	}
	dir, err := root.Open(".")
	if err == nil {
		err = errors.Join(dir.Sync(), dir.Close())
	}
	return err
}

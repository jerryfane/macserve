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

	"github.com/jerryfane/macserve/internal/keyholder"
)

// AppKeyName is the App key's file name in the keyholder's secrets
// directory, the only name the keyholder reads.
const AppKeyName = keyholder.AppKeyName

// nofollow refuses a symlink as the final path component.
const nofollow = syscall.O_NOFOLLOW

// ErrKeyExists refuses to replace an installed App key. A key is never
// overwritten; deleting an old one is a separate, deliberate owner action.
var ErrKeyExists = errors.New("a GitHub App key is already installed; macserve never replaces it")

// KeyTarget is where the App key is installed: <Root>/var/keyholder/secrets,
// the keyholder's, which the controller cannot open. Root and Root/var must
// be owned by RootUID (0 outside tests) and not writable by group or
// other; var/keyholder and its secrets must be keyholder-owned 0700
// directories, as create-users.sh creates them.
type KeyTarget struct {
	Root                       string
	RootUID                    uint32
	KeyholderUID, KeyholderGID uint32
}

// Dir is the keyholder secrets directory.
func (t KeyTarget) Dir() string { return filepath.Join(t.Root, "var", "keyholder", "secrets") }

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

func checkKeyholderDir(path string, uid, gid uint32) (fs.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("%s is not a real directory", path)
	}
	u, g, _, ok := owner(info)
	if !ok || u != uid || g != gid || info.Mode().Perm() != 0o700 || info.Mode()&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky) != 0 {
		return nil, fmt.Errorf("%s must be a keyholder-owned 0700 directory", path)
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
	if _, err := checkKeyholderDir(filepath.Dir(t.Dir()), t.KeyholderUID, t.KeyholderGID); err != nil {
		return nil, err
	}
	return checkKeyholderDir(t.Dir(), t.KeyholderUID, t.KeyholderGID)
}

// KeyInstalled reports whether any entry already holds the key's name.
func (t KeyTarget) KeyInstalled() (bool, error) {
	_, err := os.Lstat(t.Path())
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// InstallAppKey writes the App key as a keyholder-owned 0600 single-link
// regular file in the keyholder's secrets directory, with the properties of the admin
// enrollment: exclusive create (never overwrite, never follow a symlink),
// no symlink or untrusted ancestor, owner, group, mode and link count
// verified on the open descriptor, and the bytes read back. A file this
// call created but could not validate is removed again.
func InstallAppKey(t KeyTarget, data []byte) error {
	_, err := installAppKey(t, data)
	return err
}

// installAppKey is InstallAppKey returning the identity of the file it
// created, so removeAppKey can undo exactly that file.
func installAppKey(t KeyTarget, data []byte) (installed fs.FileInfo, err error) {
	if _, err := ParseAppKey(data); err != nil {
		return nil, err
	}
	dirInfo, err := t.checkTarget()
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(t.Dir())
	if err != nil {
		return nil, err
	}
	defer root.Close()
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(opened, dirInfo) {
		return nil, errors.New("the keyholder secrets directory changed during validation")
	}
	if _, err := root.Lstat(AppKeyName); err == nil {
		return nil, ErrKeyExists
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	f, err := root.OpenFile(AppKeyName, os.O_WRONLY|os.O_CREATE|os.O_EXCL|nofollow, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return nil, ErrKeyExists
	}
	if err != nil {
		return nil, err
	}
	mine, statErr := f.Stat()
	defer func() {
		if err != nil && statErr == nil {
			// Still inside the call that created it: the inode is enough.
			removeCreated(root, mine, false)
			installed = nil
		}
	}()
	if statErr != nil {
		f.Close()
		return nil, statErr
	}
	_, werr := f.Write(data)
	err = errors.Join(werr, f.Chown(int(t.KeyholderUID), int(t.KeyholderGID)), f.Chmod(0o600), f.Sync())
	info, serr := f.Stat()
	err = errors.Join(err, serr, f.Close())
	if err != nil {
		return nil, fmt.Errorf("cannot write the GitHub App key: %w", err)
	}
	uid, gid, nlink, ok := owner(info)
	if !ok || uid != t.KeyholderUID || gid != t.KeyholderGID || info.Mode() != 0o600 || nlink != 1 || info.Size() != int64(len(data)) {
		return nil, errors.New("the installed GitHub App key failed owner, mode or link validation")
	}
	back, err := root.Open(AppKeyName)
	if err != nil {
		return nil, err
	}
	defer back.Close()
	again, err := back.Stat()
	if err != nil || !os.SameFile(again, info) {
		return nil, errors.New("the installed GitHub App key changed during validation")
	}
	content, err := io.ReadAll(io.LimitReader(back, int64(len(data))+1))
	if err != nil || subtle.ConstantTimeCompare(content, data) != 1 {
		return nil, errors.New("the installed GitHub App key does not read back")
	}
	dir, err := root.Open(".")
	if err == nil {
		err = errors.Join(dir.Sync(), dir.Close())
	}
	if err != nil {
		return nil, err
	}
	return info, nil
}

// removeCreated removes the key entry only while it is still the file
// identified by created, and syncs the directory. With exact, size and
// modification time must match too, so a different file that reuses the
// inode after a removal is never deleted.
func removeCreated(root *os.Root, created fs.FileInfo, exact bool) bool {
	current, err := root.Lstat(AppKeyName)
	if err != nil || !os.SameFile(current, created) || exact && (current.Size() != created.Size() || !current.ModTime().Equal(created.ModTime())) {
		return false
	}
	if root.Remove(AppKeyName) != nil {
		return false
	}
	if dir, err := root.Open("."); err == nil {
		_ = dir.Sync()
		dir.Close()
	}
	return true
}

// removeAppKey undoes installAppKey: the key is removed only if it is
// still the file that call created (exclusive create guarantees it was
// new), never a key that existed before.
func removeAppKey(t KeyTarget, created fs.FileInfo) error {
	root, err := os.OpenRoot(t.Dir())
	if err != nil {
		return err
	}
	defer root.Close()
	if !removeCreated(root, created, true) {
		return errors.New("the installed GitHub App key could not be removed")
	}
	return nil
}

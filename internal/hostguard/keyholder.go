package hostguard

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// KeyholderAccount is the keyholder daemon's account name.
const KeyholderAccount = "_macserve_key"

// KeyholderIdentity is the configured identity the keyholder must run as
// and the accounts it must stay separate from.
type KeyholderIdentity struct {
	KeyholderUID, KeyholderGID, RPCGID uint32
	JobUID, JobGID, ControllerUID      uint32
	// StateDir is the keyholder's private 0700 state (its keys, receipts
	// and release records); SocketDir holds the RPC socket, owned by the
	// keyholder and the RPC group, 0750.
	StateDir, SocketDir string
}

// Keyholder checks, before any key is opened, that the keyholder runs as
// the dedicated non-login _macserve_key account with its configured UID and
// dedicated primary group, not root or admin, sharing no group with the
// job account, holding the RPC group the job account lacks; that its
// configuration is root-owned and protected; that its state directory is
// private with protected ancestors; and that its socket directory is the
// keyholder's and the RPC group's alone. The checks are the signer's.
func Keyholder(configPath string, id KeyholderIdentity) error {
	return rpcDaemon("keyholder", KeyholderAccount, configPath, daemonIdentity{
		UID: id.KeyholderUID, GID: id.KeyholderGID, RPCGID: id.RPCGID, JobUID: id.JobUID, JobGID: id.JobGID,
		StateDir: id.StateDir, SocketDir: id.SocketDir,
	})
}

// ReadOwnedPrivateKey is ReadPrivateKey for a root reader of a key another
// account holds (the keyholder's GitHub App key): the file and every
// ancestor must be owned by root or by owner, without a symlink or group
// or other write, and the file must have no group or other access. It is
// never a way for an unprivileged process to read another account's key:
// the kernel's own permission check still applies to the open.
func ReadOwnedPrivateKey(path string, owner uint32) ([]byte, error) {
	if err := ownedPrivatePath(path, owner); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, errors.New("private key changed while it was opened")
	}
	data, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 64<<10 {
		return nil, errors.New("private key exceeds size limit")
	}
	return data, nil
}

// ownedPrivatePath is privatePath for a regular file with owner in place
// of the reading process's own UID.
func ownedPrivatePath(path string, owner uint32) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return errors.New("private storage requires an absolute non-root path")
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (stat.Uid != 0 && stat.Uid != owner) || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return errors.New("unsafe private storage ownership or ancestor")
		}
		if current == path {
			if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || stat.Nlink != 1 {
				return errors.New("private storage has unsafe type, permissions or links")
			}
		} else if !info.IsDir() {
			return errors.New("unsafe private storage ancestor")
		}
		if current == "/" {
			return nil
		}
	}
}

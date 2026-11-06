package hostguard

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"
)

// SignerAccount is the signer daemon's account name.
const SignerAccount = "_macserve_sign"

// SignerIdentity is the configured identity the signer must run as and the
// accounts it must stay separate from.
type SignerIdentity struct {
	SignerUID, SignerGID, RPCGID  uint32
	JobUID, JobGID, ControllerUID uint32
	// StateDir is the signer's private 0700 state; SocketDir holds the RPC
	// socket, owned by the signer and the RPC group, 0750.
	StateDir, SocketDir string
}

// universalGroups are memberships every local account has implicitly
// (everyone, localaccounts); sharing them grants nothing.
var universalGroups = []uint32{12, 61}

// Signer checks, before any key or keychain is opened, that the signer runs
// as the dedicated non-login _macserve_sign account with its configured UID
// and dedicated primary group, not root or admin, sharing no group with the
// job account, holding the RPC group the job account lacks; that its
// configuration is root-owned and protected; that its state directory is
// private with protected ancestors; and that its socket directory is the
// signer's and the RPC group's alone.
func Signer(configPath string, id SignerIdentity) error {
	if err := standardAccount("signer"); err != nil {
		return err
	}
	if err := RootConfig(configPath); err != nil {
		return err
	}
	current, err := nonLoginAccount("signer")
	if err != nil {
		return err
	}
	if current.Username != SignerAccount || current.Uid != strconv.FormatUint(uint64(id.SignerUID), 10) || uint32(os.Getuid()) != id.SignerUID {
		return fmt.Errorf("signer must run as %s (UID %d)", SignerAccount, id.SignerUID)
	}
	if current.Gid != strconv.FormatUint(uint64(id.SignerGID), 10) || uint32(os.Getgid()) != id.SignerGID || uint32(os.Getegid()) != id.SignerGID {
		return errors.New("signer must run with its dedicated primary group")
	}
	groups, err := os.Getgroups()
	if err != nil {
		return err
	}
	job, err := user.LookupId(strconv.FormatUint(uint64(id.JobUID), 10))
	if err != nil {
		return err
	}
	jobGroups, err := job.GroupIds()
	if err != nil {
		return err
	}
	if err := signerGroups(id, groups, append(jobGroups, job.Gid)); err != nil {
		return err
	}
	if err := PrivateDirectory(id.StateDir); err != nil {
		return fmt.Errorf("signer state: %w", err)
	}
	return socketDirectory(id.SocketDir, id.SignerUID, id.RPCGID)
}

// signerGroups checks the signer's group set against the job account's.
func signerGroups(id SignerIdentity, signer []int, job []string) error {
	jobSet := map[uint32]bool{id.JobGID: true}
	for _, raw := range job {
		gid, err := strconv.ParseUint(raw, 10, 32)
		if err != nil {
			return fmt.Errorf("job group %q", raw)
		}
		jobSet[uint32(gid)] = true
	}
	if jobSet[id.RPCGID] || jobSet[id.SignerGID] {
		return errors.New("job account must not belong to the signer or RPC group")
	}
	hasRPC := false
	for _, raw := range signer {
		gid := uint32(raw)
		if gid == 0 || gid == 20 || gid == 80 {
			return errors.New("signer must not belong to wheel, staff or admin")
		}
		if jobSet[gid] && !slices.Contains(universalGroups, gid) {
			return fmt.Errorf("signer shares group %d with the job account", gid)
		}
		hasRPC = hasRPC || gid == id.RPCGID
	}
	if !hasRPC {
		return errors.New("signer must belong to the RPC group")
	}
	return nil
}

// socketDirectory requires dir owned by the signer and the RPC group, mode
// exactly 0750, below root-owned protected ancestors.
func socketDirectory(dir string, signerUID, rpcGID uint32) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || stat.Uid != signerUID || stat.Gid != rpcGID || info.Mode().Perm() != 0o750 {
		return errors.New("signer socket directory must be owned by the signer and RPC group, mode 0750")
	}
	return protectedPath(filepath.Dir(dir), true)
}

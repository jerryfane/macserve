package hostguard

import (
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
	return rpcDaemon("signer", SignerAccount, configPath, daemonIdentity{
		UID: id.SignerUID, GID: id.SignerGID, RPCGID: id.RPCGID, JobUID: id.JobUID, JobGID: id.JobGID,
		StateDir: id.StateDir, SocketDir: id.SocketDir,
	})
}

// daemonIdentity is what Signer and Keyholder have in common: a dedicated
// system account with its own primary group, an RPC group shared only with
// the controller, the job identity it must stay apart from, its private
// state directory and its socket directory.
type daemonIdentity struct {
	UID, GID, RPCGID    uint32
	JobUID, JobGID      uint32
	StateDir, SocketDir string
}

// rpcDaemon applies the dedicated-account checks to a role.
func rpcDaemon(role, account, configPath string, id daemonIdentity) error {
	if err := standardAccount(role); err != nil {
		return err
	}
	if err := RootConfig(configPath); err != nil {
		return err
	}
	current, err := nonLoginAccount(role)
	if err != nil {
		return err
	}
	if current.Username != account || current.Uid != strconv.FormatUint(uint64(id.UID), 10) || uint32(os.Getuid()) != id.UID {
		return fmt.Errorf("%s must run as %s (UID %d)", role, account, id.UID)
	}
	if current.Gid != strconv.FormatUint(uint64(id.GID), 10) || uint32(os.Getgid()) != id.GID || uint32(os.Getegid()) != id.GID {
		return fmt.Errorf("%s must run with its dedicated primary group", role)
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
	if err := daemonGroups(role, id, groups, append(jobGroups, job.Gid)); err != nil {
		return err
	}
	if err := PrivateDirectory(id.StateDir); err != nil {
		return fmt.Errorf("%s state: %w", role, err)
	}
	return socketDirectory(role, id.SocketDir, id.UID, id.RPCGID)
}

// daemonGroups checks the daemon's group set against the job account's.
func daemonGroups(role string, id daemonIdentity, own []int, job []string) error {
	jobSet := map[uint32]bool{id.JobGID: true}
	for _, raw := range job {
		gid, err := strconv.ParseUint(raw, 10, 32)
		if err != nil {
			return fmt.Errorf("job group %q", raw)
		}
		jobSet[uint32(gid)] = true
	}
	if jobSet[id.RPCGID] || jobSet[id.GID] {
		return fmt.Errorf("job account must not belong to the %s or RPC group", role)
	}
	hasRPC := false
	for _, raw := range own {
		gid := uint32(raw)
		if gid == 0 || gid == 20 || gid == 80 {
			return fmt.Errorf("%s must not belong to wheel, staff or admin", role)
		}
		if jobSet[gid] && !slices.Contains(universalGroups, gid) {
			return fmt.Errorf("%s shares group %d with the job account", role, gid)
		}
		hasRPC = hasRPC || gid == id.RPCGID
	}
	if !hasRPC {
		return fmt.Errorf("%s must belong to the RPC group", role)
	}
	return nil
}

// socketDirectory requires dir owned by the daemon account and the RPC
// group, mode exactly 0750, below root-owned protected ancestors.
func socketDirectory(role, dir string, uid, rpcGID uint32) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || stat.Uid != uid || stat.Gid != rpcGID || info.Mode().Perm() != 0o750 {
		return fmt.Errorf("%s socket directory must be owned by the %s and RPC group, mode 0750", role, role)
	}
	return protectedPath(filepath.Dir(dir), true)
}

package main

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/jerryfane/macserve/internal/api"
	"github.com/jerryfane/macserve/internal/controller"
	"github.com/jerryfane/macserve/internal/hostguard"
	"github.com/jerryfane/macserve/internal/signer"
)

// signerOptions connects a controller with a signer section to the signer
// daemon and returns the signer key capabilities publish; without one,
// signing is refused and it returns nil. The inbox must be the
// controller's, group the RPC group, mode 0750, below protected ancestors.
func signerOptions(config controller.Config, options *controller.Options) (*api.SignerKey, error) {
	s := config.Signer
	if s == nil {
		return nil, nil
	}
	info, err := os.Lstat(s.Inbox)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || stat.Uid != uint32(os.Getuid()) || stat.Gid != s.RPCGID || info.Mode().Perm() != 0o750 {
		return nil, errors.New("signer inbox must be the controller's, group the RPC group, mode 0750")
	}
	if err := hostguard.RootDirectory(filepath.Dir(s.Inbox)); err != nil {
		return nil, err
	}
	options.Signer = &controller.SignerOptions{
		Client: &signer.Client{Socket: s.Socket, SignerUID: s.UID},
		Inbox:  s.Inbox, RPCGID: int(s.RPCGID),
		Keys: map[string]ed25519.PublicKey{s.KeyID: s.PublicKeyBytes()},
	}
	return &api.SignerKey{KeyID: s.KeyID, PublicKey: s.PublicKey}, nil
}

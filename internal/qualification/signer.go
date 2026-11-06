package qualification

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"time"

	"github.com/jerryfane/macserve/internal/deploy"
)

// signerDenialCategory is the job report category proving the job account
// cannot reach the code signer: its state, keychain, RPC socket and inbox.
// It is a report category, not a maintenance record category: with a
// deployed signer the unix_socket_boundary category requires it as well.
const signerDenialCategory = "signer_denial"

// signerPaths are the signer locations the job account must be denied.
type signerPaths struct {
	State, KeychainDir, Keychain, KeychainSecret, SocketDir, Socket, Inbox string
}

var installedSignerPaths = signerPaths{
	State: deploy.SignerStateDir, KeychainDir: deploy.SignerKeychainDir, Keychain: deploy.SignerKeychain,
	KeychainSecret: deploy.SignerKeychainPass, SocketDir: deploy.SignerSocketDir, Socket: deploy.SignerSocket,
	Inbox: deploy.SignerInbox,
}

// signerProbeKind is one denied operation: listing or traversing a
// directory, connecting to the socket, or opening a file for reading.
type signerProbeKind string

const (
	signerList     signerProbeKind = "list"
	signerTraverse signerProbeKind = "traverse"
	signerConnect  signerProbeKind = "connect"
	signerRead     signerProbeKind = "read"
)

type signerTarget struct {
	kind signerProbeKind
	path string
}

// name is the report target: the operation and the path it was tried on.
func (t signerTarget) name() string { return string(t.kind) + ":" + t.path }

func (p signerPaths) targets() []signerTarget {
	var out []signerTarget
	for _, dir := range []string{p.State, p.KeychainDir, p.SocketDir, p.Inbox} {
		out = append(out, signerTarget{signerList, dir}, signerTarget{signerTraverse, dir})
	}
	return append(out, signerTarget{signerConnect, p.Socket}, signerTarget{signerRead, p.Keychain}, signerTarget{signerRead, p.KeychainSecret})
}

// signerDenialTargets are the report targets the session requires.
func signerDenialTargets() []string {
	var out []string
	for _, t := range installedSignerPaths.targets() {
		out = append(out, t.name())
	}
	return out
}

// signerDeployed reports whether the session must prove signer_denial: the
// deploy.env declares the signer, the controller is configured to use one,
// or its root configuration is installed. An unreadable configuration path
// refuses the session rather than skipping the probe.
func signerDeployed(env deploy.Environment, controllerSigner bool, configPath string) (bool, error) {
	if env.Signer() || controllerSigner {
		return true, nil
	}
	_, err := os.Lstat(configPath)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return false, fmt.Errorf("signer configuration %s: %w", configPath, err)
}

// signerOps performs each operation; tests substitute them.
type signerOps struct {
	list, traverse, connect, read func(string) error
}

func liveSignerOps(ctx context.Context) signerOps {
	return signerOps{
		list: func(p string) error { return probeRead(p, true) },
		// Resolving "dir/." needs search permission on dir itself.
		traverse: func(p string) error { _, err := os.Lstat(p + "/."); return err },
		connect: func(p string) error {
			d := net.Dialer{Timeout: 2 * time.Second}
			conn, err := d.DialContext(ctx, "unix", p)
			if err == nil {
				conn.Close()
			}
			return err
		},
		read: func(p string) error { return probeRead(p, false) },
	}
}

type signerRow struct {
	target string
	ok     bool
	detail string
}

// signerDenial tries every operation. Only a permission error (EACCES or
// EPERM) is a denial: success, absence or any other error fails the row.
func signerDenial(paths signerPaths, ops signerOps) []signerRow {
	var out []signerRow
	for _, t := range paths.targets() {
		var err error
		switch t.kind {
		case signerList:
			err = ops.list(t.path)
		case signerTraverse:
			err = ops.traverse(t.path)
		case signerConnect:
			err = ops.connect(t.path)
		case signerRead:
			err = ops.read(t.path)
		}
		if err == nil {
			err = errors.New("operation succeeded")
		}
		out = append(out, signerRow{t.name(), errors.Is(err, os.ErrPermission), fmt.Sprintf("%s error=%v (only EACCES/EPERM counts)", t.kind, err)})
	}
	return out
}

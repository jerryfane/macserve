// Package keyholder is the root-launched credential daemon. It runs as its
// own non-login account and holds the long-lived keys the controller must
// never read: the job receipt Ed25519 key and the GitHub App RSA key. The
// controller asks it, over a Unix socket whose peer must be the controller
// UID, to mint short-lived per-repository installation tokens and to sign
// receipts. Every receipt requires the root worker's build seal; a release
// receipt additionally requires the root-owned release scope and the
// keyholder's own GitHub check of the repository, default-branch head and
// commit tree. It is class B: only the root binary runs it, and the
// controller links only its Client.
package keyholder

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

const maxConfigBytes = 1 << 20

// Config is the root-owned keyholder configuration (keyholder.json).
type Config struct {
	KeyholderUID  uint32 `json:"keyholder_uid"`
	KeyholderGID  uint32 `json:"keyholder_gid"`
	RPCGID        uint32 `json:"rpc_gid"`
	ControllerUID uint32 `json:"controller_uid"`
	JobUID        uint32 `json:"job_uid"`
	JobGID        uint32 `json:"job_gid"`
	// StateDir is the keyholder's private 0700 home: secrets/ holds the
	// receipt and GitHub App keys, receipts/ the immutable full receipt
	// manifests, release/ the verified release provenance per job.
	StateDir string `json:"state_dir"`
	// Socket is the RPC socket, in a directory owned by the keyholder and
	// the RPC group, mode 0750.
	Socket string `json:"socket"`
	// ControllerConfig is the root-owned controller.json whose receipt and
	// github sections name the keys, the service identity and the
	// repository policy (pinned IDs and owners) tokens are minted for.
	ControllerConfig string `json:"controller_config"`
	// ReleaseScopeFile is the root-owned release scope; absent, every
	// release receipt is refused.
	ReleaseScopeFile string `json:"release_scope_file"`
	// SealKeys pins the root worker's build seal Ed25519 public keys,
	// base64 by key ID.
	SealKeys map[string]string `json:"seal_keys"`
}

var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

func cleanAbsolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/" && !strings.ContainsRune(path, 0)
}

func decodeStrict(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("trailing data")
	}
	return nil
}

func readBounded(path string, max int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, max)
	}
	return data, nil
}

// LoadConfig reads and validates a keyholder configuration file.
func LoadConfig(path string) (Config, error) {
	var c Config
	raw, err := readBounded(path, maxConfigBytes)
	if err != nil {
		return c, err
	}
	if err := decodeStrict(raw, &c); err != nil {
		return c, fmt.Errorf("keyholder config: %w", err)
	}
	return c, c.Validate()
}

// Validate checks identities are distinct, paths are clean and the seal
// keys are Ed25519 public keys.
func (c Config) Validate() error {
	ids := []uint32{c.KeyholderUID, c.ControllerUID, c.JobUID}
	if slices.Contains(ids, 0) || c.KeyholderUID == c.ControllerUID || c.KeyholderUID == c.JobUID || c.ControllerUID == c.JobUID {
		return errors.New("keyholder config: keyholder, controller and job UIDs must be distinct non-root accounts")
	}
	gids := []uint32{c.KeyholderGID, c.RPCGID, c.JobGID}
	if slices.Contains(gids, 0) || slices.Contains(gids, 20) || c.KeyholderGID == c.RPCGID || c.KeyholderGID == c.JobGID || c.RPCGID == c.JobGID {
		return errors.New("keyholder config: keyholder, RPC and job GIDs must be distinct dedicated groups")
	}
	for name, path := range map[string]string{"state_dir": c.StateDir, "socket": c.Socket, "controller_config": c.ControllerConfig, "release_scope_file": c.ReleaseScopeFile} {
		if !cleanAbsolute(path) {
			return fmt.Errorf("keyholder config: %s must be a clean absolute path", name)
		}
	}
	if _, err := c.SealPublicKeys(); err != nil {
		return err
	}
	return nil
}

// SealPublicKeys decodes the pinned worker seal keys; at least one is
// required.
func (c Config) SealPublicKeys() (map[string]ed25519.PublicKey, error) {
	if len(c.SealKeys) == 0 {
		return nil, errors.New("keyholder config: at least one worker seal key is required")
	}
	keys := make(map[string]ed25519.PublicKey, len(c.SealKeys))
	for id, encoded := range c.SealKeys {
		raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if !keyIDPattern.MatchString(id) || err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("keyholder config: seal key %q must be a base64 Ed25519 public key", id)
		}
		keys[id] = ed25519.PublicKey(raw)
	}
	return keys, nil
}

// SecretsDir, ReceiptsDir and ReleaseDir are the fixed private
// subdirectories of the state directory.
func (c Config) SecretsDir() string  { return filepath.Join(c.StateDir, "secrets") }
func (c Config) ReceiptsDir() string { return filepath.Join(c.StateDir, "receipts") }
func (c Config) ReleaseDir() string  { return filepath.Join(c.StateDir, "release") }

// ReceiptKeyName and AppKeyName are the key file names under SecretsDir.
const (
	ReceiptKeyName = "receipt-key.pem"
	AppKeyName     = "github-app.pem"
)

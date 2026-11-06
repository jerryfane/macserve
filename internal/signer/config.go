package signer

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

// Config is the root-owned signer configuration (signer.json).
type Config struct {
	SignerUID     uint32 `json:"signer_uid"`
	SignerGID     uint32 `json:"signer_gid"`
	RPCGID        uint32 `json:"rpc_gid"`
	ControllerUID uint32 `json:"controller_uid"`
	JobUID        uint32 `json:"job_uid"`
	JobGID        uint32 `json:"job_gid"`
	// StateDir is the signer's private 0700 home and state directory.
	StateDir string `json:"state_dir"`
	// Socket is the RPC socket, in a directory owned by the signer and
	// the RPC group, mode 0750.
	Socket string `json:"socket"`
	// Inbox is the controller-owned RPC-group directory holding request
	// inputs, <inbox>/<job id>/{App.xcarchive.tar,signing-manifest.json}.
	Inbox              string `json:"inbox"`
	Keychain           string `json:"keychain"`
	KeychainSecretFile string `json:"keychain_secret_file"`
	// KeyFile holds the signer receipt Ed25519 key, KeyID names it.
	KeyFile string `json:"key_file"`
	KeyID   string `json:"key_id"`
	// ReceiptKeys pins the controller's job receipt verification keys,
	// base64 Ed25519 public keys by key ID.
	ReceiptKeys map[string]string `json:"receipt_keys"`
	// PolicyFile is the root-owned admin signing policy.
	PolicyFile string `json:"policy_file"`
}

// Policy is the root-owned admin signing policy: the Apple Distribution
// identity by certificate SHA-1 and, per allowed app or app extension
// bundle identifier, its App Store profile and required entitlements.
type Policy struct {
	IdentitySHA1 string               `json:"identity_sha1"`
	Apps         map[string]AppPolicy `json:"apps"`
}

// AppPolicy is one allowed bundle's profile, team and required entitlement
// keys.
type AppPolicy struct {
	ProfilePath          string   `json:"profile_path"`
	TeamID               string   `json:"team_id"`
	RequiredEntitlements []string `json:"required_entitlements"`
}

var (
	sha1Pattern     = regexp.MustCompile(`^[0-9A-Fa-f]{40}$`)
	teamPattern     = regexp.MustCompile(`^[A-Z0-9]{10}$`)
	keyIDPattern    = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	bundleIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,254}$`)
)

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

func cleanAbsolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/" && toolPathPattern.MatchString(path)
}

// LoadConfig reads and validates a signer configuration file.
func LoadConfig(path string) (Config, error) {
	var c Config
	raw, err := readBounded(path, maxConfigBytes)
	if err != nil {
		return c, err
	}
	if err := decodeStrict(raw, &c); err != nil {
		return c, fmt.Errorf("signer config: %w", err)
	}
	return c, c.Validate()
}

// Validate checks identities are distinct and paths are clean.
func (c Config) Validate() error {
	ids := []uint32{c.SignerUID, c.ControllerUID, c.JobUID}
	if slices.Contains(ids, 0) || c.SignerUID == c.ControllerUID || c.SignerUID == c.JobUID || c.ControllerUID == c.JobUID {
		return errors.New("signer config: signer, controller and job UIDs must be distinct non-root accounts")
	}
	gids := []uint32{c.SignerGID, c.RPCGID, c.JobGID}
	if slices.Contains(gids, 0) || slices.Contains(gids, 20) || c.SignerGID == c.RPCGID || c.SignerGID == c.JobGID || c.RPCGID == c.JobGID {
		return errors.New("signer config: signer, RPC and job GIDs must be distinct dedicated groups")
	}
	for name, path := range map[string]string{"state_dir": c.StateDir, "socket": c.Socket, "inbox": c.Inbox, "keychain": c.Keychain, "keychain_secret_file": c.KeychainSecretFile, "key_file": c.KeyFile, "policy_file": c.PolicyFile} {
		if !cleanAbsolute(path) {
			return fmt.Errorf("signer config: %s must be a clean absolute path", name)
		}
	}
	for name, path := range map[string]string{"keychain": c.Keychain, "keychain_secret_file": c.KeychainSecretFile, "key_file": c.KeyFile} {
		if !strings.HasPrefix(path, c.StateDir+"/") {
			return fmt.Errorf("signer config: %s must be below state_dir", name)
		}
	}
	if strings.HasPrefix(c.Socket, c.StateDir+"/") || strings.HasPrefix(c.Inbox, c.StateDir+"/") || strings.HasPrefix(c.Socket, c.Inbox+"/") {
		return errors.New("signer config: socket and inbox must be outside state_dir and each other")
	}
	if !keyIDPattern.MatchString(c.KeyID) {
		return errors.New("signer config: key_id")
	}
	if _, err := c.ReceiptPublicKeys(); err != nil {
		return err
	}
	return nil
}

// ReceiptPublicKeys decodes the pinned controller receipt keys.
func (c Config) ReceiptPublicKeys() (map[string]ed25519.PublicKey, error) {
	if len(c.ReceiptKeys) == 0 {
		return nil, errors.New("signer config: receipt_keys pins no key")
	}
	keys := make(map[string]ed25519.PublicKey, len(c.ReceiptKeys))
	for id, encoded := range c.ReceiptKeys {
		raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if !keyIDPattern.MatchString(id) || err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("signer config: receipt key %q", id)
		}
		keys[id] = ed25519.PublicKey(raw)
	}
	return keys, nil
}

// LoadPolicy reads and validates the admin signing policy.
func LoadPolicy(path string) (Policy, error) {
	var p Policy
	raw, err := readBounded(path, maxConfigBytes)
	if err != nil {
		return p, err
	}
	if err := decodeStrict(raw, &p); err != nil {
		return p, fmt.Errorf("signer policy: %w", err)
	}
	return p, p.Validate()
}

// Validate checks the identity, profile paths, team identifiers and
// required entitlement keys.
func (p Policy) Validate() error {
	if !sha1Pattern.MatchString(p.IdentitySHA1) {
		return errors.New("signer policy: identity_sha1 must be 40 hex digits")
	}
	if len(p.Apps) == 0 {
		return errors.New("signer policy: no apps")
	}
	for id, app := range p.Apps {
		if !bundleIDPattern.MatchString(id) || !cleanAbsolute(app.ProfilePath) || !teamPattern.MatchString(app.TeamID) {
			return fmt.Errorf("signer policy: app %q", id)
		}
		for _, key := range app.RequiredEntitlements {
			if key == "" || len(key) > 256 {
				return fmt.Errorf("signer policy: app %q required entitlement", id)
			}
		}
	}
	return nil
}

// Identity is the configured identity in codesign's upper-case form.
func (p Policy) Identity() string { return strings.ToUpper(p.IdentitySHA1) }

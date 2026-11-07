package deploy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"time"

	"github.com/jerryfane/macserve/internal/controllerconfig"
	"github.com/jerryfane/macserve/internal/signer"
)

// The code signer's fixed account, groups and paths. Owners, modes and the
// account policy are those of assets/create-users.sh, which creates them.
const (
	SignerAccount = "_macserve_sign"
	SignRPCGroup  = "_macserve_signrpc"
	// Signer IDs are macOS system IDs, below every service/job/owner ID (>=501).
	SignerMinID = 200
	SignerMaxID = 499

	SignerConfigPath   = Prefix + "/config/signer.json"
	SignerPolicyPath   = Prefix + "/config/signer-policy.json"
	SignerProfilesDir  = Prefix + "/signer-profiles"
	SignerStateDir     = Prefix + "/var/signer"
	SignerKeychainDir  = SignerStateDir + "/keychain"
	SignerKeychain     = SignerKeychainDir + "/signing.keychain-db"
	SignerKeychainPass = SignerKeychainDir + "/keychain.secret"
	SignerKeyDir       = SignerStateDir + "/key"
	SignerKeyFile      = SignerKeyDir + "/signer-receipt.key"
	SignerWorkDir      = SignerStateDir + "/work"
	SignerLogDir       = SignerStateDir + "/log"
	SignerSocketDir    = Prefix + "/var/signer-run"
	SignerSocket       = SignerSocketDir + "/signer.sock"
	SignerInbox        = Prefix + "/var/signer-inbox"
	SignerPlist        = "/Library/LaunchDaemons/org.macserve.signer.plist"
)

// Signer reports whether the environment deploys the code signer.
func (e Environment) Signer() bool { return e.SignerUID != 0 }

// signerConfig is the signer.json deploy-install renders: every path is the
// fixed layout and the controller's job receipt key is the only pinned key.
func signerConfig(e Environment, hostID, receiptKeyID, receiptPublicKey string) signer.Config {
	return signer.Config{
		SignerUID: e.SignerUID, SignerGID: e.SignerGID, RPCGID: e.SignRPCGID,
		ControllerUID: e.ControllerUID, JobUID: e.JobUID, JobGID: e.JobGID,
		StateDir: SignerStateDir, Socket: SignerSocket, Inbox: SignerInbox,
		Keychain: SignerKeychain, KeychainSecretFile: SignerKeychainPass, KeyFile: SignerKeyFile,
		KeyID:       "macserve-signer-" + hostID,
		ReceiptKeys: map[string]string{receiptKeyID: receiptPublicKey},
		PolicyFile:  SignerPolicyPath,
	}
}

// signerArgs are the create-users.sh options that add the signer.
func signerArgs(e Environment) []string {
	if !e.Signer() {
		return nil
	}
	u := func(n uint32) string { return strconv.FormatUint(uint64(n), 10) }
	return []string{"--signer-uid", u(e.SignerUID), "--signer-gid", u(e.SignerGID), "--signrpc-gid", u(e.SignRPCGID)}
}

// signerInitCommand runs signer-init as the signer account. It creates the
// signer receipt key, the keychain secret and the empty keychain.
var signerInitCommand = []string{"/usr/bin/sudo", "-n", "-u", SignerAccount, Prefix + "/bin/macserve", "signer-init", "--config", SignerConfigPath}

// runSignerInit runs signer-init and returns the controller.json "signer"
// section built from its one-line {"key_id","public_key"} result.
func runSignerInit(stderr io.Writer, e Environment) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, signerInitCommand[0], signerInitCommand[1:]...)
	cmd.Dir = "/"
	cmd.Env = nativeEnv()
	var stdout bytes.Buffer
	cmd.Stdout, cmd.Stderr = &limitedWriter{w: &stdout, n: 4096}, stderr
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("signer-init failed: %w", err)
	}
	return signerSection(stdout.Bytes(), e)
}

// signerSection parses signer-init's output strictly and returns the
// controller.json "signer" section that pins its key.
func signerSection(output []byte, e Environment) ([]byte, error) {
	var result signer.InitResult
	d := json.NewDecoder(bytes.NewReader(output))
	d.DisallowUnknownFields()
	if err := d.Decode(&result); err != nil {
		return nil, fmt.Errorf("signer-init output: %w", err)
	}
	if d.More() || bytes.Count(bytes.TrimSpace(output), []byte("\n")) != 0 {
		return nil, errors.New("signer-init output must be one JSON line")
	}
	key, err := base64.StdEncoding.Strict().DecodeString(result.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize || result.KeyID == "" {
		return nil, errors.New("signer-init output lacks a key_id and an Ed25519 public_key")
	}
	section := struct {
		Signer controllerconfig.SignerConfig `json:"signer"`
	}{controllerconfig.SignerConfig{Socket: SignerSocket, UID: e.SignerUID, RPCGID: e.SignRPCGID, Inbox: SignerInbox, KeyID: result.KeyID, PublicKey: result.PublicKey}}
	return json.Marshal(section)
}

// limitedWriter keeps the first n bytes and fails once exceeded.
type limitedWriter struct {
	w io.Writer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if len(p) > l.n {
		return 0, errors.New("output exceeds limit")
	}
	l.n -= len(p)
	return l.w.Write(p)
}

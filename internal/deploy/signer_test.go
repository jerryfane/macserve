package deploy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/controllerconfig"
	"github.com/jerryfane/macserve/internal/signer"
)

const signerEnvironment = reviewedEnvironment + "SIGNER_UID=401\nSIGNER_GID=401\nSIGNRPC_GID=402\n"

func TestEnvironmentSigner(t *testing.T) {
	e, err := ParseEnvironment([]byte(reviewedEnvironment))
	if err != nil {
		t.Fatal(err)
	}
	if e.Signer() || e.SignerUID != 0 || e.SignerGID != 0 || e.SignRPCGID != 0 {
		t.Fatal("signer deployed without signer IDs")
	}
	e, err = ParseEnvironment([]byte(signerEnvironment))
	if err != nil {
		t.Fatal(err)
	}
	if !e.Signer() || e.SignerUID != 401 || e.SignerGID != 401 || e.SignRPCGID != 402 {
		t.Fatalf("signer IDs %d/%d/%d", e.SignerUID, e.SignerGID, e.SignRPCGID)
	}
	for name, entry := range map[string]string{
		"uid only":         "SIGNER_UID=401\n",
		"missing rpc":      "SIGNER_UID=401\nSIGNER_GID=401\n",
		"empty":            "SIGNER_UID=\nSIGNER_GID=401\nSIGNRPC_GID=402\n",
		"shared groups":    "SIGNER_UID=401\nSIGNER_GID=402\nSIGNRPC_GID=402\n",
		"service range":    "SIGNER_UID=612\nSIGNER_GID=401\nSIGNRPC_GID=402\n",
		"job gid":          "SIGNER_UID=401\nSIGNER_GID=611\nSIGNRPC_GID=402\n",
		"controller gid":   "SIGNER_UID=401\nSIGNER_GID=401\nSIGNRPC_GID=610\n",
		"owner uid":        "SIGNER_UID=501\nSIGNER_GID=401\nSIGNRPC_GID=402\n",
		"apple reserved":   "SIGNER_UID=99\nSIGNER_GID=401\nSIGNRPC_GID=402\n",
		"root":             "SIGNER_UID=0\nSIGNER_GID=401\nSIGNRPC_GID=402\n",
		"leading zero":     "SIGNER_UID=0401\nSIGNER_GID=401\nSIGNRPC_GID=402\n",
		"expansion":        "SIGNER_UID=$(id -u)\nSIGNER_GID=401\nSIGNRPC_GID=402\n",
		"duplicate":        "SIGNER_UID=401\nSIGNER_GID=401\nSIGNRPC_GID=402\nSIGNER_UID=403\n",
		"misspelled group": "SIGNER_UID=401\nSIGNER_GID=401\nSIGN_RPC_GID=402\n",
	} {
		if _, err := ParseEnvironment([]byte(reviewedEnvironment + entry)); err == nil {
			t.Fatalf("%s: unsafe signer identity accepted", name)
		}
	}
}

func TestMaterialSigner(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	plain, assets := fixture(t)
	rendered, err := renderAssets(plain, assets)
	if err != nil {
		t.Fatal(err)
	}
	m, err := makeMaterial(plain, []byte(reviewedEnvironment), rendered, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range m.Files {
		if f.Path == SignerConfigPath || f.Path == SignerPlist {
			t.Fatalf("deployment without signer IDs installs %s", f.Path)
		}
	}
	e, err := ParseEnvironment([]byte(signerEnvironment))
	if err != nil {
		t.Fatal(err)
	}
	if m, err = makeMaterial(e, []byte(signerEnvironment), rendered, now); err != nil {
		t.Fatal(err)
	}
	files := map[string]File{}
	for _, f := range m.Files {
		files[f.Path] = f
	}
	plist, ok := files[SignerPlist]
	if !ok || plist.UID != 0 || plist.GID != 0 || plist.Mode != 0644 || !bytes.Equal(plist.Data, rendered["launchd/org.macserve.signer.plist.tmpl"]) {
		t.Fatal("signer plist is not the rendered root-owned template")
	}
	if err := disabledPlist(plist.Data); err != nil {
		t.Fatal(err)
	}
	config, ok := files[SignerConfigPath]
	if !ok || config.UID != 0 || config.GID != 0 || config.Mode != 0644 {
		t.Fatal("signer.json is not root:wheel 0644")
	}
	stage := filepath.Join(t.TempDir(), "signer.json")
	if err := os.WriteFile(stage, config.Data, 0600); err != nil {
		t.Fatal(err)
	}
	c, err := signer.LoadConfig(stage)
	if err != nil {
		t.Fatal(err)
	}
	var pins map[string]string
	if err := json.Unmarshal(files[Prefix+"/config/deployment-pins.json"].Data, &pins); err != nil {
		t.Fatal(err)
	}
	want := signer.Config{
		SignerUID: 401, SignerGID: 401, RPCGID: 402, ControllerUID: 610, JobUID: 611, JobGID: 611,
		StateDir: "/Library/macserve/var/signer", Socket: "/Library/macserve/var/signer-run/signer.sock", Inbox: "/Library/macserve/var/signer-inbox",
		Keychain: "/Library/macserve/var/signer/keychain/signing.keychain-db", KeychainSecretFile: "/Library/macserve/var/signer/keychain/keychain.secret",
		KeyFile: "/Library/macserve/var/signer/key/signer-receipt.key", KeyID: "macserve-signer-" + pins["host_id"],
		ReceiptKeys: map[string]string{pins["receipt_key_id"]: m.ReceiptPublicKey}, PolicyFile: "/Library/macserve/config/signer-policy.json",
	}
	got, _ := json.Marshal(c)
	expected, _ := json.Marshal(want)
	if !bytes.Equal(got, expected) {
		t.Fatalf("signer.json\n got %s\nwant %s", got, expected)
	}
	if strings.Contains(string(config.Data), m.Token) {
		t.Fatal("signer.json carries the API token")
	}
}

func TestSignerSection(t *testing.T) {
	e, err := ParseEnvironment([]byte(signerEnvironment))
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString(pub)
	out, err := signerSection([]byte(`{"key_id":"macserve-signer-abc","public_key":"`+key+`"}`+"\n"), e)
	if err != nil {
		t.Fatal(err)
	}
	var section struct {
		Signer controllerconfig.SignerConfig `json:"signer"`
	}
	d := json.NewDecoder(bytes.NewReader(out))
	d.DisallowUnknownFields()
	if err := d.Decode(&section); err != nil {
		t.Fatal(err)
	}
	if section.Signer != (controllerconfig.SignerConfig{Socket: SignerSocket, UID: 401, RPCGID: 402, Inbox: SignerInbox, KeyID: "macserve-signer-abc", PublicKey: key}) {
		t.Fatalf("controller signer section %+v", section.Signer)
	}
	for name, output := range map[string]string{
		"empty":       "",
		"short key":   `{"key_id":"k","public_key":"` + base64.StdEncoding.EncodeToString(pub[:31]) + `"}`,
		"no key id":   `{"key_id":"","public_key":"` + key + `"}`,
		"extra field": `{"key_id":"k","public_key":"` + key + `","secret":"x"}`,
		"two lines":   `{"key_id":"k","public_key":"` + key + `"}` + "\n" + `{"key_id":"k","public_key":"` + key + `"}`,
		"trailing":    `{"key_id":"k","public_key":"` + key + `"} trailing`,
		"not base64":  `{"key_id":"k","public_key":"not base64!"}`,
	} {
		if _, err := signerSection([]byte(output), e); err == nil {
			t.Fatalf("%s: malformed signer-init output accepted", name)
		}
	}
	if !slices.Equal(signerInitCommand, []string{"/usr/bin/sudo", "-n", "-u", "_macserve_sign", "/Library/macserve/bin/macserve", "signer-init", "--config", "/Library/macserve/config/signer.json"}) {
		t.Fatalf("signer-init command %q", signerInitCommand)
	}
}

// deploy-install's create-users options must be accepted by the reviewed
// script; the plan mode inspects nothing.
func TestSignerArgsMatchCreateUsers(t *testing.T) {
	e, err := ParseEnvironment([]byte(signerEnvironment))
	if err != nil {
		t.Fatal(err)
	}
	if args := signerArgs(Environment{}); args != nil {
		t.Fatalf("signer options without a signer: %q", args)
	}
	script, err := filepath.Abs(filepath.Join("..", "..", "assets", "create-users.sh"))
	if err != nil {
		t.Fatal(err)
	}
	args := []string{script, "--controller-user", e.ControllerUser, "--controller-uid", "610", "--controller-gid", "610", "--job-user", e.JobUser, "--job-uid", "611", "--job-gid", "611", "--owner-user", e.OwnerUser, "--owner-uid", "501"}
	cmd := exec.Command("/bin/bash", append(args, signerArgs(e)...)...)
	cmd.Dir = t.TempDir()
	cmd.Env = []string{"PATH=/nonexistent", "HOME=" + cmd.Dir}
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "Create signer _macserve_sign uid=401 primary-group=_macserve_sign gid=401") || !strings.Contains(string(out), "_macserve_signrpc gid=402 with members buildcontroller and _macserve_sign only") {
		t.Fatalf("create-users signer plan: %v: %s", err, out)
	}
}

package deploy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/controllerconfig"
	"github.com/jerryfane/macserve/internal/keyholder"
	"github.com/jerryfane/macserve/internal/workerclient"
)

// preKeyholderEnvironment is a deploy.env written before the keyholder.
var preKeyholderEnvironment = strings.Replace(reviewedEnvironment, "KEYHOLDER_UID=411\nKEYHOLDER_GID=411\nKEYRPC_GID=412\n", "", 1)

func TestEnvironmentKeyholder(t *testing.T) {
	e, err := ParseEnvironment([]byte(preKeyholderEnvironment))
	if err != nil {
		t.Fatal(err)
	}
	if e.Keyholder() || e.KeyholderUID != 0 || e.KeyholderGID != 0 || e.KeyRPCGID != 0 {
		t.Fatal("keyholder IDs without KEYHOLDER_*")
	}
	e, err = ParseEnvironment([]byte(reviewedEnvironment))
	if err != nil {
		t.Fatal(err)
	}
	if !e.Keyholder() || e.KeyholderUID != 411 || e.KeyholderGID != 411 || e.KeyRPCGID != 412 {
		t.Fatalf("keyholder IDs %d/%d/%d", e.KeyholderUID, e.KeyholderGID, e.KeyRPCGID)
	}
	if _, err := ParseEnvironment([]byte(signerEnvironment)); err != nil {
		t.Fatalf("signer and keyholder together: %v", err)
	}
	for name, entry := range map[string]string{
		"uid only":         "KEYHOLDER_UID=411\n",
		"missing rpc":      "KEYHOLDER_UID=411\nKEYHOLDER_GID=411\n",
		"empty":            "KEYHOLDER_UID=\nKEYHOLDER_GID=411\nKEYRPC_GID=412\n",
		"shared groups":    "KEYHOLDER_UID=411\nKEYHOLDER_GID=412\nKEYRPC_GID=412\n",
		"service range":    "KEYHOLDER_UID=612\nKEYHOLDER_GID=411\nKEYRPC_GID=412\n",
		"job gid":          "KEYHOLDER_UID=411\nKEYHOLDER_GID=611\nKEYRPC_GID=412\n",
		"controller gid":   "KEYHOLDER_UID=411\nKEYHOLDER_GID=411\nKEYRPC_GID=610\n",
		"owner uid":        "KEYHOLDER_UID=501\nKEYHOLDER_GID=411\nKEYRPC_GID=412\n",
		"apple reserved":   "KEYHOLDER_UID=99\nKEYHOLDER_GID=411\nKEYRPC_GID=412\n",
		"leading zero":     "KEYHOLDER_UID=0411\nKEYHOLDER_GID=411\nKEYRPC_GID=412\n",
		"expansion":        "KEYHOLDER_UID=$(id -u)\nKEYHOLDER_GID=411\nKEYRPC_GID=412\n",
		"misspelled group": "KEYHOLDER_UID=411\nKEYHOLDER_GID=411\nKEY_RPC_GID=412\n",
		"signer uid":       "SIGNER_UID=411\nSIGNER_GID=401\nSIGNRPC_GID=402\n",
		"signer gid":       "SIGNER_UID=401\nSIGNER_GID=412\nSIGNRPC_GID=402\n",
		"signer rpc gid":   "SIGNER_UID=401\nSIGNER_GID=401\nSIGNRPC_GID=411\n",
		"duplicate":        "KEYHOLDER_UID=413\n",
	} {
		env := reviewedEnvironment + entry
		if name != "signer uid" && name != "signer gid" && name != "signer rpc gid" && name != "duplicate" {
			env = preKeyholderEnvironment + entry
		}
		if _, err := ParseEnvironment([]byte(env)); err == nil {
			t.Fatalf("%s: unsafe keyholder identity accepted", name)
		}
	}
}

func TestInstallRequiresKeyholder(t *testing.T) {
	e, assets := fixture(t)
	rendered, err := renderAssets(e, assets)
	if err != nil {
		t.Fatal(err)
	}
	old, err := ParseEnvironment([]byte(preKeyholderEnvironment))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := makeMaterial(old, []byte(preKeyholderEnvironment), rendered, time.Now()); err == nil || !strings.Contains(err.Error(), "KEYHOLDER_UID") {
		t.Fatalf("material without keyholder IDs: %v", err)
	}
	root := t.TempDir()
	envPath := filepath.Join(root, "deploy.env")
	if err := os.WriteFile(envPath, []byte(preKeyholderEnvironment), 0600); err != nil {
		t.Fatal(err)
	}
	err = Install(Options{EnvironmentPath: envPath, BinaryPath: envPath, SHA256: strings.Repeat("a", 64), ControllerBinaryPath: envPath, ControllerSHA256: strings.Repeat("a", 64), AssetsPath: root}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "KEYHOLDER_UID") {
		t.Fatalf("deploy-install without keyholder IDs: %v", err)
	}
}

// materialFiles renders the reviewed environment's material by path.
func materialFiles(t *testing.T, env string) (Environment, Material, map[string]File) {
	t.Helper()
	_, assets := fixture(t)
	e, err := ParseEnvironment([]byte(env))
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := renderAssets(e, assets)
	if err != nil {
		t.Fatal(err)
	}
	m, err := makeMaterial(e, []byte(env), rendered, time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]File{}
	for _, f := range m.Files {
		files[f.Path] = f
	}
	return e, m, files
}

func decodeFile[T any](t *testing.T, f File) T {
	t.Helper()
	var v T
	d := json.NewDecoder(bytes.NewReader(f.Data))
	d.DisallowUnknownFields()
	if err := d.Decode(&v); err != nil {
		t.Fatalf("%s: %v", f.Path, err)
	}
	return v
}

// TestControllerCannotOpenKeyFiles is the deploy permission model: the
// receipt key (and the App key path connect-github installs) is
// keyholder-owned 0600 under keyholder-owned 0700 directories that
// create-users.sh makes; controller.json only names those paths; no file
// the controller owns holds a private key other than its TLS key; and the
// worker and the keyholder pin the same seal key.
func TestControllerCannotOpenKeyFiles(t *testing.T) {
	e, m, files := materialFiles(t, reviewedEnvironment)
	c := decodeFile[controllerconfig.Config](t, files[ControllerConfigPath])
	if c.Receipt.PrivateKeyFile != KeyholderReceiptKey {
		t.Fatalf("receipt.private_key_file %s", c.Receipt.PrivateKeyFile)
	}
	for _, key := range []string{c.Receipt.PrivateKeyFile, KeyholderAppKey} {
		if !strings.HasPrefix(key, KeyholderStateDir+"/secrets/") || filepath.Dir(key) != KeyholderSecretsDir {
			t.Fatalf("%s is not in the keyholder's secrets directory", key)
		}
		// Every ancestor below Prefix/var is a keyholder-owned 0700
		// directory create-users.sh makes, which the controller cannot
		// traverse; above it, root-owned.
		for dir := filepath.Dir(key); dir != Prefix+"/var"; dir = filepath.Dir(dir) {
			if ancestorOwner(dir, e) != e.KeyholderUID || ancestorOwner(dir, e) == e.ControllerUID {
				t.Fatalf("%s is not keyholder-owned", dir)
			}
		}
	}
	script, err := os.ReadFile(filepath.Join("..", "..", "assets", "create-users.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(script, []byte(`/usr/bin/install -d -o "$keyholder_uid" -g "$keyholder_gid" -m 0700 "$prefix/var/keyholder" "$prefix/var/keyholder/secrets"`)) {
		t.Fatal("create-users.sh does not create the keyholder state and secrets 0700 keyholder-owned")
	}
	receipt, ok := files[KeyholderReceiptKey]
	if !ok || receipt.UID != e.KeyholderUID || receipt.GID != e.KeyholderGID || receipt.Mode != 0600 {
		t.Fatalf("receipt key %+v is not keyholder-owned 0600", receipt)
	}
	if _, ok := files[KeyholderAppKey]; ok {
		t.Fatal("deploy-install fabricated a GitHub App key")
	}
	if c.GitHub != nil {
		t.Fatal("deploy-install wrote a github section")
	}
	if c.Keyholder == nil || *c.Keyholder != (controllerconfig.KeyholderConfig{Socket: KeyholderSocket, UID: 411}) {
		t.Fatalf("controller keyholder section %+v", c.Keyholder)
	}
	for _, f := range m.Files {
		private := bytes.Contains(f.Data, []byte("PRIVATE KEY"))
		if f.UID == e.ControllerUID && private && f.Path != Prefix+"/var/controller/secrets/tls-key.pem" {
			t.Fatalf("controller-owned %s holds a private key", f.Path)
		}
		if strings.HasPrefix(f.Path, Prefix+"/var/controller/") && f.Path != Prefix+"/var/controller/secrets/tls-key.pem" {
			t.Fatalf("unexpected controller file %s", f.Path)
		}
		if private && f.Mode != 0600 {
			t.Fatalf("private key %s mode %v", f.Path, f.Mode)
		}
	}
	// The worker's seal key is root-only, and the keyholder pins exactly
	// its public key under the ID worker.json names.
	seal, ok := files[SealKeyPath]
	if !ok || seal.UID != 0 || seal.GID != 0 || seal.Mode != 0600 {
		t.Fatalf("seal key %+v is not root 0600", seal)
	}
	block, _ := pem.Decode(seal.Data)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatal("seal key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	sealKey, isEd := parsed.(ed25519.PrivateKey)
	if err != nil || !isEd {
		t.Fatalf("seal key is not Ed25519: %v", err)
	}
	stage := t.TempDir()
	for name, path := range map[string]string{"worker.json": Prefix + "/config/worker.json", "keyholder.json": KeyholderConfigPath} {
		if err := os.WriteFile(filepath.Join(stage, name), files[path].Data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	w, err := workerclient.LoadConfig(filepath.Join(stage, "worker.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.LeaseAuthority(); err != nil {
		t.Fatal(err)
	}
	if w.SealKeyFile != SealKeyPath || w.ProfilesFile != ProfilesPath || w.QualificationFile != QualificationPath {
		t.Fatalf("worker.json %+v", w)
	}
	k, err := keyholder.LoadConfig(filepath.Join(stage, "keyholder.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pins map[string]string
	if err := json.Unmarshal(files[Prefix+"/config/deployment-pins.json"].Data, &pins); err != nil {
		t.Fatal(err)
	}
	if w.SealKeyID != SealKeyID(pins["host_id"]) {
		t.Fatalf("seal key ID %s", w.SealKeyID)
	}
	want := KeyholderConfig(e, w.SealKeyID, base64.StdEncoding.EncodeToString(sealKey.Public().(ed25519.PublicKey)))
	got, _ := json.Marshal(k)
	expected, _ := json.Marshal(want)
	if !bytes.Equal(got, expected) || len(k.SealKeys) != 1 {
		t.Fatalf("keyholder.json\n got %s\nwant %s", got, expected)
	}
	if k.SecretsDir() != KeyholderSecretsDir || k.ReceiptsDir() != KeyholderReceiptsDir || k.ReleaseDir() != KeyholderReleaseDir {
		t.Fatal("keyholder.json state layout differs from create-users.sh")
	}
	// The receipt key the keyholder holds is the one the pins publish.
	block, _ = pem.Decode(receipt.Data)
	parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if base64.StdEncoding.EncodeToString(parsed.(ed25519.PrivateKey).Public().(ed25519.PublicKey)) != pins["receipt_public_key"] {
		t.Fatal("deployment-pins.json does not publish the keyholder's receipt key")
	}
	for path, f := range map[string]File{KeyholderConfigPath: files[KeyholderConfigPath], KeyholderPlist: files[KeyholderPlist]} {
		if f.UID != 0 || f.GID != 0 || f.Mode != 0644 {
			t.Fatalf("%s is not root:wheel 0644", path)
		}
	}
	if _, ok := files[ReleaseScopePath]; ok {
		t.Fatal("deploy-install wrote the owner's release scope")
	}
}

func TestKeyholderPlistRendered(t *testing.T) {
	_, assets := fixture(t)
	_, _, files := materialFiles(t, reviewedEnvironment)
	if !bytes.Equal(files[KeyholderPlist].Data, assets["launchd/org.macserve.keyholder.plist.tmpl"]) {
		t.Fatal("keyholder plist is not the reviewed template")
	}
	if err := disabledPlist(files[KeyholderPlist].Data); err != nil {
		t.Fatal(err)
	}
}

func TestAncestorOwner(t *testing.T) {
	e, err := ParseEnvironment([]byte(reviewedEnvironment))
	if err != nil {
		t.Fatal(err)
	}
	for dir, want := range map[string]uint32{
		Prefix:                             0,
		Prefix + "/var":                    0,
		Prefix + "/var/broker":             0,
		Prefix + "/var/controller":         610,
		Prefix + "/var/controller/secrets": 610,
		KeyholderStateDir:                  411,
		KeyholderSecretsDir:                411,
		KeyholderSocketDir:                 0,
		Prefix + "/var/keyholderx":         0,
	} {
		if got := ancestorOwner(dir, e); got != want {
			t.Errorf("%s: owner %d, want %d", dir, got, want)
		}
	}
}

func TestPickKeyholderIDs(t *testing.T) {
	uid, gid, rpc, err := PickKeyholderIDs(map[int64]bool{})
	if err != nil || uid != 499 || gid != 499 || rpc != 498 {
		t.Fatalf("%d %d %d %v", uid, gid, rpc, err)
	}
	uid, gid, rpc, err = PickKeyholderIDs(map[int64]bool{499: true, 497: true})
	if err != nil || uid != 498 || gid != 498 || rpc != 496 {
		t.Fatalf("taken IDs not skipped: %d %d %d %v", uid, gid, rpc, err)
	}
	full := map[int64]bool{}
	for id := int64(SignerMinID); id <= SignerMaxID; id++ {
		full[id] = true
	}
	delete(full, 300)
	if _, _, _, err := PickKeyholderIDs(full); err == nil {
		t.Fatal("one free system ID accepted")
	}
	e, err := ParseEnvironment([]byte(signerEnvironment))
	if err != nil {
		t.Fatal(err)
	}
	taken := e.TakenIDs()
	for _, id := range []int64{610, 611, 501, 401, 402, 411, 412} {
		if !taken[id] {
			t.Errorf("TakenIDs lacks %d", id)
		}
	}
	lines := KeyholderEnvironmentLines(499, 499, 498)
	if parsed, err := ParseEnvironment([]byte(preKeyholderEnvironment + lines)); err != nil || parsed.KeyholderUID != 499 || parsed.KeyRPCGID != 498 {
		t.Fatalf("environment lines %q: %+v %v", lines, parsed, err)
	}
}

func TestParseDirectoryListFailsClosed(t *testing.T) {
	records, err := ParseDirectoryList("root 0\n\njdoe   501\n_www -2\n")
	if err != nil || len(records) != 3 || records[1] != (DirectoryRecord{Name: "jdoe", ID: 501}) || records[2].ID != -2 {
		t.Fatalf("%+v %v", records, err)
	}
	for _, bad := range []string{"two words 5\n", "name 5 6\n", "name\n", "name x\n", "name 1.5\n"} {
		if _, err := ParseDirectoryList(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

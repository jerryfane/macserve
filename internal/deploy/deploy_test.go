package deploy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/controller"
	"github.com/jerryfane/macserve/internal/maintenance"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/workerclient"
)

const reviewedEnvironment = `CONTROLLER_USER=buildcontroller
CONTROLLER_UID=610
CONTROLLER_GID=610
JOB_USER=buildjob
JOB_UID=611
JOB_GID=611
OWNER_USER=operatorowner
OWNER_UID=501
TAILNET_IP=100.64.0.10
PORT=9443
PROTECTED_PORTS=22,9443
HOST_ADDRESSES=127.0.0.1,::1,100.64.0.10,192.0.2.10
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
REPOSITORIES=example-org/example-app:12345
`

func fixture(t *testing.T) (Environment, map[string][]byte) {
	t.Helper()
	e, err := ParseEnvironment([]byte(reviewedEnvironment))
	if err != nil {
		t.Fatal(err)
	}
	assets := map[string][]byte{}
	for _, name := range assetNames {
		b, err := os.ReadFile(filepath.Join("..", "..", "assets", name))
		if err != nil {
			t.Fatal(err)
		}
		assets[name] = b
	}
	return e, assets
}
func TestEnvironmentRejectsAmbiguousAndExecutableData(t *testing.T) {
	for name, pair := range map[string][2]string{
		"shell expansion":   {"buildcontroller", "$(touch /tmp/injected)"},
		"xml injection":     {"buildcontroller", "owner</string>"},
		"duplicate key":     {"PORT=9443", "PORT=9443\nPORT=9443"},
		"unknown key":       {"PORT=9443", "PORT=9443\nPATH=/bin"},
		"uid alias":         {"CONTROLLER_UID=610", "CONTROLLER_UID=0610"},
		"uid collision":     {"JOB_UID=611", "JOB_UID=610"},
		"gid collision":     {"JOB_GID=611", "JOB_GID=610"},
		"account collision": {"JOB_USER=buildjob", "JOB_USER=buildcontroller"},
		"address alias":     {"TAILNET_IP=100.64.0.10", "TAILNET_IP=::ffff:100.64.0.10"},
		"public listener":   {"TAILNET_IP=100.64.0.10", "TAILNET_IP=192.0.2.10"},
		"unprotected API":   {"PROTECTED_PORTS=22,9443", "PROTECTED_PORTS=22"},
		"missing host":      {"HOST_ADDRESSES=127.0.0.1,::1,100.64.0.10,192.0.2.10", "HOST_ADDRESSES=127.0.0.1"},
		"repo alias":        {"example-org/example-app:12345", "Example-Org/example-app:12345"},
		"repo ID collision": {"example-org/example-app:12345", "example-org/example-app:12345,example-org/another-app:12345"},
		"imprecise repo ID": {"example-org/example-app:12345", "example-org/example-app:9007199254740992"},
		"stale path marker": {"/Applications/Xcode.app/Contents/Developer", "/{{.DeveloperDir}}"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseEnvironment([]byte(strings.Replace(reviewedEnvironment, pair[0], pair[1], 1))); err == nil {
				t.Fatal("accepted ambiguous or executable reviewed data")
			}
		})
	}
	if _, err := ParseEnvironment(bytes.Repeat([]byte("#"), MaxEnvironment+1)); err == nil {
		t.Fatal("accepted oversized input")
	}
	path := filepath.Join(t.TempDir(), "env")
	if err := os.WriteFile(path, []byte(reviewedEnvironment), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEnvironment(path); err != nil {
		t.Fatal(err)
	}
	alias := path + "-link"
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEnvironment(alias); err == nil {
		t.Fatal("accepted symlink environment")
	}
}

func TestEnvironmentFirewallPolicy(t *testing.T) {
	options := "PF_ANCHOR=com.apple/build-service\nCOEXISTING_ANCHORS=com.apple/guest-b,com.apple/guest-a\nCOEXISTING_SERVICES=com.example.router-b,com.example.router-a\nTOLERATED_TRANSLATION_ANCHORS=com.apple/guest-a\nAPPROVED_GUEST_SUBNETS=172.20.40.128/25\n"
	e, err := ParseEnvironment([]byte(reviewedEnvironment + options))
	if err != nil {
		t.Fatal(err)
	}
	_, assets := fixture(t)
	rendered, err := renderAssets(e, assets)
	if err != nil {
		t.Fatal(err)
	}
	material, err := makeMaterial(e, []byte(reviewedEnvironment+options), rendered, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var config maintenance.Config
	for _, file := range material.Files {
		if file.Path == Prefix+"/config/maintenance.json" {
			if err := json.Unmarshal(file.Data, &config); err != nil {
				t.Fatal(err)
			}
		}
	}
	if config.PFAnchor != "com.apple/build-service" ||
		!slices.Equal(config.CoexistingAnchors, []string{"com.apple/guest-a", "com.apple/guest-b"}) ||
		!slices.Equal(config.CoexistingServices, []string{"com.example.router-a", "com.example.router-b"}) ||
		!slices.Equal(config.ToleratedTranslationAnchors, []string{"com.apple/guest-a"}) ||
		!slices.Equal(config.ApprovedGuestSubnets, []string{"172.20.40.128/25"}) {
		t.Fatalf("installed maintenance policy differs from reviewed environment: %+v", config)
	}
	for _, suffix := range []string{"", "PF_ANCHOR=\nCOEXISTING_ANCHORS=\nCOEXISTING_SERVICES=\nTOLERATED_TRANSLATION_ANCHORS=\nAPPROVED_GUEST_SUBNETS=\n"} {
		defaults, err := ParseEnvironment([]byte(reviewedEnvironment + suffix))
		if err != nil || defaults.PFAnchor != maintenance.DefaultPFAnchor || len(defaults.CoexistingAnchors)+len(defaults.CoexistingServices)+len(defaults.ToleratedTranslationAnchors)+len(defaults.ApprovedGuestSubnets) != 0 {
			t.Fatalf("omitted/empty optional policy: %+v %v", defaults, err)
		}
	}
	for _, suffix := range []string{
		"PF_ANCHOR=com.apple/*\n",
		"PF_ANCHOR=\nPF_ANCHOR=com.apple/service\n",
		"COEXISTING_ANCHORS=com.apple/macserve\n",
		"COEXISTING_ANCHORS=com.apple/macserve/child\n",
		"COEXISTING_ANCHORS=com.apple/peer,com.apple/peer\n",
		"COEXISTING_SERVICES=system/com.example.router\n",
		"COEXISTING_SERVICES=com.example.router,\n",
		"TOLERATED_TRANSLATION_ANCHORS=com.apple/guest-a\n",
		"APPROVED_GUEST_SUBNETS=172.20.40.128/25\n",
		"TOLERATED_TRANSLATION_ANCHORS=com.apple/guest-a\nAPPROVED_GUEST_SUBNETS=172.20.40.129/25\n",
		"TOLERATED_TRANSLATION_ANCHORS=com.apple/guest-a\nAPPROVED_GUEST_SUBNETS=127.0.0.0/8\n",
	} {
		if _, err := ParseEnvironment([]byte(reviewedEnvironment + suffix)); err == nil {
			t.Fatalf("unsafe firewall policy accepted: %q", suffix)
		}
	}
}
func TestRenderRejectsStaleMarkersAndActivation(t *testing.T) {
	e, assets := fixture(t)
	if _, err := renderAssets(e, assets); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"{{.StaleUID}}", "{{.JobUID}", "orphan }}", "{{.JobUID}}{{.Unknown}}"} {
		if _, err := Render([]byte(source), map[string]string{"{{.JobUID}}": "611"}); err == nil {
			t.Fatalf("accepted stale template: %q", source)
		}
	}
	name := "launchd/org.macserve.controller.plist.tmpl"
	assets[name] = bytes.Replace(assets[name], []byte("<key>Disabled</key><true/>"), []byte("<key>Disabled</key><false/>"), 1)
	if _, err := renderAssets(e, assets); err == nil {
		t.Fatal("accepted enabled launchd template")
	}
}
func TestMaterialHasValidCryptoConsumerConfigsAndPrivateIntent(t *testing.T) {
	e, assets := fixture(t)
	rendered, err := renderAssets(e, assets)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	m, err := makeMaterial(e, []byte(reviewedEnvironment), rendered, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Token) != 64 {
		t.Fatal("token must encode 256 random bits")
	}
	files := map[string]File{}
	stage := t.TempDir()
	for _, f := range m.Files {
		if _, ok := files[f.Path]; ok {
			t.Fatal("duplicate installation target")
		}
		files[f.Path] = f
		if bytes.Contains(f.Data, []byte(m.Token)) {
			t.Fatalf("plaintext token persisted at %s", f.Path)
		}
		if strings.Contains(f.Path, "/secrets/") {
			if f.Mode != 0600 || f.UID != e.ControllerUID || f.GID != e.ControllerGID {
				t.Fatal("private key is not controller-private")
			}
		} else if f.UID != 0 || f.GID != 0 || f.Mode != 0644 {
			t.Fatal("public config is not root-controlled")
		}
		if err := os.WriteFile(filepath.Join(stage, filepath.Base(f.Path)), f.Data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	c, err := controller.LoadConfig(filepath.Join(stage, "controller.json"))
	if err != nil {
		t.Fatal(err)
	}
	if c.GitHub != nil || c.Principals[0].TokenSHA256 != digest([]byte(m.Token)) || c.Receipt.Repositories["example-org/example-app"] != 12345 {
		t.Fatal("incorrect API staging policy")
	}
	if c.PolicySHA256 != digest(files[Prefix+"/config/pf-anchor.conf"].Data) {
		t.Fatal("policy hash does not bind rendered PF")
	}
	if _, err := workerclient.LoadConfig(filepath.Join(stage, "worker.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := profiles.Load(filepath.Join(stage, "profiles.json")); err != nil {
		t.Fatal(err)
	}
	var mc maintenance.Config
	if err := json.Unmarshal(files[Prefix+"/config/maintenance.json"].Data, &mc); err != nil {
		t.Fatal(err)
	}
	if mc.PFPolicyFile != Prefix+"/config/pf-anchor.conf" || mc.ControllerConfig != Prefix+"/config/controller.json" {
		t.Fatal("maintenance observes different deployment")
	}
	certData := files[Prefix+"/config/tls-cert.pem"].Data
	tlsData := files[c.TLSKey].Data
	pair, err := tls.X509KeyPair(certData, tlsData)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: e.TailnetIP, CurrentTime: now}); err != nil {
		t.Fatal(err)
	}
	if digest(cert.Raw) != m.TLSFingerprint {
		t.Fatal("incorrect public TLS fingerprint")
	}
	block, _ := pem.Decode(files[c.Receipt.PrivateKeyFile].Data)
	if block == nil {
		t.Fatal("receipt key not PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	receiptKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		t.Fatal("receipt key not Ed25519")
	}
	pub, err := base64.StdEncoding.DecodeString(m.ReceiptPublicKey)
	if err != nil || !bytes.Equal(receiptKey.Public().(ed25519.PublicKey), pub) {
		t.Fatal("receipt public pin mismatch")
	}
	if bytes.Equal(receiptKey.Public().(ed25519.PublicKey), cert.PublicKey.(ed25519.PublicKey)) {
		t.Fatal("TLS and receipt share key")
	}
	if !ed25519.Verify(pub, []byte("receipt"), ed25519.Sign(receiptKey, []byte("receipt"))) {
		t.Fatal("receipt signature failed")
	}
	if _, ok := files[Prefix+"/config/owner.pause"]; !ok {
		t.Fatal("unqualified deployment is not paused")
	}
	if _, ok := files[mc.QualificationFile]; ok {
		t.Fatal("installer fabricated qualification")
	}
}
func TestBinaryDigestAndCollisionFailClosed(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "binary")
	data := []byte("owned binary fixture")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	var staged bytes.Buffer
	if err := verifyBinary(path, digest(data), &staged); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, staged.Bytes()) {
		t.Fatal("staged digest did not cover copied bytes")
	}
	if err := verifyBinary(path, strings.Repeat("0", 64), nil); err == nil {
		t.Fatal("wrong digest accepted")
	}
	if err := requireAbsent([]string{path}); err == nil {
		t.Fatal("existing deployment target accepted")
	}
	link := filepath.Join(root, "dangling")
	if err := os.Symlink(filepath.Join(root, "missing"), link); err != nil {
		t.Fatal(err)
	}
	if err := requireAbsent([]string{link}); err == nil {
		t.Fatal("dangling target accepted")
	}
}
func TestPlanDoesNotPersistCredentialsOrMutateInputs(t *testing.T) {
	root := t.TempDir()
	envPath := filepath.Join(root, "deploy.env")
	binary := filepath.Join(root, "macserve")
	if err := os.WriteFile(envPath, []byte(reviewedEnvironment), 0600); err != nil {
		t.Fatal(err)
	}
	data := []byte("binary plan fixture")
	if err := os.WriteFile(binary, data, 0600); err != nil {
		t.Fatal(err)
	}
	assets, err := filepath.Abs(filepath.Join("..", "..", "assets"))
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := Install(Options{EnvironmentPath: envPath, BinaryPath: binary, SHA256: digest(data), AssetsPath: assets}, &output, &output); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "API_BEARER_TOKEN=") {
		t.Fatal("plan emitted bearer credential")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatal("plan persisted deployment state")
	}
	if runtime.GOOS != "darwin" || os.Getuid() != 0 || os.Geteuid() != 0 {
		if err := Install(Options{Apply: true}, &output, &output); err == nil {
			t.Fatal("native gate bypassed")
		}
	}
}
func TestBootstrapWrongDigestNeverExecutesBinary(t *testing.T) {
	if _, err := os.Stat("/usr/bin/shasum"); err != nil {
		t.Skip("bootstrap requires shasum")
	}
	root := t.TempDir()
	binary := filepath.Join(root, "untrusted")
	marker := filepath.Join(root, "executed")
	if err := os.WriteFile(binary, []byte("#!/bin/bash\nprintf unsafe > '"+marker+"'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	script, err := filepath.Abs(filepath.Join("..", "..", "assets", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/bash", script, "--env", filepath.Join(root, "unused.env"), "--binary", binary, "--sha256", strings.Repeat("0", 64))
	cmd.Env = []string{"PATH=/usr/bin:/bin", "TMPDIR=" + root}
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("wrong digest bootstrap succeeded")
	}
	if !strings.Contains(string(output), "SHA-256 mismatch") {
		t.Fatalf("unexpected refusal: %s", output)
	}
	if _, err := os.Lstat(marker); !os.IsNotExist(err) {
		t.Fatal("unverified binary executed")
	}
}

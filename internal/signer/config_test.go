package signer

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validConfig(t *testing.T) Config {
	t.Helper()
	public, _, _ := ed25519.GenerateKey(nil)
	return Config{SignerUID: 300, SignerGID: 300, RPCGID: 301, ControllerUID: 299, JobUID: 502, JobGID: 502,
		StateDir: "/Library/macserve/var/signer", Socket: "/Library/macserve/var/signer-run/signer.sock", Inbox: "/Library/macserve/var/signer-inbox",
		Keychain: "/Library/macserve/var/signer/keychain/signing.keychain-db", KeychainSecretFile: "/Library/macserve/var/signer/keychain/keychain.secret",
		KeyFile: "/Library/macserve/var/signer/key/signer-receipt.key", KeyID: "macserve-signer-studio",
		ReceiptKeys: map[string]string{"controller": base64.StdEncoding.EncodeToString(public)}, PolicyFile: "/Library/macserve/config/signer-policy.json"}
}

func TestConfigValidation(t *testing.T) {
	if err := validConfig(t).Validate(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Config){
		"signer is job":         func(c *Config) { c.SignerUID = c.JobUID },
		"rpc group is job's":    func(c *Config) { c.RPCGID = c.JobGID },
		"staff group":           func(c *Config) { c.SignerGID = 20 },
		"keychain outside":      func(c *Config) { c.Keychain = "/tmp/k.keychain-db" },
		"socket in state":       func(c *Config) { c.Socket = c.StateDir + "/s.sock" },
		"relative inbox":        func(c *Config) { c.Inbox = "inbox" },
		"no receipt keys":       func(c *Config) { c.ReceiptKeys = nil },
		"short receipt key":     func(c *Config) { c.ReceiptKeys = map[string]string{"k": "AAAA"} },
		"quoted keychain path":  func(c *Config) { c.Keychain = c.StateDir + "/key chain" },
		"controller is signer":  func(c *Config) { c.ControllerUID = c.SignerUID },
		"signer group is rpc's": func(c *Config) { c.SignerGID = c.RPCGID },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := validConfig(t)
			mutate(&c)
			if err := c.Validate(); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestLoadPolicyStrict(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	good := `{"identity_sha1":"` + strings.Repeat("a", 40) + `","apps":{"com.example.app":{"profile_path":"/Library/macserve/signer-profiles/app.mobileprovision","team_id":"ABCDE12345","required_entitlements":["aps-environment"]}}}`
	if err := os.WriteFile(path, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := LoadPolicy(path)
	if err != nil || p.Identity() != strings.Repeat("A", 40) {
		t.Fatalf("policy %+v %v", p, err)
	}
	for name, body := range map[string]string{
		"unknown key":  strings.Replace(good, `"apps"`, `"extra":1,"apps"`, 1),
		"bad identity": strings.Replace(good, strings.Repeat("a", 40), "abc", 1),
		"bad team":     strings.Replace(good, "ABCDE12345", "abc", 1),
		"relative":     strings.Replace(good, "/Library/macserve/signer-profiles/app.mobileprovision", "app.mobileprovision", 1),
		"no apps":      `{"identity_sha1":"` + strings.Repeat("a", 40) + `","apps":{}}`,
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPolicy(path); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

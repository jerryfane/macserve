package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCLISignVerify runs keygen, sign and verify as the release workflow and
// an administrator do, with a throwaway key.
func TestCLISignVerify(t *testing.T) {
	dir := t.TempDir()
	at := func(name string) string { return filepath.Join(dir, name) }
	cli := func(env map[string]string, args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := run(context.Background(), args, &stdout, &stderr, func(k string) string { return env[k] })
		return code, stdout.String(), stderr.String()
	}

	if code, _, stderr := cli(nil, "keygen", "-seed-out", at("seed"), "-pub-out", at("pub")); code != 0 {
		t.Fatalf("keygen: %d %s", code, stderr)
	}
	if info, err := os.Stat(at("seed")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("seed file: %v %v", info, err)
	}
	seed, _ := os.ReadFile(at("seed"))
	env := map[string]string{SigningKeyEnv: string(bytes.TrimSpace(seed))}

	manifest, err := Encode(goldenManifest())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(at(ManifestAsset), manifest, 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := cli(env, "sign", "-manifest", at(ManifestAsset), "-pub", at("pub"), "-out", at(SignatureAsset)); code != 0 {
		t.Fatalf("sign: %d %s", code, stderr)
	}
	if code, _, stderr := cli(env, "sign", "-manifest", at(ManifestAsset), "-pub", at("pub"), "-out", at(SignatureAsset)); code != 1 || !strings.Contains(stderr, "exists") {
		t.Fatalf("sign over an existing signature: %d %s", code, stderr)
	}

	root, controller := at("macserve"), at("controller")
	sums := goldenManifest()
	if err := os.WriteFile(at("SHA256SUMS"), []byte(sums.Binaries.Macserve.SHA256+"  "+RootAsset+"\n"+sums.Binaries.Controller.SHA256+"  "+ControllerAsset+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := cli(nil, "verify", "-pub", at("pub"), "-manifest", at(ManifestAsset), "-sig", at(SignatureAsset), "-tag", "v0.1.37", "-kind", KindCarry, "-sums", at("SHA256SUMS"))
	if code != 0 || !strings.HasPrefix(stdout, "verified ") || !strings.Contains(stdout, "kind controller-carry base_tag v0.1.36") {
		t.Fatalf("verify: %d %q %s", code, stdout, stderr)
	}

	// Expectation failures.
	if err := os.WriteFile(root, []byte("not the release bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(controller, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"commit":     {"-commit", strings.Repeat("f", 40)},
		"tag":        {"-tag", "v0.1.38"},
		"kind":       {"-kind", KindFull},
		"macserve":   {"-macserve", root},
		"controller": {"-controller", controller},
	} {
		base := []string{"verify", "-pub", at("pub"), "-manifest", at(ManifestAsset), "-sig", at(SignatureAsset)}
		if code, _, stderr := cli(nil, append(base, args...)...); code != 1 {
			t.Errorf("%s: verify exit %d %s", name, code, stderr)
		}
	}

	// A secret that is not the pinned key never signs.
	other := map[string]string{SigningKeyEnv: string(bytes.TrimSpace(EncodeKey(testSeed)))}
	if code, _, stderr := cli(other, "sign", "-manifest", at(ManifestAsset), "-pub", at("pub"), "-out", at("other.sig")); code != 1 || !strings.Contains(stderr, "not the pinned") {
		t.Fatalf("sign with another key: %d %s", code, stderr)
	}
	if code, _, stderr := cli(nil, "sign", "-manifest", at(ManifestAsset), "-pub", at("pub"), "-out", at("none.sig")); code != 1 || !strings.Contains(stderr, "is empty") {
		t.Fatalf("sign without a key: %d %s", code, stderr)
	}
	if code, _, _ := cli(nil, "verify", "-pub", at("pub")); code != 2 {
		t.Fatalf("verify usage: %d", code)
	}
}

// The same path given for -macserve and -controller is checked against both
// signed digests: a file matching only the controller digest is refused.
func TestCLIVerifyChecksBothDigestsForOnePath(t *testing.T) {
	dir := t.TempDir()
	at := func(name string) string { return filepath.Join(dir, name) }
	cli := func(env map[string]string, args ...string) (int, string) {
		var stdout, stderr bytes.Buffer
		code := run(context.Background(), args, &stdout, &stderr, func(k string) string { return env[k] })
		return code, stderr.String()
	}
	if code, stderr := cli(nil, "keygen", "-seed-out", at("seed"), "-pub-out", at("pub")); code != 0 {
		t.Fatalf("keygen: %d %s", code, stderr)
	}
	seed, _ := os.ReadFile(at("seed"))
	env := map[string]string{SigningKeyEnv: string(bytes.TrimSpace(seed))}
	binary := []byte("controller release bytes")
	if err := os.WriteFile(at("controller"), binary, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(binary)
	m := goldenManifest()
	m.Binaries.Controller.SHA256 = hex.EncodeToString(sum[:])
	if m.Binaries.Macserve.SHA256 == m.Binaries.Controller.SHA256 {
		t.Fatal("fixture digests must differ")
	}
	manifest, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(at(ManifestAsset), manifest, 0o644); err != nil {
		t.Fatal(err)
	}
	if code, stderr := cli(env, "sign", "-manifest", at(ManifestAsset), "-pub", at("pub"), "-out", at(SignatureAsset)); code != 0 {
		t.Fatalf("sign: %d %s", code, stderr)
	}
	base := []string{"verify", "-pub", at("pub"), "-manifest", at(ManifestAsset), "-sig", at(SignatureAsset)}
	if code, stderr := cli(nil, append(base, "-controller", at("controller"))...); code != 0 {
		t.Fatalf("controller alone: %d %s", code, stderr)
	}
	for _, args := range [][]string{
		{"-macserve", at("controller")},
		{"-macserve", at("controller"), "-controller", at("controller")},
		{"-controller", at("controller"), "-macserve", at("controller")},
	} {
		if code, stderr := cli(nil, append(base, args...)...); code != 1 || !strings.Contains(stderr, m.Binaries.Macserve.SHA256) {
			t.Fatalf("%v: verify exit %d %s", args, code, stderr)
		}
	}
}

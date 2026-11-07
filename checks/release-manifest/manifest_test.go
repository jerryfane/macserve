package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testSeed is a throwaway key for tests only; it signs nothing real.
var testSeed = bytes.Repeat([]byte{7}, ed25519.SeedSize)

func testKey() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(testSeed) }

func goldenManifest() Manifest {
	return Manifest{
		Schema: Schema, Tag: "v0.1.37", Commit: "0123456789abcdef0123456789abcdef01234567",
		Kind: KindCarry, BaseTag: "v0.1.36",
		Binaries: Binaries{
			Macserve:   Digest{SHA256: strings.Repeat("a", 64)},
			Controller: Digest{SHA256: strings.Repeat("b", 64)},
		},
		StoreSchemaVersion: 6,
		CreatedAt:          canonicalTime(time.Date(2026, 11, 7, 12, 0, 0, 999, time.UTC)),
	}
}

func TestEncodeGolden(t *testing.T) {
	want, err := os.ReadFile(filepath.Join("testdata", "golden-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Encode(goldenManifest())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("canonical bytes changed:\n%s\nwant:\n%s", got, want)
	}
	m, err := Parse(want)
	if err != nil {
		t.Fatal(err)
	}
	if m != goldenManifest() {
		t.Fatalf("Parse = %+v", m)
	}
}

func TestParseRejectsNonCanonical(t *testing.T) {
	golden, err := Encode(goldenManifest())
	if err != nil {
		t.Fatal(err)
	}
	g := string(golden)
	cases := map[string]string{
		"no trailing newline":   strings.TrimSuffix(g, "\n"),
		"two trailing newlines": g + "\n",
		"compact":               `{"schema":"macserve-release-manifest/1"}`,
		"tabs":                  strings.ReplaceAll(g, "  ", "\t"),
		"CRLF":                  strings.ReplaceAll(g, "\n", "\r\n"),
		"key order": strings.Replace(g, `"tag": "v0.1.37",`+"\n  "+`"commit": "0123456789abcdef0123456789abcdef01234567",`,
			`"commit": "0123456789abcdef0123456789abcdef01234567",`+"\n  "+`"tag": "v0.1.37",`, 1),
		"unknown field":   strings.Replace(g, `"schema"`, `"extra": 1,`+"\n  "+`"schema"`, 1),
		"trailing data":   g + "{}",
		"escaped string":  strings.Replace(g, `"v0.1.36"`, `"v0.1.3\u0036"`, 1),
		"uppercase sha":   strings.Replace(g, strings.Repeat("a", 64), strings.Repeat("A", 64), 1),
		"other schema":    strings.Replace(g, "manifest/1", "manifest/2", 1),
		"offset time":     strings.Replace(g, "2026-11-07T12:00:00Z", "2026-11-07T13:00:00+01:00", 1),
		"fractional time": strings.Replace(g, "2026-11-07T12:00:00Z", "2026-11-07T12:00:00.5Z", 1),
		"unknown kind":    strings.Replace(g, `"controller-carry"`, `"carry"`, 1),
		"base after tag":  strings.Replace(g, `"base_tag": "v0.1.36"`, `"base_tag": "v0.1.38"`, 1),
		"base equals tag": strings.Replace(g, `"base_tag": "v0.1.36"`, `"base_tag": "v0.1.37"`, 1),
		"full with base":  strings.Replace(g, `"controller-carry"`, `"full"`, 1),
		"zero schema":     strings.Replace(g, `"store_schema_version": 6`, `"store_schema_version": 0`, 1),
		"short commit":    strings.Replace(g, "01234567\"", "0123456\"", 1),
		"duplicate key":   strings.Replace(g, `"tag": "v0.1.37",`, `"tag": "v0.1.37",`+"\n  "+`"tag": "v0.1.37",`, 1),
		"missing controller": strings.Replace(g, `,
    "macserve-controller": {
      "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    }`, "", 1),
	}
	for name, text := range cases {
		if text == g {
			t.Fatalf("%s: case does not change the manifest", name)
		}
		if _, err := Parse([]byte(text)); err == nil {
			t.Errorf("%s: Parse accepted", name)
		}
	}
	full := goldenManifest()
	full.Kind, full.BaseTag = KindFull, full.Tag
	if _, err := Encode(full); err != nil {
		t.Fatalf("full manifest: %v", err)
	}
}

func TestSignVerify(t *testing.T) {
	key := testKey()
	pub := key.Public().(ed25519.PublicKey)
	manifest, err := Encode(goldenManifest())
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(key, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 89 || sig[88] != '\n' {
		t.Fatalf("signature file %q is not 88 base64 characters and a newline", sig)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || !ed25519.Verify(pub, manifest, raw) {
		t.Fatalf("signature is not raw Ed25519 over the exact bytes: %v", err)
	}
	m, err := Verify(pub, manifest, sig)
	if err != nil {
		t.Fatal(err)
	}
	if m != goldenManifest() {
		t.Fatalf("Verify = %+v", m)
	}
	if _, err := Verify(pub, manifest, bytes.TrimSuffix(sig, []byte("\n"))); err != nil {
		t.Fatalf("signature without newline: %v", err)
	}

	tampered := bytes.Replace(manifest, []byte(`"store_schema_version": 6`), []byte(`"store_schema_version": 7`), 1)
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	otherSig, _ := Sign(other, manifest)
	for name, tc := range map[string]struct {
		pub           ed25519.PublicKey
		manifest, sig []byte
		want          string
	}{
		"tampered manifest": {pub, tampered, sig, "does not verify"},
		"other key":         {pub, manifest, otherSig, "does not verify"},
		"wrong public key":  {other.Public().(ed25519.PublicKey), manifest, sig, "does not verify"},
		"short signature":   {pub, manifest, EncodeKey(raw[:63]), "63 bytes"},
		"not base64":        {pub, manifest, []byte("!!!!\n"), "not standard base64"},
		"unpadded":          {pub, manifest, []byte(strings.TrimRight(strings.TrimSpace(string(sig)), "=")), "not standard base64"},
		"CRLF":              {pub, manifest, []byte(strings.TrimSpace(string(sig)) + "\r\n"), "not standard base64"},
	} {
		if _, err := Verify(tc.pub, tc.manifest, tc.sig); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err %v, want %q", name, err, tc.want)
		}
	}

	// A signature over non-canonical bytes verifies cryptographically but
	// the manifest is still refused; Sign never produces one.
	loose := []byte(strings.TrimSuffix(string(manifest), "\n") + " \n")
	if _, err := Verify(pub, loose, EncodeKey(ed25519.Sign(key, loose))); err == nil || !strings.Contains(err.Error(), "canonical") {
		t.Errorf("non-canonical signed manifest: %v", err)
	}
	if _, err := Sign(key, loose); err == nil {
		t.Error("Sign accepted non-canonical bytes")
	}
}

func TestParseKeys(t *testing.T) {
	seedText := EncodeKey(testSeed)
	key, err := ParseSeed(seedText)
	if err != nil {
		t.Fatal(err)
	}
	if !key.Equal(testKey()) {
		t.Fatal("seed decodes to another key")
	}
	if _, err := ParseSeed(bytes.TrimSuffix(seedText, []byte("\n"))); err != nil {
		t.Fatalf("seed without newline: %v", err)
	}
	for name, text := range map[string]string{
		"64-byte private key": string(EncodeKey(testKey())),
		"public key size":     base64.StdEncoding.EncodeToString(testSeed[:31]),
		"PEM":                 "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcH\n-----END PRIVATE KEY-----\n",
		"hex":                 strings.Repeat("07", 32),
		"empty":               "",
	} {
		if _, err := ParseSeed([]byte(text)); err == nil {
			t.Errorf("%s: ParseSeed accepted", name)
		}
	}
	pub, err := ParsePublicKey(EncodeKey(testKey().Public().(ed25519.PublicKey)))
	if err != nil || !pub.Equal(testKey().Public()) {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	if _, err := ParsePublicKey(seedText[:10]); err == nil {
		t.Error("ParsePublicKey accepted a short key")
	}
}

// The production public key committed next to the tool must parse; the
// workflow's sign step refuses a secret that does not match it.
func TestPinnedPublicKey(t *testing.T) {
	data, err := os.ReadFile("release-signing.pub")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKey(data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(data, []byte("\n")) || bytes.Count(data, []byte("\n")) != 1 {
		t.Fatalf("release-signing.pub must be one base64 line: %q", data)
	}
	t.Logf("pinned release signing key %s", KeyID(pub))
}

func TestSumsDigest(t *testing.T) {
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	sums := []byte(a + "  " + RootAsset + "\n" + b + " *" + ControllerAsset + "\n")
	if got, err := sumsDigest(sums, RootAsset); err != nil || got != a {
		t.Fatalf("root = %q, %v", got, err)
	}
	if got, err := sumsDigest(sums, ControllerAsset); err != nil || got != b {
		t.Fatalf("controller = %q, %v", got, err)
	}
	for name, text := range map[string]string{
		"missing":   a + "  other\n",
		"duplicate": a + "  " + RootAsset + "\n" + b + "  " + RootAsset + "\n",
		"malformed": a + " " + RootAsset + "\n",
		"uppercase": strings.ToUpper(a) + "  " + RootAsset + "\n",
	} {
		if _, err := sumsDigest([]byte(text), RootAsset); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseVersion(t *testing.T) {
	if n, err := parseVersion([]byte(`{"version":"v0.1.36","commit":"` + strings.Repeat("c", 40) + `","store_schema_version":6}` + "\n")); err != nil || n != 6 {
		t.Fatalf("parseVersion = %d, %v", n, err)
	}
	for _, text := range []string{
		`{"version":"v0.1.36","commit":""}`,
		`{"version":"v0.1.36","commit":"","store_schema_version":0}`,
		`{"version":"v0.1.36","commit":"","store_schema_version":6,"extra":1}`,
		`{"store_schema_version":6}{}`,
	} {
		if _, err := parseVersion([]byte(text)); err == nil {
			t.Errorf("parseVersion(%s) accepted", text)
		}
	}
}

package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"time"
)

const (
	// Schema is the only manifest schema this tool writes or accepts.
	Schema = "macserve-release-manifest/1"
	// KindFull is a release whose binaries were both built from its tag.
	KindFull = "full"
	// KindCarry is a release that republishes base_tag's root binary bytes
	// and ships a new controller binary.
	KindCarry = "controller-carry"

	// RootAsset and ControllerAsset are the release assets the manifest's
	// binaries.macserve and binaries.macserve-controller describe.
	RootAsset       = "macserve-darwin-arm64"
	ControllerAsset = "macserve-controller-darwin-arm64"
	// ManifestAsset and SignatureAsset are the published file names.
	ManifestAsset  = "release-manifest.json"
	SignatureAsset = "release-manifest.json.sig"

	// SigningKeyEnv holds the CI signing key: standard padded base64 of the
	// raw 32-byte Ed25519 seed.
	SigningKeyEnv = "MACSERVE_RELEASE_SIGNING_KEY"

	maxManifest = 64 << 10
	maxKeyFile  = 4 << 10
)

var (
	hex64    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	commitRE = regexp.MustCompile(`^[0-9a-f]{40}$`)
	semver   = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	b64      = base64.StdEncoding.Strict()
	// base64Line is one line of padded standard base64 characters.
	base64Line = regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)
)

// Digest is one binary's sha256 over its unsigned release bytes.
type Digest struct {
	SHA256 string `json:"sha256"`
}

// Binaries are the two release binaries.
type Binaries struct {
	Macserve   Digest `json:"macserve"`
	Controller Digest `json:"macserve-controller"`
}

// Manifest is release-manifest.json. Field order is the canonical order.
type Manifest struct {
	Schema             string   `json:"schema"`
	Tag                string   `json:"tag"`
	Commit             string   `json:"commit"`
	Kind               string   `json:"kind"`
	BaseTag            string   `json:"base_tag"`
	Binaries           Binaries `json:"binaries"`
	StoreSchemaVersion int      `json:"store_schema_version"`
	CreatedAt          string   `json:"created_at"`
}

// Validate checks every field of m.
func (m Manifest) Validate() error {
	switch {
	case m.Schema != Schema:
		return fmt.Errorf("schema %q is not %q", m.Schema, Schema)
	case !semver.MatchString(m.Tag):
		return fmt.Errorf("tag %q is not vX.Y.Z", m.Tag)
	case !commitRE.MatchString(m.Commit):
		return fmt.Errorf("commit %q is not 40 lowercase hex", m.Commit)
	case !semver.MatchString(m.BaseTag):
		return fmt.Errorf("base_tag %q is not vX.Y.Z", m.BaseTag)
	case !hex64.MatchString(m.Binaries.Macserve.SHA256):
		return fmt.Errorf("binaries.macserve.sha256 %q is not 64 lowercase hex", m.Binaries.Macserve.SHA256)
	case !hex64.MatchString(m.Binaries.Controller.SHA256):
		return fmt.Errorf("binaries.macserve-controller.sha256 %q is not 64 lowercase hex", m.Binaries.Controller.SHA256)
	case m.StoreSchemaVersion < 1:
		return fmt.Errorf("store_schema_version %d is not positive", m.StoreSchemaVersion)
	}
	switch m.Kind {
	case KindFull:
		if m.BaseTag != m.Tag {
			return fmt.Errorf("kind %s: base_tag %s differs from tag %s", KindFull, m.BaseTag, m.Tag)
		}
	case KindCarry:
		if compareSemver(m.BaseTag, m.Tag) >= 0 {
			return fmt.Errorf("kind %s: base_tag %s does not precede tag %s", KindCarry, m.BaseTag, m.Tag)
		}
	default:
		return fmt.Errorf("kind %q is not %s or %s", m.Kind, KindFull, KindCarry)
	}
	t, err := time.Parse(time.RFC3339, m.CreatedAt)
	if err != nil {
		return fmt.Errorf("created_at: %v", err)
	}
	if canonicalTime(t) != m.CreatedAt {
		return fmt.Errorf("created_at %q is not UTC RFC 3339 with whole seconds (%s)", m.CreatedAt, canonicalTime(t))
	}
	return nil
}

// canonicalTime is the only created_at form: UTC, whole seconds, "Z".
func canonicalTime(t time.Time) string {
	return t.UTC().Truncate(time.Second).Format(time.RFC3339)
}

// Encode returns the canonical bytes of m: two-space indented JSON in field
// order, one trailing newline. These are the bytes CI signs.
func Encode(m Manifest) ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// Parse decodes a manifest strictly: at most 64 KiB, one JSON object with
// exactly the schema's fields, valid values, and bytes equal to Encode of
// the result (so whitespace, key order, escapes and duplicates cannot vary).
func Parse(data []byte) (Manifest, error) {
	var m Manifest
	if len(data) > maxManifest {
		return m, fmt.Errorf("manifest is %d bytes, over %d", len(data), maxManifest)
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&m); err != nil {
		return m, fmt.Errorf("manifest: %w", err)
	}
	if d.Decode(new(any)) != io.EOF {
		return m, errors.New("manifest: trailing data")
	}
	canonical, err := Encode(m)
	if err != nil {
		return m, fmt.Errorf("manifest: %w", err)
	}
	if !bytes.Equal(canonical, data) {
		return m, errors.New("manifest: bytes are not the canonical encoding")
	}
	return m, nil
}

// decodeKeyText decodes a key or signature file: standard padded base64,
// optionally followed by exactly one "\n", decoding to exactly n bytes.
func decodeKeyText(what string, data []byte, n int) ([]byte, error) {
	if len(data) > maxKeyFile {
		return nil, fmt.Errorf("%s: %d bytes, too large", what, len(data))
	}
	text := bytes.TrimSuffix(data, []byte("\n"))
	// encoding/base64 skips CR and LF anywhere: allow one line only.
	if !base64Line.Match(text) {
		return nil, fmt.Errorf("%s: not standard base64 on one line", what)
	}
	raw, err := b64.DecodeString(string(text))
	if err != nil {
		return nil, fmt.Errorf("%s: not standard base64: %v", what, err)
	}
	if len(raw) != n {
		return nil, fmt.Errorf("%s: %d bytes, want %d", what, len(raw), n)
	}
	return raw, nil
}

// ParseSeed decodes the signing key: base64 of the raw 32-byte Ed25519
// seed (RFC 8032 private key), no PEM.
func ParseSeed(text []byte) (ed25519.PrivateKey, error) {
	seed, err := decodeKeyText(SigningKeyEnv, text, ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// ParsePublicKey decodes a public key file: base64 of the raw 32 bytes.
func ParsePublicKey(text []byte) (ed25519.PublicKey, error) {
	raw, err := decodeKeyText("public key", text, ed25519.PublicKeySize)
	if err != nil {
		return nil, err
	}
	return ed25519.PublicKey(raw), nil
}

// EncodeKey renders raw key or signature bytes as written to files.
func EncodeKey(raw []byte) []byte {
	return []byte(b64.EncodeToString(raw) + "\n")
}

// Sign returns the signature file for manifest: base64 of the raw 64-byte
// Ed25519 signature over the exact manifest bytes, then "\n". It refuses a
// manifest Parse rejects.
func Sign(key ed25519.PrivateKey, manifest []byte) ([]byte, error) {
	if _, err := Parse(manifest); err != nil {
		return nil, err
	}
	return EncodeKey(ed25519.Sign(key, manifest)), nil
}

// Verify checks sig (a signature file) over the exact manifest bytes with
// pub, then parses the manifest strictly. The signature is checked first:
// unsigned bytes are never parsed.
func Verify(pub ed25519.PublicKey, manifest, sig []byte) (Manifest, error) {
	if len(manifest) > maxManifest {
		return Manifest{}, fmt.Errorf("manifest is %d bytes, over %d", len(manifest), maxManifest)
	}
	raw, err := decodeKeyText("signature", sig, ed25519.SignatureSize)
	if err != nil {
		return Manifest{}, err
	}
	if !ed25519.Verify(pub, manifest, raw) {
		return Manifest{}, errors.New("signature does not verify with the public key")
	}
	return Parse(manifest)
}

// KeyID is a short fingerprint of a public key for logs: the first 16 hex
// digits of sha256 over the raw 32 bytes.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// sumsDigest parses SHA256SUMS strictly ("<64 hex>  <name>" or
// "<64 hex> *<name>" per line) and returns the single digest of asset.
func sumsDigest(sums []byte, asset string) (string, error) {
	var found []string
	scanner := bufio.NewScanner(bytes.NewReader(sums))
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 67 || !hex64.MatchString(line[:64]) || (line[64:66] != "  " && line[64:66] != " *") {
			return "", fmt.Errorf("malformed SHA256SUMS line %q", line)
		}
		if line[66:] == asset {
			found = append(found, line[:64])
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	switch len(found) {
	case 0:
		return "", fmt.Errorf("SHA256SUMS has no %s entry", asset)
	case 1:
		return found[0], nil
	}
	return "", fmt.Errorf("SHA256SUMS lists %s %d times", asset, len(found))
}

// compareSemver orders two vX.Y.Z tags.
func compareSemver(a, b string) int {
	pa, pb := semver.FindStringSubmatch(a), semver.FindStringSubmatch(b)
	if pa == nil || pb == nil {
		panic("compareSemver: not vX.Y.Z")
	}
	for i := 1; i <= 3; i++ {
		x, _ := strconv.ParseUint(pa[i], 10, 64)
		y, _ := strconv.ParseUint(pb[i], 10, 64)
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

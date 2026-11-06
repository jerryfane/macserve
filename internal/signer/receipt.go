package signer

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/jerryfane/macserve/internal/receipt"
)

// ReceiptSchema is the signer receipt format version.
const ReceiptSchema = 1

// MaxReceiptBytes bounds a signer receipt envelope.
const MaxReceiptBytes = 128 << 10

// ReceiptPayload is what a signer receipt attests: the job and its receipt,
// the exact sealed archive and signing manifest signed, the identity, the
// resulting ipa and, per bundle, the embedded profile and the SHA-256 of the
// entitlements plist signed into it. Frameworks carry no profile or
// entitlements.
type ReceiptPayload struct {
	Schema                int             `json:"schema"`
	JobID                 string          `json:"job_id"`
	JobReceiptSHA256      string          `json:"job_receipt_sha256"`
	Repository            RepositoryRef   `json:"repository"`
	Commit                string          `json:"commit"`
	BuildName             string          `json:"build_name"`
	BuildNumber           string          `json:"build_number"`
	Archive               DigestRef       `json:"archive"`
	SigningManifestSHA256 string          `json:"signing_manifest_sha256"`
	IdentitySHA1          string          `json:"identity_sha1"`
	TeamID                string          `json:"team_id"`
	IPA                   DigestRef       `json:"ipa"`
	Bundles               []SignedBundle  `json:"bundles"`
	Dylibs                []string        `json:"dylibs"`
	SignedAt              time.Time       `json:"signed_at"`
	Signer                SignerReference `json:"signer"`
}

// RepositoryRef is the job receipt's repository identity.
type RepositoryRef struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// DigestRef names a file by artifact name, SHA-256 and size.
type DigestRef struct {
	Name      string `json:"name"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

// SignedBundle is one signed bundle of the manifest.
type SignedBundle struct {
	Path               string `json:"path"`
	BundleID           string `json:"bundle_id"`
	ProfileUUID        string `json:"profile_uuid,omitempty"`
	ProfileSHA256      string `json:"profile_sha256,omitempty"`
	EntitlementsSHA256 string `json:"entitlements_sha256,omitempty"`
}

// SignerReference names the signer receipt key.
type SignerReference struct {
	KeyID string `json:"key_id"`
}

// sealReceipt signs payload into a canonical receipt.Envelope.
func sealReceipt(payload ReceiptPayload, key ed25519.PrivateKey) ([]byte, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	canonical, err := receipt.Canonical(raw)
	if err != nil {
		return nil, err
	}
	envelope := receipt.Envelope{Payload: canonical, Signature: receipt.Signature{Algorithm: "Ed25519", KeyID: payload.Signer.KeyID, Encoding: "base64", Value: base64.StdEncoding.EncodeToString(ed25519.Sign(key, canonical))}}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	out, err := receipt.Canonical(encoded)
	if err != nil {
		return nil, err
	}
	if len(out) > MaxReceiptBytes {
		return nil, errors.New("signer receipt exceeds its size limit")
	}
	return out, nil
}

// VerifyReceipt authenticates a canonical signer receipt with the pinned
// signer keys and returns its payload. It does not check the payload
// against any job; callers compare the fields they rely on.
func VerifyReceipt(raw []byte, keys map[string]ed25519.PublicKey) (ReceiptPayload, error) {
	var p ReceiptPayload
	invalid := errors.New("invalid signer receipt")
	if len(raw) == 0 || len(raw) > MaxReceiptBytes {
		return p, invalid
	}
	canonical, err := receipt.Canonical(raw)
	if err != nil || !bytes.Equal(canonical, raw) {
		return p, invalid
	}
	var envelope receipt.Envelope
	if err := decodeStrict(raw, &envelope); err != nil {
		return p, invalid
	}
	sig := envelope.Signature
	key, ok := keys[sig.KeyID]
	if !ok || len(key) != ed25519.PublicKeySize || sig.Algorithm != "Ed25519" || sig.Encoding != "base64" {
		return p, invalid
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(sig.Value)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return p, invalid
	}
	payload, err := receipt.Canonical(envelope.Payload)
	if err != nil || !ed25519.Verify(key, payload, signature) {
		return p, invalid
	}
	if err := decodeStrict(payload, &p); err != nil {
		return ReceiptPayload{}, invalid
	}
	if p.Schema != ReceiptSchema || p.Signer.KeyID != sig.KeyID || !sha64(p.IPA.SHA256) || p.IPA.SizeBytes <= 0 || p.IPA.Name != IPAArtifact || !sha64(p.Archive.SHA256) || !sha64(p.SigningManifestSHA256) || !sha64(p.JobReceiptSHA256) || len(p.Bundles) == 0 || !slices.IsSortedFunc(p.Bundles, func(a, b SignedBundle) int {
		if a.Path < b.Path {
			return -1
		}
		return 1
	}) {
		return ReceiptPayload{}, invalid
	}
	return p, nil
}

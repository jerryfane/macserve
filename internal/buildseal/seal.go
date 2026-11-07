// Package buildseal is the root worker's authenticated record of what it
// built: the canonical request it accepted, the profile or template it
// resolved from the root registry, the recipe it derived, the toolchain pins,
// the Git tree it computed from the source bytes it extracted, and the
// digests of the result and its archive evidence. The worker signs the seal
// with a root-held Ed25519 key; the keyholder verifies it with the pinned
// public key before it signs any receipt, so the controller can neither
// forge nor alter it. It is class B.
package buildseal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/worker"
)

// Schema names the seal format.
const Schema = "macserve-build-seal/1"

// MaxEnvelopeBytes bounds an encoded envelope.
const MaxEnvelopeBytes = 256 << 10

var (
	ErrInvalid  = errors.New("invalid build seal")
	keyIDFormat = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
)

// Resolution is the worker's own resolution of a lease against the root
// registry: the profile or template identity and its digest. A lease the
// worker refused has none, and its seal cannot support a success receipt.
type Resolution struct {
	ProfileID      string            `json:"profile_id"`
	ProfileVersion int               `json:"profile_version"`
	ProfileDigest  string            `json:"profile_digest"`
	Xcode          model.Xcode       `json:"xcode"`
	DeveloperDir   string            `json:"developer_dir"`
	Flutter        *model.FlutterPin `json:"flutter,omitempty"`
}

// Seal is the canonical record. SnapshotDigest is the SHA-256 of the
// admitted profile snapshot's JSON exactly as leased; RecipeDigest is that of
// the effective recipe (the snapshot, or a template job's derivation from
// its reported repository configuration), empty when none derives.
// SourceTree is the Git tree the worker computed from the bytes it
// extracted, empty unless extraction verified it.
type Seal struct {
	Schema                string        `json:"schema"`
	JobID                 string        `json:"job_id"`
	WorkerEpoch           string        `json:"worker_epoch"`
	Request               model.Request `json:"request"`
	RequestDigest         string        `json:"request_digest"`
	SnapshotDigest        string        `json:"snapshot_digest"`
	Resolution            *Resolution   `json:"resolution,omitempty"`
	RecipeDigest          string        `json:"recipe_digest,omitempty"`
	Source                worker.Source `json:"source"`
	SourceTree            string        `json:"source_tree,omitempty"`
	State                 model.State   `json:"state"`
	ResultDigest          string        `json:"result_digest"`
	ArtifactsDigest       string        `json:"artifacts_digest"`
	ArchiveSHA256         string        `json:"archive_sha256,omitempty"`
	SigningManifestSHA256 string        `json:"signing_manifest_sha256,omitempty"`
	SealedAt              time.Time     `json:"sealed_at"`
}

// Envelope carries the exact signed seal bytes and the Ed25519 signature.
// Seal is an opaque byte string (base64 in JSON): embedded as raw JSON it
// would be re-encoded on every hop (HTML escaping) and stop verifying.
type Envelope struct {
	Seal      []byte `json:"seal"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

// Digest is the SHA-256 of a value's encoding/json form, the encoding the
// controller and worker already digest requests and results with.
func Digest(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// New builds the seal of a worker result for job. resolution is nil when
// the worker refused the lease; sourceTree is the computed tree, empty when
// extraction did not verify one.
func New(job model.Job, resolution *Resolution, sourceTree string, result worker.Result, now time.Time) (Seal, error) {
	s := Seal{Schema: Schema, JobID: job.ID, WorkerEpoch: job.WorkerEpoch, Request: job.Request, RequestDigest: job.RequestDigest, Resolution: resolution, Source: result.Source, SourceTree: sourceTree, State: result.State, SealedAt: now.UTC()}
	var err error
	if s.SnapshotDigest, err = Digest(job.Profile); err != nil {
		return Seal{}, err
	}
	if resolution != nil {
		if effective, err := profiles.Effective(job.Profile, result.Observation.Recipe); err == nil {
			if s.RecipeDigest, err = Digest(effective); err != nil {
				return Seal{}, err
			}
		}
	}
	if s.ResultDigest, err = Digest(result); err != nil {
		return Seal{}, err
	}
	artifacts := result.Artifacts
	if artifacts == nil {
		artifacts = []evidence.Artifact{}
	}
	if s.ArtifactsDigest, err = Digest(artifacts); err != nil {
		return Seal{}, err
	}
	for _, a := range result.Artifacts {
		switch a.Name {
		case profiles.ArchiveArtifact:
			s.ArchiveSHA256 = a.SHA256
		case profiles.SigningManifestArtifact:
			s.SigningManifestSHA256 = a.SHA256
		}
	}
	return s, nil
}

// Sign encodes s and signs the exact bytes.
func Sign(key ed25519.PrivateKey, keyID string, s Seal) (Envelope, error) {
	if len(key) != ed25519.PrivateKeySize || !keyIDFormat.MatchString(keyID) || s.Schema != Schema {
		return Envelope{}, ErrInvalid
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{Seal: raw, KeyID: keyID, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, raw))}, nil
}

// Verify checks the envelope's signature with the pinned key it names and
// decodes the seal strictly.
func Verify(env Envelope, keys map[string]ed25519.PublicKey) (Seal, error) {
	key, ok := keys[env.KeyID]
	if !ok || len(key) != ed25519.PublicKeySize || len(env.Seal) == 0 || len(env.Seal) > MaxEnvelopeBytes {
		return Seal{}, fmt.Errorf("%w: unknown key or bounds", ErrInvalid)
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(env.Signature)
	if err != nil || !ed25519.Verify(key, env.Seal, signature) {
		return Seal{}, fmt.Errorf("%w: signature", ErrInvalid)
	}
	var s Seal
	decoder := json.NewDecoder(bytes.NewReader(env.Seal))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&s); err != nil || decoder.More() || s.Schema != Schema {
		return Seal{}, fmt.Errorf("%w: encoding", ErrInvalid)
	}
	return s, nil
}

// SealDigest is the SHA-256 of the signed seal bytes; it names one seal.
func (env Envelope) SealDigest() string {
	sum := sha256.Sum256(env.Seal)
	return hex.EncodeToString(sum[:])
}

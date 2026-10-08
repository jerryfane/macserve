package receipt

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/worker"
)

func NewSigner(options Options) (*Signer, error) {
	key, err := checkedPrivate(options.PrivateKey)
	if err != nil || options.Root == "" || !filepath.IsAbs(options.Root) || options.KeyID == "" || len(options.KeyID) > 128 || options.Repository == nil || options.Service.ID == "" || options.Service.HostID == "" || options.Service.Version == "" || !validDigest(options.Service.BinarySHA256) {
		return nil, fmt.Errorf("%w: signer configuration", ErrInvalid)
	}
	options.PrivateKey = key
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Approval == nil {
		options.Approval = func(_ context.Context, j model.Job) (Approval, error) {
			return Approval{Intake: "private_api", Identity: j.Principal, AttemptID: j.ID}, nil
		}
	}
	if err := os.MkdirAll(options.Root, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(options.Root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("%w: signer root must be a private directory", ErrInvalid)
	}
	root, err := os.OpenRoot(options.Root)
	if err != nil {
		return nil, err
	}
	return &Signer{options: options, root: root}, nil
}
func (s *Signer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	clear(s.options.PrivateKey)
	return s.root.Close()
}
func validJobID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
func observed(o worker.Observation) Observation {
	return Observation{Xcode: o.Xcode, SDKVersion: o.SDKVersion, SDKBuild: o.SDKBuild, SwiftVersion: o.SwiftVersion, OSVersion: o.OSVersion, OSBuild: o.OSBuild, Architecture: o.Architecture, RuntimeVersion: o.RuntimeVersion, RuntimeBuild: o.RuntimeBuild, DeviceUDID: o.DeviceUDID}
}

func (s *Signer) Seal(ctx context.Context, job model.Job, result worker.Result) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validJobID(job.ID) || !result.State.Terminal() {
		return nil, ErrInvalid
	}
	repository, err := s.options.Repository(ctx, job)
	if err != nil {
		return nil, err
	}
	approval, err := s.options.Approval(ctx, job)
	if err != nil {
		return nil, err
	}
	if repository.ID <= 0 || repository.Name != job.Request.Repo || approval.Intake == "" || approval.Identity == "" || approval.AttemptID == "" {
		return nil, ErrInvalid
	}
	// Persisted job state and completion timestamps may change after sealing.
	// Only immutable admission/dispatch inputs participate in replay identity.
	input := struct {
		JobID, Principal, ProfileDigest, RequestDigest, WorkerEpoch string
		Request                                                     model.Request
		Profile                                                     model.Profile
		CreatedAt                                                   time.Time
		Deadline                                                    *time.Time
		Service                                                     ServiceIdentity
		Repository                                                  Repository
		Approval                                                    Approval
		Result                                                      worker.Result
	}{job.ID, job.Principal, job.ProfileDigest, job.RequestDigest, job.WorkerEpoch, job.Request, job.Profile, job.CreatedAt, job.Deadline, s.options.Service, repository, approval, result}
	inputDigest, err := valueDigest(input)
	if err != nil {
		return nil, err
	}
	replayID := job.ID + "-input-" + inputDigest
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, os.ErrClosed
	}
	if raw, err := s.load(replayID); err == nil {
		var existing Payload
		if err := strictDecode(raw, &existing); err != nil || existing.InputDigest != inputDigest || existing.JobID != job.ID {
			return nil, fmt.Errorf("%w: immutable manifest conflict", ErrInvalid)
		}
		if err := s.linkManifest(replayID, job.ID, raw); err != nil {
			return nil, err
		}
		return s.publish(existing, raw)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	p := Payload{Schema: 1, JobID: job.ID, AttemptID: approval.AttemptID, InputDigest: inputDigest, Service: s.options.Service, Repository: repository, Approval: approval, Request: job.Request, ProfileDigest: job.ProfileDigest, ProfileVersion: job.Profile.Version, Source: result.Source, Observation: observed(result.Observation), State: result.State, Reason: result.Reason, ExitCode: result.ExitCode, Signal: result.Signal, CreatedAt: job.CreatedAt, StartedAt: result.StartedAt, FinishedAt: result.FinishedAt, Deadline: job.Deadline, SealedAt: s.options.Now().UTC(), WorkerEpoch: job.WorkerEpoch, Resources: ResourcePolicy{TimeoutSeconds: job.Request.TimeoutSeconds, MemoryLimitMiB: job.Profile.MemoryLimitMiB, PeakMemoryMiB: result.PeakMemoryMiB, CleanupRequired: true, CleanupOK: result.CleanupOK}, Tests: testEvidence(job.Request.Kind, job.Profile.RequiredTests, result.Summary), Logs: []evidence.Artifact{}, LogsTruncated: result.LogsTruncated, CommandCount: len(result.Commands), ArtifactCount: len(result.Artifacts), Details: &Details{Profile: job.Profile, Result: result}}
	p.RequestDigest = job.RequestDigest
	for _, a := range result.Artifacts {
		if a.Name == "evidence/stdout.log" || a.Name == "evidence/stderr.log" {
			p.Logs = append(p.Logs, a)
		}
	}
	for _, item := range []struct {
		value  any
		target *string
	}{{result.Commands, &p.Digests.Commands}, {result.Artifacts, &p.Digests.Artifacts}, {manifestMap(result.Observation.GeneratedDigests), &p.Digests.Generated}, {manifestMap(result.Observation.LockfileDigests), &p.Digests.Lockfiles}, {cases(result.Summary), &p.Digests.TestCases}} {
		*item.target, err = valueDigest(item.value)
		if err != nil {
			return nil, err
		}
	}
	p.Missing = incomplete(p)
	p.Complete = len(p.Missing) == 0
	if result.State == model.Succeeded {
		if err := ValidateSuccess(p, expectedFor(p)); err != nil {
			return nil, err
		}
	}
	full, err := canonicalValue(p)
	if err != nil {
		return nil, err
	}
	// Refuse unpublishable evidence before creating its immutable manifest.
	published, err := s.publish(p, full)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.persist(replayID, full); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		prior, readErr := s.load(replayID)
		if readErr != nil {
			return nil, readErr
		}
		var existing Payload
		if strictDecode(prior, &existing) != nil || existing.InputDigest != inputDigest || existing.JobID != job.ID {
			return nil, fmt.Errorf("%w: immutable manifest conflict", ErrInvalid)
		}
		if err := s.linkManifest(replayID, job.ID, prior); err != nil {
			return nil, err
		}
		return s.publish(existing, prior)
	}
	if err := s.linkManifest(replayID, job.ID, full); err != nil {
		return nil, err
	}
	return published, nil
}
func (s *Signer) envelope(p Payload) (json.RawMessage, error) {
	raw, err := canonicalValue(p)
	if err != nil {
		return nil, err
	}
	signature := ed25519.Sign(s.options.PrivateKey, raw)
	return canonicalValue(Envelope{Payload: raw, Signature: Signature{Algorithm: "Ed25519", KeyID: s.options.KeyID, Encoding: "base64", Value: base64.StdEncoding.EncodeToString(signature)}})
}
func (s *Signer) publish(p Payload, full []byte) (json.RawMessage, error) {
	raw, err := s.envelope(p)
	if err != nil {
		return nil, err
	}
	if len(raw) <= MaxReceiptBytes {
		return raw, nil
	}
	p.Details = nil
	digest := hashBytes(full)
	p.Manifest = &ManifestReference{SHA256: digest, SizeBytes: int64(len(full)), URL: manifestURL(p.JobID, digest)}
	raw, err = s.envelope(p)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxReceiptBytes {
		return nil, fmt.Errorf("%w: compact receipt exceeds publication limit", ErrInvalid)
	}
	return raw, nil
}

// Manifest returns one immutable candidate. The authenticated controller route
// must first match the digest to the terminal job's committed receipt.
func (s *Signer) Manifest(ctx context.Context, jobID, digest string) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validJobID(jobID) || !validDigest(digest) {
		return nil, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, os.ErrClosed
	}
	raw, err := s.load(jobID + "-manifest-" + digest)
	if err != nil {
		return nil, err
	}
	if hashBytes(raw) != digest {
		return nil, ErrInvalid
	}
	return raw, nil
}
func (s *Signer) load(id string) ([]byte, error) {
	name := id + ".json"
	info, err := s.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > maxManifestBytes {
		return nil, ErrInvalid
	}
	f, err := s.root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxManifestBytes+1))
	if err != nil {
		return nil, err
	}
	c, err := canonical(raw)
	if err != nil || !bytes.Equal(c, raw) {
		return nil, ErrInvalid
	}
	return raw, nil
}
func (s *Signer) persist(id string, raw []byte) error {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	name := ".pending-" + hex.EncodeToString(random)
	f, err := s.root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer s.root.Remove(name)
	if _, err = f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	// Link is atomic and never overwrites an existing input candidate, including
	// when two controllers race. Both paths stay confined to the opened root.
	if err = s.root.Link(name, id+".json"); err != nil {
		return err
	}
	if err = s.root.Remove(name); err != nil {
		return err
	}
	dir, err := s.root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func manifestURL(jobID, digest string) string {
	return "/v1/jobs/" + jobID + "/receipt/manifest?sha256=" + digest
}

func (s *Signer) linkManifest(replayID, jobID string, raw []byte) error {
	name := jobID + "-manifest-" + hashBytes(raw)
	err := s.root.Link(replayID+".json", name+".json")
	if errors.Is(err, os.ErrExist) {
		existing, readErr := s.load(name)
		if readErr != nil {
			return readErr
		}
		if !bytes.Equal(existing, raw) {
			return ErrInvalid
		}
	} else if err != nil {
		return err
	}
	dir, err := s.root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

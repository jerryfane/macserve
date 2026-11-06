package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/signer"
	"github.com/jerryfane/macserve/internal/store"
	"golang.org/x/sys/unix"
)

// ErrSigningUnavailable refuses signing on a controller without a signer.
var ErrSigningUnavailable = errors.New("signing is not configured")

// SignClient is the signer RPC (signer.Client in production).
type SignClient interface {
	Sign(ctx context.Context, req signer.Request, ipa io.Writer) (signer.Result, error)
}

// SignerOptions connects the controller to the signer daemon.
type SignerOptions struct {
	Client SignClient
	// Inbox is the controller-owned directory, group RPCGID mode 0750,
	// where a request's archive and manifest copies are handed over.
	Inbox  string
	RPCGID int
	// Keys pins the signer receipt verification keys by key ID.
	Keys map[string]ed25519.PublicKey
}

// Sign starts signing a succeeded ios_archive job, or returns its signing
// in progress or done (idempotent). A started signing runs in the
// background; its record moves to signed or sign_failed.
func (c *Controller) Sign(ctx context.Context, id string) (store.SigningRecord, error) {
	if c.options.Signer == nil {
		return store.SigningRecord{}, ErrSigningUnavailable
	}
	if !safeID(id) {
		return store.SigningRecord{}, store.ErrNotFound
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return store.SigningRecord{}, errors.New("controller closed")
	}
	record, started, err := c.options.Store.BeginSigning(ctx, id, c.options.Now())
	if err != nil || !started {
		c.mu.Unlock()
		return record, err
	}
	c.background.Add(1)
	c.mu.Unlock()
	go func() {
		defer c.background.Done()
		status, reason := store.Signed, ""
		artifacts, err := c.sign(c.ctx, id)
		if err != nil {
			status, reason, artifacts = store.SignFailed, err.Error(), nil
		}
		c.finishSigning(id, status, reason, artifacts)
	}()
	return record, nil
}

// signingFallbackReason replaces an outcome the store refused to record.
const signingFallbackReason = "signing outcome could not be recorded"

// finishSigning records a signing's outcome, even during shutdown, so no
// finished signing stays in progress: the reason is bounded valid UTF-8,
// and an outcome the store refuses is replaced by sign_failed with a fixed
// reason, retried briefly. A restart fails anything still in progress.
func (c *Controller) finishSigning(id string, status store.SigningStatus, reason string, artifacts []evidence.Artifact) {
	err := c.options.Store.FinishSigning(context.Background(), id, status, signingReason(reason), artifacts, c.options.Now())
	for attempt := 1; err != nil && !errors.Is(err, store.ErrTransition) && attempt <= 3; attempt++ {
		err = c.options.Store.FinishSigning(context.Background(), id, store.SignFailed, signingFallbackReason, nil, c.options.Now())
		if err != nil {
			time.Sleep(time.Duration(attempt) * 100 * time.Millisecond)
		}
	}
}

// signingReason is reason as valid UTF-8 within store.MaxReasonBytes,
// truncated at a rune boundary with a marker.
func signingReason(reason string) string {
	const marker = " [truncated]"
	reason = strings.ToValidUTF8(reason, "\uFFFD")
	if len(reason) <= store.MaxReasonBytes {
		return reason
	}
	cut := store.MaxReasonBytes - len(marker)
	for cut > 0 && !utf8.RuneStart(reason[cut]) {
		cut--
	}
	return reason[:cut] + marker
}

// SigningStatus returns a job's signing record.
func (c *Controller) SigningStatus(ctx context.Context, id string) (store.SigningRecord, error) {
	return c.options.Store.GetSigning(ctx, id)
}

// sign hands the job's receipt, archive and manifest to the signer, checks
// the returned signer receipt against them, and stores the ipa and signer
// receipt as the job's App.ipa and signer-receipt.json artifacts.
func (c *Controller) sign(ctx context.Context, id string) ([]evidence.Artifact, error) {
	options := c.options.Signer
	job, err := c.options.Store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if job.Request.Kind != model.IOSArchive || job.State != model.Succeeded {
		return nil, store.ErrTransition
	}
	var completion Completion
	if err := json.Unmarshal(job.Result, &completion); err != nil {
		return nil, err
	}
	if len(completion.Receipt) == 0 {
		return nil, ErrNotReady
	}
	var archive, manifest evidence.Artifact
	for _, a := range completion.Result.Artifacts {
		switch a.Name {
		case profiles.ArchiveArtifact:
			archive = a
		case profiles.SigningManifestArtifact:
			manifest = a
		}
	}
	if archive.ID == "" || manifest.ID == "" {
		return nil, errors.New("job has no archive and signing manifest artifacts")
	}
	archivePath, manifestPath := signer.RequestPaths(options.Inbox, id)
	inbox := filepath.Dir(archivePath)
	if err := os.RemoveAll(inbox); err != nil {
		return nil, err
	}
	defer os.RemoveAll(inbox)
	if err := os.Mkdir(inbox, 0o700); err != nil {
		return nil, err
	}
	if err := errors.Join(os.Chown(inbox, -1, options.RPCGID), os.Chmod(inbox, 0o750)); err != nil {
		return nil, err
	}
	for _, item := range []struct {
		artifact evidence.Artifact
		target   string
	}{{archive, archivePath}, {manifest, manifestPath}} {
		if err := c.handOver(ctx, id, item.artifact, item.target, options.RPCGID); err != nil {
			return nil, fmt.Errorf("hand over %s: %w", item.artifact.Name, err)
		}
	}
	directory := "artifacts/" + id
	temporary, err := randomName()
	if err != nil {
		return nil, err
	}
	temporary = directory + "/" + temporary
	ipa, err := c.root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	defer c.root.Remove(temporary)
	result, signErr := options.Client.Sign(ctx, signer.Request{JobID: id, Receipt: completion.Receipt, ArchivePath: archivePath, ManifestPath: manifestPath}, ipa)
	if signErr == nil {
		signErr = ipa.Sync()
	}
	if err := errors.Join(signErr, ipa.Close()); err != nil {
		return nil, err
	}
	payload, err := signer.VerifyReceipt(result.Receipt, options.Keys)
	if err != nil {
		return nil, err
	}
	receiptDigest := sha256.Sum256(completion.Receipt)
	if payload.JobID != id || payload.IPA.SHA256 != result.IPASHA256 || payload.IPA.SizeBytes != result.IPASize || payload.Archive.SHA256 != archive.SHA256 || payload.Archive.SizeBytes != archive.SizeBytes || payload.SigningManifestSHA256 != manifest.SHA256 || payload.JobReceiptSHA256 != hex.EncodeToString(receiptDigest[:]) {
		return nil, errors.New("signer receipt does not match the job, its artifacts or the received ipa")
	}
	expires := c.options.Now().Add(7 * 24 * time.Hour)
	ipaArtifact := evidence.Artifact{ID: result.IPASHA256, Name: signer.IPAArtifact, MediaType: "application/octet-stream", SizeBytes: result.IPASize, SHA256: result.IPASHA256, ExpiresAt: expires}
	receiptDigestOut := sha256.Sum256(result.Receipt)
	receiptHex := hex.EncodeToString(receiptDigestOut[:])
	receiptArtifact := evidence.Artifact{ID: receiptHex, Name: signer.ReceiptArtifact, MediaType: "application/json", SizeBytes: int64(len(result.Receipt)), SHA256: receiptHex, ExpiresAt: expires}
	c.evidenceMu.Lock()
	defer c.evidenceMu.Unlock()
	if err := c.trimPool(ctx, result.IPASize+receiptArtifact.SizeBytes, maxArtifactPoolBytes); err != nil {
		return nil, err
	}
	if err := c.root.Rename(temporary, directory+"/"+ipaArtifact.ID); err != nil {
		return nil, err
	}
	c.poolBytes += result.IPASize
	if err := c.durable(directory+"/"+receiptArtifact.ID, result.Receipt); err != nil {
		return nil, err
	}
	c.poolBytes += receiptArtifact.SizeBytes
	return []evidence.Artifact{ipaArtifact, receiptArtifact}, nil
}

// handOver copies a stored artifact, checking its size and digest, into the
// inbox as a group-readable (0640, RPC group) file.
func (c *Controller) handOver(ctx context.Context, id string, a evidence.Artifact, target string, gid int) error {
	source, _, err := c.Artifact(ctx, id, a.ID)
	if err != nil {
		return err
	}
	defer source.Close()
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	hash := sha256.New()
	copied, err := io.Copy(io.MultiWriter(out, hash), io.LimitReader(source, a.SizeBytes+1))
	if err == nil && (copied != a.SizeBytes || hex.EncodeToString(hash.Sum(nil)) != a.SHA256) {
		err = evidence.ErrArtifact
	}
	if err == nil {
		err = errors.Join(out.Chown(-1, gid), out.Chmod(0o640))
	}
	return errors.Join(err, out.Close())
}

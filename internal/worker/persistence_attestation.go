package worker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/jerryfane/macserve/internal/hostguard"
)

// PersistenceFullScanTimeout bounds every explicit or maintenance full scan.
// Hot admission never walks or hashes a registered code tree.
const PersistenceFullScanTimeout = 8 * time.Minute

// PersistenceOperationTimeout leaves room around a full scan for protected
// authority publication and explicit reset's account cleanup and admission.
const PersistenceOperationTimeout = 9 * time.Minute

const persistenceAttestationFile = "persistence-attestation.json"

const persistenceAttestationLockTimeout = time.Second

var errPersistenceAttestationRevoked = errors.New("persistence attestation unavailable or revoked; reviewed acceptance and reset required")

// Build identity is immutable process metadata, not a filesystem trust cache.
var persistenceAttestationBuild = func() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return runtime.Version()
	}
	identity := info.GoVersion + ":" + info.Main.Path + ":" + info.Main.Version
	for _, setting := range info.Settings {
		if setting.Key == "vcs.revision" || setting.Key == "vcs.modified" {
			identity += ":" + setting.Key + "=" + setting.Value
		}
	}
	return identity
}()

// PersistenceAttestationMetadata contains only bounded, non-private health data.
// LastVerified survives revocation; it is not a claim that a revoked record is valid.
type PersistenceAttestationMetadata struct {
	LastVerified time.Time `json:"last_verified,omitempty"`
	Valid        bool      `json:"valid"`
	NeedsReview  bool      `json:"needs_review"`
	RevokedAt    time.Time `json:"revoked_at,omitempty"`
	Reason       string    `json:"reason,omitempty"`
}

type persistenceAttestationBinding struct {
	Version        int    `json:"version"`
	Build          string `json:"build"`
	ManifestSHA256 string `json:"manifest_sha256"`
	Boot           string `json:"boot"`
	JobUID         uint32 `json:"job_uid"`
	JobGID         uint32 `json:"job_gid"`
	OwnerUID       uint32 `json:"owner_uid"`
	ControllerUID  uint32 `json:"controller_uid"`
	HelperPath     string `json:"helper_path"`
}

type persistenceAttestation struct {
	PersistenceAttestationMetadata
	Binding  persistenceAttestationBinding `json:"binding"`
	Revision string                        `json:"revision"`
}

func attestationBinding(options Options, accepted []byte) (persistenceAttestationBinding, error) {
	boot, err := bootIdentity()
	if err != nil || boot == "" {
		return persistenceAttestationBinding{}, errors.Join(err, errors.New("boot identity unavailable"))
	}
	return persistenceAttestationBinding{Version: 1, Build: persistenceAttestationBuild, ManifestSHA256: persistenceHash(accepted), Boot: boot, JobUID: options.JobUID, JobGID: options.JobGID, OwnerUID: options.OwnerUID, ControllerUID: options.ControllerUID, HelperPath: options.HelperPath}, nil
}

// The scan lock serializes expensive inspections across processes. Publication
// has its own short-lived lock, so admission, revocation and review never wait
// for a full scan. Protected atomic snapshots do not require either lock.
func withAttestationRoot(ctx context.Context, options Options, operation func(*os.Root) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	parent := filepath.Dir(options.PersistencePath)
	name := filepath.Base(options.PersistencePath)
	if !filepath.IsAbs(options.PersistencePath) || filepath.Clean(options.PersistencePath) != options.PersistencePath || name == persistenceAttestationFile || name == persistenceAttestationFile+".lock" || name == persistenceAttestationFile+".scan.lock" {
		return errors.New("invalid persistence attestation authority path")
	}
	if runtime.GOOS == "darwin" {
		if err := hostguard.CheckProtectedPathContext(ctx, parent, true); err != nil {
			return err
		}
	} else {
		if _, err := registrationPath(parent, true, registrationWriters{}); err != nil {
			return err
		}
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := ctx.Err(); err != nil {
		return err
	}
	return operation(root)
}

func withAttestationLock(options Options, operation func(*os.Root) error) error {
	return withAttestationLockContext(context.Background(), options, operation)
}

func withAttestationLockContext(ctx context.Context, options Options, operation func(*os.Root) error) error {
	return withAttestationFileLock(ctx, options, persistenceAttestationFile+".lock", persistenceAttestationLockTimeout, operation)
}

func withAttestationFileLock(ctx context.Context, options Options, name string, wait time.Duration, operation func(*os.Root) error) error {
	waitCtx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	return withAttestationRoot(waitCtx, options, func(root *os.Root) error {
		lock, err := root.OpenFile(name, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
		if err != nil {
			return err
		}
		defer lock.Close()
		info, err := lock.Stat()
		if err != nil {
			return err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || st.Nlink != 1 {
			return errors.New("unprotected persistence attestation lock")
		}
		var retry *time.Ticker
		for {
			if err := waitCtx.Err(); err != nil {
				return err
			}
			err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
			if err == nil {
				break
			}
			if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EINTR) {
				return err
			}
			if retry == nil {
				retry = time.NewTicker(10 * time.Millisecond)
				defer retry.Stop()
			}
			select {
			case <-waitCtx.Done():
				return waitCtx.Err()
			case <-retry.C:
			}
		}
		defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		if err := waitCtx.Err(); err != nil {
			return err
		}
		return operation(root)
	})
}

func readAttestation(options Options) (persistenceAttestation, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), persistenceAdmissionTimeout)
	defer cancel()
	return readAttestationContext(ctx, options)
}

func readAttestationContext(ctx context.Context, options Options) (persistenceAttestation, []byte, error) {
	var record persistenceAttestation
	if err := ctx.Err(); err != nil {
		return record, nil, err
	}
	path := filepath.Join(filepath.Dir(options.PersistencePath), persistenceAttestationFile)
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return record, nil, nil
	} else if err != nil {
		return record, nil, err
	}
	var err error
	if runtime.GOOS == "darwin" {
		err = hostguard.CheckProtectedPathContext(ctx, path, false)
	} else {
		err = hostguard.RootConfig(path)
	}
	if err != nil {
		return record, nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return record, nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Mode().Perm() != 0600 {
		return record, nil, errors.New("unprotected persistence attestation")
	}
	data, err := io.ReadAll(io.LimitReader(file, 16385))
	if err != nil || len(data) > 16384 {
		return record, nil, errors.New("persistence attestation unavailable")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return record, nil, err
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(data, canonical) || len(record.Revision) != 32 || record.Valid == record.NeedsReview {
		return record, nil, errors.New("invalid persistence attestation")
	}
	switch record.Reason {
	case "", "mismatch", "inspection_unavailable", "authority_changed", "reset_required":
	default:
		return record, nil, errors.New("invalid persistence attestation reason")
	}
	if record.Valid && (record.LastVerified.IsZero() || !record.RevokedAt.IsZero() || record.Reason != "") {
		return record, nil, errors.New("incomplete persistence attestation")
	}
	return record, data, ctx.Err()
}

func writeAttestation(root *os.Root, record persistenceAttestation) error {
	var revision [16]byte
	if _, err := rand.Read(revision[:]); err != nil {
		return err
	}
	record.Revision = hex.EncodeToString(revision[:])
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return durableFile(root, persistenceAttestationFile, data)
}

// PersistenceAttestationStatus reads protected atomic snapshots without waiting
// for either writer lock. Bracketing the authority binding detects concurrent
// publication; an unstable snapshot refuses readiness rather than retrying.
// Age alone never grants or revokes admission.
func PersistenceAttestationStatus(options Options) (PersistenceAttestationMetadata, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var status PersistenceAttestationMetadata
	err := withAttestationRoot(ctx, options, func(_ *os.Root) error {
		record, data, err := readAttestationContext(ctx, options)
		if err != nil {
			return err
		}
		status = record.PersistenceAttestationMetadata
		if len(data) == 0 {
			status.Reason = "missing"
			return nil
		}
		_, accepted, err := readPersistenceContext(ctx, options.PersistencePath, options.JobUID)
		if err != nil {
			return err
		}
		binding, err := attestationBinding(options, accepted)
		if err != nil {
			return err
		}
		latest, _, err := readAttestationContext(ctx, options)
		if err != nil {
			return err
		}
		_, after, err := readPersistenceContext(ctx, options.PersistencePath, options.JobUID)
		if err != nil {
			return err
		}
		if latest.Revision != record.Revision || !bytes.Equal(accepted, after) {
			return errors.New("persistence authority or attestation changed during status read")
		}
		if record.Valid && record.Binding != binding {
			status.Valid, status.NeedsReview, status.Reason = false, true, "authority_changed"
		}
		return ctx.Err()
	})
	if err != nil {
		status.Valid = false
	}
	return status, err
}

// Reviewed acceptance deliberately establishes reset_required. No automatic
// failure, even a confirmed mismatch, may undo that operator-owned marker.
func attestationReasonPrecedence(reason string) int {
	switch reason {
	case "reset_required":
		return 4
	case "mismatch":
		return 3
	case "authority_changed":
		return 2
	case "inspection_unavailable":
		return 1
	default:
		return 0
	}
}

func revokeAttestation(root *os.Root, record persistenceAttestation, cause error) error {
	reason := "inspection_unavailable"
	if errors.Is(cause, ErrContamination) {
		reason = "mismatch"
	}
	if record.NeedsReview && attestationReasonPrecedence(record.Reason) >= attestationReasonPrecedence(reason) {
		return nil
	}
	record.Valid, record.NeedsReview = false, true
	record.RevokedAt = time.Now().UTC()
	record.Reason = reason
	return writeAttestation(root, record)
}

func revokePersistenceAttestation(options Options, cause error) error {
	ctx, cancel := context.WithTimeout(context.Background(), persistenceAttestationLockTimeout)
	defer cancel()
	return withAttestationLockContext(ctx, options, func(root *os.Root) error {
		record, _, err := readAttestationContext(ctx, options)
		if err != nil {
			return err
		}
		return revokeAttestation(root, record, cause)
	})
}

// Only the revision actually inspected may be revoked. In particular, a stale
// failed scan or hot observation cannot revoke a newer verified publication.
func revokePersistenceAttestationRevision(ctx context.Context, options Options, revision string, cause error) error {
	return withAttestationLockContext(ctx, options, func(root *os.Root) error {
		record, _, err := readAttestationContext(ctx, options)
		if err != nil {
			return err
		}
		if record.Revision != revision {
			return nil
		}
		return revokeAttestation(root, record, cause)
	})
}

func markPersistenceReviewed(options Options) error {
	ctx, cancel := context.WithTimeout(context.Background(), persistenceAttestationLockTimeout)
	defer cancel()
	return withAttestationLockContext(ctx, options, func(root *os.Root) error {
		record, _, err := readAttestationContext(ctx, options)
		if err != nil {
			return err
		}
		_, accepted, err := readPersistenceContext(ctx, options.PersistencePath, options.JobUID)
		if err != nil {
			return err
		}
		record.Binding, err = attestationBinding(options, accepted)
		if err != nil {
			return err
		}
		record.Valid, record.NeedsReview, record.Reason = false, true, "reset_required"
		record.RevokedAt = time.Now().UTC()
		return writeAttestation(root, record)
	})
}

// VerifyPersistenceAttestation fully measures accepted registration code and
// atomically publishes its attestation. It never clears quarantine or a revoked
// attestation: fresh reviewed acceptance followed by explicit reset is required.
func VerifyPersistenceAttestation(ctx context.Context, options Options) error {
	return verifyPersistenceAttestation(ctx, options, false, collectPersistence)
}

func verifyPersistenceAttestation(ctx context.Context, options Options, reset bool, collect func(context.Context, Options) (PersistenceManifest, error)) error {
	ctx, cancel := context.WithTimeout(ctx, PersistenceOperationTimeout)
	defer cancel()
	// A contending invocation does not inspect or revoke anything. Its bounded
	// wait precedes the full 480-second collector budget, within the 540-second
	// operation budget shared with explicit reset.
	return withAttestationFileLock(ctx, options, persistenceAttestationFile+".scan.lock", persistenceAdmissionTimeout, func(_ *os.Root) (result error) {
		scanCtx, cancel := context.WithTimeout(ctx, PersistenceFullScanTimeout)
		defer cancel()
		var revision string
		var checked bool
		defer func() {
			if result != nil && checked && !errors.Is(result, errPersistenceAttestationRevoked) {
				// Preserve full-scan failure evidence even after its deadline,
				// without allowing cleanup to block behind a stuck publisher.
				cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(scanCtx), persistenceAttestationLockTimeout)
				defer cancel()
				result = errors.Join(result, revokePersistenceAttestationRevision(cleanupCtx, options, revision, result))
			}
		}()
		var accepted []byte
		var expected PersistenceManifest
		var binding persistenceAttestationBinding
		err := withAttestationLockContext(scanCtx, options, func(_ *os.Root) error {
			record, _, err := readAttestationContext(scanCtx, options)
			if err != nil {
				return err
			}
			if record.NeedsReview && !(reset && record.Reason == "reset_required") {
				return errPersistenceAttestationRevoked
			}
			revision, checked = record.Revision, true
			expected, accepted, err = readPersistenceContext(scanCtx, options.PersistencePath, options.JobUID)
			if err != nil {
				return err
			}
			binding, err = attestationBinding(options, accepted)
			return err
		})
		if err != nil {
			return err
		}
		current, err := collect(scanCtx, options)
		if err != nil {
			return err
		}
		if err := matchPersistence(expected, current); err != nil {
			return err
		}
		return withAttestationLockContext(scanCtx, options, func(root *os.Root) error {
			if err := scanCtx.Err(); err != nil {
				return err
			}
			latest, _, err := readAttestationContext(scanCtx, options)
			if err != nil {
				return err
			}
			_, after, err := readPersistenceContext(scanCtx, options.PersistencePath, options.JobUID)
			if err != nil {
				return err
			}
			afterBinding, err := attestationBinding(options, after)
			if err != nil {
				return err
			}
			if latest.Revision != revision || !bytes.Equal(after, accepted) || afterBinding != binding {
				return errors.New("persistence authority or attestation changed during inspection")
			}
			if err := scanCtx.Err(); err != nil {
				return err
			}
			return writeAttestation(root, persistenceAttestation{PersistenceAttestationMetadata: PersistenceAttestationMetadata{Valid: true, LastVerified: time.Now().UTC()}, Binding: binding})
		})
	})
}

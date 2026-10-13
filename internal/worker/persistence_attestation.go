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

// Publication uses a separate, short-lived cross-process lock, never worker.lock.
// The expensive scan runs unlocked; its initial revision must still match when
// publishing. A scan begun before a revocation or review cannot overwrite it.
func withAttestationLock(options Options, operation func(*os.Root) error) error {
	parent := filepath.Dir(options.PersistencePath)
	if !filepath.IsAbs(options.PersistencePath) || filepath.Clean(options.PersistencePath) != options.PersistencePath || filepath.Base(options.PersistencePath) == persistenceAttestationFile || filepath.Base(options.PersistencePath) == persistenceAttestationFile+".lock" {
		return errors.New("invalid persistence attestation authority path")
	}
	if runtime.GOOS == "darwin" {
		if err := hostguard.CheckProtectedPath(parent, true); err != nil {
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
	name := persistenceAttestationFile + ".lock"
	lock, err := root.OpenFile(name, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
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
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	return operation(root)
}

func readAttestation(options Options) (persistenceAttestation, []byte, error) {
	var record persistenceAttestation
	path := filepath.Join(filepath.Dir(options.PersistencePath), persistenceAttestationFile)
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return record, nil, nil
	} else if err != nil {
		return record, nil, err
	}
	var err error
	if runtime.GOOS == "darwin" {
		err = hostguard.CheckProtectedPath(path, false)
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
	return record, data, nil
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

// PersistenceAttestationStatus reads fresh protected metadata and its current
// boot/identity/manifest binding. Age alone never grants or revokes admission.
func PersistenceAttestationStatus(options Options) (PersistenceAttestationMetadata, error) {
	var status PersistenceAttestationMetadata
	err := withAttestationLock(options, func(_ *os.Root) error {
		record, data, err := readAttestation(options)
		if err != nil {
			return err
		}
		status = record.PersistenceAttestationMetadata
		if len(data) == 0 {
			status.Reason = "missing"
			return nil
		}
		_, accepted, err := readPersistence(options.PersistencePath, options.JobUID)
		if err != nil {
			status.Valid = false
			return err
		}
		binding, err := attestationBinding(options, accepted)
		if err != nil {
			status.Valid = false
			return err
		}
		if record.Valid && record.Binding != binding {
			status.Valid, status.NeedsReview, status.Reason = false, true, "authority_changed"
		}
		return nil
	})
	return status, err
}

func revokePersistenceAttestation(options Options, cause error) error {
	return withAttestationLock(options, func(root *os.Root) error {
		record, _, err := readAttestation(options)
		if err != nil {
			return err
		}
		// Keep the first failure and last successful verification, including
		// when a later scanner merely finds that admission was already revoked.
		if record.NeedsReview && record.Reason != "reset_required" {
			return nil
		}
		record.Valid, record.NeedsReview = false, true
		record.RevokedAt = time.Now().UTC()
		record.Reason = "inspection_unavailable"
		if errors.Is(cause, ErrContamination) {
			record.Reason = "mismatch"
		}
		return writeAttestation(root, record)
	})
}

func markPersistenceReviewed(options Options) error {
	return withAttestationLock(options, func(root *os.Root) error {
		record, _, err := readAttestation(options)
		if err != nil {
			return err
		}
		_, accepted, err := readPersistence(options.PersistencePath, options.JobUID)
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

func verifyPersistenceAttestation(ctx context.Context, options Options, reset bool, collect func(context.Context, Options) (PersistenceManifest, error)) (result error) {
	ctx, cancel := context.WithTimeout(ctx, PersistenceFullScanTimeout)
	defer cancel()
	defer func() {
		if result != nil && !errors.Is(result, errPersistenceAttestationRevoked) {
			result = errors.Join(result, revokePersistenceAttestation(options, result))
		}
	}()
	var initial []byte
	var accepted []byte
	var expected PersistenceManifest
	var binding persistenceAttestationBinding
	err := withAttestationLock(options, func(_ *os.Root) error {
		record, data, err := readAttestation(options)
		if err != nil {
			return err
		}
		if record.NeedsReview && !(reset && record.Reason == "reset_required") {
			return errPersistenceAttestationRevoked
		}
		initial = data
		expected, accepted, err = readPersistence(options.PersistencePath, options.JobUID)
		if err != nil {
			return err
		}
		binding, err = attestationBinding(options, accepted)
		return err
	})
	if err != nil {
		return err
	}
	current, err := collect(ctx, options)
	if err != nil {
		return err
	}
	if err := matchPersistence(expected, current); err != nil {
		return err
	}
	return withAttestationLock(options, func(root *os.Root) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		_, latest, err := readAttestation(options)
		if err != nil {
			return err
		}
		_, after, err := readPersistence(options.PersistencePath, options.JobUID)
		if err != nil {
			return err
		}
		afterBinding, err := attestationBinding(options, after)
		if err != nil {
			return err
		}
		if !bytes.Equal(latest, initial) || !bytes.Equal(after, accepted) || afterBinding != binding {
			return errors.New("persistence authority or attestation changed during inspection")
		}
		return writeAttestation(root, persistenceAttestation{PersistenceAttestationMetadata: PersistenceAttestationMetadata{Valid: true, LastVerified: time.Now().UTC()}, Binding: binding})
	})
}

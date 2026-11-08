package maintenance

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/jerryfane/macserve/internal/hostguard"
	"github.com/jerryfane/macserve/internal/worker"
	"github.com/jerryfane/macserve/internal/workerclient"
)

const persistenceScanInterval = 6 * time.Hour

// A periodic scan that fails without observing contamination (it ran out of
// time, a background registration changed while it ran, inspection was
// incomplete, or maintenance stopped) leaves the attestation in place and is
// retried persistenceRetryInterval after it ended. The scan after
// persistenceInconclusiveLimit consecutive inconclusive scans revokes on any
// failure, as every explicit scan does. On 2026-11-08 one such failure took the
// Studio out of service until an owner sitting although nothing had changed.
const (
	persistenceRetryInterval     = 10 * time.Minute
	persistenceInconclusiveLimit = 3
)

func persistenceOptions(c Config) (worker.Options, error) {
	if err := hostguard.RootConfig(c.WorkerConfig); err != nil {
		return worker.Options{}, err
	}
	wc, err := workerclient.LoadConfig(c.WorkerConfig)
	if err != nil {
		return worker.Options{}, err
	}
	return worker.Options{Root: wc.Root, ExportRoot: wc.ExportRoot, WorkspaceRoot: wc.WorkspaceRoot,
		JobUID: wc.JobUID, JobGID: wc.JobGID, OwnerUID: wc.OwnerUID, ControllerUID: wc.ControllerUID,
		HelperPath: wc.HelperPath, BaselinePath: wc.BaselinePath, PersistencePath: wc.PersistencePath}, nil
}

// VerifyPersistence performs the explicit full qualification scan, separately
// from Inspect's eight-second live observation. It never clears a revocation.
func VerifyPersistence(ctx context.Context, c Config) error {
	return scanPersistence(ctx, c, worker.VerifyPersistenceAttestation)
}

// RebindPersistenceBuild is VerifyPersistence for a carried release: it
// refuses unless the stored attestation differs from the live binding only in
// the macserve build (see worker.RebindPersistenceBuild).
func RebindPersistenceBuild(ctx context.Context, c Config) error {
	return scanPersistence(ctx, c, worker.RebindPersistenceBuild)
}

func scanPersistence(ctx context.Context, c Config, scan func(context.Context, worker.Options) error) error {
	current, err := LoadConfig(c.path)
	if err != nil {
		return err
	}
	opts, err := persistenceOptions(current)
	if err != nil {
		return err
	}
	return scan(ctx, opts)
}

// A monitor owns at most one scan. No worker lock is held: the worker publishes
// a protected atomic attestation, and admissions continue using fresh cheap checks.
type persistenceMonitor struct {
	verify      func(ctx context.Context, opts worker.Options, revokeInconclusive bool) error
	done        chan struct{}
	result      error // of the scan that closed done; read only after done closes
	finished    time.Time
	nextAttempt time.Time
	// inconclusive counts consecutive periodic scans that left the attestation
	// in place without verifying it.
	inconclusive int
	now          func() time.Time
}

func (m *persistenceMonitor) schedule(ctx context.Context, now time.Time, opts worker.Options, status worker.PersistenceAttestationMetadata, statusErr error) {
	if m.done != nil {
		select {
		case <-m.done:
			m.done = nil
			if errors.Is(m.result, worker.ErrPersistenceScanInconclusive) {
				m.inconclusive++
				m.nextAttempt = m.finished.Add(persistenceRetryInterval)
				log.Printf("macserve maintenance: periodic persistence scan inconclusive (%d of %d before it revokes); retrying after %s: %v",
					m.inconclusive, persistenceInconclusiveLimit, m.nextAttempt.UTC().Format(time.RFC3339), m.result)
			} else {
				if m.result != nil {
					log.Printf("macserve maintenance: periodic persistence scan failed: %v", m.result)
				}
				m.inconclusive = 0
			}
		default:
			return
		}
	}
	if ctx.Err() != nil || status.NeedsReview || !status.RevokedAt.IsZero() || now.Before(m.nextAttempt) {
		return
	}
	if statusErr == nil && status.Valid && now.Before(status.LastVerified.Add(persistenceScanInterval)) {
		m.inconclusive = 0
		return
	}
	revokeInconclusive := m.inconclusive >= persistenceInconclusiveLimit
	m.nextAttempt = now.Add(persistenceScanInterval)
	m.done = make(chan struct{})
	done := m.done
	clock := m.now
	if clock == nil {
		clock = time.Now
	}
	go func() {
		defer close(done)
		// The worker bounds the collector at 480s; the 540s operation deadline
		// leaves publication/revocation headroom, independently of the 8s tick.
		scanCtx, cancel := context.WithTimeout(ctx, worker.PersistenceOperationTimeout)
		defer cancel()
		// Contamination always revokes; other failures revoke only once
		// persistenceInconclusiveLimit consecutive scans were inconclusive.
		m.result = m.verify(scanCtx, opts, revokeInconclusive)
		m.finished = clock()
	}()
}

func monitorPersistence(ctx context.Context, path string) {
	m := persistenceMonitor{verify: worker.ReverifyPersistenceAttestation}
	defer func() {
		if m.done != nil {
			<-m.done // Allow a running scan's protected publication to finish before exit.
		}
	}()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		if current, err := LoadConfig(path); err == nil {
			if opts, err := persistenceOptions(current); err == nil {
				status, statusErr := worker.PersistenceAttestationStatus(opts)
				m.schedule(ctx, time.Now(), opts, status, statusErr)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

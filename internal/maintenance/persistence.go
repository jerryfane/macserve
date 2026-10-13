package maintenance

import (
	"context"
	"time"

	"github.com/jerryfane/macserve/internal/hostguard"
	"github.com/jerryfane/macserve/internal/worker"
	"github.com/jerryfane/macserve/internal/workerclient"
)

const persistenceScanInterval = 6 * time.Hour

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
	current, err := LoadConfig(c.path)
	if err != nil {
		return err
	}
	opts, err := persistenceOptions(current)
	if err != nil {
		return err
	}
	return worker.VerifyPersistenceAttestation(ctx, opts)
}

// A monitor owns at most one scan. No worker lock is held: the worker publishes
// a protected atomic attestation, and admissions continue using fresh cheap checks.
type persistenceMonitor struct {
	verify      func(context.Context, worker.Options) error
	done        chan struct{}
	nextAttempt time.Time
}

func (m *persistenceMonitor) schedule(ctx context.Context, now time.Time, opts worker.Options, status worker.PersistenceAttestationMetadata, statusErr error) {
	if m.done != nil {
		select {
		case <-m.done:
			m.done = nil
		default:
			return
		}
	}
	if ctx.Err() != nil || status.NeedsReview || !status.RevokedAt.IsZero() || now.Before(m.nextAttempt) {
		return
	}
	if statusErr == nil && status.Valid && now.Before(status.LastVerified.Add(persistenceScanInterval)) {
		return
	}
	m.nextAttempt = now.Add(persistenceScanInterval)
	m.done = make(chan struct{})
	done := m.done
	go func() {
		defer close(done)
		// The worker bounds the collector at 480s; the 540s operation deadline
		// leaves publication/revocation headroom, independently of the 8s tick.
		scanCtx, cancel := context.WithTimeout(ctx, worker.PersistenceOperationTimeout)
		defer cancel()
		_ = m.verify(scanCtx, opts) // Verification durably revokes on any failure.
	}()
}

func monitorPersistence(ctx context.Context, path string) {
	m := persistenceMonitor{verify: worker.VerifyPersistenceAttestation}
	defer func() {
		if m.done != nil {
			<-m.done // Allow cancellation's protected revocation to finish before exit.
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

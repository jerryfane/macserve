package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jerryfane/macserve/internal/model"
)

// RegisterWorker records the authenticated, locally recovered worker epoch. A
// replacement fences the old epoch permanently, including after job retention.
func (s *Store) RegisterWorker(ctx context.Context, epoch string) error {
	if !validOpaque(epoch, 256) {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Retire the earlier controller epoch table without reopening its last epoch.
	var legacy bool
	if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='worker_runtime')").Scan(&legacy); err != nil {
		return err
	}
	if legacy {
		if _, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO invalid_epochs(epoch) SELECT epoch FROM worker_runtime WHERE epoch<>?", epoch); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "DROP TABLE worker_runtime"); err != nil {
			return err
		}
	}
	var invalid bool
	if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM invalid_epochs WHERE epoch=?)", epoch).Scan(&invalid); err != nil {
		return err
	}
	if invalid {
		return ErrLease
	}
	job, err := scanJob(tx.QueryRowContext(ctx, "SELECT "+jobColumns+" FROM jobs WHERE state IN ("+activeStates+")"))
	if err == nil {
		if job.WorkerEpoch == epoch {
			return tx.Commit()
		}
		return ErrTransition
	}
	if !errors.Is(err, ErrNotFound) {
		return err
	}
	var old string
	err = tx.QueryRowContext(ctx, "SELECT acknowledged_epoch FROM service_state WHERE singleton=1").Scan(&old)
	if err != nil {
		return err
	}
	if old != "" && old != epoch {
		if _, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO invalid_epochs(epoch) VALUES(?)", old); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, "UPDATE service_state SET acknowledged_epoch=?,quarantined=0,quarantine_reason='',generation=generation+1 WHERE singleton=1 AND (quarantined=1 OR acknowledged_epoch<>?)", epoch, epoch); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Active(ctx context.Context) (model.Job, error) {
	return scanJob(s.db.QueryRowContext(ctx, "SELECT "+jobColumns+" FROM jobs WHERE state IN ("+activeStates+")"))
}

// Fail atomically ends uncertain or controller-side preparation work. Uncertain
// cleanup fences its epoch before releasing the global active slot.
func (s *Store) Fail(ctx context.Context, id, lease string, state model.State, cleanupOK bool, reason string, now time.Time) error {
	return s.fail(ctx, id, lease, state, cleanupOK, true, reason, now)
}

// FailPreparation fences an uncertain preparation epoch without claiming the
// worker left live processes: it has not received this lease. Independent source
// cleanup debt keeps admission closed until the controller confirms removal.
func (s *Store) FailPreparation(ctx context.Context, id, lease string, state model.State, cleanupOK bool, reason string, now time.Time) error {
	return s.fail(ctx, id, lease, state, cleanupOK, false, reason, now)
}

func (s *Store) fail(ctx context.Context, id, lease string, state model.State, cleanupOK, workerUncertain bool, reason string, now time.Time) error {
	if !model.Finalizing.CanTransition(state) || state == model.Succeeded || !validReason(reason) || !validTime(now) {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	job, err := getTx(ctx, tx, id)
	if err != nil {
		return err
	}
	if lease == "" || job.LeaseToken != lease {
		return ErrLease
	}
	if !active(job.State) {
		return ErrTransition
	}
	if !cleanupOK {
		if workerUncertain {
			err = quarantine(ctx, tx, job.WorkerEpoch, reason)
		} else {
			_, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO invalid_epochs(epoch) VALUES(?)", job.WorkerEpoch)
		}
		if err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, "UPDATE jobs SET state=?,cleanup_ok=?,reason=?,updated_at=?,finished_at=? WHERE id=?", state, cleanupOK, reason, now.UnixNano(), now.UnixNano(), id)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// LogsTruncated reads the durable completeness bit without fetching log pages.
func (s *Store) LogsTruncated(ctx context.Context, id string) (bool, error) {
	var truncated bool
	err := s.db.QueryRowContext(ctx, "SELECT logs_truncated FROM jobs WHERE id=?", id).Scan(&truncated)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return truncated, err
}

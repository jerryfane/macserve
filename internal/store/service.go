package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jerryfane/macserve/internal/model"
)

const serviceColumns = "paused,pause_reason,pause_mode,generation,(quarantined OR " + sourceCleanupPending + "),CASE WHEN " + sourceCleanupPending + " THEN CASE WHEN quarantined=1 THEN quarantine_reason || '; controller source cleanup pending' ELSE 'controller source cleanup pending' END ELSE quarantine_reason END"

func scanService(row scanner) (model.ServiceState, error) {
	var state model.ServiceState
	err := row.Scan(&state.Paused, &state.PauseReason, &state.PauseMode, &state.Generation, &state.Quarantined, &state.QuarantineReason)
	return state, err
}

func (s *Store) ServiceState(ctx context.Context) (model.ServiceState, error) {
	return scanService(s.db.QueryRowContext(ctx, "SELECT "+serviceColumns+" FROM service_state WHERE singleton=1"))
}

func (s *Store) Pause(ctx context.Context, reason, mode string, now time.Time) (model.ServiceState, error) {
	if mode != "drain" && mode != "cancel_active" || !validReason(reason) || !validTime(now) {
		return model.ServiceState{}, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.ServiceState{}, err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, "UPDATE service_state SET paused=1,pause_reason=?,pause_mode=?,generation=generation+1 WHERE singleton=1", reason, mode)
	if err != nil {
		return model.ServiceState{}, err
	}
	if mode == "cancel_active" {
		job, err := scanJob(tx.QueryRowContext(ctx, "SELECT "+jobColumns+" FROM jobs WHERE state IN ("+activeStates+")"))
		if err == nil {
			if err := cancelTx(ctx, tx, job, reason, now); err != nil {
				return model.ServiceState{}, err
			}
		} else if !errors.Is(err, ErrNotFound) {
			return model.ServiceState{}, err
		}
	}
	state, err := scanService(tx.QueryRowContext(ctx, "SELECT "+serviceColumns+" FROM service_state WHERE singleton=1"))
	if err != nil {
		return model.ServiceState{}, err
	}
	if err := tx.Commit(); err != nil {
		return model.ServiceState{}, err
	}
	return state, nil
}

// Resume clears only the manual pause, never the independent quarantine gate.
func (s *Store) Resume(ctx context.Context) (model.ServiceState, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.ServiceState{}, err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, "UPDATE service_state SET paused=0,pause_reason='',pause_mode='',generation=generation+1 WHERE singleton=1 AND paused=1")
	if err != nil {
		return model.ServiceState{}, err
	}
	state, err := scanService(tx.QueryRowContext(ctx, "SELECT "+serviceColumns+" FROM service_state WHERE singleton=1"))
	if err != nil {
		return model.ServiceState{}, err
	}
	if err := tx.Commit(); err != nil {
		return model.ServiceState{}, err
	}
	return state, nil
}

func quarantine(ctx context.Context, tx *sql.Tx, epoch, reason string) error {
	if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO invalid_epochs(epoch) VALUES(?)", epoch); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, "UPDATE service_state SET quarantined=1,quarantine_reason=?,generation=generation+1 WHERE singleton=1", reason)
	return err
}

// Recover interrupts rather than resumes an old execution. Its epoch remains
// invalid even after metadata retention expires or a later epoch is acknowledged.
// Call only at controller startup after excluding another live controller.
func (s *Store) Recover(ctx context.Context, now time.Time) error {
	if !validTime(now) {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	job, err := scanJob(tx.QueryRowContext(ctx, "SELECT "+jobColumns+" FROM jobs WHERE state IN ("+activeStates+")"))
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := quarantine(ctx, tx, job.WorkerEpoch, "interrupted worker requires quiescence verification"); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "UPDATE jobs SET state='interrupted',reason='controller recovery',cleanup_ok=0,updated_at=?,finished_at=? WHERE id=?", now.UnixNano(), now.UnixNano(), job.ID)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// AcknowledgeQuiescent is a trust boundary: the caller must authenticate the new
// worker's peer identity and prove the previous process/device set is quiescent.
// A string alone is not proof. This method enforces no active job and rejects all
// epochs previously invalidated by interruption or failed cleanup.
func (s *Store) AcknowledgeQuiescent(ctx context.Context, workerEpoch string) error {
	if !validOpaque(workerEpoch, 256) {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists bool
	if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM jobs WHERE state IN ("+activeStates+"))").Scan(&exists); err != nil {
		return err
	}
	if exists {
		return ErrTransition
	}
	if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM invalid_epochs WHERE epoch=?)", workerEpoch).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return ErrLease
	}
	var prior string
	if err := tx.QueryRowContext(ctx, "SELECT acknowledged_epoch FROM service_state WHERE singleton=1").Scan(&prior); err != nil {
		return err
	}
	if prior != "" && prior != workerEpoch {
		if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO invalid_epochs(epoch) VALUES(?)", prior); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, "UPDATE service_state SET acknowledged_epoch=?,quarantined=0,quarantine_reason='',generation=generation+1 WHERE singleton=1 AND (quarantined=1 OR acknowledged_epoch<>?)", workerEpoch, workerEpoch)
	if err != nil {
		return err
	}
	return tx.Commit()
}

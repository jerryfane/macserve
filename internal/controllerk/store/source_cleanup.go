package store

import (
	"context"
)

// Cleanup debt intentionally has no foreign key: pruning a terminal job must not
// erase the controller's obligation to reclaim its private source export.
const sourceCleanupSchema = `
CREATE TABLE source_cleanup (job_id TEXT PRIMARY KEY);
INSERT INTO source_cleanup(job_id) SELECT id FROM jobs WHERE worker_epoch<>'' AND (state IN ('preparing','running','cancelling','finalizing') OR cleanup_ok=0);
CREATE TRIGGER source_cleanup_insert AFTER INSERT ON source_cleanup BEGIN
 UPDATE service_state SET generation=generation+1 WHERE singleton=1;
END;
CREATE TRIGGER source_cleanup_delete AFTER DELETE ON source_cleanup BEGIN
 UPDATE service_state SET generation=generation+1 WHERE singleton=1;
END;
PRAGMA user_version=3;
`

const sourceCleanupPending = "EXISTS(SELECT 1 FROM source_cleanup LEFT JOIN jobs ON jobs.id=source_cleanup.job_id WHERE jobs.id IS NULL OR jobs.state NOT IN (" + activeStates + "))"

// RequireSourceCleanup records intent before the exporter can write any bytes.
// Active jobs already exclude other claims; their intent is not a quarantine.
func (s *Store) RequireSourceCleanup(ctx context.Context, id string) error {
	if !validOpaque(id, 128) {
		return ErrInvalid
	}
	_, err := s.db.ExecContext(ctx, "INSERT OR IGNORE INTO source_cleanup(job_id) VALUES(?)", id)
	return err
}

// PendingSourceCleanup returns only inactive exports, never an export still
// being prepared, streamed, or used to verify a worker completion.
func (s *Store) PendingSourceCleanup(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT source_cleanup.job_id FROM source_cleanup LEFT JOIN jobs ON jobs.id=source_cleanup.job_id WHERE jobs.id IS NULL OR jobs.state NOT IN ("+activeStates+") ORDER BY source_cleanup.job_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ConfirmSourceCleanup clears controller-owned debt only after protected removal
// succeeds. It never acknowledges worker quiescence or rewrites job evidence.
func (s *Store) ConfirmSourceCleanup(ctx context.Context, id string) error {
	if !validOpaque(id, 128) {
		return ErrInvalid
	}
	_, err := s.db.ExecContext(ctx, "DELETE FROM source_cleanup WHERE job_id=?", id)
	return err
}

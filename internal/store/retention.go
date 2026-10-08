package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

const reviewSchema = `
ALTER TABLE service_state ADD COLUMN acknowledged_epoch TEXT NOT NULL DEFAULT '';
ALTER TABLE service_state ADD COLUMN retained_log_bytes INTEGER NOT NULL DEFAULT 0 CHECK(retained_log_bytes>=0);
ALTER TABLE jobs ADD COLUMN logs_evicted INTEGER NOT NULL DEFAULT 0 CHECK(logs_evicted IN (0,1));
UPDATE service_state SET retained_log_bytes=(SELECT COALESCE(SUM(length(text)),0) FROM logs), acknowledged_epoch=COALESCE((SELECT worker_epoch FROM jobs WHERE state IN ('preparing','running','cancelling','finalizing') LIMIT 1),'') WHERE singleton=1;
CREATE TRIGGER logs_account_insert AFTER INSERT ON logs BEGIN
 UPDATE service_state SET retained_log_bytes=retained_log_bytes+length(NEW.text) WHERE singleton=1;
END;
CREATE TRIGGER logs_account_delete AFTER DELETE ON logs BEGIN
 UPDATE service_state SET retained_log_bytes=retained_log_bytes-length(OLD.text) WHERE singleton=1;
END;
PRAGMA user_version=2;
`

// reserveLog evicts only old terminal bytes. Result envelopes, log sequence and
// completeness-at-finalization remain immutable; a separate tombstone records
// retention loss. The caller's transaction also covers insertion and accounting.
func (s *Store) reserveLog(ctx context.Context, tx *sql.Tx, size int64) (bool, error) {
	for {
		var total int64
		if err := tx.QueryRowContext(ctx, "SELECT retained_log_bytes FROM service_state WHERE singleton=1").Scan(&total); err != nil {
			return false, err
		}
		if size <= s.options.MaxTotalLogBytes-total {
			return true, nil
		}
		var id string
		err := tx.QueryRowContext(ctx, "SELECT id FROM jobs WHERE state IN ("+terminalStates+") AND log_bytes>0 ORDER BY finished_at,sequence LIMIT 1").Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if err := evictLogs(ctx, tx, id); err != nil {
			return false, err
		}
	}
}
func evictLogs(ctx context.Context, tx *sql.Tx, id string) error {
	if _, err := tx.ExecContext(ctx, "DELETE FROM logs WHERE job_id=?", id); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, "UPDATE jobs SET log_bytes=0,logs_evicted=1 WHERE id=?", id)
	return err
}
func (s *Store) pruneLogs(ctx context.Context, tx *sql.Tx, now time.Time) error {
	cutoff := now.Add(-s.options.LogRetention).UnixNano()
	predicate := "state IN (" + terminalStates + ") AND finished_at<=? AND log_bytes>0"
	if _, err := tx.ExecContext(ctx, "DELETE FROM logs WHERE job_id IN (SELECT id FROM jobs WHERE "+predicate+")", cutoff); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, "UPDATE jobs SET log_bytes=0,logs_evicted=1 WHERE "+predicate, cutoff)
	return err
}

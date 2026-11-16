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
// A job Prune tombstoned whose records are not all deleted yet is a candidate
// too: its bytes are still retained.
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
		err := tx.QueryRowContext(ctx, "SELECT id FROM jobs WHERE state IN ("+terminalStates+") AND (log_bytes>0 OR logs_evicted=1 AND EXISTS(SELECT 1 FROM logs WHERE logs.job_id=jobs.id)) ORDER BY finished_at,sequence LIMIT 1").Scan(&id)
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

// Prune's batches: pruneBatchJobs bounds the job rows, pruneBatchRows the
// log records and pruneBatchBytes the log and job bytes one write
// transaction changes. A batch always makes progress: its first row is
// taken whatever its size.
const (
	pruneBatchJobs  = 200
	pruneBatchRows  = 2000
	pruneBatchBytes = 4 << 20
)

// expireLogs tombstones the logs of at most pruneBatchJobs terminal jobs
// finished at or before cutoff, and returns how many. Their records are
// deleted afterwards (deleteExpiredLogs): a reader sees the tombstone
// (ErrLogExpired), never a partial log.
func expireLogs(ctx context.Context, tx *sql.Tx, cutoff time.Time) (int64, error) {
	result, err := tx.ExecContext(ctx, "UPDATE jobs SET log_bytes=0,logs_evicted=1 WHERE id IN (SELECT id FROM jobs WHERE state IN ("+terminalStates+") AND finished_at<=? AND log_bytes>0 LIMIT ?)", cutoff.UnixNano(), pruneBatchJobs)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// deleteExpiredLogs deletes one batch of the records of tombstoned logs,
// oldest job and record first, and returns how many; the accounting trigger
// releases their bytes.
func deleteExpiredLogs(ctx context.Context, tx *sql.Tx) (int64, error) {
	rows, err := tx.QueryContext(ctx, "SELECT job_id,sequence,length(text) FROM logs WHERE job_id IN (SELECT id FROM jobs WHERE logs_evicted=1) ORDER BY job_id,sequence LIMIT ?", pruneBatchRows)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	// The batch is a prefix of each job's records it reaches.
	type span struct {
		id   string
		last int64
	}
	var spans []span
	var count, bytes int64
	for rows.Next() {
		var id string
		var sequence, size int64
		if err := rows.Scan(&id, &sequence, &size); err != nil {
			return 0, err
		}
		if count > 0 && bytes+size > pruneBatchBytes {
			break
		}
		count, bytes = count+1, bytes+size
		if len(spans) > 0 && spans[len(spans)-1].id == id {
			spans[len(spans)-1].last = sequence
		} else {
			spans = append(spans, span{id, sequence})
		}
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	var deleted int64
	for _, span := range spans {
		result, err := tx.ExecContext(ctx, "DELETE FROM logs WHERE job_id=? AND sequence<=?", span.id, span.last)
		if err != nil {
			return 0, err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return 0, err
		}
		deleted += n
	}
	return deleted, nil
}

// deleteRetiredJobs deletes one batch of the terminal jobs finished at or
// before cutoff, oldest first, and returns how many. Their logs were deleted
// before (Prune), so their own rows are what the batch bounds.
func deleteRetiredJobs(ctx context.Context, tx *sql.Tx, cutoff time.Time) (int64, error) {
	rows, err := tx.QueryContext(ctx, "SELECT id,length(request)+length(profile)+IFNULL(length(result),0) FROM jobs WHERE state IN ("+terminalStates+") AND finished_at<=? ORDER BY finished_at LIMIT ?", cutoff.UnixNano(), pruneBatchJobs)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var ids []string
	var bytes int64
	for rows.Next() {
		var id string
		var size int64
		if err := rows.Scan(&id, &size); err != nil {
			return 0, err
		}
		if len(ids) > 0 && bytes+size > pruneBatchBytes {
			break
		}
		ids, bytes = append(ids, id), bytes+size
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	var deleted int64
	for _, id := range ids {
		result, err := tx.ExecContext(ctx, "DELETE FROM jobs WHERE id=?", id)
		if err != nil {
			return 0, err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return 0, err
		}
		deleted += n
	}
	return deleted, nil
}

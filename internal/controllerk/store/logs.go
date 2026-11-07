package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jerryfane/macserve/internal/model"
)

const MaxLogRecordBytes = 64 << 10
const MaxLogPageBytes = 1 << 20

// AppendLog preserves raw bytes without sanitizing terminal controls. Renderers
// must escape untrusted output. A rejected oversized record or full log persists
// the completeness flag separately, so a full byte cap cannot hide truncation.
func (s *Store) AppendLog(ctx context.Context, id, lease, stream, text string, now time.Time) (int64, error) {
	if stream != "stdout" && stream != "stderr" && stream != "system" || text == "" || !validTime(now) {
		return 0, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var sequence, bytes int64
	var state model.State
	var currentLease string
	err = tx.QueryRowContext(ctx, "SELECT log_sequence,log_bytes,state,lease_token FROM jobs WHERE id=?", id).Scan(&sequence, &bytes, &state, &currentLease)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	if !active(state) {
		return 0, ErrTransition
	}
	if lease == "" || lease != currentLease {
		return 0, ErrLease
	}
	fits := len(text) <= MaxLogRecordBytes && int64(len(text)) <= s.options.MaxLogBytes-bytes && int64(len(text)) <= s.options.MaxTotalLogBytes
	if fits {
		fits, err = s.reserveLog(ctx, tx, int64(len(text)))
		if err != nil {
			return 0, err
		}
	}
	if !fits {
		if _, err := tx.ExecContext(ctx, "UPDATE jobs SET logs_truncated=1 WHERE id=?", id); err != nil {
			return 0, err
		}
		if err := tx.Commit(); err != nil {
			return 0, err
		}
		return 0, ErrLogLimit
	}
	sequence++
	_, err = tx.ExecContext(ctx, "INSERT INTO logs(job_id,sequence,time,stream,text) VALUES(?,?,?,?,?)", id, sequence, now.UnixNano(), stream, []byte(text))
	if err != nil {
		return 0, err
	}
	_, err = tx.ExecContext(ctx, "UPDATE jobs SET log_sequence=?,log_bytes=log_bytes+? WHERE id=?", sequence, len(text), id)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return sequence, nil
}

// Logs returns whole records strictly within the raw-text byte budget. If the
// first pending record cannot fit, ErrInvalid asks the caller to increase the
// budget (at least MaxLogRecordBytes always permits progress). The third return
// value reports permanent lost output, not whether another page is available.
func (s *Store) Logs(ctx context.Context, id string, after int64, maxBytes int) ([]model.LogRecord, int64, bool, error) {
	if maxBytes == 0 {
		maxBytes = MaxLogRecordBytes
	}
	if after < 0 || maxBytes < 1 || maxBytes > MaxLogPageBytes {
		return nil, after, false, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, after, false, err
	}
	defer tx.Rollback()
	var truncated, expired bool
	err = tx.QueryRowContext(ctx, "SELECT logs_truncated,logs_evicted FROM jobs WHERE id=?", id).Scan(&truncated, &expired)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, after, false, ErrNotFound
	}
	if err != nil {
		return nil, after, false, err
	}
	if expired {
		return nil, after, truncated, ErrLogExpired
	}
	rows, err := tx.QueryContext(ctx, "SELECT sequence,time,stream,text FROM logs WHERE job_id=? AND sequence>? ORDER BY sequence", id, after)
	if err != nil {
		return nil, after, truncated, err
	}
	defer rows.Close()
	records := make([]model.LogRecord, 0)
	remaining := maxBytes
	next := after
	for rows.Next() {
		var record model.LogRecord
		var timestamp int64
		if err := rows.Scan(&record.Seq, &timestamp, &record.Stream, &record.Text); err != nil {
			return nil, after, truncated, err
		}
		if len(record.Text) > remaining {
			if len(records) == 0 {
				return nil, after, truncated, fmt.Errorf("%w: next log record needs %d bytes", ErrInvalid, len(record.Text))
			}
			break
		}
		record.Time = time.Unix(0, timestamp).UTC()
		records = append(records, record)
		next = record.Seq
		remaining -= len(record.Text)
		if remaining == 0 {
			break
		}
	}
	if err := rows.Err(); err != nil {
		return nil, after, truncated, err
	}
	return records, next, truncated, nil
}

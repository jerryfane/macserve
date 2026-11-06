package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/model"
)

// A succeeded ios_archive job's signing sub-status. It never changes the
// job's own state; a row is deleted with its job.
const signingSchema = `
CREATE TABLE signings (
 job_id TEXT PRIMARY KEY REFERENCES jobs(id) ON DELETE CASCADE,
 status TEXT NOT NULL CHECK(status IN ('signing','signed','sign_failed')),
 reason TEXT NOT NULL DEFAULT '',
 started_at INTEGER NOT NULL,
 updated_at INTEGER NOT NULL,
 artifacts BLOB,
 CHECK(status <> 'signed' OR artifacts IS NOT NULL)
);
PRAGMA user_version=5;
`

// SigningStatus is a signing sub-status.
type SigningStatus string

const (
	Signing    SigningStatus = "signing"
	Signed     SigningStatus = "signed"
	SignFailed SigningStatus = "sign_failed"
)

// SigningRecord is a job's signing sub-status and, once signed, the stored
// ipa and signer receipt artifacts.
type SigningRecord struct {
	JobID     string              `json:"-"`
	Status    SigningStatus       `json:"status"`
	Reason    string              `json:"reason,omitempty"`
	StartedAt time.Time           `json:"started_at"`
	UpdatedAt time.Time           `json:"updated_at"`
	Artifacts []evidence.Artifact `json:"artifacts,omitempty"`
}

// GetSigning returns a job's signing record, ErrNotFound when it was never
// signed.
func (s *Store) GetSigning(ctx context.Context, id string) (SigningRecord, error) {
	return scanSigning(s.db.QueryRowContext(ctx, "SELECT job_id,status,reason,started_at,updated_at,artifacts FROM signings WHERE job_id=?", id))
}

func scanSigning(row scanner) (SigningRecord, error) {
	var r SigningRecord
	var started, updated int64
	var artifacts []byte
	err := row.Scan(&r.JobID, &r.Status, &r.Reason, &started, &updated, &artifacts)
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	if err != nil {
		return r, err
	}
	r.StartedAt, r.UpdatedAt = time.Unix(0, started).UTC(), time.Unix(0, updated).UTC()
	if artifacts != nil {
		if err := json.Unmarshal(artifacts, &r.Artifacts); err != nil {
			return r, err
		}
	}
	return r, nil
}

// BeginSigning starts signing a succeeded ios_archive job unless a signing
// is in progress or done: it returns the existing record and false then. A
// job without a record, or whose last signing failed, moves to signing and
// BeginSigning returns true; the caller must finish it.
func (s *Store) BeginSigning(ctx context.Context, id string, now time.Time) (SigningRecord, bool, error) {
	if !validTime(now) {
		return SigningRecord{}, false, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SigningRecord{}, false, err
	}
	defer tx.Rollback()
	job, err := scanJob(tx.QueryRowContext(ctx, "SELECT "+jobColumns+" FROM jobs WHERE id=?", id))
	if err != nil {
		return SigningRecord{}, false, err
	}
	if job.Request.Kind != model.IOSArchive || job.State != model.Succeeded || len(job.Result) == 0 {
		return SigningRecord{}, false, ErrTransition
	}
	existing, err := scanSigning(tx.QueryRowContext(ctx, "SELECT job_id,status,reason,started_at,updated_at,artifacts FROM signings WHERE job_id=?", id))
	if err == nil && existing.Status != SignFailed {
		return existing, false, nil
	}
	if err != nil && !errors.Is(err, ErrNotFound) {
		return SigningRecord{}, false, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO signings(job_id,status,reason,started_at,updated_at,artifacts) VALUES(?,'signing','',?,?,NULL) ON CONFLICT(job_id) DO UPDATE SET status='signing',reason='',started_at=excluded.started_at,updated_at=excluded.updated_at,artifacts=NULL", id, now.UnixNano(), now.UnixNano()); err != nil {
		return SigningRecord{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return SigningRecord{}, false, err
	}
	return SigningRecord{JobID: id, Status: Signing, StartedAt: now.UTC(), UpdatedAt: now.UTC()}, true, nil
}

// FinishSigning records the outcome of the signing BeginSigning started:
// signed with its artifacts, or sign_failed with a reason.
func (s *Store) FinishSigning(ctx context.Context, id string, status SigningStatus, reason string, artifacts []evidence.Artifact, now time.Time) error {
	if !validTime(now) || !validReason(reason) || status != Signed && status != SignFailed || (status == Signed) != (len(artifacts) > 0) {
		return ErrInvalid
	}
	var encoded []byte
	if status == Signed {
		var err error
		if encoded, err = json.Marshal(artifacts); err != nil {
			return err
		}
	}
	result, err := s.db.ExecContext(ctx, "UPDATE signings SET status=?,reason=?,updated_at=?,artifacts=? WHERE job_id=? AND status='signing'", string(status), reason, now.UnixNano(), encoded, id)
	if err != nil {
		return err
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return errors.Join(err, ErrTransition)
	}
	return nil
}

// InterruptSignings fails every signing left in progress by a previous
// controller process; a new request retries it.
func (s *Store) InterruptSignings(ctx context.Context, now time.Time) error {
	if !validTime(now) {
		return ErrInvalid
	}
	_, err := s.db.ExecContext(ctx, "UPDATE signings SET status='sign_failed',reason='interrupted by controller restart',updated_at=? WHERE status='signing'", now.UnixNano())
	return err
}

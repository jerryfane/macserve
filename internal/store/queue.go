package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jerryfane/macserve/internal/model"
)

func requestBytes(request model.Request) ([]byte, string, error) {
	if !validSHA(request.SHA) || !validRepo(request.Repo) || !validOpaque(request.Profile, 256) || !validOpaque(request.Xcode.Version, 128) || !validOpaque(request.Xcode.Build, 128) || request.TimeoutSeconds <= 0 || request.TimeoutSeconds > 3600 || request.Context.PullRequest < 0 {
		return nil, "", ErrInvalid
	}
	switch request.Kind {
	case model.Build, model.UnitTest, model.SimulatorUITest:
	default:
		return nil, "", ErrInvalid
	}
	if request.Kind != model.Build && request.Simulator == nil {
		return nil, "", ErrInvalid
	}
	if sim := request.Simulator; sim != nil && (!validOpaque(sim.Runtime, 256) || !validOpaque(sim.RuntimeBuild, 128) || !validOpaque(sim.DeviceType, 256)) {
		return nil, "", ErrInvalid
	}
	data, err := json.Marshal(request)
	if err != nil {
		return nil, "", err
	}
	if len(data) > 16<<10 {
		return nil, "", ErrInvalid
	}
	digest := sha256.Sum256(data)
	return data, hex.EncodeToString(digest[:]), nil
}

func validSHA(sha string) bool {
	if len(sha) != 40 {
		return false
	}
	for _, c := range sha {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func validRepo(repo string) bool {
	owner, name, found := strings.Cut(repo, "/")
	if !found {
		return false
	}
	for _, part := range [2]string{owner, name} {
		if len(part) == 0 || len(part) > 100 || part == "." || part == ".." {
			return false
		}
		for _, c := range part {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
				return false
			}
		}
	}
	return true
}

func profileBytes(admission model.Admission) ([]byte, error) {
	request, profile := admission.Request, admission.Profile
	if profile.ID != request.Profile || profile.Repo != request.Repo || profile.Kind != request.Kind || profile.Xcode != request.Xcode || profile.Version <= 0 || profile.DefaultTimeoutSeconds <= 0 || profile.MaxTimeoutSeconds < profile.DefaultTimeoutSeconds || profile.MaxTimeoutSeconds > 3600 || request.TimeoutSeconds > profile.MaxTimeoutSeconds || profile.MemoryLimitMiB <= 0 || !validOpaque(profile.Run.Executable, 4096) || !validOpaque(profile.DeveloperDir, 4096) {
		return nil, ErrInvalid
	}
	if (request.Simulator == nil) != (profile.Simulator == nil) || request.Simulator != nil && *request.Simulator != *profile.Simulator {
		return nil, ErrInvalid
	}
	data, err := json.Marshal(profile)
	if err != nil {
		return nil, err
	}
	if len(data) > 1<<20 {
		return nil, ErrInvalid
	}
	digest := sha256.Sum256(data)
	if admission.ProfileDigest != hex.EncodeToString(digest[:]) {
		return nil, ErrInvalid
	}
	return data, nil
}

// Enqueue checks idempotency before capacity and current profile validation. A
// retry keeps its first profile snapshot even when the supplied profile changed.
func (s *Store) Enqueue(ctx context.Context, principal, key string, admission model.Admission, now time.Time) (model.Job, bool, error) {
	if !validOpaque(principal, 256) || !validOpaque(key, 256) || !validTime(now) {
		return model.Job{}, false, ErrInvalid
	}
	request, digest, err := requestBytes(admission.Request)
	if err != nil {
		return model.Job{}, false, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.Job{}, false, err
	}
	defer tx.Rollback()
	original, err := scanJob(tx.QueryRowContext(ctx, "SELECT "+jobColumns+" FROM jobs WHERE principal=? AND idempotency_key=?", principal, key))
	if err == nil {
		if original.RequestDigest != digest {
			return model.Job{}, false, ErrConflict
		}
		return original, true, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return model.Job{}, false, err
	}
	profile, err := profileBytes(admission)
	if err != nil {
		return model.Job{}, false, err
	}
	if err := s.expire(ctx, tx, now); err != nil {
		return model.Job{}, false, err
	}
	var total, own int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*),COALESCE(SUM(principal=?),0) FROM jobs WHERE state NOT IN ("+terminalStates+")", principal).Scan(&total, &own); err != nil {
		return model.Job{}, false, err
	}
	if total >= s.options.QueueLimit || own >= s.options.PerPrincipalLimit {
		// Expiry remains durable even when another outstanding job fills capacity.
		if err := tx.Commit(); err != nil {
			return model.Job{}, false, err
		}
		return model.Job{}, false, ErrFull
	}
	id, err := randomToken("j_")
	if err != nil {
		return model.Job{}, false, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO jobs(id,principal,idempotency_key,repo,request,profile,request_digest,profile_digest,state,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, id, principal, key, admission.Request.Repo, request, profile, digest, admission.ProfileDigest, model.Queued, now.UnixNano(), now.UnixNano())
	if err != nil {
		return model.Job{}, false, err
	}
	job, err := getTx(ctx, tx, id)
	if err != nil {
		return model.Job{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return model.Job{}, false, err
	}
	return job, false, nil
}

// Claim holds a database write reservation from eligibility checks through lease
// assignment. The database additionally prohibits a second active row, even if
// a future caller bypasses the normal dispatch path.
func (s *Store) Claim(ctx context.Context, workerEpoch string, now time.Time) (model.Job, error) {
	if !validOpaque(workerEpoch, 256) || !validTime(now) {
		return model.Job{}, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		if contention(err) {
			return model.Job{}, ErrNoJob
		}
		return model.Job{}, err
	}
	defer tx.Rollback()
	if err := s.expire(ctx, tx, now); err != nil {
		return model.Job{}, err
	}
	var blocked bool
	if err := tx.QueryRowContext(ctx, "SELECT paused OR quarantined OR EXISTS(SELECT 1 FROM jobs WHERE state IN ("+activeStates+")) FROM service_state WHERE singleton=1").Scan(&blocked); err != nil {
		return model.Job{}, err
	}
	if blocked {
		if err := tx.Commit(); err != nil {
			return model.Job{}, err
		}
		return model.Job{}, ErrNoJob
	}
	var stale bool
	if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM invalid_epochs WHERE epoch=?)", workerEpoch).Scan(&stale); err != nil {
		return model.Job{}, err
	}
	if stale {
		return model.Job{}, ErrLease
	}
	var acknowledged string
	if err := tx.QueryRowContext(ctx, "SELECT acknowledged_epoch FROM service_state WHERE singleton=1").Scan(&acknowledged); err != nil {
		return model.Job{}, err
	}
	if acknowledged != "" && acknowledged != workerEpoch {
		return model.Job{}, ErrLease
	}
	job, err := scanJob(tx.QueryRowContext(ctx, "SELECT "+jobColumns+" FROM jobs WHERE state='queued' ORDER BY sequence LIMIT 1"))
	if errors.Is(err, ErrNotFound) {
		if err := tx.Commit(); err != nil {
			return model.Job{}, err
		}
		return model.Job{}, ErrNoJob
	}
	if err != nil {
		return model.Job{}, err
	}
	deadline := now.Add(time.Duration(job.Request.TimeoutSeconds) * time.Second)
	if !validTime(deadline) {
		return model.Job{}, ErrInvalid
	}
	lease, err := randomToken("")
	if err != nil {
		return model.Job{}, err
	}
	_, err = tx.ExecContext(ctx, "UPDATE jobs SET state='preparing',worker_epoch=?,lease_token=?,started_at=?,deadline=?,updated_at=? WHERE id=?", workerEpoch, lease, now.UnixNano(), deadline.UnixNano(), now.UnixNano(), job.ID)
	if err != nil {
		if contention(err) || uniqueViolation(err) {
			return model.Job{}, ErrNoJob
		}
		return model.Job{}, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE service_state SET acknowledged_epoch=? WHERE singleton=1", workerEpoch); err != nil {
		return model.Job{}, err
	}
	job, err = getTx(ctx, tx, job.ID)
	if err != nil {
		return model.Job{}, err
	}
	if err := tx.Commit(); err != nil {
		return model.Job{}, err
	}
	return job, nil
}

func active(state model.State) bool {
	return state == model.Preparing || state == model.Running || state == model.Cancelling || state == model.Finalizing
}

func (s *Store) Transition(ctx context.Context, id, lease string, from, to model.State, reason string, now time.Time) error {
	if !active(from) || !active(to) || !from.CanTransition(to) {
		return ErrTransition
	}
	if !validReason(reason) || !validTime(now) {
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
	if job.State != from {
		return ErrTransition
	}
	_, err = tx.ExecContext(ctx, "UPDATE jobs SET state=?,reason=?,updated_at=?,cancel_requested=cancel_requested OR ? WHERE id=?", to, reason, now.UnixNano(), to == model.Cancelling, id)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func cancelTx(ctx context.Context, tx *sql.Tx, job model.Job, reason string, now time.Time) error {
	if job.State.Terminal() || job.CancelRequested {
		return nil
	}
	state := job.State
	var finished any
	if state == model.Queued {
		state = model.Cancelled
		finished = now.UnixNano()
	} else if state == model.Preparing || state == model.Running {
		state = model.Cancelling
	}
	_, err := tx.ExecContext(ctx, "UPDATE jobs SET state=?,cancel_requested=1,reason=?,updated_at=?,finished_at=? WHERE id=?", state, reason, now.UnixNano(), finished, job.ID)
	return err
}

func (s *Store) Cancel(ctx context.Context, id, reason string, now time.Time) (model.Job, error) {
	if !validReason(reason) || !validTime(now) {
		return model.Job{}, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.Job{}, err
	}
	defer tx.Rollback()
	job, err := getTx(ctx, tx, id)
	if err != nil {
		return model.Job{}, err
	}
	if err := cancelTx(ctx, tx, job, reason, now); err != nil {
		return model.Job{}, err
	}
	job, err = getTx(ctx, tx, id)
	if err != nil {
		return model.Job{}, err
	}
	if err := tx.Commit(); err != nil {
		return model.Job{}, err
	}
	return job, nil
}

// Finish stores the complete result envelope (including caller-supplied exit
// metadata) together with the terminal state. Cleanup uncertainty quarantines
// dispatch in the same transaction that releases the active singleton.
func (s *Store) Finish(ctx context.Context, id, lease string, state model.State, result json.RawMessage, cleanupOK bool, reason string, now time.Time) error {
	if !model.Finalizing.CanTransition(state) || state == model.Succeeded && !cleanupOK {
		return ErrTransition
	}
	if int64(len(result)) > s.options.MaxResultBytes {
		return ErrResultLimit
	}
	if result != nil && !json.Valid(result) || !validReason(reason) || !validTime(now) {
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
	if job.State != model.Finalizing || job.CancelRequested && state == model.Succeeded {
		return ErrTransition
	}
	if !cleanupOK {
		if err := quarantine(ctx, tx, job.WorkerEpoch, "cleanup could not be proven"); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, "UPDATE jobs SET state=?,result=?,cleanup_ok=?,reason=?,updated_at=?,finished_at=? WHERE id=?", state, []byte(result), cleanupOK, reason, now.UnixNano(), now.UnixNano(), id)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) expire(ctx context.Context, tx *sql.Tx, now time.Time) error {
	cutoff := now.Add(-s.options.QueueTTL)
	if !validTime(cutoff) {
		return fmt.Errorf("%w: expiry time outside supported range", ErrInvalid)
	}
	_, err := tx.ExecContext(ctx, "UPDATE jobs SET state='expired',reason='queue TTL elapsed',updated_at=?,finished_at=? WHERE state='queued' AND created_at<=?", now.UnixNano(), now.UnixNano(), cutoff.UnixNano())
	return err
}

// Prune retains terminal metadata and idempotency for Retention after terminal
// completion. It does not delete artifact bytes, which the caller owns.
func (s *Store) Prune(ctx context.Context, now time.Time) error {
	if !validTime(now) || !validTime(now.Add(-s.options.Retention)) || !validTime(now.Add(-s.options.LogRetention)) {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.expire(ctx, tx, now); err != nil {
		return err
	}
	if err := s.pruneLogs(ctx, tx, now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM jobs WHERE state IN ("+terminalStates+") AND finished_at<=?", now.Add(-s.options.Retention).UnixNano()); err != nil {
		return err
	}
	return tx.Commit()
}

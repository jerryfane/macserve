package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jerryfane/macserve/internal/model"
)

// GitHubRunDue reports whether the run of key needs a new attempt, so a
// consumer run needs its producer's test products now: it is unknown or has
// no job (waiting, blocked or skipped), or its current attempt ended because
// of the service (serviceEnded), which an ensure admission reruns.
func (s *Store) GitHubRunDue(ctx context.Context, key string) (bool, error) {
	var jobID string
	err := s.db.QueryRowContext(ctx, "SELECT current_job FROM github_runs WHERE run_key=?", key).Scan(&jobID)
	if errors.Is(err, sql.ErrNoRows) || err == nil && jobID == "" {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	job, err := scanJob(s.db.QueryRowContext(ctx, "SELECT "+jobColumns+" FROM jobs WHERE id=?", jobID))
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var current int
	if err = s.db.QueryRowContext(ctx, "SELECT rerun FROM github_attempts WHERE job_id=?", jobID).Scan(&current); err != nil {
		return false, err
	}
	return serviceEnded(job, current == attemptAutomatic), nil
}

// PinnedProducts is the set of test products digests the products pool must
// keep whatever their age or the pool's budget: those an unfinished
// (queued or active) consumer job names (Request.Products), and those of
// each succeeded build-for-testing producer job that is the current attempt
// of a current eligible GitHub run, whose head's consumers (waiting, held
// back as drafts or rerun later) run from them. A store without GitHub
// intake (InitializeGitHub never ran) has no such run. It is a snapshot:
// EvictUnpinnedProduct rechecks one digest's pins when an eviction commits.
func (s *Store) PinnedProducts(ctx context.Context) (map[string]bool, error) {
	return pinnedProducts(ctx, s.db)
}

// EvictUnpinnedProduct records the eviction of the retained digest sha256
// at now unless it is pinned (PinnedProducts) at that moment, in one
// transaction; it reports whether it recorded the eviction. A consumer's
// admission (enqueueTx, which requires the digest retained) and this
// eviction are serialized by the store: either the admission commits first
// and pins the digest, so it is kept, or the eviction commits first and the
// admission is refused (ErrProductsUnavailable). The caller removes the
// bytes only after the eviction is recorded.
func (s *Store) EvictUnpinnedProduct(ctx context.Context, sha256 string, now time.Time) (bool, error) {
	if !validDigest(sha256) || !validTime(now) {
		return false, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	// A write first takes the database's write lock, so no admission
	// commits between the pin check and the eviction.
	if _, err = tx.ExecContext(ctx, "UPDATE products SET used_at=used_at WHERE sha256=?", sha256); err != nil {
		return false, err
	}
	pinned, err := pinnedProducts(ctx, tx)
	if err != nil || pinned[sha256] {
		return false, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE products SET evicted_at=? WHERE sha256=? AND evicted_at IS NULL", now.UnixNano(), sha256); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// rowQueryer is a database or transaction that pinnedProducts reads.
type rowQueryer interface {
	queryer
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func pinnedProducts(ctx context.Context, q rowQueryer) (map[string]bool, error) {
	pinned := map[string]bool{}
	consumers, err := q.QueryContext(ctx, "SELECT "+jobColumns+" FROM jobs WHERE state NOT IN ("+terminalStates+")")
	if err != nil {
		return nil, err
	}
	err = eachJob(consumers, func(job model.Job) {
		if job.Request.Products != nil {
			pinned[job.Request.Products.SHA256] = true
		}
	})
	if err != nil {
		return nil, err
	}
	var github bool
	if err = q.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='github_current_runs')").Scan(&github); err != nil || !github {
		return pinned, err
	}
	producers, err := q.QueryContext(ctx, `SELECT `+jobColumns+` FROM jobs WHERE state='succeeded'
 AND id IN (SELECT r.current_job FROM github_runs r JOIN github_current_runs c ON c.run_key=r.run_key AND c.repository_id=r.repository_id WHERE c.eligible=1)`)
	if err != nil {
		return nil, err
	}
	err = eachJob(producers, func(job model.Job) {
		if ref, err := ProducerProducts(job); err == nil {
			pinned[ref.SHA256] = true
		}
	})
	if err != nil {
		return nil, err
	}
	return pinned, nil
}

// eachJob calls use with each job of rows and closes them.
func eachJob(rows *sql.Rows, use func(model.Job)) error {
	defer rows.Close()
	for rows.Next() {
		job, err := scanJob(rows)
		if err != nil {
			return err
		}
		use(job)
	}
	return rows.Err()
}

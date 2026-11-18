package store

import (
	"context"
	"database/sql"
	"errors"

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
// intake (InitializeGitHub never ran) has no such run.
func (s *Store) PinnedProducts(ctx context.Context) (map[string]bool, error) {
	pinned := map[string]bool{}
	consumers, err := s.db.QueryContext(ctx, "SELECT "+jobColumns+" FROM jobs WHERE state NOT IN ("+terminalStates+")")
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
	if err = s.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='github_current_runs')").Scan(&github); err != nil || !github {
		return pinned, err
	}
	producers, err := s.db.QueryContext(ctx, `SELECT `+jobColumns+` FROM jobs WHERE state='succeeded'
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

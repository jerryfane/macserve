package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jerryfane/macserve/internal/model"
)

// GitHubRun is the durable logical requirement. Attempts and request mappings
// remain immutable when the current attempt changes.
type GitHubRun struct {
	Key, Repository, SHA, Profile, JobID, AttemptID, Blocked string
	RepositoryID                                             int64
	PolicyRevision                                           int
	CheckID                                                  int64
	PullRequests                                             []int
}

type GitHubRequest struct {
	CommentID             int64
	RequestID, BodySHA256 string
}

type GitHubAdmission struct {
	Run         GitHubRun
	Admission   model.Admission
	PullRequest int
	Mode        string
	Request     *GitHubRequest
}

type GitHubCursor struct {
	ETag                  string
	FullAt, CommentsSince time.Time
	Pulls                 []byte
}

type GitHubPublication struct {
	Run        GitHubRun
	Token      string
	Generation int64
	Failures   int
}

var ErrRerunLimit = errors.New("GitHub rerun limit reached")
var ErrCorrelationLimit = errors.New("GitHub request correlation limit reached")

// InitializeGitHub is additive for existing private-API stores. The triggers
// make every later job transition durable publication work in its own commit.
func (s *Store) InitializeGitHub(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, githubSchema); err != nil {
		return err
	}
	return tx.Commit()
}

const githubSchema = `
CREATE TABLE IF NOT EXISTS github_runs (
 run_key TEXT PRIMARY KEY, repository_id INTEGER NOT NULL, repository TEXT NOT NULL,
 sha TEXT NOT NULL, profile TEXT NOT NULL, policy_revision INTEGER NOT NULL,
 current_job TEXT NOT NULL DEFAULT '', attempt_id TEXT NOT NULL DEFAULT '',
 check_id INTEGER NOT NULL DEFAULT 0, blocked TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS github_attempts (
 job_id TEXT PRIMARY KEY, run_key TEXT NOT NULL REFERENCES github_runs(run_key),
 attempt_id TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL, rerun INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS github_requests (
 repository_id INTEGER NOT NULL, comment_id INTEGER NOT NULL,
 request_id TEXT NOT NULL, body_sha256 TEXT NOT NULL,
 run_key TEXT NOT NULL REFERENCES github_runs(run_key), job_id TEXT NOT NULL,
 PRIMARY KEY(repository_id,comment_id)
);
CREATE TABLE IF NOT EXISTS github_run_pulls (
 run_key TEXT NOT NULL REFERENCES github_runs(run_key), pull_request INTEGER NOT NULL,
 PRIMARY KEY(run_key,pull_request)
);
CREATE TABLE IF NOT EXISTS github_outbox (
 run_key TEXT PRIMARY KEY REFERENCES github_runs(run_key), generation INTEGER NOT NULL DEFAULT 1,
 next_at INTEGER NOT NULL DEFAULT 0, failures INTEGER NOT NULL DEFAULT 0,
 lease_token TEXT NOT NULL DEFAULT '', lease_until INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS github_cursors (
 repository_id INTEGER PRIMARY KEY, etag TEXT NOT NULL, full_at INTEGER NOT NULL,
 comments_since INTEGER NOT NULL, pulls BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS github_observed_heads (
 repository_id INTEGER NOT NULL, pull_request INTEGER NOT NULL, sha TEXT NOT NULL,
 eligible INTEGER NOT NULL, observed_at INTEGER NOT NULL,
 PRIMARY KEY(repository_id,pull_request,sha)
);
CREATE TRIGGER IF NOT EXISTS github_job_publication AFTER UPDATE OF state,result,cancel_requested ON jobs
BEGIN
 INSERT INTO github_outbox(run_key)
 SELECT run_key FROM github_runs WHERE current_job=NEW.id
 ON CONFLICT(run_key) DO UPDATE SET generation=generation+1;
END;
`

const githubRunColumns = "run_key,repository_id,repository,sha,profile,policy_revision,current_job,attempt_id,check_id,blocked"

func scanGitHubRun(row scanner) (GitHubRun, error) {
	var run GitHubRun
	err := row.Scan(&run.Key, &run.RepositoryID, &run.Repository, &run.SHA, &run.Profile, &run.PolicyRevision, &run.JobID, &run.AttemptID, &run.CheckID, &run.Blocked)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return run, err
}

func githubDirty(ctx context.Context, tx *sql.Tx, key string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO github_outbox(run_key) VALUES(?) ON CONFLICT(run_key) DO UPDATE SET generation=generation+1`, key)
	return err
}

// AdmitGitHub coalesces automatic and comment intake using the same queue
// transaction as Enqueue. A worker can never see an unlinked GitHub job.
func (s *Store) AdmitGitHub(ctx context.Context, input GitHubAdmission, now time.Time) (GitHubRun, error) {
	r := input.Run
	if !validOpaque(r.Key, 256) || r.RepositoryID <= 0 || r.PolicyRevision <= 0 || input.PullRequest <= 0 || !validTime(now) || (input.Mode != "ensure" && input.Mode != "rerun") || r.Repository != input.Admission.Request.Repo || r.SHA != input.Admission.Request.SHA || r.Profile != input.Admission.Request.Profile {
		return GitHubRun{}, ErrInvalid
	}
	if q := input.Request; q != nil && (q.CommentID <= 0 || !validOpaque(q.RequestID, 128) || len(q.BodySHA256) != 64) {
		return GitHubRun{}, ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return GitHubRun{}, err
	}
	defer tx.Rollback()
	if q := input.Request; q != nil {
		var key, digest, requestID, jobID string
		err = tx.QueryRowContext(ctx, "SELECT run_key,body_sha256,request_id,job_id FROM github_requests WHERE repository_id=? AND comment_id=?", r.RepositoryID, q.CommentID).Scan(&key, &digest, &requestID, &jobID)
		if err == nil {
			if key != r.Key || digest != q.BodySHA256 || requestID != q.RequestID {
				return GitHubRun{}, ErrConflict
			}
			previous, err := scanGitHubRun(tx.QueryRowContext(ctx, "SELECT "+githubRunColumns+" FROM github_runs WHERE run_key=?", key))
			if err != nil {
				return GitHubRun{}, err
			}
			previous.JobID = jobID
			if err = tx.QueryRowContext(ctx, "SELECT attempt_id FROM github_attempts WHERE job_id=?", jobID).Scan(&previous.AttemptID); err != nil {
				return GitHubRun{}, err
			}
			return previous, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return GitHubRun{}, err
		}
	}
	existing, err := scanGitHubRun(tx.QueryRowContext(ctx, "SELECT "+githubRunColumns+" FROM github_runs WHERE run_key=?", r.Key))
	if err != nil && !errors.Is(err, ErrNotFound) {
		return GitHubRun{}, err
	}
	found := err == nil
	if found {
		r = existing
	}
	var count int
	if input.Request != nil {
		if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM github_requests WHERE run_key=?", r.Key).Scan(&count); err != nil {
			return GitHubRun{}, err
		}
		if count >= 128 {
			return GitHubRun{}, ErrCorrelationLimit
		}
	}
	create := r.JobID == ""
	rerun := false
	if !create && input.Mode == "rerun" {
		job, err := getTx(ctx, tx, r.JobID)
		if err != nil {
			return GitHubRun{}, err
		}
		if job.State.Terminal() {
			create = true
			rerun = true
		}
	}
	// Keep the current check's update and attempt replacement ordered across
	// independent controller handles. A crashed publisher's reservation expires.
	if create || r.Blocked != "" {
		var publishing bool
		if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM github_outbox WHERE run_key=? AND lease_until>?)", r.Key, now.UnixNano()).Scan(&publishing); err != nil {
			return GitHubRun{}, err
		}
		if publishing {
			return GitHubRun{}, ErrFull
		}
	}
	if rerun {
		if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM github_attempts WHERE run_key=? AND rerun=1 AND created_at>?", r.Key, now.Add(-time.Hour).UnixNano()).Scan(&count); err != nil {
			return GitHubRun{}, err
		}
		if count >= 2 {
			return GitHubRun{}, ErrRerunLimit
		}
	}
	dirty := create || r.Blocked != "" || input.Request != nil
	if !found {
		_, err = tx.ExecContext(ctx, "INSERT INTO github_runs(run_key,repository_id,repository,sha,profile,policy_revision) VALUES(?,?,?,?,?,?)", r.Key, r.RepositoryID, r.Repository, r.SHA, r.Profile, r.PolicyRevision)
		if err != nil {
			return GitHubRun{}, err
		}
	}
	if create {
		attempt, err := randomToken("a_")
		if err != nil {
			return GitHubRun{}, err
		}
		job, _, err := s.enqueueTx(ctx, tx, fmt.Sprintf("github:%d", r.RepositoryID), attempt, input.Admission, now)
		if err != nil {
			return GitHubRun{}, err
		}
		r.JobID = job.ID
		r.AttemptID = attempt
		_, err = tx.ExecContext(ctx, "INSERT INTO github_attempts(job_id,run_key,attempt_id,created_at,rerun) VALUES(?,?,?,?,?)", job.ID, r.Key, attempt, now.UnixNano(), rerun)
		if err != nil {
			return GitHubRun{}, err
		}
	}
	r.Blocked = ""
	_, err = tx.ExecContext(ctx, "UPDATE github_runs SET current_job=?,attempt_id=?,blocked='' WHERE run_key=?", r.JobID, r.AttemptID, r.Key)
	if err != nil {
		return GitHubRun{}, err
	}
	_, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO github_run_pulls(run_key,pull_request) VALUES(?,?)", r.Key, input.PullRequest)
	if err != nil {
		return GitHubRun{}, err
	}
	if q := input.Request; q != nil {
		_, err = tx.ExecContext(ctx, "INSERT INTO github_requests(repository_id,comment_id,request_id,body_sha256,run_key,job_id) VALUES(?,?,?,?,?,?)", r.RepositoryID, q.CommentID, q.RequestID, q.BodySHA256, r.Key, r.JobID)
		if err != nil {
			return GitHubRun{}, err
		}
	}
	if dirty {
		if err = githubDirty(ctx, tx, r.Key); err != nil {
			return GitHubRun{}, err
		}
	}
	if err = tx.Commit(); err != nil {
		return GitHubRun{}, err
	}
	return r, nil
}

func (s *Store) GitHubByJob(ctx context.Context, jobID string) (GitHubRun, error) {
	run, err := scanGitHubRun(s.db.QueryRowContext(ctx, "SELECT "+githubRunColumns+" FROM github_runs WHERE run_key=(SELECT run_key FROM github_attempts WHERE job_id=?)", jobID))
	if err != nil {
		return run, err
	}
	// Provenance belongs to this immutable attempt, not the current one.
	run.JobID = jobID
	if err = s.db.QueryRowContext(ctx, "SELECT attempt_id FROM github_attempts WHERE job_id=?", jobID).Scan(&run.AttemptID); err != nil {
		return run, err
	}
	run.PullRequests, err = s.GitHubPulls(ctx, run.Key)
	return run, err
}

func (s *Store) GitHubPulls(ctx context.Context, key string) ([]int, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT pull_request FROM github_run_pulls WHERE run_key=? ORDER BY pull_request", key)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []int
	for rows.Next() {
		var n int
		if err = rows.Scan(&n); err != nil {
			return nil, err
		}
		result = append(result, n)
	}
	return result, rows.Err()
}

func (s *Store) GitHubRuns(ctx context.Context, repoID int64) ([]GitHubRun, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+githubRunColumns+" FROM github_runs WHERE repository_id=?", repoID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var runs []GitHubRun
	for rows.Next() {
		r, err := scanGitHubRun(rows)
		if err != nil {
			return nil, err
		}
		runs = append(runs, r)
	}
	return runs, rows.Err()
}

func (s *Store) GitHubRequests(ctx context.Context, jobID string) ([]GitHubRequest, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT comment_id,request_id,body_sha256 FROM github_requests WHERE job_id=? ORDER BY comment_id", jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	requests := make([]GitHubRequest, 0)
	for rows.Next() {
		var q GitHubRequest
		if err = rows.Scan(&q.CommentID, &q.RequestID, &q.BodySHA256); err != nil {
			return nil, err
		}
		requests = append(requests, q)
	}
	return requests, rows.Err()
}

// BlockGitHub records a non-success requirement without ever admitting code.
// Existing active work is cancelled atomically with the publication request.
func (s *Store) BlockGitHub(ctx context.Context, r GitHubRun, reason string, now time.Time) error {
	if !validOpaque(r.Key, 256) || r.RepositoryID <= 0 || !validRepo(r.Repository) || !validSHA(r.SHA) || !validOpaque(r.Profile, 256) || r.PolicyRevision <= 0 || !validReason(reason) || reason == "" || !validTime(now) {
		return ErrInvalid
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var publishing bool
	if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM github_outbox WHERE run_key=? AND lease_until>?)", r.Key, now.UnixNano()).Scan(&publishing); err != nil {
		return err
	}
	if publishing {
		return ErrFull
	}
	old, err := scanGitHubRun(tx.QueryRowContext(ctx, "SELECT "+githubRunColumns+" FROM github_runs WHERE run_key=?", r.Key))
	if errors.Is(err, ErrNotFound) {
		_, err = tx.ExecContext(ctx, "INSERT INTO github_runs(run_key,repository_id,repository,sha,profile,policy_revision,blocked) VALUES(?,?,?,?,?,?,?)", r.Key, r.RepositoryID, r.Repository, r.SHA, r.Profile, r.PolicyRevision, reason)
	} else if err == nil {
		if old.Blocked == reason {
			return nil
		}
		_, err = tx.ExecContext(ctx, "UPDATE github_runs SET blocked=? WHERE run_key=?", reason, r.Key)
		if err == nil && old.JobID != "" {
			var job model.Job
			job, err = getTx(ctx, tx, old.JobID)
			if err == nil {
				err = cancelTx(ctx, tx, job, reason, now)
			}
		}
	}
	if err != nil {
		return err
	}
	if err = githubDirty(ctx, tx, r.Key); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) GitHubCursor(ctx context.Context, repositoryID int64) (GitHubCursor, error) {
	var c GitHubCursor
	var full, since int64
	err := s.db.QueryRowContext(ctx, "SELECT etag,full_at,comments_since,pulls FROM github_cursors WHERE repository_id=?", repositoryID).Scan(&c.ETag, &full, &since, &c.Pulls)
	if errors.Is(err, sql.ErrNoRows) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if full != 0 {
		c.FullAt = time.Unix(0, full).UTC()
	}
	if since != 0 {
		c.CommentsSince = time.Unix(0, since).UTC()
	}
	return c, nil
}
func (s *Store) SaveGitHubCursor(ctx context.Context, id int64, c GitHubCursor) error {
	var full, since int64
	if !c.FullAt.IsZero() {
		full = c.FullAt.UnixNano()
	}
	if !c.CommentsSince.IsZero() {
		since = c.CommentsSince.UnixNano()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO github_cursors(repository_id,etag,full_at,comments_since,pulls) VALUES(?,?,?,?,?) ON CONFLICT(repository_id) DO UPDATE SET etag=excluded.etag,full_at=excluded.full_at,comments_since=excluded.comments_since,pulls=excluded.pulls`, id, c.ETag, full, since, c.Pulls)
	return err
}
func (s *Store) ObserveGitHubHead(ctx context.Context, repoID int64, pr int, sha string, eligible bool, now time.Time) error {
	if !validSHA(sha) || pr <= 0 || repoID <= 0 || !validTime(now) {
		return ErrInvalid
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO github_observed_heads(repository_id,pull_request,sha,eligible,observed_at) VALUES(?,?,?,?,?) ON CONFLICT(repository_id,pull_request,sha) DO UPDATE SET eligible=excluded.eligible,observed_at=excluded.observed_at`, repoID, pr, sha, eligible, now.UnixNano())
	return err
}

// NextGitHubPublication reserves one current logical check. Network calls must
// finish within one minute; the longer lease tolerates a lost response/restart.
func (s *Store) NextGitHubPublication(ctx context.Context, now time.Time) (GitHubPublication, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return GitHubPublication{}, err
	}
	defer tx.Rollback()
	var p GitHubPublication
	var key string
	err = tx.QueryRowContext(ctx, "SELECT run_key,generation,failures FROM github_outbox WHERE next_at<=? AND lease_until<=? ORDER BY next_at,run_key LIMIT 1", now.UnixNano(), now.UnixNano()).Scan(&key, &p.Generation, &p.Failures)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	if err != nil {
		return p, err
	}
	p.Run, err = scanGitHubRun(tx.QueryRowContext(ctx, "SELECT "+githubRunColumns+" FROM github_runs WHERE run_key=?", key))
	if err != nil {
		return p, err
	}
	p.Token, err = randomToken("")
	if err != nil {
		return p, err
	}
	_, err = tx.ExecContext(ctx, "UPDATE github_outbox SET lease_token=?,lease_until=? WHERE run_key=?", p.Token, now.Add(10*time.Minute).UnixNano(), key)
	if err != nil {
		return p, err
	}
	if err = tx.Commit(); err != nil {
		return p, err
	}
	return p, nil
}

func (s *Store) FinishGitHubPublication(ctx context.Context, p GitHubPublication, checkID int64, retryAt time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var token string
	if err = tx.QueryRowContext(ctx, "SELECT lease_token FROM github_outbox WHERE run_key=?", p.Run.Key).Scan(&token); err != nil {
		return err
	}
	if token != p.Token {
		return ErrLease
	}
	if checkID > 0 {
		_, err = tx.ExecContext(ctx, "UPDATE github_runs SET check_id=? WHERE run_key=? AND current_job=?", checkID, p.Run.Key, p.Run.JobID)
		if err != nil {
			return err
		}
	}
	if retryAt.IsZero() {
		_, err = tx.ExecContext(ctx, "DELETE FROM github_outbox WHERE run_key=? AND generation=?", p.Run.Key, p.Generation)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, "UPDATE github_outbox SET lease_token='',lease_until=0,failures=0,next_at=0 WHERE run_key=?", p.Run.Key)
	} else {
		_, err = tx.ExecContext(ctx, "UPDATE github_outbox SET lease_token='',lease_until=0,failures=failures+1,next_at=? WHERE run_key=?", retryAt.UnixNano(), p.Run.Key)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

// ReconcileGitHubPublications repairs remote deletion/drift even without a
// local job transition. It preserves an in-flight publisher's generation fence.
func (s *Store) ReconcileGitHubPublications(ctx context.Context, repositoryID int64) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO github_outbox(run_key)
 SELECT run_key FROM github_runs WHERE repository_id=?
 ON CONFLICT(run_key) DO UPDATE SET generation=generation+1`, repositoryID)
	return err
}

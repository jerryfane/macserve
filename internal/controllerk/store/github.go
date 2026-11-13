package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jerryfane/macserve/internal/controllerconfig"
	"github.com/jerryfane/macserve/internal/model"
)

// GitHubRun is the durable logical requirement. Attempts and request mappings
// remain immutable when the current attempt changes. Shard is a policy matrix
// entry's shard, part of the run's check name; empty for every other run.
// Skipped is why a jobless matrix run was not run (SkipGitHub), published as
// a neutral check; Blocked, a refusal published as action_required.
type GitHubRun struct {
	Key, Repository, SHA, Profile, Shard, JobID, AttemptID, Blocked, Skipped string
	RepositoryID                                                             int64
	PolicyRevision                                                           int
	CheckID                                                                  int64
	PullRequests                                                             []int
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
	CommentsScanAt        time.Time
	CommentsPage          int
}

type GitHubPublication struct {
	Run        GitHubRun
	Token      string
	Generation int64
	Failures   int
}

var ErrRerunLimit = errors.New("GitHub rerun limit reached")
var ErrCorrelationLimit = errors.New("GitHub request correlation limit reached")

// github_attempts.rerun records why an attempt was created: the run's first
// attempt (0), a requested rerun (1: comment mode=rerun or the owner API
// POST /v1/admin/github/rerun) or an automatic rerun (2) of an attempt the
// service ended. Requested and automatic reruns are bounded separately, each
// at two per run in any hour.
const (
	attemptInitial   = 0
	attemptRerun     = 1
	attemptAutomatic = 2
)

// serviceEnded reports a GitHub attempt that ended because of the service or
// its operator rather than its head, its GitHub run or its own budget: state
// cancelled or interrupted with a recorded cancel reason whose source is
//   - host_readiness or gate_error (the readiness gate),
//   - controller_shutdown (the controller stopped with it active),
//   - admin_pause (an administrator's cancel_active pause),
//   - worker_admission (the worker refused it before it ran for a cause of
//     its own, such as a registered tree ACL census cut short on a loaded
//     host), or
//   - client from a principal other than the job's own (an operator's
//     POST /v1/jobs/<id>/cancel; a GitHub attempt's principal is
//     github:<repository id>, never an API principal, so every API cancel of
//     one is an operator's), unless the attempt was itself an automatic
//     rerun (automatic): cancelling the service's own rerun keeps the head
//     cancelled.
//
// Never github (supersession or ineligibility), deadline or log_limit, nor an
// attempt interrupted without a cancel request (a lost worker or a fenced
// worker epoch) or that failed, timed out or succeeded.
func serviceEnded(job model.Job, automatic bool) bool {
	if job.State != model.Cancelled && job.State != model.Interrupted || job.CancelReason == nil {
		return false
	}
	switch job.CancelReason.Source {
	case model.CancelHostReadiness, model.CancelGateError, model.CancelShutdown, model.CancelAdminPause, model.CancelWorkerAdmission:
		return true
	case model.CancelClient:
		return job.CancelReason.Principal != job.Principal && !automatic
	}
	return false
}

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
	// Runs admitted before policy matrices have no shard and were not skipped.
	for _, column := range []string{"shard", "skipped"} {
		var exists bool
		if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM pragma_table_info('github_runs') WHERE name=?)", column).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			if _, err = tx.ExecContext(ctx, "ALTER TABLE github_runs ADD COLUMN "+column+" TEXT NOT NULL DEFAULT ''"); err != nil {
				return err
			}
		}
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
CREATE TABLE IF NOT EXISTS github_comment_scans (
 repository_id INTEGER PRIMARY KEY, started_at INTEGER NOT NULL, page INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS github_current_runs (
 repository_id INTEGER NOT NULL, run_key TEXT NOT NULL, eligible INTEGER NOT NULL,
 PRIMARY KEY(repository_id,run_key)
);
CREATE INDEX IF NOT EXISTS github_runs_repository ON github_runs(repository_id);
CREATE INDEX IF NOT EXISTS github_attempts_run ON github_attempts(run_key);
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

const githubRunColumns = "run_key,repository_id,repository,sha,profile,shard,policy_revision,current_job,attempt_id,check_id,blocked,skipped"

func scanGitHubRun(row scanner) (GitHubRun, error) {
	var run GitHubRun
	err := row.Scan(&run.Key, &run.RepositoryID, &run.Repository, &run.SHA, &run.Profile, &run.Shard, &run.PolicyRevision, &run.JobID, &run.AttemptID, &run.CheckID, &run.Blocked, &run.Skipped)
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
// An automatic first admission (mode ensure, no comment request) that the
// queue has no space for records the run waiting, without a job, and returns
// ErrFull; a later admission of the run starts its first attempt.
func (s *Store) AdmitGitHub(ctx context.Context, input GitHubAdmission, now time.Time) (GitHubRun, error) {
	r := input.Run
	if !validOpaque(r.Key, 256) || r.RepositoryID <= 0 || r.PolicyRevision <= 0 || input.PullRequest <= 0 || !validTime(now) || (input.Mode != "ensure" && input.Mode != "rerun") || r.Repository != input.Admission.Request.Repo || r.SHA != input.Admission.Request.SHA || r.Profile != input.Admission.Request.Profile || r.Shard != input.Admission.Request.Shard {
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
	kind := attemptInitial
	if !create {
		job, err := getTx(ctx, tx, r.JobID)
		if err != nil {
			return GitHubRun{}, err
		}
		var current int
		if err = tx.QueryRowContext(ctx, "SELECT rerun FROM github_attempts WHERE job_id=?", r.JobID).Scan(&current); err != nil {
			return GitHubRun{}, err
		}
		if input.Mode == "rerun" && job.State.Terminal() {
			create, kind = true, attemptRerun
		} else if input.Mode == "ensure" && serviceEnded(job, current == attemptAutomatic) {
			create, kind = true, attemptAutomatic
		}
	}
	// Keep the current check's update and attempt replacement ordered across
	// independent controller handles. A crashed publisher's reservation expires.
	if create || r.Blocked != "" || r.Skipped != "" {
		var publishing bool
		if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM github_outbox WHERE run_key=? AND lease_until>?)", r.Key, now.UnixNano()).Scan(&publishing); err != nil {
			return GitHubRun{}, err
		}
		if publishing && kind == attemptAutomatic {
			// The next poll retries the automatic rerun.
			create, kind = false, attemptInitial
		} else if publishing {
			return GitHubRun{}, ErrFull
		}
	}
	if kind != attemptInitial {
		// Requested reruns (comment mode=rerun, owner API) and automatic reruns
		// are bounded separately, each at two per run per hour.
		if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM github_attempts WHERE run_key=? AND rerun=? AND created_at>?", r.Key, kind, now.Add(-time.Hour).UnixNano()).Scan(&count); err != nil {
			return GitHubRun{}, err
		}
		if count >= 2 && kind == attemptAutomatic {
			// Over the bound the service-cancelled attempt stays current.
			create, kind = false, attemptInitial
		} else if count >= 2 {
			return GitHubRun{}, ErrRerunLimit
		}
	}
	dirty := create || r.Blocked != "" || r.Skipped != "" || input.Request != nil
	if !found {
		_, err = tx.ExecContext(ctx, "INSERT INTO github_runs(run_key,repository_id,repository,sha,profile,shard,policy_revision) VALUES(?,?,?,?,?,?,?)", r.Key, r.RepositoryID, r.Repository, r.SHA, r.Profile, r.Shard, r.PolicyRevision)
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
		if errors.Is(err, ErrFull) && r.JobID == "" && input.Mode == "ensure" && input.Request == nil {
			return GitHubRun{}, awaitQueueTx(ctx, tx, r, found, input.PullRequest)
		}
		if err != nil {
			return GitHubRun{}, err
		}
		r.JobID = job.ID
		r.AttemptID = attempt
		_, err = tx.ExecContext(ctx, "INSERT INTO github_attempts(job_id,run_key,attempt_id,created_at,rerun) VALUES(?,?,?,?,?)", job.ID, r.Key, attempt, now.UnixNano(), kind)
		if err != nil {
			return GitHubRun{}, err
		}
	}
	r.Blocked, r.Skipped = "", ""
	_, err = tx.ExecContext(ctx, "UPDATE github_runs SET current_job=?,attempt_id=?,blocked='',skipped='' WHERE run_key=?", r.JobID, r.AttemptID, r.Key)
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

// awaitQueueTx records r, whose first job the queue has no space for, as
// waiting: a run of pull without a job, blocked or skipped reason, whose
// check says it waits for queue space. Only a new run or a change from
// blocked or skipped is publication work, so a run that keeps waiting is not
// republished every poll. The queue expiry enqueueTx applied commits too.
func awaitQueueTx(ctx context.Context, tx *sql.Tx, r GitHubRun, found bool, pull int) error {
	changed := !found || r.Blocked != "" || r.Skipped != ""
	if found && changed {
		if _, err := tx.ExecContext(ctx, "UPDATE github_runs SET blocked='',skipped='' WHERE run_key=?", r.Key); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO github_run_pulls(run_key,pull_request) VALUES(?,?)", r.Key, pull); err != nil {
		return err
	}
	if changed {
		if err := githubDirty(ctx, tx, r.Key); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return ErrFull
}

// GitHubRun returns the run of key, ErrNotFound when none was recorded.
func (s *Store) GitHubRun(ctx context.Context, key string) (GitHubRun, error) {
	return scanGitHubRun(s.db.QueryRowContext(ctx, "SELECT "+githubRunColumns+" FROM github_runs WHERE run_key=?", key))
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

// GitHubRunsByHead returns the runs of one head, profile and shard ("" for a
// run of no policy matrix entry), with their pull requests, in the repository
// named by ID, by name, or by both (0 and "" leave that one open). Several
// runs exist only when the policy revision, pins or repository identity
// changed; the caller selects the one its current policy admits.
func (s *Store) GitHubRunsByHead(ctx context.Context, repositoryID int64, repository, sha, profile, shard string) ([]GitHubRun, error) {
	if repositoryID < 0 || repositoryID == 0 && repository == "" || !validSHA(sha) || !validOpaque(profile, 256) || shard != "" && !validOpaque(shard, 32) {
		return nil, ErrInvalid
	}
	rows, err := s.db.QueryContext(ctx, "SELECT "+githubRunColumns+" FROM github_runs WHERE (?=0 OR repository_id=?) AND (?='' OR repository=?) AND sha=? AND profile=? AND shard=? ORDER BY run_key",
		repositoryID, repositoryID, repository, repository, sha, profile, shard)
	if err != nil {
		return nil, err
	}
	var runs []GitHubRun
	for rows.Next() {
		run, err := scanGitHubRun(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		runs = append(runs, run)
	}
	if err = errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, err
	}
	for i := range runs {
		if runs[i].PullRequests, err = s.GitHubPulls(ctx, runs[i].Key); err != nil {
			return nil, err
		}
	}
	return runs, nil
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

// GitHubActiveRuns avoids revisiting retained audit history on every poll.
func (s *Store) GitHubActiveRuns(ctx context.Context, repoID int64) ([]GitHubRun, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+githubRunColumns+" FROM github_runs WHERE repository_id=? AND current_job IN (SELECT id FROM jobs WHERE state NOT IN ("+terminalStates+"))", repoID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var runs []GitHubRun
	for rows.Next() {
		run, err := scanGitHubRun(rows)
		if err != nil {
			return nil, err
		}
		runs = append(runs, run)
	}
	return runs, rows.Err()
}

// GitHubTrackedRepositories maps each repository ID that still has a current
// run or a run with an unfinished job to the names its runs were admitted
// under: the durable set a departure reconciliation must consider, also after
// a restart.
func (s *Store) GitHubTrackedRepositories(ctx context.Context) (map[int64][]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT repository_id,repository FROM github_runs
 WHERE run_key IN (SELECT run_key FROM github_current_runs)
 OR current_job IN (SELECT id FROM jobs WHERE state NOT IN (`+terminalStates+`))
 ORDER BY repository_id,repository`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tracked := make(map[int64][]string)
	for rows.Next() {
		var id int64
		var name string
		if err = rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		tracked[id] = append(tracked[id], name)
	}
	return tracked, rows.Err()
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
	if !validOpaque(r.Key, 256) || r.RepositoryID <= 0 || !controllerconfig.ValidRepository(r.Repository) || !validSHA(r.SHA) || !validOpaque(r.Profile, 256) || r.Shard != "" && !validOpaque(r.Shard, 32) || r.PolicyRevision <= 0 || !validReason(reason) || reason == "" || !validTime(now) {
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
		_, err = tx.ExecContext(ctx, "INSERT INTO github_runs(run_key,repository_id,repository,sha,profile,shard,policy_revision,blocked) VALUES(?,?,?,?,?,?,?,?)", r.Key, r.RepositoryID, r.Repository, r.SHA, r.Profile, r.Shard, r.PolicyRevision, reason)
	} else if err == nil {
		if old.Blocked == reason && old.Skipped == "" {
			return nil
		}
		_, err = tx.ExecContext(ctx, "UPDATE github_runs SET blocked=?,skipped='' WHERE run_key=?", reason, r.Key)
		if err == nil && old.JobID != "" {
			var job model.Job
			job, err = getTx(ctx, tx, old.JobID)
			if err == nil {
				err = cancelTx(ctx, tx, job, reason, model.CancelReason{Source: model.CancelGitHub, Detail: reason}, now)
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

// SkipGitHub records that a matrix run of pull request pull is not run (why:
// summary), published as a neutral check, without admitting code. The run
// keeps its pull request like an admitted run, so an owner rerun can still
// start its first attempt. Only a run without an attempt can be skipped:
// ErrConflict refuses a run that already has a job.
func (s *Store) SkipGitHub(ctx context.Context, r GitHubRun, pull int, summary string, now time.Time) error {
	if !validOpaque(r.Key, 256) || r.RepositoryID <= 0 || !controllerconfig.ValidRepository(r.Repository) || !validSHA(r.SHA) || !validOpaque(r.Profile, 256) || !validOpaque(r.Shard, 32) || r.PolicyRevision <= 0 || pull <= 0 || !validReason(summary) || summary == "" || !validTime(now) {
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
	changed := true
	old, err := scanGitHubRun(tx.QueryRowContext(ctx, "SELECT "+githubRunColumns+" FROM github_runs WHERE run_key=?", r.Key))
	if errors.Is(err, ErrNotFound) {
		_, err = tx.ExecContext(ctx, "INSERT INTO github_runs(run_key,repository_id,repository,sha,profile,shard,policy_revision,skipped) VALUES(?,?,?,?,?,?,?,?)", r.Key, r.RepositoryID, r.Repository, r.SHA, r.Profile, r.Shard, r.PolicyRevision, summary)
	} else if err == nil {
		if old.JobID != "" {
			return ErrConflict
		}
		changed = old.Skipped != summary || old.Blocked != ""
		if changed {
			_, err = tx.ExecContext(ctx, "UPDATE github_runs SET skipped=?,blocked='' WHERE run_key=?", summary, r.Key)
		}
	}
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO github_run_pulls(run_key,pull_request) VALUES(?,?)", r.Key, pull); err != nil {
		return err
	}
	if changed {
		if err = githubDirty(ctx, tx, r.Key); err != nil {
			return err
		}
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
	var scanAt int64
	err = s.db.QueryRowContext(ctx, "SELECT started_at,page FROM github_comment_scans WHERE repository_id=?", repositoryID).Scan(&scanAt, &c.CommentsPage)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return c, err
	}
	if scanAt != 0 {
		c.CommentsScanAt = time.Unix(0, scanAt).UTC()
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
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO github_cursors(repository_id,etag,full_at,comments_since,pulls) VALUES(?,?,?,?,?) ON CONFLICT(repository_id) DO UPDATE SET etag=excluded.etag,full_at=excluded.full_at,comments_since=excluded.comments_since,pulls=excluded.pulls`, id, c.ETag, full, since, c.Pulls); err != nil {
		return err
	}
	var scanAt int64
	if !c.CommentsScanAt.IsZero() {
		scanAt = c.CommentsScanAt.UnixNano()
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO github_comment_scans(repository_id,started_at,page) VALUES(?,?,?) ON CONFLICT(repository_id) DO UPDATE SET started_at=excluded.started_at,page=excluded.page`, id, scanAt, c.CommentsPage); err != nil {
		return err
	}
	return tx.Commit()
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
	// Best-effort policy rejections must never starve admitted-job evidence.
	err = tx.QueryRowContext(ctx, `SELECT o.run_key,o.generation,o.failures
 FROM github_outbox o JOIN github_runs r ON r.run_key=o.run_key
 WHERE o.next_at<=? AND o.lease_until<=?
 ORDER BY r.current_job='',o.next_at,o.run_key LIMIT 1`, now.UnixNano(), now.UnixNano()).Scan(&key, &p.Generation, &p.Failures)
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

// ReconcileGitHubPublications repairs only current eligible requirements.
// Ineligible heads fail closed even without a check; their initial rejection is
// not periodically republished. Retained attempts/correlations are audit history.
func (s *Store) ReconcileGitHubPublications(ctx context.Context, repositoryID int64) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO github_outbox(run_key)
 SELECT run_key FROM github_runs WHERE repository_id=?
 AND run_key IN (SELECT run_key FROM github_current_runs WHERE repository_id=? AND eligible=1)
 ON CONFLICT(run_key) DO UPDATE SET generation=generation+1`, repositoryID, repositoryID)
	return err
}

// MaintainGitHub replaces the current-head snapshot (key to eligibility) and retires obsolete work.
// Active jobs, live publisher leases, and provenance for retained jobs survive.
// Jobless blocked heads have no audit correlations and are retired immediately;
// obsolete terminal publications get 24 hours to drain before being retired.
func (s *Store) MaintainGitHub(ctx context.Context, repositoryID int64, keys map[string]bool, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "DELETE FROM github_current_runs WHERE repository_id=?", repositoryID); err != nil {
		return err
	}
	for key, eligible := range keys {
		if _, err = tx.ExecContext(ctx, "INSERT INTO github_current_runs(repository_id,run_key,eligible) VALUES(?,?,?)", repositoryID, key, eligible); err != nil {
			return err
		}
	}
	obsolete := `repository_id=? AND run_key NOT IN (SELECT run_key FROM github_current_runs WHERE repository_id=?)`
	if _, err = tx.ExecContext(ctx, `DELETE FROM github_outbox WHERE lease_until<=? AND run_key IN
 (SELECT run_key FROM github_runs WHERE `+obsolete+` AND
 (current_job='' OR NOT EXISTS(SELECT 1 FROM jobs WHERE id=current_job)
 OR current_job IN (SELECT id FROM jobs WHERE state IN (`+terminalStates+`) AND finished_at<=?)))`,
		now.UnixNano(), repositoryID, repositoryID, now.Add(-24*time.Hour).UnixNano()); err != nil {
		return err
	}
	retired := `SELECT run_key FROM github_runs WHERE ` + obsolete + `
 AND run_key NOT IN (SELECT run_key FROM github_outbox)
 AND NOT EXISTS(SELECT 1 FROM github_attempts a JOIN jobs j ON j.id=a.job_id WHERE a.run_key=github_runs.run_key)`
	for _, table := range []string{"github_requests", "github_run_pulls", "github_attempts"} {
		if _, err = tx.ExecContext(ctx, "DELETE FROM "+table+" WHERE run_key IN ("+retired+")", repositoryID, repositoryID); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM github_runs WHERE run_key IN ("+retired+")", repositoryID, repositoryID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM github_observed_heads WHERE repository_id=? AND observed_at<?", repositoryID, now.Add(-24*time.Hour).UnixNano()); err != nil {
		return err
	}
	return tx.Commit()
}

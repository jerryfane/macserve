// Package store owns the durable, single-worker SQLite queue.
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jerryfane/macserve/internal/model"
	"modernc.org/sqlite"
)

var (
	ErrNotFound   = errors.New("not found")
	ErrConflict   = errors.New("idempotency conflict")
	ErrFull       = errors.New("queue full")
	ErrNoJob      = errors.New("no claimable job")
	ErrTransition = errors.New("invalid state transition")
	ErrLease      = errors.New("invalid lease")
	ErrInvalid    = errors.New("invalid input")
	ErrLogLimit   = errors.New("log limit exceeded")
)

type Options struct {
	QueueLimit        int
	PerPrincipalLimit int
	QueueTTL          time.Duration
	Retention         time.Duration
	MaxLogBytes       int64
}

type Store struct {
	db      *sql.DB
	options Options
}

const activeStates = "'preparing','running','cancelling','finalizing'"
const terminalStates = "'succeeded','failed','timed_out','cancelled','interrupted','expired'"

// Open creates a private on-disk database. The immediate parent directory is
// dedicated store storage: existing non-private directories are rejected rather
// than chmodded. Zero option values select defaults; negative values are invalid.
func Open(path string, options Options) (*Store, error) {
	if options.QueueLimit < 0 || options.PerPrincipalLimit < 0 || options.QueueTTL < 0 || options.Retention < 0 || options.MaxLogBytes < 0 {
		return nil, ErrInvalid
	}
	if options.QueueLimit == 0 {
		options.QueueLimit = 50
	}
	if options.PerPrincipalLimit == 0 {
		options.PerPrincipalLimit = 10
	}
	if options.QueueTTL == 0 {
		options.QueueTTL = 24 * time.Hour
	}
	if options.Retention == 0 {
		options.Retention = 90 * 24 * time.Hour
	}
	if options.MaxLogBytes == 0 {
		options.MaxLogBytes = 256 << 20
	}
	if path == "" || path == ":memory:" || strings.IndexByte(path, 0) >= 0 {
		return nil, ErrInvalid
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(absolute)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("%w: store directory must be private", ErrInvalid)
	}
	for _, name := range []string{absolute, absolute + "-wal", absolute + "-shm", absolute + "-journal"} {
		if info, err := os.Lstat(name); err == nil {
			if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
				return nil, fmt.Errorf("%w: database files must be private regular files", ErrInvalid)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	file, err := os.OpenFile(absolute, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	uri := url.URL{Scheme: "file", Path: absolute}
	query := uri.Query()
	query.Add("_pragma", "busy_timeout(5000)")
	query.Add("_pragma", "foreign_keys(1)")
	query.Add("_pragma", "journal_mode(WAL)")
	query.Add("_pragma", "synchronous(FULL)")
	query.Set("_txlock", "immediate")
	uri.RawQuery = query.Encode()
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return nil, err
	}
	// One connection per handle; SQLite's immediate write transactions and the
	// partial unique index provide serialization across independent handles.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s := &Store{db: db, options: options}
	if err := s.initialize(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) initialize(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version > 1 {
		return fmt.Errorf("unsupported store schema version %d", version)
	}
	if version == 0 {
		if _, err := tx.ExecContext(ctx, schema); err != nil {
			return err
		}
	}
	return tx.Commit()
}

const schema = `
CREATE TABLE jobs (
 sequence INTEGER PRIMARY KEY AUTOINCREMENT,
 id TEXT NOT NULL UNIQUE,
 principal TEXT NOT NULL,
 idempotency_key TEXT NOT NULL,
 repo TEXT NOT NULL,
 request BLOB NOT NULL,
 profile BLOB NOT NULL,
 request_digest TEXT NOT NULL,
 profile_digest TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('queued','preparing','running','cancelling','finalizing','succeeded','failed','timed_out','cancelled','interrupted','expired')),
 reason TEXT NOT NULL DEFAULT '',
 created_at INTEGER NOT NULL,
 updated_at INTEGER NOT NULL,
 started_at INTEGER,
 finished_at INTEGER,
 deadline INTEGER,
 worker_epoch TEXT NOT NULL DEFAULT '',
 lease_token TEXT NOT NULL DEFAULT '',
 cancel_requested INTEGER NOT NULL DEFAULT 0 CHECK(cancel_requested IN (0,1)),
 result BLOB,
 cleanup_ok INTEGER NOT NULL DEFAULT 0 CHECK(cleanup_ok IN (0,1)),
 log_sequence INTEGER NOT NULL DEFAULT 0,
 log_bytes INTEGER NOT NULL DEFAULT 0,
 logs_truncated INTEGER NOT NULL DEFAULT 0 CHECK(logs_truncated IN (0,1)),
 UNIQUE(principal,idempotency_key),
 CHECK(state NOT IN ('preparing','running','cancelling','finalizing') OR (lease_token <> '' AND worker_epoch <> '' AND started_at IS NOT NULL AND deadline IS NOT NULL))
);
CREATE UNIQUE INDEX jobs_one_active ON jobs ((1)) WHERE state IN ('preparing','running','cancelling','finalizing');
CREATE INDEX jobs_fifo ON jobs(state,sequence);
CREATE INDEX jobs_repo ON jobs(repo,sequence);
CREATE INDEX jobs_principal ON jobs(principal,state);
CREATE INDEX jobs_retention ON jobs(finished_at) WHERE finished_at IS NOT NULL;
CREATE TABLE service_state (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 paused INTEGER NOT NULL DEFAULT 0,
 pause_reason TEXT NOT NULL DEFAULT '',
 pause_mode TEXT NOT NULL DEFAULT '',
 generation INTEGER NOT NULL DEFAULT 0,
 quarantined INTEGER NOT NULL DEFAULT 0,
 quarantine_reason TEXT NOT NULL DEFAULT ''
);
INSERT INTO service_state(singleton) VALUES(1);
CREATE TABLE invalid_epochs (epoch TEXT PRIMARY KEY);
CREATE TABLE logs (
 job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
 sequence INTEGER NOT NULL,
 time INTEGER NOT NULL,
 stream TEXT NOT NULL CHECK(stream IN ('stdout','stderr','system')),
 text BLOB NOT NULL,
 PRIMARY KEY(job_id,sequence)
);
PRAGMA user_version=1;
`

const jobColumns = `id,principal,request,profile,profile_digest,request_digest,state,reason,created_at,updated_at,started_at,finished_at,deadline,worker_epoch,lease_token,cancel_requested,result,cleanup_ok`

type scanner interface{ Scan(...any) error }

func scanJob(row scanner) (model.Job, error) {
	return scanJobSequence(row, nil)
}

func scanJobSequence(row scanner, sequence *int64) (model.Job, error) {
	var job model.Job
	var request, profile, result []byte
	var created, updated int64
	var started, finished, deadline sql.NullInt64
	dest := []any{sequence, &job.ID, &job.Principal, &request, &profile, &job.ProfileDigest, &job.RequestDigest, &job.State, &job.Reason, &created, &updated, &started, &finished, &deadline, &job.WorkerEpoch, &job.LeaseToken, &job.CancelRequested, &result, &job.CleanupOK}
	if sequence == nil {
		dest = dest[1:]
	}
	err := row.Scan(dest...)
	if errors.Is(err, sql.ErrNoRows) {
		return job, ErrNotFound
	}
	if err != nil {
		return job, err
	}
	if err := json.Unmarshal(request, &job.Request); err != nil {
		return job, err
	}
	if err := json.Unmarshal(profile, &job.Profile); err != nil {
		return job, err
	}
	job.CreatedAt = time.Unix(0, created).UTC()
	job.UpdatedAt = time.Unix(0, updated).UTC()
	job.StartedAt = optionalTime(started)
	job.FinishedAt = optionalTime(finished)
	job.Deadline = optionalTime(deadline)
	job.Result = json.RawMessage(result)
	return job, nil
}

func optionalTime(value sql.NullInt64) *time.Time {
	if !value.Valid {
		return nil
	}
	t := time.Unix(0, value.Int64).UTC()
	return &t
}

func getTx(ctx context.Context, tx *sql.Tx, id string) (model.Job, error) {
	return scanJob(tx.QueryRowContext(ctx, "SELECT "+jobColumns+" FROM jobs WHERE id=?", id))
}

func (s *Store) Get(ctx context.Context, id string) (model.Job, error) {
	return scanJob(s.db.QueryRowContext(ctx, "SELECT "+jobColumns+" FROM jobs WHERE id=?", id))
}

// Lookup permits retry normalization against the original approved snapshot even
// if the profile registry has changed or removed that profile since admission.
func (s *Store) Lookup(ctx context.Context, principal, key string) (model.Job, error) {
	if !validOpaque(principal, 256) || !validOpaque(key, 256) {
		return model.Job{}, ErrInvalid
	}
	return scanJob(s.db.QueryRowContext(ctx, "SELECT "+jobColumns+" FROM jobs WHERE principal=? AND idempotency_key=?", principal, key))
}

// List is ascending insertion order. Cursors are durable sequence positions, not
// offsets, so deleting older jobs cannot skip the next result. Repository access
// is always an explicit allowlist, including when continuing a cursor.
func (s *Store) List(ctx context.Context, repos []string, cursor string, limit int) ([]model.Job, string, error) {
	if limit == 0 {
		limit = 50
	}
	if limit < 1 || limit > 1000 || len(repos) > 1000 {
		return nil, "", ErrInvalid
	}
	var after int64
	if cursor != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil {
			return nil, "", ErrInvalid
		}
		after, err = strconv.ParseInt(string(decoded), 10, 64)
		if err != nil || after < 1 {
			return nil, "", ErrInvalid
		}
	}
	if len(repos) == 0 {
		return []model.Job{}, "", nil
	}
	jobs := make([]model.Job, 0, limit)
	args := make([]any, 0, len(repos)+2)
	args = append(args, after)
	for _, repo := range repos {
		args = append(args, repo)
	}
	args = append(args, limit+1)
	rows, err := s.db.QueryContext(ctx, "SELECT sequence,"+jobColumns+" FROM jobs WHERE sequence>? AND repo IN ("+strings.TrimSuffix(strings.Repeat("?,", len(repos)), ",")+") ORDER BY sequence LIMIT ?", args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	var last int64
	for rows.Next() {
		if len(jobs) == limit {
			return jobs, base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(last, 10))), nil
		}
		var sequence int64
		job, err := scanJobSequence(rows, &sequence)
		if err != nil {
			return nil, "", err
		}
		jobs = append(jobs, job)
		last = sequence
	}
	return jobs, "", rows.Err()
}

func randomToken(prefix string) (string, error) {
	var bytes [24]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(bytes[:]), nil
}

func validOpaque(value string, max int) bool {
	return value != "" && len(value) <= max && utf8.ValidString(value) && strings.TrimSpace(value) == value && strings.IndexFunc(value, unicode.IsControl) < 0
}

func validReason(value string) bool { return len(value) <= 4096 && utf8.ValidString(value) }
func validTime(now time.Time) bool  { return !now.IsZero() && now.Equal(time.Unix(0, now.UnixNano())) }

func contention(err error) bool {
	var sqliteErr *sqlite.Error
	if !errors.As(err, &sqliteErr) {
		return false
	}
	// SQLITE_BUSY (including extended codes) and SQLITE_LOCKED.
	return sqliteErr.Code()&255 == 5 || sqliteErr.Code()&255 == 6
}

func uniqueViolation(err error) bool {
	var sqliteErr *sqlite.Error
	return errors.As(err, &sqliteErr) && sqliteErr.Code() == 2067 // SQLITE_CONSTRAINT_UNIQUE
}

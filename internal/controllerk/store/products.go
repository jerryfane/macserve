package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// productsSchema is the products pool's ledger (schema version 9): one row
// per content-addressed test-products.tar the controller retains for
// build-for-testing producer jobs, named by its SHA-256. evicted_at is NULL
// while the bytes are in the pool; an evicted row is the eviction's proof
// (digest, bytes, time) until Prune drops it with the job metadata
// retention.
const productsSchema = `
CREATE TABLE products (
 sha256 TEXT PRIMARY KEY CHECK(length(sha256)=64),
 bytes INTEGER NOT NULL CHECK(bytes>=0),
 job_id TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 used_at INTEGER NOT NULL,
 evicted_at INTEGER
);
CREATE INDEX products_evicted ON products(evicted_at) WHERE evicted_at IS NOT NULL;
PRAGMA user_version=9;
`

// Product is one products pool record. JobID is the producer job that last
// stored the bytes; CreatedAt is when they last entered the pool and UsedAt
// when they were last stored or used. EvictedAt is nil while the bytes are
// retained.
type Product struct {
	SHA256    string
	Bytes     int64
	JobID     string
	CreatedAt time.Time
	UsedAt    time.Time
	EvictedAt *time.Time
}

// RecordProduct records that the pool holds the bytes of sha256, stored for
// producer job jobID at now. Bytes that were evicted re-enter the pool with
// a new creation time; retained bytes keep theirs.
func (s *Store) RecordProduct(ctx context.Context, sha256 string, bytes int64, jobID string, now time.Time) error {
	if !validDigest(sha256) || bytes < 0 || !validOpaque(jobID, 128) || !validTime(now) {
		return ErrInvalid
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO products(sha256,bytes,job_id,created_at,used_at) VALUES(?,?,?,?,?)
ON CONFLICT(sha256) DO UPDATE SET bytes=excluded.bytes,job_id=excluded.job_id,used_at=excluded.used_at,
 created_at=CASE WHEN evicted_at IS NULL THEN created_at ELSE excluded.created_at END,evicted_at=NULL`, sha256, bytes, jobID, now.UnixNano(), now.UnixNano())
	return err
}

// RetainedProducts lists the records of the bytes in the pool.
func (s *Store) RetainedProducts(ctx context.Context) ([]Product, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT sha256,bytes,job_id,created_at,used_at FROM products WHERE evicted_at IS NULL ORDER BY sha256")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var products []Product
	for rows.Next() {
		var p Product
		var created, used int64
		if err := rows.Scan(&p.SHA256, &p.Bytes, &p.JobID, &created, &used); err != nil {
			return nil, err
		}
		p.CreatedAt, p.UsedAt = time.Unix(0, created).UTC(), time.Unix(0, used).UTC()
		products = append(products, p)
	}
	return products, rows.Err()
}

// GetProduct returns the record of sha256, retained or evicted.
func (s *Store) GetProduct(ctx context.Context, sha256 string) (Product, error) {
	var p Product
	var created, used int64
	var evicted sql.NullInt64
	err := s.db.QueryRowContext(ctx, "SELECT sha256,bytes,job_id,created_at,used_at,evicted_at FROM products WHERE sha256=?", sha256).Scan(&p.SHA256, &p.Bytes, &p.JobID, &created, &used, &evicted)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	if err != nil {
		return p, err
	}
	p.CreatedAt, p.UsedAt = time.Unix(0, created).UTC(), time.Unix(0, used).UTC()
	if evicted.Valid {
		at := time.Unix(0, evicted.Int64).UTC()
		p.EvictedAt = &at
	}
	return p, nil
}

// EvictProduct records that the bytes of sha256 left the pool at now. The
// row stays as the eviction's proof; an already evicted row keeps its time.
func (s *Store) EvictProduct(ctx context.Context, sha256 string, now time.Time) error {
	if !validDigest(sha256) || !validTime(now) {
		return ErrInvalid
	}
	_, err := s.db.ExecContext(ctx, "UPDATE products SET evicted_at=? WHERE sha256=? AND evicted_at IS NULL", now.UnixNano(), sha256)
	return err
}

// TouchProduct records a use of the retained bytes of sha256 at now: it
// moves their use time forward, never back, and changes nothing else (the
// producer, the creation time). An evicted or unknown digest is unchanged.
func (s *Store) TouchProduct(ctx context.Context, sha256 string, now time.Time) error {
	if !validDigest(sha256) || !validTime(now) {
		return ErrInvalid
	}
	_, err := s.db.ExecContext(ctx, "UPDATE products SET used_at=MAX(used_at,?) WHERE sha256=? AND evicted_at IS NULL", now.UnixNano(), sha256)
	return err
}

// deleteEvictionProofs drops the products records evicted at or before
// cutoff, at most pruneBatchJobs of them.
func deleteEvictionProofs(ctx context.Context, tx *sql.Tx, cutoff time.Time) (int64, error) {
	result, err := tx.ExecContext(ctx, "DELETE FROM products WHERE sha256 IN (SELECT sha256 FROM products WHERE evicted_at IS NOT NULL AND evicted_at<=? LIMIT ?)", cutoff.UnixNano(), pruneBatchJobs)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// validDigest reports whether value is a lowercase hex SHA-256.
func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

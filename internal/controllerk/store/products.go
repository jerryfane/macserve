package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
)

// ErrProductsUnavailable refuses a consumer whose producer did not seal
// usable test products, or whose bytes left the products pool: its job ID
// is unknown or pruned, it has not succeeded, it is no build-for-testing
// job, its result names no products, or the bytes were evicted.
var ErrProductsUnavailable = errors.New("test products unavailable")

// ProducerProducts returns the reference a consumer of producer names: the
// producer's job ID, the SHA-256 of its test-products.tar artifact and the
// .xctestrun its worker observed, from its stored (normalized) result. It
// fails with ErrProductsUnavailable unless producer is a succeeded
// build-for-testing job whose result holds both.
func ProducerProducts(producer model.Job) (model.ProductsRef, error) {
	if producer.State != model.Succeeded || !producer.Request.BuildForTesting || len(producer.Result) == 0 {
		return model.ProductsRef{}, ErrProductsUnavailable
	}
	// The stored result is the controller's completion record, whose
	// "result" is the normalized worker result.
	var completion struct {
		Result struct {
			State     model.State `json:"state"`
			Artifacts []struct {
				Name   string `json:"name"`
				SHA256 string `json:"sha256"`
			} `json:"artifacts"`
			Observation struct {
				Xctestrun string `json:"xctestrun"`
			} `json:"observation"`
		} `json:"result"`
	}
	if err := json.Unmarshal(producer.Result, &completion); err != nil || completion.Result.State != model.Succeeded {
		return model.ProductsRef{}, ErrProductsUnavailable
	}
	result := completion.Result
	ref := model.ProductsRef{ProducerJobID: producer.ID, Xctestrun: result.Observation.Xctestrun}
	for _, a := range result.Artifacts {
		if a.Name == profiles.TestProductsArtifact {
			ref.SHA256 = a.SHA256
			break
		}
	}
	if !profiles.ValidProductsRef(ref) {
		return model.ProductsRef{}, ErrProductsUnavailable
	}
	return ref, nil
}

// consumableProducts admits the products reference of request, a consumer
// job: its producer must be a succeeded build-for-testing job of the same
// repository and commit whose sealed products ref names exactly, and the
// products pool must still hold those bytes. A reference to another
// commit's or repository's products, or to other bytes, is invalid; a
// producer that has none to offer, or whose bytes were evicted, leaves the
// products unavailable.
func consumableProducts(ctx context.Context, tx *sql.Tx, request model.Request, ref model.ProductsRef) error {
	producer, err := getTx(ctx, tx, ref.ProducerJobID)
	if errors.Is(err, ErrNotFound) {
		return ErrProductsUnavailable
	}
	if err != nil {
		return err
	}
	if producer.Request.Repo != request.Repo || producer.Request.SHA != request.SHA {
		return ErrInvalid
	}
	sealed, err := ProducerProducts(producer)
	if err != nil {
		return err
	}
	if sealed != ref {
		return ErrInvalid
	}
	var retained bool
	err = tx.QueryRowContext(ctx, "SELECT evicted_at IS NULL FROM products WHERE sha256=?", ref.SHA256).Scan(&retained)
	if errors.Is(err, sql.ErrNoRows) || err == nil && !retained {
		return ErrProductsUnavailable
	}
	return err
}

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

package store

import (
	"context"
	"database/sql"

	"github.com/jerryfane/macserve/internal/model"
)

// QueueView is the queue as Claim reads it, for read-only reporting: every
// queued job in the fair order (fairOrder) and every active job, oldest claim
// first, from one read transaction. It claims, expires and reserves nothing,
// so a queued job past its TTL still shows until the next claim or admission
// expires it.
type QueueView struct {
	Queued []model.Job
	Active []model.Job
}

// QueueView reads the queue without a write reservation.
func (s *Store) QueueView(ctx context.Context) (QueueView, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return QueueView{}, err
	}
	defer tx.Rollback()
	active, err := activeJobs(ctx, tx)
	if err != nil {
		return QueueView{}, err
	}
	rows, err := tx.QueryContext(ctx, fairOrder)
	if err != nil {
		return QueueView{}, err
	}
	defer rows.Close()
	var queued []model.Job
	for rows.Next() {
		job, err := scanJob(rows)
		if err != nil {
			return QueueView{}, err
		}
		queued = append(queued, job)
	}
	if err := rows.Err(); err != nil {
		return QueueView{}, err
	}
	return QueueView{Queued: queued, Active: active}, nil
}

// MemoryAdmits reports whether Claim's concurrent memory cap
// (ConcurrentMemoryCapMiB) admits job beside v's active jobs.
func (v QueueView) MemoryAdmits(job model.Job) bool {
	return memoryAdmits(v.Active, job)
}

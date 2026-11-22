package store

import (
	"context"
	"database/sql"

	"github.com/jerryfane/macserve/internal/githubwire"
	"github.com/jerryfane/macserve/internal/model"
)

// MaxTierPasses bounds how long a queued full-tier shard waits behind
// fast-tier work (#193): Claim takes an early job ahead of a late one at most
// MaxTierPasses times until a late job is claimed. Then claims follow the
// fair order alone, so the oldest late job is claimed when it reaches the
// fair order's head, before any further pass. A claim of a late job, or a
// claim while no late job is queued, starts the count afresh. The count
// lives in the Store handle: a restarted controller may let MaxTierPasses
// more early jobs pass, never an unbounded number.
const MaxTierPasses = 3

// claimClass is how a queued job's GitHub tier bears on the claim order
// (tierOrder).
type claimClass int

const (
	// inOrder keeps a job's fair-order place relative to every other job:
	// API jobs and every GitHub job of an untiered policy.
	inOrder claimClass = iota
	// early is a GitHub job of a tiered policy that is not a full-tier
	// shard: a fast-tier shard or a build (a build-for-testing producer
	// included), the per-push signal and what the shards need.
	early
	// late is a GitHub job of a full-tier matrix shard.
	late
)

// SetRunTiers registers fn, which names the tier a GitHub run is claimed in
// under the policy it was admitted by: githubwire.TierFull for a full-tier
// matrix shard, githubwire.TierFast for any other run of a tiered policy, ""
// otherwise. Claim reads it to take fast-tier work ahead of full-tier shards
// (tierOrder); without it every job keeps the fair order. One fn is kept; a
// later call replaces it. fn runs inside claim and queue-view transactions
// and must not call the Store.
func (s *Store) SetRunTiers(fn func(GitHubRun) string) { s.runTiers.Store(&fn) }

// queuedGitHubRuns is the GitHub run of each queued job that is a GitHub
// attempt: its repository, profile and shard.
const queuedGitHubRuns = `SELECT a.job_id,r.repository_id,r.repository,r.profile,r.shard FROM jobs AS j JOIN github_attempts AS a ON a.job_id=j.id JOIN github_runs AS r ON r.run_key=a.run_key WHERE j.state='queued'`

// queued is every queued job in the fair order (fairOrder) with the claim
// class of each early or late one by job ID; every job is inOrder until
// SetRunTiers registers the tiers, which only a GitHub poller does after
// creating the GitHub tables.
func (s *Store) queued(ctx context.Context, tx *sql.Tx) ([]model.Job, map[string]claimClass, error) {
	fair, err := fairQueued(ctx, tx)
	if err != nil {
		return nil, nil, err
	}
	tiers := s.runTiers.Load()
	if tiers == nil || len(fair) == 0 {
		return fair, nil, nil
	}
	rows, err := tx.QueryContext(ctx, queuedGitHubRuns)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	classes := make(map[string]claimClass)
	for rows.Next() {
		var id string
		var run GitHubRun
		if err := rows.Scan(&id, &run.RepositoryID, &run.Repository, &run.Profile, &run.Shard); err != nil {
			return nil, nil, err
		}
		switch (*tiers)(run) {
		case githubwire.TierFast:
			classes[id] = early
		case githubwire.TierFull:
			classes[id] = late
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	return fair, classes, nil
}

// fairQueued is every queued job in the fair order (fairOrder).
func fairQueued(ctx context.Context, tx *sql.Tx) ([]model.Job, error) {
	rows, err := tx.QueryContext(ctx, fairOrder)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var fair []model.Job
	for rows.Next() {
		job, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		fair = append(fair, job)
	}
	return fair, rows.Err()
}

// claimOrder is the order Claim takes the queued jobs in: the fair order
// with the tiers applied (tierOrder), or the fair order alone while a late
// job is queued after MaxTierPasses passes.
func (s *Store) claimOrder(fair []model.Job, classes map[string]claimClass) []model.Job {
	if s.tierPasses.Load() >= MaxTierPasses && lateQueued(fair, classes) {
		return fair
	}
	return tierOrder(fair, classes)
}

func lateQueued(fair []model.Job, classes map[string]claimClass) bool {
	for _, job := range fair {
		if classes[job.ID] == late {
			return true
		}
	}
	return false
}

// tierOrder reorders fair, the fair order, by GitHub tier: within each
// stretch of consecutive early and late jobs of one repository, the early
// jobs go before the late ones, each class keeping its own order. An inOrder
// job and the next repository's first job end a stretch, so no job passes an
// inOrder job, a job of its own class or a job of a repository the fair
// order puts first: per-repository fairness and every inOrder job's place
// are unchanged.
func tierOrder(fair []model.Job, classes map[string]claimClass) []model.Job {
	if len(classes) == 0 {
		return fair
	}
	order := make([]model.Job, 0, len(fair))
	var held []model.Job
	for i, job := range fair {
		if i > 0 && (classes[job.ID] == inOrder || job.Request.Repo != fair[i-1].Request.Repo) {
			order = append(order, held...)
			held = held[:0]
		}
		if classes[job.ID] == late {
			held = append(held, job)
		} else {
			order = append(order, job)
		}
	}
	return append(order, held...)
}

// claimable is the first job of order a claim may take, passing over
// concurrent simulator_script jobs (model.Profile.Concurrent) when
// skipConcurrent is set, for a claim while one such job is active.
func claimable(order []model.Job, skipConcurrent bool) (model.Job, bool) {
	for _, job := range order {
		if !skipConcurrent || !job.Profile.Concurrent() {
			return job, true
		}
	}
	return model.Job{}, false
}

// countPass records a committed claim of job, taken where fairHead headed
// the fair order: a pass when they differ (an early job taken ahead of a
// late one), a fresh count when job is late or no late job was queued.
func (s *Store) countPass(job, fairHead model.Job, fair []model.Job, classes map[string]claimClass) {
	switch {
	case classes[job.ID] == late || !lateQueued(fair, classes):
		s.tierPasses.Store(0)
	case job.ID != fairHead.ID:
		s.tierPasses.Add(1)
	}
}

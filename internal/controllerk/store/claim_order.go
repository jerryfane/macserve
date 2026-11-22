package store

import (
	"context"
	"database/sql"

	"github.com/jerryfane/macserve/internal/githubwire"
	"github.com/jerryfane/macserve/internal/model"
)

// MaxTierPasses bounds how long a queued full-tier shard waits behind
// fast-tier work (#193): Claim takes a repository's early jobs ahead of its
// late ones at most MaxTierPasses times until one of its late jobs is
// claimed. Then that repository's jobs follow the fair order alone, so its
// oldest late job is claimed when it reaches the fair order's head, before
// any further pass. The count is the repository's own: claims of other
// repositories' jobs neither add to it nor start it afresh. A claim of one
// of its late jobs, or of its job while none of its late jobs is queued,
// starts it afresh. The counts live in the Store handle: a restarted
// controller may let MaxTierPasses more early jobs pass, never an unbounded
// number.
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

// TierQuery is what names a queued GitHub job's tier: its run's repository
// and the run's profile and matrix shard ("" for a build).
type TierQuery struct {
	RepositoryID   int64
	Repository     string
	Profile, Shard string
}

// SetRunTiers registers fn, which names the tier a GitHub run is claimed in
// under the policy it was admitted by: githubwire.TierFull for a full-tier
// matrix shard, githubwire.TierFast for any other run of a tiered policy, ""
// otherwise. Claim reads it to take fast-tier work ahead of full-tier shards
// (tierOrder); without it every job keeps the fair order. One fn is kept; a
// later call replaces it. fn runs inside claim and queue-view transactions
// and must not call the Store.
func (s *Store) SetRunTiers(fn func(TierQuery) string) { s.runTiers.Store(&fn) }

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
		var query TierQuery
		if err := rows.Scan(&id, &query.RepositoryID, &query.Repository, &query.Profile, &query.Shard); err != nil {
			return nil, nil, err
		}
		switch (*tiers)(query) {
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
// with the tiers applied (tierOrder) to every repository but those whose
// queued late jobs were passed MaxTierPasses times.
func (s *Store) claimOrder(fair []model.Job, classes map[string]claimClass) []model.Job {
	if len(classes) == 0 {
		return fair
	}
	s.passesMu.Lock()
	exhausted := make(map[string]bool)
	for repo, passes := range s.tierPasses {
		exhausted[repo] = passes >= MaxTierPasses
	}
	s.passesMu.Unlock()
	return tierOrder(fair, classes, exhausted)
}

// tierOrder reorders fair, the fair order, by GitHub tier: within each
// stretch of consecutive early and late jobs of one repository, the early
// jobs go before the late ones, each class keeping its own order. An inOrder
// job and the next repository's first job end a stretch, so no job passes an
// inOrder job, a job of its own class or a job of a repository the fair
// order puts first: per-repository fairness and every inOrder job's place
// are unchanged. The jobs of a repository in exhausted keep the fair order.
func tierOrder(fair []model.Job, classes map[string]claimClass, exhausted map[string]bool) []model.Job {
	order := make([]model.Job, 0, len(fair))
	var held []model.Job
	for i, job := range fair {
		if i > 0 && (classes[job.ID] == inOrder || job.Request.Repo != fair[i-1].Request.Repo) {
			order = append(order, held...)
			held = held[:0]
		}
		if classes[job.ID] == late && !exhausted[job.Request.Repo] {
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

// countPass records a committed claim of job from fair, the fair order it
// was claimed from, in job's repository's count: a pass when one of the
// repository's late jobs precedes job in the fair order, a fresh count when
// job is late or none of the repository's late jobs is queued. The count of
// every other repository with no late job queued is dropped too.
func (s *Store) countPass(job model.Job, fair []model.Job, classes map[string]claimClass) {
	waiting := make(map[string]bool)
	passed, ahead := false, true
	for _, queued := range fair {
		if queued.ID == job.ID {
			ahead = false
		}
		if classes[queued.ID] != late {
			continue
		}
		waiting[queued.Request.Repo] = true
		passed = passed || ahead && queued.Request.Repo == job.Request.Repo
	}
	s.passesMu.Lock()
	defer s.passesMu.Unlock()
	for repo := range s.tierPasses {
		if !waiting[repo] {
			delete(s.tierPasses, repo)
		}
	}
	switch {
	case classes[job.ID] == late:
		delete(s.tierPasses, job.Request.Repo)
	case passed:
		if s.tierPasses == nil {
			s.tierPasses = make(map[string]int)
		}
		s.tierPasses[job.Request.Repo]++
	}
}

package store

import (
	"context"
	"database/sql"

	"github.com/jerryfane/macserve/internal/model"
)

// Concurrent jobs share one worker account in lanes. Every active job holds
// the lane Claim assigned it, and the database keeps two active rows off one
// lane even for a writer bypassing Claim: an active row must carry a lane of at
// least 1, and active lanes are unique. A finished job keeps its lane as
// history. The single active row a version 6 database may hold takes lane 1;
// older finished rows have none.
const laneSchema = `
DROP INDEX jobs_one_active;
ALTER TABLE jobs ADD COLUMN lane INTEGER;
UPDATE jobs SET lane=1 WHERE state IN ('preparing','running','cancelling','finalizing');
CREATE UNIQUE INDEX jobs_active_lane ON jobs(lane) WHERE state IN ('preparing','running','cancelling','finalizing');
CREATE TRIGGER jobs_active_lane_insert BEFORE INSERT ON jobs WHEN NEW.state IN ('preparing','running','cancelling','finalizing') AND (NEW.lane IS NULL OR NEW.lane<1) BEGIN
 SELECT RAISE(ABORT,'active job requires a lane');
END;
CREATE TRIGGER jobs_active_lane_update BEFORE UPDATE OF state,lane ON jobs WHEN NEW.state IN ('preparing','running','cancelling','finalizing') AND (NEW.lane IS NULL OR NEW.lane<1) BEGIN
 SELECT RAISE(ABORT,'active job requires a lane');
END;
PRAGMA user_version=7;
`

type queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

// activeJobs returns every active job, oldest claim first.
func activeJobs(ctx context.Context, q queryer) ([]model.Job, error) {
	rows, err := q.QueryContext(ctx, "SELECT "+jobColumns+" FROM jobs WHERE state IN ("+activeStates+") ORDER BY started_at,sequence")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var jobs []model.Job
	for rows.Next() {
		job, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	return jobs, rows.Err()
}

// ActiveJobs returns every job holding a lane, oldest claim first.
func (s *Store) ActiveJobs(ctx context.Context) ([]model.Job, error) {
	return activeJobs(ctx, s.db)
}

// freeLane is the lowest lane in 1..lanes no active job holds, or 0.
func freeLane(active []model.Job, lanes int) int {
	for lane := 1; lane <= lanes; lane++ {
		taken := false
		for _, job := range active {
			taken = taken || job.Lane == lane
		}
		if !taken {
			return lane
		}
	}
	return 0
}

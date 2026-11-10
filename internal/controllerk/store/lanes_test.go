package store

import (
	"context"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
)

// undoLaneSchema returns a current database to the version 6 jobs table, for
// tests that emulate an older database.
const undoLaneSchema = "DROP TRIGGER jobs_active_lane_insert; DROP TRIGGER jobs_active_lane_update; DROP INDEX jobs_active_lane; ALTER TABLE jobs DROP COLUMN lane; CREATE UNIQUE INDEX jobs_one_active ON jobs ((1)) WHERE state IN ('preparing','running','cancelling','finalizing');"

func claimLanes(t *testing.T, s *Store, epoch string, now time.Time, lanes int) model.Job {
	t.Helper()
	job, err := s.Claim(context.Background(), epoch, now, lanes)
	if err != nil {
		t.Fatal(err)
	}
	return job
}

func enqueueArchive(t *testing.T, s *Store, key string, now time.Time) model.Job {
	t.Helper()
	job, _, err := s.Enqueue(context.Background(), "principal", key, archiveAdmission(t), now)
	if err != nil {
		t.Fatal(err)
	}
	return job
}

func TestClaimFillsLowestFreeLaneUpToLanes(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t, Options{})
	for _, key := range []string{"a", "b", "c", "d"} {
		enqueueJob(t, s, "principal", key, testNow)
	}
	first := claimLanes(t, s, "epoch", testNow, 2)
	second := claimLanes(t, s, "epoch", testNow.Add(time.Second), 2)
	if first.Lane != 1 || second.Lane != 2 || first.ID == second.ID {
		t.Fatalf("lanes = %d,%d", first.Lane, second.Lane)
	}
	if got := getJob(t, s, second.ID); got.Lane != 2 {
		t.Fatalf("stored lane = %d", got.Lane)
	}
	_, err := s.Claim(ctx, "epoch", testNow.Add(2*time.Second), 2)
	requireError(t, err, ErrNoJob)
	active, err := s.ActiveJobs(ctx)
	if err != nil || len(active) != 2 || active[0].ID != first.ID || active[1].ID != second.ID {
		t.Fatalf("active = %+v %v", active, err)
	}
	finishJob(t, s, first, model.Succeeded, true, testNow.Add(3*time.Second))
	third := claimLanes(t, s, "epoch", testNow.Add(4*time.Second), 2)
	if third.Lane != 1 {
		t.Fatalf("freed lane not reused: %d", third.Lane)
	}
	if got := getJob(t, s, first.ID); got.Lane != 1 {
		t.Fatalf("finished job lost its lane: %d", got.Lane)
	}
}

func TestClaimSingleLaneRefusesSecondJob(t *testing.T) {
	s, _ := newStore(t, Options{})
	enqueueJob(t, s, "principal", "a", testNow)
	enqueueJob(t, s, "principal", "b", testNow)
	if job := claimLanes(t, s, "epoch", testNow, 1); job.Lane != 1 {
		t.Fatalf("lane = %d", job.Lane)
	}
	_, err := s.Claim(context.Background(), "epoch", testNow, 1)
	requireError(t, err, ErrNoJob)
	for _, lanes := range []int{0, model.MaxConcurrentJobs + 1} {
		_, err := s.Claim(context.Background(), "epoch", testNow, lanes)
		requireError(t, err, ErrInvalid)
	}
}

// An exclusive job at the fair head drains the lanes; nothing behind it is
// claimed meanwhile, and once claimed it holds every lane.
func TestExclusiveHeadDrainsLanesAndBlocksWhileActive(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t, Options{})
	build := enqueueJob(t, s, "principal", "build-1", testNow)
	archive := enqueueArchive(t, s, "archive", testNow.Add(time.Second))
	later := enqueueJob(t, s, "principal", "build-2", testNow.Add(2*time.Second))
	running := claimLanes(t, s, "epoch", testNow.Add(3*time.Second), 3)
	if running.ID != build.ID {
		t.Fatalf("claimed %s, want the head %s", running.ID, build.ID)
	}
	_, err := s.Claim(ctx, "epoch", testNow.Add(4*time.Second), 3)
	requireError(t, err, ErrNoJob)
	if got := getJob(t, s, later.ID); got.State != model.Queued {
		t.Fatalf("later job jumped the exclusive head: %s", got.State)
	}
	finishJob(t, s, running, model.Succeeded, true, testNow.Add(5*time.Second))
	exclusive := claimLanes(t, s, "epoch", testNow.Add(6*time.Second), 3)
	if exclusive.ID != archive.ID || exclusive.Lane != 1 {
		t.Fatalf("claimed %s lane %d, want the archive in lane 1", exclusive.ID, exclusive.Lane)
	}
	_, err = s.Claim(ctx, "epoch", testNow.Add(7*time.Second), 3)
	requireError(t, err, ErrNoJob)
	finishJob(t, s, exclusive, model.Failed, true, testNow.Add(8*time.Second))
	if job := claimLanes(t, s, "epoch", testNow.Add(9*time.Second), 3); job.ID != later.ID {
		t.Fatalf("claimed %s, want %s", job.ID, later.ID)
	}
}

// A version 6 database's single active job takes lane 1 and stays active; it
// still finishes on its lease, and the next claim takes the other lane.
func TestLaneMigrationKeepsVersion6ActiveJob(t *testing.T) {
	ctx := context.Background()
	s, path := newStore(t, Options{})
	enqueueJob(t, s, "principal", "old", testNow)
	enqueueJob(t, s, "principal", "new", testNow)
	enqueueJob(t, s, "principal", "third", testNow)
	old := claimJob(t, s, "epoch", testNow)
	if _, err := s.db.ExecContext(ctx, undoLaneSchema+"PRAGMA user_version=6;"); err != nil {
		t.Fatal(err)
	}
	requireError(t, s.Close(), nil)
	s = openStore(t, path, Options{})
	var version int
	requireError(t, s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version), nil)
	if version != SchemaVersion {
		t.Fatalf("user_version = %d", version)
	}
	migrated := getJob(t, s, old.ID)
	if migrated.State != model.Preparing || migrated.Lane != 1 || migrated.LeaseToken != old.LeaseToken {
		t.Fatalf("migrated active job: %+v", migrated)
	}
	if job := claimLanes(t, s, "epoch", testNow.Add(time.Second), 2); job.Lane != 2 {
		t.Fatalf("lane beside migrated job = %d", job.Lane)
	}
	_, err := s.Claim(ctx, "epoch", testNow.Add(2*time.Second), 2)
	requireError(t, err, ErrNoJob)
	finishJob(t, s, migrated, model.Succeeded, true, testNow.Add(3*time.Second))
	if job := claimLanes(t, s, "epoch", testNow.Add(4*time.Second), 2); job.Lane != 1 {
		t.Fatalf("migrated lane not freed: %d", job.Lane)
	}
}

func TestActiveLaneIndexRejectsSharedOrMissingLane(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t, Options{})
	enqueueJob(t, s, "principal", "a", testNow)
	enqueueJob(t, s, "principal", "b", testNow)
	enqueueJob(t, s, "principal", "c", testNow)
	first := claimLanes(t, s, "epoch", testNow, 2)
	second := claimLanes(t, s, "epoch", testNow, 2)
	if _, err := s.db.ExecContext(ctx, "UPDATE jobs SET lane=? WHERE id=?", first.Lane, second.ID); !uniqueViolation(err) {
		t.Fatalf("shared active lane: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, "UPDATE jobs SET lane=NULL WHERE id=?", second.ID); err == nil {
		t.Fatal("active job without a lane")
	}
	// A bypassing claim without a lane is refused too.
	if _, err := s.db.ExecContext(ctx, "UPDATE jobs SET state='preparing',worker_epoch='epoch',lease_token='lease',started_at=?,deadline=? WHERE state='queued'", testNow.UnixNano(), testNow.UnixNano()); err == nil {
		t.Fatal("active job claimed without a lane")
	}
}

// Every active row belongs to the registered epoch, controller recovery
// interrupts all of them, and pause cancel_active cancels all of them.
func TestActiveSetRegistrationRecoveryAndPause(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t, Options{})
	enqueueJob(t, s, "principal", "a", testNow)
	enqueueJob(t, s, "principal", "b", testNow)
	requireError(t, s.RegisterWorker(ctx, "epoch"), nil)
	first := claimLanes(t, s, "epoch", testNow, 2)
	second := claimLanes(t, s, "epoch", testNow, 2)
	requireError(t, s.RegisterWorker(ctx, "epoch"), nil)
	requireError(t, s.RegisterWorker(ctx, "other"), ErrTransition)
	if _, err := s.Pause(ctx, "owner", "cancel_active", "admin", testNow); err != nil {
		t.Fatal(err)
	}
	for _, job := range []model.Job{first, second} {
		if got := getJob(t, s, job.ID); !got.CancelRequested || got.State != model.Cancelling {
			t.Fatalf("pause left %s uncancelled: %+v", job.ID, got)
		}
	}
	requireError(t, s.Recover(ctx, testNow.Add(time.Second)), nil)
	for _, job := range []model.Job{first, second} {
		if got := getJob(t, s, job.ID); got.State != model.Interrupted {
			t.Fatalf("recovery left %s %s", job.ID, got.State)
		}
	}
	if active, err := s.ActiveJobs(ctx); err != nil || len(active) != 0 {
		t.Fatalf("active after recovery = %+v %v", active, err)
	}
}

// Concurrent jobs' summed memory budgets stay within ConcurrentMemoryCapMiB;
// a job alone is never refused by the cap.
func TestClaimKeepsConcurrentMemoryBudgetsUnderCap(t *testing.T) {
	running := []model.Job{{Profile: model.Profile{MemoryLimitMiB: 64 << 10}}}
	if !memoryAdmits(nil, model.Job{Profile: model.Profile{MemoryLimitMiB: 200 << 10}}) {
		t.Fatal("cap refused a job running alone")
	}
	if !memoryAdmits(running, model.Job{Profile: model.Profile{MemoryLimitMiB: 64 << 10}}) {
		t.Fatal("cap refused budgets summing to the cap")
	}
	if memoryAdmits(running, model.Job{Profile: model.Profile{MemoryLimitMiB: 64<<10 + 1}}) {
		t.Fatal("cap admitted budgets above it")
	}
	// Through Claim: three default 32 GiB jobs fit beside each other.
	s, _ := newStore(t, Options{})
	for _, key := range []string{"a", "b", "c"} {
		enqueueJob(t, s, "principal", key, testNow)
	}
	for i := range 3 {
		if job := claimLanes(t, s, "epoch", testNow.Add(time.Duration(i)*time.Second), 3); job.Profile.MemoryLimitMiB*3 > ConcurrentMemoryCapMiB {
			t.Fatalf("fixture budget %d MiB does not fit three lanes", job.Profile.MemoryLimitMiB)
		}
	}
}

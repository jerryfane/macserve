package store

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
)

// Prune deletes in bounded batches, each its own transaction, yet removes
// everything due: more retired jobs than one job batch, and more log
// records and log bytes than one log batch, some in a single job. Logs past
// log retention go while their job stays, recent logs and jobs stay, and
// retained_log_bytes still equals the bytes of the records left (#167).
func TestPruneDeletesEverythingDueInBoundedBatches(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t, Options{Retention: 48 * time.Hour, LogRetention: 24 * time.Hour})
	finished := func(key string, at time.Time) model.Job {
		enqueueJob(t, s, "principal", key, at)
		job := claimJob(t, s, "epoch", at)
		if _, err := s.AppendLog(ctx, job.ID, job.LeaseToken, "stdout", key+"\n", at); err != nil {
			t.Fatal(err)
		}
		finishJob(t, s, job, model.Succeeded, true, at)
		return job
	}
	// Setup needs no durability; the store's one connection takes the pragma.
	if _, err := s.db.ExecContext(ctx, "PRAGMA synchronous=OFF"); err != nil {
		t.Fatal(err)
	}
	var retired []model.Job
	for i := range pruneBatchJobs + 5 {
		retired = append(retired, finished(fmt.Sprintf("retired-%d", i), testNow))
	}
	// One job past log retention holds more records, and more bytes, than
	// one log batch: its log alone takes several.
	enqueueJob(t, s, "principal", "large", testNow.Add(30*time.Hour))
	large := claimJob(t, s, "epoch", testNow.Add(30*time.Hour))
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	big := strings.Repeat("b", 60<<10)
	records, size := pruneBatchRows+100, int64(0)
	for i := 1; i <= records; i++ {
		text := "line\n"
		if i%10 == 0 {
			text = big
		}
		size += int64(len(text))
		if _, err := tx.ExecContext(ctx, "INSERT INTO logs(job_id,sequence,time,stream,text) VALUES(?,?,?,?,?)", large.ID, i, testNow.UnixNano(), "stdout", []byte(text)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.ExecContext(ctx, "UPDATE jobs SET log_sequence=?,log_bytes=? WHERE id=?", records, size, large.ID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if size <= 2*pruneBatchBytes {
		t.Fatalf("large log %d bytes fits two batches", size)
	}
	finishJob(t, s, large, model.Failed, true, testNow.Add(30*time.Hour))
	recent := finished("recent", testNow.Add(59*time.Hour))

	counts, err := s.Prune(ctx, testNow.Add(60*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if counts.Jobs != int64(len(retired)) || counts.LogJobs != int64(len(retired))+1 || counts.LogRows != int64(len(retired)+records) {
		t.Fatalf("prune counts %+v", counts)
	}
	// Job, log record and log byte batches each took more than one
	// transaction: one expiry, two tombstone, at least three record (and
	// a last empty one) and three job batches.
	if counts.Batches < 1+2+4+3 {
		t.Fatalf("prune ran %d transactions", counts.Batches)
	}
	for _, job := range retired {
		if _, err := s.Get(ctx, job.ID); err != ErrNotFound {
			t.Fatalf("retired job %s kept: %v", job.ID, err)
		}
	}
	if got := getJob(t, s, large.ID); got.State != model.Failed {
		t.Fatalf("job within retention: %+v", got)
	}
	_, _, _, err = s.Logs(ctx, large.ID, 0, 0)
	requireError(t, err, ErrLogExpired)
	logs, _, _, err := s.Logs(ctx, recent.ID, 0, 0)
	if err != nil || len(logs) != 1 || logs[0].Text != "recent\n" {
		t.Fatalf("recent logs %+v %v", logs, err)
	}
	var retained, remaining, rows int64
	if err := s.db.QueryRowContext(ctx, "SELECT retained_log_bytes FROM service_state WHERE singleton=1").Scan(&retained); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COALESCE(SUM(length(text)),0),COUNT(*) FROM logs").Scan(&remaining, &rows); err != nil {
		t.Fatal(err)
	}
	if retained != remaining || remaining != int64(len("recent\n")) || rows != 1 {
		t.Fatalf("retained_log_bytes %d, records %d of %d bytes", retained, rows, remaining)
	}
	if counts, err := s.Prune(ctx, testNow.Add(60*time.Hour)); err != nil || counts.Jobs != 0 || counts.LogRows != 0 || counts.LogJobs != 0 {
		t.Fatalf("second prune %+v %v", counts, err)
	}
}

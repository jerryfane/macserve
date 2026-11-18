package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

// undoWorkerLogSeqSchema returns a current database to the version 7 jobs
// table, for tests that emulate an older database.
const undoWorkerLogSeqSchema = undoProductsSchema + "ALTER TABLE jobs DROP COLUMN worker_log_seq; ALTER TABLE jobs DROP COLUMN worker_log_lease;"

// logTexts is every record of id, in order.
func logTexts(t *testing.T, s *Store, id string) []string {
	t.Helper()
	records, _, _, err := s.Logs(context.Background(), id, 0, MaxLogPageBytes)
	if err != nil {
		t.Fatal(err)
	}
	texts := make([]string, len(records))
	for i, record := range records {
		texts[i] = record.Text
	}
	return texts
}

// A resent worker chunk (its first answer was lost) is acknowledged without
// a second append; controller and seq-less records keep appending beside
// the worker's seq; a gap is refused and appends nothing; a new lease of the
// job counts from 1 again.
func TestWorkerLogSeqAppendsOnceAndRefusesGap(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t, Options{})
	enqueueJob(t, s, "principal", "key", testNow)
	job := claimJob(t, s, "epoch", testNow)
	appendSeq := func(text string, seq int64) (int64, error) {
		return s.AppendWorkerLog(ctx, job.ID, job.LeaseToken, "stdout", text, seq, testNow)
	}
	if sequence, err := appendSeq("one\n", 1); err != nil || sequence != 1 {
		t.Fatalf("seq 1: %d %v", sequence, err)
	}
	if sequence, err := appendSeq("one\n", 1); err != nil || sequence != 0 {
		t.Fatalf("resent seq 1: %d %v", sequence, err)
	}
	if _, err := s.AppendLog(ctx, job.ID, job.LeaseToken, "system", "controller\n", testNow); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AppendLog(ctx, job.ID, job.LeaseToken, "stderr", "seq-less\n", testNow); err != nil {
		t.Fatal(err)
	}
	if sequence, err := appendSeq("two\n", 2); err != nil || sequence != 4 {
		t.Fatalf("seq 2: %d %v", sequence, err)
	}
	_, err := appendSeq("lost three\n", 4)
	requireError(t, err, ErrLogGap)
	_, err = s.AppendWorkerLog(ctx, job.ID, job.LeaseToken, "system", "x", 3, testNow)
	requireError(t, err, ErrInvalid)
	_, err = appendSeq("x", -1)
	requireError(t, err, ErrInvalid)
	want := []string{"one\n", "controller\n", "seq-less\n", "two\n"}
	if got := logTexts(t, s, job.ID); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("logs = %q, want %q", got, want)
	}
	// A new lease of the job (the column the claim rewrites) counts anew.
	if _, err := s.db.ExecContext(ctx, "UPDATE jobs SET lease_token='second' WHERE id=?", job.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AppendWorkerLog(ctx, job.ID, "second", "stdout", "again\n", 1, testNow); err != nil {
		t.Fatalf("seq 1 of a new lease: %v", err)
	}
	if got := logTexts(t, s, job.ID); len(got) != 5 || got[4] != "again\n" {
		t.Fatalf("new lease logs = %q", got)
	}
}

// A resent chunk that did not fit the log limit is refused again: it was
// never recorded, and the limit's truncation and cancellation stand.
func TestWorkerLogSeqKeepsLogLimit(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t, Options{MaxLogBytes: 8})
	enqueueJob(t, s, "principal", "key", testNow)
	job := claimJob(t, s, "epoch", testNow)
	if _, err := s.AppendWorkerLog(ctx, job.ID, job.LeaseToken, "stdout", "12345", 1, testNow); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		_, err := s.AppendWorkerLog(ctx, job.ID, job.LeaseToken, "stdout", "oversized", 2, testNow)
		requireError(t, err, ErrLogLimit)
	}
	truncated, err := s.LogsTruncated(ctx, job.ID)
	if err != nil || !truncated {
		t.Fatalf("logs truncated %v %v", truncated, err)
	}
	if got := getJob(t, s, job.ID); !got.CancelRequested {
		t.Fatal("log limit did not request cancellation")
	}
	if got := logTexts(t, s, job.ID); len(got) != 1 {
		t.Fatalf("logs = %q", got)
	}
}

// A version 7 database gains the worker log seq with its active job: the
// job's first worker chunk is seq 1, and a resend is acknowledged once.
func TestWorkerLogSeqMigrationFromVersion7(t *testing.T) {
	ctx := context.Background()
	s, path := newStore(t, Options{})
	enqueueJob(t, s, "principal", "key", testNow)
	job := claimJob(t, s, "epoch", testNow)
	if _, err := s.AppendLog(ctx, job.ID, job.LeaseToken, "stdout", "before\n", testNow); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, undoWorkerLogSeqSchema+"PRAGMA user_version=7;"); err != nil {
		t.Fatal(err)
	}
	requireError(t, s.Close(), nil)
	s = openStore(t, path, Options{})
	var version int
	requireError(t, s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version), nil)
	if version != SchemaVersion || SchemaVersion != 9 {
		t.Fatalf("user_version = %d, SchemaVersion = %d", version, SchemaVersion)
	}
	for range 2 {
		if _, err := s.AppendWorkerLog(ctx, job.ID, job.LeaseToken, "stdout", "after\n", 1, testNow.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if got := logTexts(t, s, job.ID); strings.Join(got, "") != "before\nafter\n" {
		t.Fatalf("migrated logs = %q", got)
	}
}

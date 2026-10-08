package store

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
)

func TestLogsPreserveRawTextAndPaginate(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t, Options{})
	enqueueJob(t, s, "principal", "key", testNow)
	job := claimJob(t, s, "epoch", testNow)
	texts := []string{"one\n", "\x1b[31mred\x00\xff", "last\n"}
	streams := []string{"stdout", "stderr", "system"}
	for i, text := range texts {
		sequence, err := s.AppendLog(ctx, job.ID, job.LeaseToken, streams[i], text, testNow.Add(time.Duration(i)*time.Second))
		if err != nil || sequence != int64(i+1) {
			t.Fatalf("append sequence=%d err=%v", sequence, err)
		}
	}
	first, next, truncated, err := s.Logs(ctx, job.ID, 0, len(texts[0]))
	if err != nil || truncated || next != 1 || len(first) != 1 || first[0].Text != texts[0] || first[0].Stream != "stdout" || !first[0].Time.Equal(testNow) {
		t.Fatalf("first logs: %+v %d %v %v", first, next, truncated, err)
	}
	_, unchanged, truncated, err := s.Logs(ctx, job.ID, next, 1)
	requireError(t, err, ErrInvalid)
	if unchanged != next || truncated {
		t.Fatal("small page advanced cursor or implied data loss")
	}
	second, next, truncated, err := s.Logs(ctx, job.ID, next, len(texts[1]))
	if err != nil || truncated || next != 2 || len(second) != 1 || second[0].Text != texts[1] || second[0].Stream != "stderr" {
		t.Fatalf("raw text changed: %+v %d %v %v", second, next, truncated, err)
	}
	last, next, truncated, err := s.Logs(ctx, job.ID, next, 0)
	if err != nil || truncated || next != 3 || len(last) != 1 || last[0].Text != texts[2] {
		t.Fatalf("last page: %+v %d %v %v", last, next, truncated, err)
	}
	empty, final, truncated, err := s.Logs(ctx, job.ID, next, 0)
	if err != nil || truncated || final != next || len(empty) != 0 {
		t.Fatalf("end cursor changed: %+v %d %v %v", empty, final, truncated, err)
	}
	_, _, _, err = s.Logs(ctx, "missing", 0, 0)
	requireError(t, err, ErrNotFound)
	_, err = s.AppendLog(ctx, "missing", "lease", "stdout", "text", testNow)
	requireError(t, err, ErrNotFound)
	_, err = s.AppendLog(ctx, job.ID, job.LeaseToken, "untrusted", "text", testNow)
	requireError(t, err, ErrInvalid)
	_, err = s.AppendLog(ctx, job.ID, job.LeaseToken, "stdout", "", testNow)
	requireError(t, err, ErrInvalid)
	_, _, _, err = s.Logs(ctx, job.ID, -1, 0)
	requireError(t, err, ErrInvalid)
}

func TestLogLimitPersistsCompletenessOutsideByteCap(t *testing.T) {
	ctx := context.Background()
	s, path := newStore(t, Options{MaxLogBytes: 8})
	enqueueJob(t, s, "principal", "key", testNow)
	job := claimJob(t, s, "epoch", testNow)
	if _, err := s.AppendLog(ctx, job.ID, job.LeaseToken, "stdout", "12345", testNow); err != nil {
		t.Fatal(err)
	}
	sequence, err := s.AppendLog(ctx, job.ID, job.LeaseToken, "stderr", "oversized", testNow)
	requireError(t, err, ErrLogLimit)
	if sequence != 0 {
		t.Fatal("rejected record was assigned a sequence")
	}
	sequence, err = s.AppendLog(ctx, job.ID, job.LeaseToken, "system", "678", testNow)
	if err != nil || sequence != 2 {
		t.Fatalf("exact cap: %d %v", sequence, err)
	}
	_, err = s.AppendLog(ctx, job.ID, job.LeaseToken, "stdout", "x", testNow)
	requireError(t, err, ErrLogLimit)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openStore(t, path, Options{MaxLogBytes: 8})
	records, next, truncated, err := s.Logs(ctx, job.ID, 0, 8)
	if err != nil || !truncated || next != 2 || len(records) != 2 || records[0].Text+records[1].Text != "12345678" {
		t.Fatalf("cap or marker lost: %+v %d %v %v", records, next, truncated, err)
	}
	records, next, truncated, err = s.Logs(ctx, job.ID, 2, 8)
	if err != nil || !truncated || next != 2 || len(records) != 0 {
		t.Fatal("empty final page concealed truncation")
	}
}

func TestRecordSizeLimitDoesNotConsumeSequence(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t, Options{})
	enqueueJob(t, s, "principal", "key", testNow)
	job := claimJob(t, s, "epoch", testNow)
	_, err := s.AppendLog(ctx, job.ID, job.LeaseToken, "stdout", strings.Repeat("x", MaxLogRecordBytes+1), testNow)
	requireError(t, err, ErrLogLimit)
	text := strings.Repeat("x", MaxLogRecordBytes)
	sequence, err := s.AppendLog(ctx, job.ID, job.LeaseToken, "stdout", text, testNow)
	if err != nil || sequence != 1 {
		t.Fatalf("boundary record: %d %v", sequence, err)
	}
	records, next, truncated, err := s.Logs(ctx, job.ID, 0, 0)
	if err != nil || !truncated || next != 1 || len(records) != 1 || records[0].Text != text {
		t.Fatal("record boundary lost bytes or completeness")
	}
}

func TestIndependentLogWritersPreserveEverySequence(t *testing.T) {
	ctx := context.Background()
	one, path := newStore(t, Options{})
	two := openStore(t, path, Options{})
	enqueueJob(t, one, "principal", "key", testNow)
	job := claimJob(t, one, "epoch", testNow)
	var group sync.WaitGroup
	failures := make(chan error, 2)
	start := make(chan struct{})
	for _, handle := range []*Store{one, two} {
		group.Add(1)
		go func(handle *Store) {
			defer group.Done()
			<-start
			for range 10 {
				if _, err := handle.AppendLog(ctx, job.ID, job.LeaseToken, "stdout", "line\n", testNow); err != nil {
					failures <- err
					return
				}
			}
		}(handle)
	}
	close(start)
	group.Wait()
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	records, next, truncated, err := one.Logs(ctx, job.ID, 0, 0)
	if err != nil || truncated || next != 20 || len(records) != 20 {
		t.Fatalf("concurrent log loss: records=%d next=%d truncated=%v err=%v", len(records), next, truncated, err)
	}
	for i, record := range records {
		if record.Seq != int64(i+1) || record.Text != "line\n" {
			t.Fatalf("non-monotonic record: %+v", record)
		}
	}
}

func TestQueuedExpiryAndRetainedIdempotencyBoundary(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t, Options{QueueTTL: time.Hour, Retention: 2 * time.Hour})
	job := enqueueJob(t, s, "principal", "key", testNow)
	if _, err := s.Pause(ctx, "paused", "drain", testNow); err != nil {
		t.Fatal(err)
	}
	_, err := s.Claim(ctx, "epoch", testNow.Add(time.Hour-time.Nanosecond))
	requireError(t, err, ErrNoJob)
	if got := getJob(t, s, job.ID); got.State != model.Queued {
		t.Fatal("expired before TTL boundary")
	}
	_, err = s.Claim(ctx, "epoch", testNow.Add(time.Hour))
	requireError(t, err, ErrNoJob)
	expired := getJob(t, s, job.ID)
	if expired.State != model.Expired || expired.FinishedAt == nil || !expired.FinishedAt.Equal(testNow.Add(time.Hour)) {
		t.Fatalf("paused expiry did not persist: %+v", expired)
	}
	if err := s.Prune(ctx, testNow.Add(3*time.Hour-time.Nanosecond)); err != nil {
		t.Fatal(err)
	}
	replay, ok, err := s.Enqueue(ctx, "principal", "key", admissionFixture(), testNow.Add(3*time.Hour-time.Nanosecond))
	if err != nil || !ok || replay.ID != job.ID || replay.State != model.Expired {
		t.Fatal("idempotency lost before retention boundary")
	}
	if err := s.Prune(ctx, testNow.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	_, err = s.Get(ctx, job.ID)
	requireError(t, err, ErrNotFound)
	_, err = s.Lookup(ctx, "principal", "key")
	requireError(t, err, ErrNotFound)
	newJob, ok, err := s.Enqueue(ctx, "principal", "key", admissionFixture(), testNow.Add(3*time.Hour))
	if err != nil || ok || newJob.ID == job.ID {
		t.Fatalf("retired key could not be reused: %+v %v %v", newJob, ok, err)
	}
}

func TestExpiryDoesNotInterruptActiveAndRetentionStartsAtFinish(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t, Options{QueueTTL: time.Hour, Retention: time.Hour, QueueLimit: 2})
	first := enqueueJob(t, s, "principal", "active", testNow)
	second := enqueueJob(t, s, "principal", "queued", testNow)
	active := claimJob(t, s, "epoch", testNow)
	if err := s.Prune(ctx, testNow.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got := getJob(t, s, first.ID); got.State != model.Preparing {
		t.Fatal("TTL interrupted active job")
	}
	if got := getJob(t, s, second.ID); got.State != model.Expired {
		t.Fatal("prune failed to expire queued job")
	}
	third := enqueueJob(t, s, "principal", "capacity-freed", testNow.Add(2*time.Hour))
	if _, err := s.AppendLog(ctx, first.ID, active.LeaseToken, "system", "final output", testNow); err != nil {
		t.Fatal(err)
	}
	finishJob(t, s, active, model.Succeeded, true, testNow.Add(2*time.Hour))
	if err := s.Prune(ctx, testNow.Add(3*time.Hour-time.Nanosecond)); err != nil {
		t.Fatal(err)
	}
	if got := getJob(t, s, first.ID); got.State != model.Succeeded {
		t.Fatal("retention started at admission instead of completion")
	}
	if err := s.Prune(ctx, testNow.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	_, err := s.Get(ctx, first.ID)
	requireError(t, err, ErrNotFound)
	_, _, _, err = s.Logs(ctx, first.ID, 0, 0)
	requireError(t, err, ErrNotFound)
	if got := getJob(t, s, third.ID); got.State != model.Expired {
		t.Fatal("newly expired job was immediately pruned")
	}
}

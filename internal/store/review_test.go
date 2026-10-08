package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/jerryfane/macserve/internal/model"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLogAppendRequiresActiveLeaseAndPreservesFinalEvidence(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t, Options{})
	queued := enqueueJob(t, s, "principal", "review-log", testNow)
	_, err := s.AppendLog(ctx, queued.ID, "invented", "stdout", "queued injection", testNow)
	requireError(t, err, ErrTransition)
	job := claimJob(t, s, "epoch", testNow)
	for _, lease := range []string{"", "wrong-lease"} {
		_, err := s.AppendLog(ctx, job.ID, lease, "stderr", strings.Repeat("x", MaxLogRecordBytes+1), testNow)
		requireError(t, err, ErrLease)
	}
	if _, err := s.AppendLog(ctx, job.ID, job.LeaseToken, "stdout", "final evidence", testNow); err != nil {
		t.Fatal(err)
	}
	finishJob(t, s, job, model.Succeeded, true, testNow.Add(time.Second))
	_, err = s.AppendLog(ctx, job.ID, job.LeaseToken, "stderr", strings.Repeat("x", MaxLogRecordBytes+1), testNow.Add(2*time.Second))
	requireError(t, err, ErrTransition)
	logs, next, truncated, err := s.Logs(ctx, job.ID, 0, 0)
	if err != nil || len(logs) != 1 || logs[0].Text != "final evidence" || next != 1 || truncated {
		t.Fatalf("final evidence changed: %+v %d %v %v", logs, next, truncated, err)
	}
	queued = enqueueJob(t, s, "principal", "second-log", testNow.Add(2*time.Second))
	second := claimJob(t, s, "epoch", testNow.Add(2*time.Second))
	if second.ID != queued.ID {
		t.Fatal("wrong next job")
	}
	_, err = s.AppendLog(ctx, second.ID, job.LeaseToken, "stdout", "cross-job injection", testNow.Add(2*time.Second))
	requireError(t, err, ErrLease)
}

func TestResultEnvelopeLimitIsAtomic(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t, Options{MaxResultBytes: 32})
	enqueueJob(t, s, "principal", "result-boundary", testNow)
	job := claimJob(t, s, "epoch", testNow)
	if err := s.Transition(ctx, job.ID, job.LeaseToken, model.Preparing, model.Finalizing, "", testNow); err != nil {
		t.Fatal(err)
	}
	tooLarge := json.RawMessage(`"` + strings.Repeat("x", 31) + `"`)
	requireError(t, s.Finish(ctx, job.ID, job.LeaseToken, model.Failed, tooLarge, false, "oversized", testNow), ErrResultLimit)
	if got := getJob(t, s, job.ID); got.State != model.Finalizing || len(got.Result) != 0 {
		t.Fatalf("oversized result partly committed: %+v", got)
	}
	state, err := s.ServiceState(ctx)
	if err != nil || state.Quarantined {
		t.Fatalf("rejected envelope changed quarantine: %+v %v", state, err)
	}
	exact := json.RawMessage(`"` + strings.Repeat("x", 30) + `"`)
	if err := s.Finish(ctx, job.ID, job.LeaseToken, model.Succeeded, exact, true, "", testNow); err != nil {
		t.Fatal(err)
	}
	if got := getJob(t, s, job.ID); got.State != model.Succeeded || string(got.Result) != string(exact) {
		t.Fatalf("boundary result not retained: %+v", got)
	}
}

func TestRetainedLogsEvictOldestTerminalBytesWithoutRewritingResult(t *testing.T) {
	ctx := context.Background()
	options := Options{MaxLogBytes: 8, MaxTotalLogBytes: 10}
	s, path := newStore(t, options)
	enqueueJob(t, s, "principal", "old", testNow)
	old := claimJob(t, s, "epoch", testNow)
	if _, err := s.AppendLog(ctx, old.ID, old.LeaseToken, "stdout", "123456", testNow); err != nil {
		t.Fatal(err)
	}
	finishJob(t, s, old, model.Succeeded, true, testNow.Add(time.Second))
	sealed := getJob(t, s, old.ID)
	enqueueJob(t, s, "principal", "current", testNow.Add(2*time.Second))
	current := claimJob(t, s, "epoch", testNow.Add(2*time.Second))
	if _, err := s.AppendLog(ctx, current.ID, current.LeaseToken, "stdout", "abcd", testNow); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.Logs(ctx, old.ID, 0, 0); err != nil {
		t.Fatalf("evicted before capacity: %v", err)
	}
	if _, err := s.AppendLog(ctx, current.ID, current.LeaseToken, "stderr", "e", testNow); err != nil {
		t.Fatal(err)
	}
	_, _, _, err := s.Logs(ctx, old.ID, 0, 0)
	requireError(t, err, ErrLogExpired)
	if got := getJob(t, s, old.ID); got.State != sealed.State || string(got.Result) != string(sealed.Result) || !got.CleanupOK {
		t.Fatalf("eviction rewrote sealed result: %+v", got)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openStore(t, path, options)
	logs, next, truncated, err := s.Logs(ctx, current.ID, 0, 0)
	if err != nil || next != 2 || truncated || len(logs) != 2 || logs[0].Text+logs[1].Text != "abcde" {
		t.Fatalf("live logs lost after reopen: %+v %d %v %v", logs, next, truncated, err)
	}
	finishJob(t, s, current, model.Succeeded, true, testNow.Add(3*time.Second))
	enqueueJob(t, s, "principal", "next", testNow.Add(4*time.Second))
	nextJob := claimJob(t, s, "epoch", testNow.Add(4*time.Second))
	if _, err := s.AppendLog(ctx, nextJob.ID, nextJob.LeaseToken, "stdout", "123456", testNow); err != nil {
		t.Fatal(err)
	}
	_, _, _, err = s.Logs(ctx, current.ID, 0, 0)
	requireError(t, err, ErrLogExpired)
}

func TestGlobalLogLimitDoesNotEvictActiveEvidence(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t, Options{MaxLogBytes: 64, MaxTotalLogBytes: 8})
	enqueueJob(t, s, "principal", "active", testNow)
	job := claimJob(t, s, "epoch", testNow)
	if _, err := s.AppendLog(ctx, job.ID, job.LeaseToken, "stdout", "123456", testNow); err != nil {
		t.Fatal(err)
	}
	_, err := s.AppendLog(ctx, job.ID, job.LeaseToken, "stdout", "789", testNow)
	requireError(t, err, ErrLogLimit)
	logs, next, truncated, err := s.Logs(ctx, job.ID, 0, 0)
	if err != nil || next != 1 || !truncated || len(logs) != 1 || logs[0].Text != "123456" {
		t.Fatalf("active evidence evicted: %+v %d %v %v", logs, next, truncated, err)
	}
}

func TestLogExpiryKeepsResultAndIdempotency(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t, Options{LogRetention: time.Hour, Retention: 24 * time.Hour})
	enqueueJob(t, s, "principal", "expiry", testNow)
	job := claimJob(t, s, "epoch", testNow)
	if _, err := s.AppendLog(ctx, job.ID, job.LeaseToken, "stdout", "raw", testNow); err != nil {
		t.Fatal(err)
	}
	finished := testNow.Add(time.Minute)
	finishJob(t, s, job, model.Succeeded, true, finished)
	before := getJob(t, s, job.ID)
	if err := s.Prune(ctx, finished.Add(time.Hour-time.Nanosecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.Logs(ctx, job.ID, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := s.Prune(ctx, finished.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	_, _, _, err := s.Logs(ctx, job.ID, 0, 0)
	requireError(t, err, ErrLogExpired)
	replay, err := s.Lookup(ctx, "principal", "expiry")
	if err != nil || replay.ID != job.ID || string(replay.Result) != string(before.Result) {
		t.Fatalf("log expiry removed immutable metadata: %+v %v", replay, err)
	}
}

func TestAcknowledgedEpochIsTheOnlyEpochThatCanClaimAfterRecovery(t *testing.T) {
	ctx := context.Background()
	s, path := newStore(t, Options{})
	enqueueJob(t, s, "principal", "lost", testNow)
	next := enqueueJob(t, s, "principal", "next", testNow)
	job := claimJob(t, s, "lost-epoch", testNow)
	finishJob(t, s, job, model.Failed, false, testNow)
	if err := s.AcknowledgeQuiescent(ctx, "verified-epoch"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openStore(t, path, Options{})
	_, err := s.Claim(ctx, "unverified-epoch", testNow)
	requireError(t, err, ErrLease)
	if got := getJob(t, s, next.ID); got.State != model.Queued {
		t.Fatal("unverified epoch claimed a job")
	}
	job = claimJob(t, s, "verified-epoch", testNow)
	if job.ID != next.ID {
		t.Fatal("verified epoch lost FIFO job")
	}
	finishJob(t, s, job, model.Succeeded, true, testNow)
	if err := s.AcknowledgeQuiescent(ctx, "replacement-epoch"); err != nil {
		t.Fatal(err)
	}
	requireError(t, s.AcknowledgeQuiescent(ctx, "verified-epoch"), ErrLease)
}

func TestVersionOneLogsRemainAccountedAfterMigration(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(dir, "queue.sqlite")
	legacy, err := sql.Open("sqlite", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.ExecContext(ctx, schema); err != nil {
		legacy.Close()
		t.Fatal(err)
	}
	admission := admissionFixture()
	request, _ := json.Marshal(admission.Request)
	profile, _ := json.Marshal(admission.Profile)
	_, err = legacy.ExecContext(ctx, `INSERT INTO jobs(id,principal,idempotency_key,repo,request,profile,request_digest,profile_digest,state,created_at,updated_at,finished_at,log_sequence,log_bytes) VALUES('legacy','principal','legacy',?,?,?,?,?,'succeeded',?,?,?,1,6)`, admission.Request.Repo, request, profile, strings.Repeat("a", 64), admission.ProfileDigest, testNow.UnixNano(), testNow.UnixNano(), testNow.UnixNano())
	if err != nil {
		legacy.Close()
		t.Fatal(err)
	}
	if _, err := legacy.ExecContext(ctx, "INSERT INTO logs(job_id,sequence,time,stream,text) VALUES('legacy',1,?,'stdout',?)", testNow.UnixNano(), []byte("123456")); err != nil {
		legacy.Close()
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filename, 0600); err != nil {
		t.Fatal(err)
	}
	s := openStore(t, filename, Options{MaxTotalLogBytes: 6})
	records, _, _, err := s.Logs(ctx, "legacy", 0, 0)
	if err != nil || len(records) != 1 || records[0].Text != "123456" {
		t.Fatalf("migration lost old logs: %+v %v", records, err)
	}
	enqueueJob(t, s, "principal", "new", testNow.Add(time.Second))
	job := claimJob(t, s, "epoch", testNow.Add(time.Second))
	if _, err := s.AppendLog(ctx, job.ID, job.LeaseToken, "stdout", "new", testNow); err != nil {
		t.Fatal(err)
	}
	_, _, _, err = s.Logs(ctx, "legacy", 0, 0)
	requireError(t, err, ErrLogExpired)
	if got := getJob(t, s, "legacy"); got.State != model.Succeeded {
		t.Fatal("migration/eviction changed terminal state")
	}
}

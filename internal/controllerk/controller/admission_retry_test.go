package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/buildseal"
	"github.com/jerryfane/macserve/internal/controllerk/store"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/protocol"
	"github.com/jerryfane/macserve/internal/worker"
)

// The documented retry bound and first backoff (docs/architecture.md),
// stated here so the tests hold the controller to them.
const (
	inconclusiveReason = "lane admission: context deadline exceeded"
	retries            = 3
	firstBackoff       = 2 * time.Minute
)

// claimLease registers the worker and returns the lease of the next queued
// job the controller claims and prepares, or nil when it claims none.
func claimLease(t *testing.T, f *runtimeFixture) *protocol.Lease {
	t.Helper()
	c := f.controller
	if err := c.register(context.Background(), protocol.Registration{Epoch: "epoch-a", Quiescent: true}); err != nil {
		t.Fatal(err)
	}
	if lease, err := c.next(context.Background(), "epoch-a", nil); err != nil || lease != nil {
		t.Fatalf("preparation admission: %v %v", lease, err)
	}
	c.prep.Wait()
	lease, err := c.next(context.Background(), "epoch-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	return lease
}

// refuseAdmission posts the worker's admission refusal of lease: an
// inconclusive one (idle verdict not_required, cleanup_ok, no evidence), or
// with verdict another idle verdict.
func refuseAdmission(t *testing.T, f *runtimeFixture, lease protocol.Lease, verdict string) {
	t.Helper()
	now := f.controller.options.Now()
	result := worker.Result{State: model.Failed, Reason: inconclusiveReason, CleanupOK: true, Source: lease.Source, StartedAt: now, FinishedAt: now, Concurrency: &worker.Concurrency{Lane: 1, MaxLanes: 1, IdleVerdict: verdict}}
	completion := map[string]any{"result": result, "seal": buildseal.Envelope{}, "admission_refused": protocol.AdmissionACLCensusUnavailable}
	if status := lifecycleRequest(t, f.controller, lease, "/complete", completion); status != http.StatusNoContent {
		t.Fatalf("refusal status %d", status)
	}
}

func getJob(t *testing.T, f *runtimeFixture, id string) model.Job {
	t.Helper()
	job, err := f.db.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return job
}

// #154: a job the worker refuses inconclusively (an admission inspection
// cut short on a loaded host) returns to the queue, held back 2, 4 and 8
// minutes, instead of being cancelled; the refusal after the third retry
// cancels it as worker_admission, naming the retries.
func TestInconclusiveAdmissionRefusalRequeuesWithBackoff(t *testing.T) {
	f := newRuntime(t)
	job := f.enqueue(t, "job", model.Build)
	var elapsed time.Duration
	for retry := 1; retry <= retries; retry++ {
		lease := claimLease(t, f)
		if lease == nil || lease.Job.ID != job.ID {
			t.Fatalf("retry %d: lease %+v", retry, lease)
		}
		refuseAdmission(t, f, *lease, worker.IdleNotRequired)
		backoff := firstBackoff << (retry - 1)
		next := f.now.Add(elapsed + backoff)
		queued := getJob(t, f, job.ID)
		want := fmt.Sprintf("admission retry %d/%d after %s, next at %s", retry, retries, inconclusiveReason, next.UTC().Format(time.RFC3339))
		if queued.State != model.Queued || queued.CancelRequested || queued.CancelReason != nil || queued.Lane != 0 || queued.LeaseToken != "" || queued.Reason != want {
			t.Fatalf("retry %d: job %+v, want queued with reason %q", retry, queued, want)
		}
		f.controller.mu.Lock()
		active, epoch := len(f.controller.active), f.controller.epoch
		f.controller.mu.Unlock()
		if active != 0 || epoch == "" {
			t.Fatalf("retry %d: %d active, epoch %q", retry, active, epoch)
		}
		// Not claimed again before its backoff ends.
		f.offset.Store(int64(elapsed + backoff - time.Second))
		if lease := claimLease(t, f); lease != nil || getJob(t, f, job.ID).State != model.Queued {
			t.Fatalf("retry %d: reclaimed before its backoff: %+v", retry, lease)
		}
		elapsed += backoff
		f.offset.Store(int64(elapsed))
	}
	lease := claimLease(t, f)
	if lease == nil || lease.Job.ID != job.ID {
		t.Fatalf("final attempt: lease %+v", lease)
	}
	refuseAdmission(t, f, *lease, worker.IdleNotRequired)
	cancelled := getJob(t, f, job.ID)
	detail := fmt.Sprintf("after %d admission retries: %s", retries, inconclusiveReason)
	if cancelled.State != model.Cancelled || !cancelled.CleanupOK || cancelled.CancelReason == nil || cancelled.CancelReason.Source != model.CancelWorkerAdmission || cancelled.CancelReason.Detail != detail {
		t.Fatalf("after the last retry: %+v %+v, want cancelled worker_admission %q", cancelled, cancelled.CancelReason, detail)
	}
}

// A refusal outside the inconclusive class (here an admission refusal whose
// idle verdict is not not_required) is cancelled at once, as before #154.
func TestConclusiveAdmissionRefusalCancelsAtOnce(t *testing.T) {
	f := newRuntime(t)
	job := f.enqueue(t, "job", model.Build)
	lease := claimLease(t, f)
	if lease == nil {
		t.Fatal("no lease")
	}
	refuseAdmission(t, f, *lease, worker.IdleDeferred)
	cancelled := getJob(t, f, job.ID)
	if cancelled.State != model.Cancelled || cancelled.CancelReason == nil || cancelled.CancelReason.Source != model.CancelWorkerAdmission || cancelled.CancelReason.Detail != inconclusiveReason {
		t.Fatalf("job %+v %+v, want cancelled worker_admission at once", cancelled, cancelled.CancelReason)
	}
}

// A pull-mode attempt is retried in place: while it waits out its backoff
// the poller's ensure joins it rather than starting an automatic rerun, and
// only the cancellation after its last retry is rerun (#119).
func TestPullModeAdmissionRetryIsNotRerun(t *testing.T) {
	f := newRuntime(t)
	ctx := context.Background()
	if err := f.db.InitializeGitHub(ctx); err != nil {
		t.Fatal(err)
	}
	admission := runtimeAdmission(model.Build)
	admission.Request.Context.PullRequest = 7
	input := store.GitHubAdmission{Run: store.GitHubRun{Key: strings.Repeat("b", 64), RepositoryID: 123, Repository: admission.Request.Repo, SHA: admission.Request.SHA, Profile: admission.Request.Profile, PolicyRevision: 1}, Admission: admission, PullRequest: 7, Mode: "ensure"}
	first, err := f.db.AdmitGitHub(ctx, input, f.now)
	if err != nil {
		t.Fatal(err)
	}
	var elapsed time.Duration
	for retry := 1; retry <= retries+1; retry++ {
		lease := claimLease(t, f)
		if lease == nil || lease.Job.ID != first.JobID {
			t.Fatalf("attempt %d: lease %+v", retry, lease)
		}
		refuseAdmission(t, f, *lease, worker.IdleNotRequired)
		if retry > retries {
			break
		}
		run, err := f.db.AdmitGitHub(ctx, input, f.now.Add(elapsed+time.Second))
		if err != nil || run.JobID != first.JobID || run.AttemptID != first.AttemptID {
			t.Fatalf("retry %d: ensure started a rerun of a requeued attempt: %+v %v", retry, run, err)
		}
		elapsed += firstBackoff << (retry - 1)
		f.offset.Store(int64(elapsed))
	}
	if job := getJob(t, f, first.JobID); job.State != model.Cancelled || job.CancelReason == nil || job.CancelReason.Source != model.CancelWorkerAdmission {
		t.Fatalf("last refusal: %+v", job)
	}
	run, err := f.db.AdmitGitHub(ctx, input, f.now.Add(elapsed+time.Second))
	if err != nil || run.JobID == first.JobID {
		t.Fatalf("cancelled attempt not rerun: %+v %v", run, err)
	}
}

// signalReader closes read on its first Read: the handler authenticated
// the request and now waits for its body.
type signalReader struct {
	io.Reader
	once sync.Once
	read chan struct{}
}

func (r *signalReader) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.read) })
	return r.Reader.Read(p)
}

// A completion of a lease authenticated before its job returned to the
// queue and was leased again (a retried delivery of the refusal, or any
// other delayed completion) is refused as a stale lease and never reaches
// the replacement lease (#156 review): the replacement keeps running,
// uncancelled, on its own lease.
func TestStaleCompletionCannotReachReplacementLease(t *testing.T) {
	for _, refused := range []bool{true, false} {
		t.Run(fmt.Sprintf("refused=%v", refused), func(t *testing.T) {
			f := newRuntime(t)
			c := f.controller
			job := f.enqueue(t, "job", model.Build)
			first := claimLease(t, f)
			if first == nil {
				t.Fatal("no lease")
			}
			now := c.options.Now()
			zero := 0
			result := worker.Result{State: model.Succeeded, CleanupOK: true, ExitCode: &zero, Source: first.Source, StartedAt: now, FinishedAt: now}
			completion := map[string]any{"result": result, "seal": buildseal.Envelope{}}
			if refused {
				result = worker.Result{State: model.Failed, Reason: inconclusiveReason, CleanupOK: true, Source: first.Source, StartedAt: now, FinishedAt: now, Concurrency: &worker.Concurrency{Lane: 1, MaxLanes: 1, IdleVerdict: worker.IdleNotRequired}}
				completion = map[string]any{"result": result, "seal": buildseal.Envelope{}, "admission_refused": protocol.AdmissionACLCensusUnavailable}
			}
			data, err := json.Marshal(completion)
			if err != nil {
				t.Fatal(err)
			}
			// The stale request authenticates the first lease, then waits
			// for its body while the job is requeued and leased again.
			pr, pw := io.Pipe()
			body := &signalReader{Reader: pr, read: make(chan struct{})}
			r := httptest.NewRequest(http.MethodPost, protocol.Prefix+"/jobs/"+first.Job.ID+"/complete", body)
			r = r.WithContext(context.WithValue(r.Context(), peerKey{}, true))
			r.Header.Set(protocol.EpochHeader, first.Job.WorkerEpoch)
			r.Header.Set(protocol.LeaseHeader, first.Token)
			stale := httptest.NewRecorder()
			done := make(chan struct{})
			go func() {
				defer close(done)
				c.handler().ServeHTTP(stale, r)
			}()
			select {
			case <-body.read:
			case <-done:
				t.Fatalf("stale request ended before its body: %d", stale.Code)
			}
			refuseAdmission(t, f, *first, worker.IdleNotRequired)
			f.offset.Store(int64(firstBackoff))
			second := claimLease(t, f)
			if second == nil || second.Job.ID != job.ID || second.Token == first.Token {
				t.Fatalf("replacement lease %+v", second)
			}
			if status := lifecycleRequest(t, c, *second, "/stage", protocol.Stage{State: model.Running}); status != http.StatusNoContent {
				t.Fatalf("replacement running: %d", status)
			}
			go func() {
				pw.Write(data)
				pw.Close()
			}()
			<-done
			if stale.Code != http.StatusGone {
				t.Fatalf("stale completion status %d, want %d", stale.Code, http.StatusGone)
			}
			current := getJob(t, f, job.ID)
			if current.State != model.Running || current.CancelRequested || current.CancelReason != nil || current.LeaseToken != second.Token {
				t.Fatalf("stale completion reached the replacement: %+v", current)
			}
			c.mu.Lock()
			a := c.execution(job.ID)
			c.mu.Unlock()
			if a == nil || a.job.LeaseToken != second.Token {
				t.Fatalf("replacement execution %+v", a)
			}
		})
	}
}

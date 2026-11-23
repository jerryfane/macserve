package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/buildseal"
	"github.com/jerryfane/macserve/internal/controllerk/store"
	"github.com/jerryfane/macserve/internal/health"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/protocol"
	"github.com/jerryfane/macserve/internal/worker"
)

// laneFixture is a runtime whose controller runs lanes jobs at once behind a
// mutable readiness gate with disk for every lane.
type laneFixture struct {
	*runtimeFixture
	mu   sync.Mutex
	gate health.GateState
	err  error
}

func newLanes(t *testing.T, lanes int) *laneFixture {
	t.Helper()
	f := &laneFixture{runtimeFixture: newRuntime(t), gate: health.GateState{Ready: true, FreeBytes: 1 << 50}}
	f.controller.options.Lanes = lanes
	f.controller.options.Gate = func(context.Context) (health.GateState, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.gate, f.err
	}
	return f
}

func (f *laneFixture) setGate(gate health.GateState, err error) {
	f.mu.Lock()
	f.gate, f.err = gate, err
	f.mu.Unlock()
}

func (f *laneFixture) register(t *testing.T, epoch string, lanes int) {
	t.Helper()
	if err := f.controller.register(context.Background(), protocol.Registration{Epoch: epoch, Quiescent: true, Lanes: lanes}); err != nil {
		t.Fatal(err)
	}
}

// claim asks /next once, which must claim a job and start its preparation,
// then waits for the preparation.
func (f *laneFixture) claim(t *testing.T, epoch string, running ...string) {
	t.Helper()
	before := len(f.activeIDs())
	if lease, err := f.controller.next(context.Background(), epoch, running); err != nil || lease != nil {
		t.Fatalf("claim: %v %v", lease, err)
	}
	f.controller.prep.Wait()
	if after := len(f.activeIDs()); after != before+1 {
		t.Fatalf("no claim: %d active, was %d", after, before)
	}
}

// offer asks /next once, which must return a lease.
func (f *laneFixture) offer(t *testing.T, epoch string, running ...string) protocol.Lease {
	t.Helper()
	lease, err := f.controller.next(context.Background(), epoch, running)
	if err != nil || lease == nil {
		t.Fatalf("offer: %v %v", lease, err)
	}
	return *lease
}

// start takes the next job through claim and delivery to running.
func (f *laneFixture) start(t *testing.T, epoch string, running ...string) protocol.Lease {
	t.Helper()
	f.claim(t, epoch, running...)
	lease := f.offer(t, epoch, running...)
	if code := lifecycleRequest(t, f.controller, lease, "/stage", protocol.Stage{State: model.Running}); code != http.StatusNoContent {
		t.Fatalf("running stage %d", code)
	}
	return lease
}

func (f *laneFixture) activeIDs() []string {
	f.controller.mu.Lock()
	defer f.controller.mu.Unlock()
	ids := []string{}
	for _, a := range f.controller.active {
		ids = append(ids, a.job.ID)
	}
	return ids
}

func (f *laneFixture) job(t *testing.T, id string) model.Job {
	t.Helper()
	job, err := f.db.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return job
}

func TestTwoLanesRunIndependentLeases(t *testing.T) {
	f := newLanes(t, 2)
	f.enqueue(t, "one", model.Build)
	f.enqueue(t, "two", model.Build)
	f.register(t, "epoch-a", 2)
	first := f.start(t, "epoch-a")
	second := f.start(t, "epoch-a", first.Job.ID)
	if first.Job.ID == second.Job.ID || first.Job.Lane != 1 || second.Job.Lane != 2 || first.Token == second.Token {
		t.Fatalf("leases: %+v %+v", first.Job, second.Job)
	}
	for _, lease := range []protocol.Lease{first, second} {
		if code := lifecycleRequest(t, f.controller, lease, "/heartbeat", struct{}{}); code != http.StatusOK {
			t.Fatalf("heartbeat %s: %d", lease.Job.ID, code)
		}
	}
	if err := f.controller.complete(context.Background(), first.Job, f.result(t, first), buildseal.Envelope{}); err != nil {
		t.Fatal(err)
	}
	if code := lifecycleRequest(t, f.controller, first, "/heartbeat", struct{}{}); code != http.StatusGone {
		t.Fatalf("completed lease heartbeat %d", code)
	}
	if ids := f.activeIDs(); len(ids) != 1 || ids[0] != second.Job.ID {
		t.Fatalf("active after first completion: %v", ids)
	}
	if code := lifecycleRequest(t, f.controller, second, "/heartbeat", struct{}{}); code != http.StatusOK {
		t.Fatalf("sibling heartbeat after completion %d", code)
	}
	if err := f.controller.complete(context.Background(), second.Job, f.result(t, second), buildseal.Envelope{}); err != nil {
		t.Fatal(err)
	}
	for _, lease := range []protocol.Lease{first, second} {
		if job := f.job(t, lease.Job.ID); job.State != model.Succeeded || !job.CleanupOK {
			t.Fatalf("%s: %s cleanup=%t", job.ID, job.State, job.CleanupOK)
		}
	}
	status, err := f.controller.Status(context.Background())
	if err != nil || len(status.ActiveJobs) != 0 || status.MaxConcurrentJobs != 2 {
		t.Fatalf("status: %+v %v", status, err)
	}
}

func TestWorkerLanesCapControllerLanes(t *testing.T) {
	f := newLanes(t, 2)
	f.enqueue(t, "one", model.Build)
	second := f.enqueue(t, "two", model.Build)
	// A worker before lanes registers none: one lane.
	f.register(t, "epoch-a", 0)
	first := f.start(t, "epoch-a")
	if lease, err := f.controller.next(context.Background(), "epoch-a", []string{first.Job.ID}); lease != nil || err != nil {
		t.Fatalf("second lease beside a one-lane worker: %v %v", lease, err)
	}
	f.controller.prep.Wait()
	if job := f.job(t, second.ID); job.State != model.Queued || len(f.activeIDs()) != 1 {
		t.Fatalf("one-lane worker got a second job: %s %v", job.State, f.activeIDs())
	}
	// The same epoch registering two lanes lifts the cap.
	f.register(t, "epoch-a", 2)
	f.claim(t, "epoch-a", first.Job.ID)
	if job := f.job(t, second.ID); job.State != model.Preparing || job.Lane != 2 {
		t.Fatalf("second job: %s lane %d", job.State, job.Lane)
	}
}

// A lane's disk is reserved only while the gate admits another job.
func TestSecondLaneNeedsDiskForAnotherJob(t *testing.T) {
	f := newLanes(t, 2)
	f.enqueue(t, "one", model.Build)
	second := f.enqueue(t, "two", model.Build)
	f.register(t, "epoch-a", 2)
	f.setGate(health.GateState{Ready: true, FreeBytes: health.AdmissionFloorBytes + health.JobReservationBytes}, nil)
	first := f.start(t, "epoch-a")
	if lease, err := f.controller.next(context.Background(), "epoch-a", []string{first.Job.ID}); lease != nil || err != nil {
		t.Fatalf("next: %v %v", lease, err)
	}
	if job := f.job(t, second.ID); job.State != model.Queued {
		t.Fatalf("second job claimed without disk for it: %s", job.State)
	}
	f.setGate(health.GateState{Ready: true, FreeBytes: health.AdmissionFloorBytes + 2*health.JobReservationBytes}, nil)
	f.claim(t, "epoch-a", first.Job.ID)
}

func TestCapacityOnlyGateCancelsNewestJobAtInterval(t *testing.T) {
	f := newLanes(t, 2)
	f.enqueue(t, "one", model.Build)
	f.enqueue(t, "two", model.Build)
	f.register(t, "epoch-a", 2)
	first := f.start(t, "epoch-a")
	second := f.start(t, "epoch-a", first.Job.ID)
	f.setGate(health.GateState{CancelActive: true, CapacityOnly: true, Blockers: []string{"disk_emergency"}}, nil)
	f.controller.checkActive(context.Background())
	newest := f.job(t, second.Job.ID)
	if !newest.CancelRequested || newest.CancelReason == nil || newest.CancelReason.Source != model.CancelHostReadiness {
		t.Fatalf("newest job not cancelled: %+v", newest)
	}
	if f.job(t, first.Job.ID).CancelRequested {
		t.Fatal("capacity cancellation took the oldest job too")
	}
	// The gate is re-evaluated after the interval, not on the next tick.
	f.offset.Store(int64(capacityCancelInterval - time.Second))
	if code := lifecycleRequest(t, f.controller, first, "/heartbeat", struct{}{}); code != http.StatusOK {
		t.Fatalf("heartbeat %d", code)
	}
	f.controller.checkActive(context.Background())
	if f.job(t, first.Job.ID).CancelRequested {
		t.Fatal("second capacity cancellation inside the interval")
	}
	f.offset.Store(int64(capacityCancelInterval + time.Second))
	if code := lifecycleRequest(t, f.controller, first, "/heartbeat", struct{}{}); code != http.StatusOK {
		t.Fatalf("heartbeat %d", code)
	}
	f.controller.checkActive(context.Background())
	if job := f.job(t, first.Job.ID); !job.CancelRequested || job.State != model.Cancelling {
		t.Fatalf("persisting capacity blocker spared the remaining job: %+v", job)
	}
}

func TestTrustGateCancelsEveryJob(t *testing.T) {
	for _, tc := range []struct {
		name   string
		gate   health.GateState
		err    error
		source model.CancelSource
	}{
		{"trust-blocker", health.GateState{CancelActive: true, Blockers: []string{"isolation_unavailable", "disk_emergency"}}, nil, model.CancelHostReadiness},
		{"gate-error", health.GateState{}, errors.New("health read interrupted"), model.CancelGateError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLanes(t, 2)
			f.enqueue(t, "one", model.Build)
			f.enqueue(t, "two", model.Build)
			f.register(t, "epoch-a", 2)
			first := f.start(t, "epoch-a")
			second := f.start(t, "epoch-a", first.Job.ID)
			f.setGate(tc.gate, tc.err)
			f.controller.checkActive(context.Background())
			for _, lease := range []protocol.Lease{first, second} {
				job := f.job(t, lease.Job.ID)
				if !job.CancelRequested || job.CancelReason == nil || job.CancelReason.Source != tc.source {
					t.Fatalf("%s not cancelled for the host: %+v", job.ID, job)
				}
			}
		})
	}
}

// A lane's failed cleanup fences new claims for its epoch at once, ends a
// sibling lease never delivered, and lets a delivered sibling finish; the
// worker's next epoch then registers and claims again.
func TestCleanupFailureFencesClaimsWhileSiblingCompletes(t *testing.T) {
	f := newLanes(t, 3)
	f.enqueue(t, "one", model.Build)
	f.enqueue(t, "two", model.Build)
	undelivered := f.enqueue(t, "three", model.Build)
	waiting := f.enqueue(t, "four", model.Build)
	f.register(t, "epoch-a", 3)
	first := f.start(t, "epoch-a")
	second := f.start(t, "epoch-a", first.Job.ID)
	f.claim(t, "epoch-a", first.Job.ID, second.Job.ID)
	result := f.result(t, first)
	result.CleanupOK = false
	if err := f.controller.complete(context.Background(), first.Job, result, buildseal.Envelope{}); err != nil {
		t.Fatal(err)
	}
	if job := f.job(t, first.Job.ID); job.State != model.Failed || job.CleanupOK {
		t.Fatalf("uncertain cleanup: %s cleanup=%t", job.State, job.CleanupOK)
	}
	if _, err := f.controller.next(context.Background(), "epoch-a", []string{second.Job.ID}); !errors.Is(err, store.ErrLease) {
		t.Fatalf("fenced epoch asked for work: %v", err)
	}
	f.controller.checkActive(context.Background())
	f.controller.prep.Wait()
	if job := f.job(t, undelivered.ID); job.State != model.Interrupted || job.Reason != fencedBeforeDelivery {
		t.Fatalf("undelivered sibling: %s %q", job.State, job.Reason)
	}
	if code := lifecycleRequest(t, f.controller, second, "/heartbeat", struct{}{}); code != http.StatusOK {
		t.Fatalf("sibling heartbeat %d", code)
	}
	if err := f.controller.register(context.Background(), protocol.Registration{Epoch: "epoch-b", Quiescent: true, Lanes: 3}); !errors.Is(err, store.ErrTransition) {
		t.Fatalf("new epoch registered under a live sibling: %v", err)
	}
	if err := f.controller.complete(context.Background(), second.Job, f.result(t, second), buildseal.Envelope{}); err != nil {
		t.Fatal(err)
	}
	if job := f.job(t, second.Job.ID); job.State != model.Succeeded || !job.CleanupOK {
		t.Fatalf("sibling: %s cleanup=%t", job.State, job.CleanupOK)
	}
	if job := f.job(t, waiting.ID); job.State != model.Queued {
		t.Fatalf("fenced epoch claimed: %s", job.State)
	}
	f.register(t, "epoch-b", 3)
	f.claim(t, "epoch-b")
	if job := f.job(t, waiting.ID); job.State != model.Preparing || job.WorkerEpoch != "epoch-b" || job.Lane != 1 {
		t.Fatalf("new epoch claim: %+v", job)
	}
}

// #214: a delivered lease the worker refused before it started because
// another job's cleanup left it draining returns to the queue, but the
// epoch that job's failed cleanup fenced cannot claim it: only the new
// epoch the worker registers after its idle check passes does, in its old
// place and with a new lease. The refused lease is gone.
func TestDrainRefusedLeaseWaitsForNewEpoch(t *testing.T) {
	f := newLanes(t, 2)
	f.enqueue(t, "one", model.Build)
	refused := f.enqueue(t, "two", model.Build)
	later := f.enqueue(t, "later", model.Build)
	f.register(t, "epoch-a", 2)
	first := f.start(t, "epoch-a")
	f.claim(t, "epoch-a", first.Job.ID)
	second := f.offer(t, "epoch-a", first.Job.ID)
	if second.Job.ID != refused.ID {
		t.Fatalf("second lease %s, want %s", second.Job.ID, refused.ID)
	}
	result := f.result(t, first)
	result.CleanupOK = false
	if err := f.controller.complete(context.Background(), first.Job, result, buildseal.Envelope{}); err != nil {
		t.Fatal(err)
	}
	refusal := f.result(t, second)
	refusal.State, refusal.CleanupOK, refusal.ExitCode = model.Failed, true, nil
	refusal.Reason = "worker draining: job " + first.Job.ID + " cleanup unverified"
	completion := protocol.Completion{Result: refusal, AdmissionRefused: "worker_draining"}
	if code := lifecycleRequest(t, f.controller, second, "/complete", completion); code != http.StatusOK {
		t.Fatalf("drain refusal %d", code)
	}
	if job := f.job(t, refused.ID); job.State != model.Queued || job.LeaseToken != "" || job.WorkerEpoch != "" {
		t.Fatalf("refused job: %+v", job)
	}
	if _, err := f.controller.next(context.Background(), "epoch-a", nil); !errors.Is(err, store.ErrLease) {
		t.Fatalf("fenced epoch asked for work: %v", err)
	}
	if job := f.job(t, refused.ID); job.State != model.Queued {
		t.Fatalf("fenced epoch claimed the refused job: %s", job.State)
	}
	f.offset.Store(int64(time.Minute))
	f.register(t, "epoch-b", 2)
	f.claim(t, "epoch-b")
	lease := f.offer(t, "epoch-b")
	if lease.Job.ID != refused.ID || lease.Token == second.Token || lease.Job.WorkerEpoch != "epoch-b" || lease.Job.Deadline == nil || !lease.Job.Deadline.After(*second.Job.Deadline) {
		t.Fatalf("reclaimed lease: %+v", lease.Job)
	}
	if job := f.job(t, later.ID); job.State != model.Queued {
		t.Fatalf("later job claimed first: %s", job.State)
	}
	if code := lifecycleRequest(t, f.controller, second, "/heartbeat", struct{}{}); code != http.StatusGone {
		t.Fatalf("refused lease heartbeat %d, want 410", code)
	}
}

// drainRefusal is the completion a worker sends for lease's job refused
// before it started because the worker drains (#214).
func drainRefusal(t *testing.T, f *laneFixture, lease protocol.Lease) []byte {
	t.Helper()
	result := f.result(t, lease)
	result.State, result.CleanupOK, result.ExitCode = model.Failed, true, nil
	result.Reason = "worker draining: job j_other cleanup unverified"
	data, err := json.Marshal(protocol.Completion{Result: result, AdmissionRefused: "worker_draining"})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// answer is a completion request's status and whether its reply retired
// the worker's epoch (protocol.CompletionReply).
type answer struct {
	code    int
	retired bool
}

// retiredAnswer is the answer to a drain refusal whose job was requeued.
var retiredAnswer = answer{http.StatusOK, true}

// completeWith posts lease's completion, read from body, as the worker does.
func completeWith(c *Controller, lease protocol.Lease, body io.Reader) answer {
	r := httptest.NewRequest(http.MethodPost, protocol.Prefix+"/jobs/"+lease.Job.ID+"/complete", body)
	r = r.WithContext(context.WithValue(r.Context(), peerKey{}, true))
	r.Header.Set(protocol.EpochHeader, lease.Job.WorkerEpoch)
	r.Header.Set(protocol.LeaseHeader, lease.Token)
	w := httptest.NewRecorder()
	c.handler().ServeHTTP(w, r)
	var reply struct {
		EpochRetired bool `json:"epoch_retired"`
	}
	if w.Code == http.StatusOK {
		_ = json.Unmarshal(w.Body.Bytes(), &reply)
	}
	return answer{w.Code, reply.EpochRetired}
}

// await waits for milestone while the handler answering on answered has
// not answered; an early answer, or none within the bound, fails t.
func await(t *testing.T, milestone <-chan struct{}, answered <-chan answer, what string) {
	t.Helper()
	select {
	case <-milestone:
	case got := <-answered:
		t.Fatalf("handler answered %+v before %s", got, what)
	case <-time.After(30 * time.Second):
		t.Fatalf("no %s", what)
	}
}

// answerOf waits, bounded, for the answer of a released handler.
func answerOf(t *testing.T, answered <-chan answer) answer {
	t.Helper()
	select {
	case got := <-answered:
		return got
	case <-time.After(30 * time.Second):
		t.Fatal("released handler never answered")
		return answer{}
	}
}

// gatedBody signals reading on its first Read, after the handler
// authenticated the request, and then waits for release.
type gatedBody struct {
	data             *bytes.Reader
	once             sync.Once
	reading, release chan struct{}
}

func (b *gatedBody) Read(p []byte) (int, error) {
	b.once.Do(func() {
		close(b.reading)
		<-b.release
	})
	return b.data.Read(p)
}

// #214 review: a drain refusal whose request was authenticated before the
// job returned to the queue and was claimed again under a new lease is
// bound to the lease it authenticated: it is gone (410), and the new lease,
// its source included, is untouched.
func TestDelayedDrainRefusalCannotEndReplacementLease(t *testing.T) {
	f := newLanes(t, 1)
	refused := f.enqueue(t, "one", model.Build)
	f.register(t, "epoch-a", 1)
	f.claim(t, "epoch-a")
	old := f.offer(t, "epoch-a")
	data := drainRefusal(t, f, old)
	body := &gatedBody{data: bytes.NewReader(data), reading: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(body.release) })
	t.Cleanup(release)
	delayed := make(chan answer, 1)
	go func() { delayed <- completeWith(f.controller, old, body) }()
	await(t, body.reading, delayed, "the delayed request read its body")
	if got := completeWith(f.controller, old, bytes.NewReader(data)); got != retiredAnswer {
		t.Fatalf("drain refusal %+v", got)
	}
	f.register(t, "epoch-b", 1)
	f.claim(t, "epoch-b")
	replacement := f.offer(t, "epoch-b")
	release()
	if got := answerOf(t, delayed); got.code != http.StatusGone {
		t.Fatalf("delayed refusal of the old lease %+v, want 410", got)
	}
	if job := f.job(t, refused.ID); job.State != model.Preparing || job.LeaseToken != replacement.Token || job.WorkerEpoch != "epoch-b" {
		t.Fatalf("replacement lease changed: %+v", job)
	}
	if _, err := os.Stat(filepath.Join(f.source.directory, refused.ID+".tar")); err != nil {
		t.Fatalf("replacement source removed: %v", err)
	}
	if ids := f.activeIDs(); len(ids) != 1 || ids[0] != refused.ID {
		t.Fatalf("active %v", ids)
	}
}

// #214 review: a second delivery of a drain refusal while the first one
// removes the lease's source owns nothing: it is refused as retryable (409)
// without touching the source, so it cannot delete the source of the lease
// that claims the job next; a retry after the requeue is gone (410).
func TestOverlappingDrainRefusalsLeaveReplacementSource(t *testing.T) {
	f := newLanes(t, 1)
	refused := f.enqueue(t, "one", model.Build)
	f.register(t, "epoch-a", 1)
	f.claim(t, "epoch-a")
	old := f.offer(t, "epoch-a")
	data := drainRefusal(t, f, old)
	paused, resume := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(resume) })
	t.Cleanup(release)
	var removals atomic.Int32
	f.source.removing = func(string) {
		if removals.Add(1) == 1 {
			close(paused)
			<-resume
		}
	}
	first := make(chan answer, 1)
	go func() { first <- completeWith(f.controller, old, bytes.NewReader(data)) }()
	await(t, paused, first, "the first refusal removed the source")
	if got := completeWith(f.controller, old, bytes.NewReader(data)); got.code != http.StatusConflict {
		t.Fatalf("overlapping refusal %+v, want 409", got)
	}
	if n := removals.Load(); n != 1 {
		t.Fatalf("overlapping refusal removed the source: %d removals", n)
	}
	release()
	if got := answerOf(t, first); got != retiredAnswer {
		t.Fatalf("drain refusal %+v", got)
	}
	f.register(t, "epoch-b", 1)
	f.claim(t, "epoch-b")
	replacement := f.offer(t, "epoch-b")
	if got := completeWith(f.controller, old, bytes.NewReader(data)); got.code != http.StatusGone {
		t.Fatalf("retried refusal %+v, want 410", got)
	}
	if n := removals.Load(); n != 1 {
		t.Fatalf("retried refusal removed the source: %d removals", n)
	}
	if job := f.job(t, refused.ID); job.State != model.Preparing || job.LeaseToken != replacement.Token {
		t.Fatalf("replacement lease changed: %+v", job)
	}
	if _, err := os.Stat(filepath.Join(f.source.directory, refused.ID+".tar")); err != nil {
		t.Fatalf("replacement source removed: %v", err)
	}
}

// #214 review: the refusing lane and the lane whose cleanup failed report
// independently. A poll of the refusing epoch outstanding when the refusal
// commits, before the failed cleanup fences the epoch, claims nothing: the
// refusal fenced the epoch with the requeue, so the job keeps its place
// for the epoch the worker registers after its idle check.
func TestPollBeforeCleanupReportCannotClaimDrainRefusedJob(t *testing.T) {
	f := newLanes(t, 3)
	f.enqueue(t, "one", model.Build)
	refused := f.enqueue(t, "two", model.Build)
	later := f.enqueue(t, "later", model.Build)
	f.register(t, "epoch-a", 3)
	first := f.start(t, "epoch-a")
	f.claim(t, "epoch-a", first.Job.ID)
	second := f.offer(t, "epoch-a", first.Job.ID)
	if got := completeWith(f.controller, second, bytes.NewReader(drainRefusal(t, f, second))); got != retiredAnswer {
		t.Fatalf("drain refusal %+v", got)
	}
	if _, err := f.controller.next(context.Background(), "epoch-a", []string{first.Job.ID}); !errors.Is(err, store.ErrLease) {
		t.Fatalf("outstanding poll of the refusing epoch: %v", err)
	}
	f.controller.prep.Wait()
	for _, id := range []string{refused.ID, later.ID} {
		if job := f.job(t, id); job.State != model.Queued {
			t.Fatalf("refusing epoch claimed %s: %s %s", id, job.State, job.WorkerEpoch)
		}
	}
	result := f.result(t, first)
	result.CleanupOK = false
	if err := f.controller.complete(context.Background(), first.Job, result, buildseal.Envelope{}); err != nil {
		t.Fatal(err)
	}
	f.register(t, "epoch-b", 3)
	f.claim(t, "epoch-b")
	if lease := f.offer(t, "epoch-b"); lease.Job.ID != refused.ID {
		t.Fatalf("new epoch claimed %s first, want %s", lease.Job.ID, refused.ID)
	}
}

// A worker that restarts under a new epoch fences the old one: a lease the
// old epoch claimed and prepared but never received ends as fenced before
// delivery, its source is removed, and the new epoch registers and claims.
// Before, the registration was refused while the lease waited for its
// deadline, and the restarted worker exited on every 409.
func TestNewEpochFencesUndeliveredLease(t *testing.T) {
	f := newLanes(t, 2)
	stale := f.enqueue(t, "one", model.Build)
	next := f.enqueue(t, "two", model.Build)
	f.register(t, "epoch-a", 2)
	f.claim(t, "epoch-a")
	if _, err := os.Stat(filepath.Join(f.source.directory, stale.ID+".tar")); err != nil {
		t.Fatal(err)
	}
	f.register(t, "epoch-b", 2)
	if job := f.job(t, stale.ID); job.State != model.Interrupted || job.Reason != fencedBeforeDelivery || !job.CleanupOK {
		t.Fatalf("undelivered lease: %s %q cleanup=%t", job.State, job.Reason, job.CleanupOK)
	}
	if _, err := os.Stat(filepath.Join(f.source.directory, stale.ID+".tar")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("source kept: %v", err)
	}
	if _, err := f.controller.next(context.Background(), "epoch-a", nil); !errors.Is(err, store.ErrLease) {
		t.Fatalf("old epoch asked for work: %v", err)
	}
	f.claim(t, "epoch-b")
	// The replaced epoch cannot register again and end the new one's lease.
	if err := f.controller.register(context.Background(), protocol.Registration{Epoch: "epoch-a", Quiescent: true, Lanes: 2}); !errors.Is(err, store.ErrLease) {
		t.Fatalf("old epoch registered again: %v", err)
	}
	if job := f.job(t, next.ID); job.State != model.Preparing || job.WorkerEpoch != "epoch-b" || job.Lane != 1 {
		t.Fatalf("new epoch claim: %+v", job)
	}
	lease := f.offer(t, "epoch-b")
	if lease.Job.ID != next.ID {
		t.Fatalf("new epoch lease: %+v", lease.Job)
	}
}

// A new epoch cancels an older epoch's lease still preparing: registration
// is retried (not refused) until the preparation has ended as fenced.
func TestNewEpochCancelsPreparingLease(t *testing.T) {
	f := newLanes(t, 2)
	stale := f.enqueue(t, "one", model.Build)
	f.register(t, "epoch-a", 2)
	f.source.release, f.source.started = make(chan struct{}), make(chan struct{})
	if lease, err := f.controller.next(context.Background(), "epoch-a", nil); lease != nil || err != nil {
		t.Fatalf("claim: %v %v", lease, err)
	}
	<-f.source.started
	if err := f.controller.register(context.Background(), protocol.Registration{Epoch: "epoch-b", Quiescent: true, Lanes: 2}); !errors.Is(err, ErrNotReady) {
		t.Fatalf("registration beside a preparing lease: %v", err)
	}
	f.controller.prep.Wait()
	if job := f.job(t, stale.ID); job.State != model.Interrupted || job.Reason != fencedBeforeDelivery {
		t.Fatalf("preparing lease: %s %q", job.State, job.Reason)
	}
	f.source.release, f.source.started = nil, nil
	f.register(t, "epoch-b", 2)
}

// The fence is irreversible while the controller removes the fenced lease's
// source without its lock: the older epoch can neither register again nor
// receive the lease being ended.
func TestFencedEpochCannotReturnDuringSourceRemoval(t *testing.T) {
	f := newLanes(t, 2)
	stale := f.enqueue(t, "one", model.Build)
	f.register(t, "epoch-a", 2)
	f.claim(t, "epoch-a")
	var registerErr, nextErr error
	var delivered *protocol.Lease
	f.source.removing = func(id string) {
		if id != stale.ID || delivered != nil || registerErr != nil {
			return
		}
		registerErr = f.controller.register(context.Background(), protocol.Registration{Epoch: "epoch-a", Quiescent: true, Lanes: 2})
		delivered, nextErr = f.controller.next(context.Background(), "epoch-a", nil)
	}
	f.register(t, "epoch-b", 2)
	f.source.removing = nil
	if !errors.Is(registerErr, store.ErrLease) || delivered != nil || !errors.Is(nextErr, store.ErrLease) {
		t.Fatalf("fenced epoch during source removal: register %v, lease %v %v", registerErr, delivered, nextErr)
	}
	if job := f.job(t, stale.ID); job.State != model.Interrupted || job.Reason != fencedBeforeDelivery {
		t.Fatalf("undelivered lease: %s %q", job.State, job.Reason)
	}
}

// A prepared lease never delivered ends at its deadline although its epoch
// is current and no worker asks for it.
func TestUndeliveredLeaseEndsAtDeadline(t *testing.T) {
	f := newLanes(t, 2)
	stale := f.enqueue(t, "one", model.Build)
	f.register(t, "epoch-a", 2)
	f.claim(t, "epoch-a")
	f.offset.Store(int64(f.job(t, stale.ID).Deadline.Sub(f.now) + time.Second))
	f.controller.checkActive(context.Background())
	if job := f.job(t, stale.ID); job.State != model.TimedOut || len(f.activeIDs()) != 0 {
		t.Fatalf("undelivered lease past its deadline: %s %v", job.State, f.activeIDs())
	}
	f.register(t, "epoch-b", 2)
}

func nextRequest(t *testing.T, c *Controller, epoch, body string) (int, []byte) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, protocol.Prefix+"/next", bytes.NewReader([]byte(body)))
	r = r.WithContext(context.WithValue(r.Context(), peerKey{}, true))
	r.Header.Set(protocol.EpochHeader, epoch)
	w := httptest.NewRecorder()
	c.handler().ServeHTTP(w, r)
	return w.Code, w.Body.Bytes()
}

// A preparing lease whose /next response was lost is offered again unless
// the worker reports it running; then a free lane claims the next job.
func TestLostNextResponseReofferedOnlyWhenNotRunning(t *testing.T) {
	f := newLanes(t, 2)
	f.enqueue(t, "one", model.Build)
	second := f.enqueue(t, "two", model.Build)
	f.register(t, "epoch-a", 2)
	f.claim(t, "epoch-a")
	code, raw := nextRequest(t, f.controller, "epoch-a", `{}`)
	var first protocol.Lease
	if code != http.StatusOK || json.Unmarshal(raw, &first) != nil {
		t.Fatalf("first offer %d %s", code, raw)
	}
	code, raw = nextRequest(t, f.controller, "epoch-a", `{}`)
	var retried protocol.Lease
	if code != http.StatusOK || json.Unmarshal(raw, &retried) != nil || retried.Job.ID != first.Job.ID || retried.Token != first.Token {
		t.Fatalf("lost response not re-offered: %d %s", code, raw)
	}
	if code, raw := nextRequest(t, f.controller, "epoch-a", `{"running":["`+first.Job.ID+`"]}`); code != http.StatusNoContent {
		t.Fatalf("running lease re-offered: %d %s", code, raw)
	}
	f.controller.prep.Wait()
	if job := f.job(t, second.ID); job.State != model.Preparing {
		t.Fatalf("free lane did not claim: %s", job.State)
	}
	code, raw = nextRequest(t, f.controller, "epoch-a", `{"running":["`+first.Job.ID+`"]}`)
	var next protocol.Lease
	if code != http.StatusOK || json.Unmarshal(raw, &next) != nil || next.Job.ID != second.ID {
		t.Fatalf("second lease: %d %s", code, raw)
	}
	for _, body := range []string{`{"running":["../escape"]}`, `{"running":"j"}`, `{"lanes":2}`} {
		if code, _ := nextRequest(t, f.controller, "epoch-a", body); code != http.StatusBadRequest {
			t.Fatalf("%s accepted: %d", body, code)
		}
	}
}

// A lease prepared beside a running lane waits for a worker that stopped
// asking for work (it drains until idle) in the queue, not in preparing:
// after undeliveredWait it returns to queued without a deadline, keeps its
// place, and is claimed again with a new deadline when the worker asks.
// A lease with no delivered sibling waits however long the worker's idle
// recovery takes. Before, it burned its deadline from the first claim
// (Studio v0.1.46, 2026-11-11), and a later job could be claimed first.
// Simulator jobs return and are claimed again alike: the start stagger
// (simulatorStartGap) allows the second lane's claim beside a running
// simulator job and the returned job's claim once the worker asks again.
func TestUndeliveredLeaseReturnsToQueueWhileWorkerDrains(t *testing.T) {
	for _, kind := range []model.Kind{model.Build, model.SimulatorUITest} {
		t.Run(string(kind), func(t *testing.T) { undeliveredLeaseReturnsToQueue(t, kind) })
	}
}

func undeliveredLeaseReturnsToQueue(t *testing.T, kind model.Kind) {
	f := newLanes(t, 2)
	f.enqueue(t, "one", kind)
	waiting := f.enqueue(t, "two", kind)
	later := f.enqueue(t, "three", kind)
	f.register(t, "epoch-a", 2)
	first := f.start(t, "epoch-a")
	f.claim(t, "epoch-a", first.Job.ID)
	if job := f.job(t, waiting.ID); job.State != model.Preparing || job.Lane != 2 {
		t.Fatalf("second lane: %s lane %d", job.State, job.Lane)
	}
	tarball := filepath.Join(f.source.directory, waiting.ID+".tar")
	// The worker drains: it heartbeats lane 1 and asks for nothing.
	f.offset.Store(int64(time.Minute - time.Second))
	if code := lifecycleRequest(t, f.controller, first, "/heartbeat", struct{}{}); code != http.StatusOK {
		t.Fatalf("heartbeat %d", code)
	}
	f.controller.checkActive(context.Background())
	if job := f.job(t, waiting.ID); job.State != model.Preparing {
		t.Fatalf("requeued early: %s", job.State)
	}
	f.offset.Store(int64(time.Minute + time.Second))
	if code := lifecycleRequest(t, f.controller, first, "/heartbeat", struct{}{}); code != http.StatusOK {
		t.Fatalf("heartbeat %d", code)
	}
	f.controller.checkActive(context.Background())
	job := f.job(t, waiting.ID)
	if job.State != model.Queued || job.Deadline != nil || job.Lane != 0 || job.WorkerEpoch != "" || job.LeaseToken != "" || job.Reason != "returned to queue: the worker stopped asking for another lane before delivery" {
		t.Fatalf("undelivered lease while the worker drains: %+v", job)
	}
	if _, err := os.Stat(tarball); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("source kept: %v", err)
	}
	if ids := f.activeIDs(); len(ids) != 1 || ids[0] != first.Job.ID {
		t.Fatalf("active %v", ids)
	}
	if err := f.controller.complete(context.Background(), first.Job, f.result(t, first), buildseal.Envelope{}); err != nil {
		t.Fatal(err)
	}
	// Idle, the worker asks again: the requeued job keeps its place.
	f.offset.Store(int64(10 * time.Minute))
	lease := f.start(t, "epoch-a")
	if lease.Job.ID != waiting.ID || lease.Job.Lane != 1 || !lease.Job.Deadline.Equal(f.now.Add(10*time.Minute+600*time.Second)) {
		t.Fatalf("reclaimed lease: %+v", lease.Job)
	}
	if job := f.job(t, later.ID); job.State != model.Queued {
		t.Fatalf("later job: %s", job.State)
	}
	// Alone, a prepared lease waits for the worker's idle recovery.
	if err := f.controller.complete(context.Background(), lease.Job, f.result(t, lease), buildseal.Envelope{}); err != nil {
		t.Fatal(err)
	}
	f.claim(t, "epoch-a")
	f.offset.Store(int64(10*time.Minute + time.Minute + time.Minute))
	f.controller.checkActive(context.Background())
	if job := f.job(t, later.ID); job.State != model.Preparing {
		t.Fatalf("lone lease requeued: %s", job.State)
	}
}

// Six lanes, six queued simulator UI test jobs and a build: a simulator job is
// claimed only while no other is starting, so the six are claimed over
// minutes instead of one per work request (four within 8 s overloaded the
// Studio, 2026-11-13). A simulator job is starting until it reports running
// or until simulatorStartGap after its delivery; one not yet delivered holds
// however long its source takes. The build, at the fair head, is claimed
// beside a starting simulator job, and all six simulator jobs run.
func TestSimulatorStartsAreStaggered(t *testing.T) {
	f := newLanes(t, 6)
	release := make(chan struct{})
	f.source.release = release
	ui := []model.Job{f.enqueue(t, "ui-1", model.SimulatorUITest)}
	build := f.enqueue(t, "build", model.Build)
	for _, key := range []string{"ui-2", "ui-3", "ui-4", "ui-5", "ui-6"} {
		ui = append(ui, f.enqueue(t, key, model.SimulatorUITest))
	}
	f.register(t, "epoch-a", 6)
	var running []string
	ask := func(at time.Duration) *protocol.Lease {
		t.Helper()
		f.offset.Store(int64(at))
		lease, err := f.controller.next(context.Background(), "epoch-a", running)
		if err != nil {
			t.Fatal(err)
		}
		if lease != nil {
			running = append(running, lease.Job.ID)
		}
		return lease
	}
	claims := func(at time.Duration, want model.Job) {
		t.Helper()
		before := len(f.activeIDs())
		if lease := ask(at); lease != nil {
			t.Fatalf("at %s delivered %s, want a claim of %s", at, lease.Job.ID, want.ID)
		}
		if ids := f.activeIDs(); len(ids) != before+1 || ids[before] != want.ID {
			t.Fatalf("at %s active %v, want %s claimed", at, ids, want.ID)
		}
	}
	holds := func(at time.Duration) {
		t.Helper()
		before := f.activeIDs()
		if lease := ask(at); lease != nil || len(f.activeIDs()) != len(before) {
			t.Fatalf("at %s: lease %v, active %v, want nothing claimed beside %v", at, lease, f.activeIDs(), before)
		}
	}
	delivers := func(at time.Duration, want model.Job) protocol.Lease {
		t.Helper()
		f.controller.prep.Wait()
		lease := ask(at)
		if lease == nil || lease.Job.ID != want.ID {
			t.Fatalf("at %s delivered %v, want %s", at, lease, want.ID)
		}
		return *lease
	}
	runs := func(lease protocol.Lease) {
		t.Helper()
		if code := lifecycleRequest(t, f.controller, lease, "/stage", protocol.Stage{State: model.Running}); code != http.StatusNoContent {
			t.Fatalf("running stage of %s: %d", lease.Job.ID, code)
		}
	}
	claims(0, ui[0])
	claims(0, build)
	holds(time.Minute)
	holds(2 * time.Minute)
	close(release)
	leases := []protocol.Lease{delivers(2*time.Minute, ui[0])}
	built := delivers(2*time.Minute, build)
	holds(2 * time.Minute)
	holds(3*time.Minute - time.Second)
	claims(3*time.Minute, ui[1])
	leases = append(leases, delivers(3*time.Minute, ui[1]))
	// Running, a simulator job no longer holds the next start.
	runs(leases[1])
	claims(3*time.Minute, ui[2])
	leases = append(leases, delivers(3*time.Minute, ui[2]))
	runs(built)
	if err := f.controller.complete(context.Background(), built.Job, f.result(t, built), buildseal.Envelope{}); err != nil {
		t.Fatal(err)
	}
	for i, at := range []time.Duration{4 * time.Minute, 5 * time.Minute, 6 * time.Minute} {
		holds(at - time.Second)
		claims(at, ui[3+i])
		leases = append(leases, delivers(at, ui[3+i]))
	}
	lanes := map[int]bool{}
	for i, lease := range leases {
		if i != 1 {
			runs(lease)
		}
		job := f.job(t, lease.Job.ID)
		if job.State != model.Running || lanes[job.Lane] {
			t.Fatalf("%s: %s in lane %d, lanes taken %v", job.ID, job.State, job.Lane, lanes)
		}
		lanes[job.Lane] = true
	}
	if len(lanes) != 6 {
		t.Fatalf("lanes %v", lanes)
	}
}

// pulse sends lease's heartbeat and returns the controller's reply.
func pulse(t *testing.T, c *Controller, lease protocol.Lease) protocol.Heartbeat {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, protocol.Prefix+"/jobs/"+lease.Job.ID+"/heartbeat", bytes.NewReader([]byte("{}")))
	r = r.WithContext(context.WithValue(r.Context(), peerKey{}, true))
	r.Header.Set(protocol.EpochHeader, lease.Job.WorkerEpoch)
	r.Header.Set(protocol.LeaseHeader, lease.Token)
	w := httptest.NewRecorder()
	c.handler().ServeHTTP(w, r)
	var value protocol.Heartbeat
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &value) != nil {
		t.Fatalf("heartbeat %d %s", w.Code, w.Body.Bytes())
	}
	return value
}

// A completion the worker holds for its idle check (unattributed residue
// remained beside a sibling) lives on heartbeats past the finalizing window
// and past the job's deadline, which is judged when it was held; nothing is
// claimed beside it; once the sibling has ended it completes with its
// result.
func TestHeldCompletionWaitsForIdleCheck(t *testing.T) {
	f := newLanes(t, 2)
	admission := runtimeAdmission(model.Build)
	admission.Request.TimeoutSeconds = 60
	if _, _, err := f.db.Enqueue(context.Background(), "owner", "one", admission, f.now); err != nil {
		t.Fatal(err)
	}
	// The sibling's deadline must outlast the held job's finalizing window
	// (worker.FinalizationTimeout, which includes a command's process cleanup
	// under load, #194).
	sibling := runtimeAdmission(model.Build)
	sibling.Profile.DefaultTimeoutSeconds, sibling.Profile.MaxTimeoutSeconds, sibling.Request.TimeoutSeconds = 1200, 1200, 1200
	data, _ := json.Marshal(sibling.Profile)
	digest := sha256.Sum256(data)
	sibling.ProfileDigest = hex.EncodeToString(digest[:])
	if _, _, err := f.db.Enqueue(context.Background(), "owner", "two", sibling, f.now); err != nil {
		t.Fatal(err)
	}
	waiting := f.enqueue(t, "three", model.Build)
	f.register(t, "epoch-a", 2)
	first := f.start(t, "epoch-a")
	second := f.start(t, "epoch-a", first.Job.ID)
	if code := lifecycleRequest(t, f.controller, first, "/stage", protocol.Stage{State: model.Running, Held: true}); code != http.StatusConflict {
		t.Fatalf("held running stage: %d", code)
	}
	if code := lifecycleRequest(t, f.controller, first, "/stage", protocol.Stage{State: model.Finalizing, Held: true}); code != http.StatusNoContent {
		t.Fatalf("held stage: %d", code)
	}
	// The sibling runs past the held job's deadline and finalizing window.
	o := f.controller.options
	end := first.Job.Deadline.Sub(f.now) + o.CleanupTimeout + o.DeliveryTimeout + o.HeartbeatTimeout + time.Minute
	if end >= second.Job.Deadline.Sub(f.now) {
		t.Fatalf("sibling deadline %s within the hold %s", second.Job.Deadline.Sub(f.now), end)
	}
	for at := time.Duration(0); at <= end; at += 20 * time.Second {
		f.offset.Store(int64(at))
		if p := pulse(t, f.controller, first); p.Cancel {
			t.Fatalf("held completion told to cancel at +%s", at)
		}
		pulse(t, f.controller, second)
		f.controller.checkActive(context.Background())
	}
	if job := f.job(t, first.Job.ID); job.State != model.Finalizing || job.CancelRequested {
		t.Fatalf("held completion: %s cancel=%t", job.State, job.CancelRequested)
	}
	if err := f.controller.complete(context.Background(), second.Job, f.result(t, second), buildseal.Envelope{}); err != nil {
		t.Fatal(err)
	}
	if lease, err := f.controller.next(context.Background(), "epoch-a", []string{first.Job.ID}); lease != nil || err != nil {
		t.Fatalf("claimed beside a held completion: %v %v", lease, err)
	}
	f.controller.prep.Wait()
	if job := f.job(t, waiting.ID); job.State != model.Queued {
		t.Fatalf("claimed beside a held completion: %s", job.State)
	}
	if err := f.controller.complete(context.Background(), first.Job, f.result(t, first), buildseal.Envelope{}); err != nil {
		t.Fatal(err)
	}
	if job := f.job(t, first.Job.ID); job.State != model.Succeeded || !job.CleanupOK {
		t.Fatalf("held completion after its deadline: %s %q", job.State, job.Reason)
	}
}

// A held completion whose worker stops (a restart) ends once its heartbeat
// is lost, quiescence required, and the worker's next epoch registers; one
// still held after the idle check's window ends likewise.
func TestHeldCompletionEndsWithoutWorker(t *testing.T) {
	for name, heartbeats := range map[string]bool{"worker restart": false, "hold past idle window": true} {
		t.Run(name, func(t *testing.T) {
			f := newLanes(t, 2)
			f.enqueue(t, "one", model.Build)
			f.register(t, "epoch-a", 2)
			lease := f.start(t, "epoch-a")
			if code := lifecycleRequest(t, f.controller, lease, "/stage", protocol.Stage{State: model.Finalizing, Held: true}); code != http.StatusNoContent {
				t.Fatalf("held stage: %d", code)
			}
			o := f.controller.options
			limit := o.HeartbeatTimeout + time.Second
			if heartbeats {
				limit = o.CleanupTimeout + o.DeliveryTimeout + o.HeartbeatTimeout + time.Minute
			}
			for at := time.Duration(0); at <= limit; at += 10 * time.Second {
				f.offset.Store(int64(at))
				if heartbeats {
					lifecycleRequest(t, f.controller, lease, "/heartbeat", struct{}{})
				}
				f.controller.checkActive(context.Background())
			}
			f.offset.Store(int64(limit))
			f.controller.checkActive(context.Background())
			if job := f.job(t, lease.Job.ID); job.State != model.Interrupted || job.CleanupOK || job.Reason != "worker heartbeat lost; quiescence required" {
				t.Fatalf("held completion without its idle check: %s %q", job.State, job.Reason)
			}
			if err := f.controller.complete(context.Background(), lease.Job, worker.Result{State: model.Succeeded, CleanupOK: true}, buildseal.Envelope{}); !errors.Is(err, store.ErrLease) {
				t.Fatalf("late completion of an ended hold: %v", err)
			}
			f.register(t, "epoch-b", 2)
		})
	}
}

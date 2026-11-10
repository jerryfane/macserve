package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/buildseal"
	"github.com/jerryfane/macserve/internal/controllerk/store"
	"github.com/jerryfane/macserve/internal/health"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/protocol"
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

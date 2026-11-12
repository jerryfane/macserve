package workerclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/protocol"
	"github.com/jerryfane/macserve/internal/worker"
)

// holdWorld is a fake controller and engine sharing one event log. The
// engine runs each job until its gate closes; job "j_held" ends beside the
// other with unattributed residue (idle verdict deferred). Recover records
// whether a job still executed.
type holdWorld struct {
	t         *testing.T
	mu        sync.Mutex
	queue     []string
	deadlines map[string]time.Time
	events    []string
	epochs    []string
	complete  map[string]worker.Result
	gates     map[string]chan struct{}
	started   chan string
	live      int
	// recoverErr is the verdict of the first Recover after a hold.
	recoverErr error
	held       bool
	// failHeld is how many held-stage requests fail (503) before one is
	// recorded. window is the controller's finalizing window: a completion
	// not recorded as held by then is refused (410), the lease ended.
	failHeld   int
	window     time.Duration
	finalizing map[string]time.Time
	heldAcked  map[string]bool
}

func newHoldWorld(t *testing.T, queue ...string) *holdWorld {
	w := &holdWorld{t: t, queue: queue, deadlines: map[string]time.Time{}, complete: map[string]worker.Result{}, gates: map[string]chan struct{}{}, started: make(chan string, 8), finalizing: map[string]time.Time{}, heldAcked: map[string]bool{}}
	for _, id := range queue {
		w.gates[id] = make(chan struct{})
	}
	return w
}

func (w *holdWorld) event(e string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.events = append(w.events, e)
}

func (w *holdWorld) snapshot() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.events)
}

// wait waits until the event log contains e.
func (w *holdWorld) wait(ctx context.Context, e string) {
	w.t.Helper()
	for !slices.Contains(w.snapshot(), e) {
		select {
		case <-ctx.Done():
			w.t.Fatalf("no %q: %v", e, w.snapshot())
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func (w *holdWorld) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, protocol.Prefix)
	id := strings.Split(strings.TrimPrefix(path, "/jobs/"), "/")[0]
	w.mu.Lock()
	defer w.mu.Unlock()
	switch {
	case path == "/register":
		var reg protocol.Registration
		json.NewDecoder(r.Body).Decode(&reg)
		w.epochs = append(w.epochs, reg.Epoch)
		rw.WriteHeader(http.StatusNoContent)
	case path == "/next":
		if len(w.queue) == 0 {
			rw.WriteHeader(http.StatusNoContent)
			return
		}
		id := w.queue[0]
		w.queue = w.queue[1:]
		w.events = append(w.events, "lease "+id)
		deadline, ok := w.deadlines[id]
		if !ok {
			deadline = time.Now().Add(time.Minute)
		}
		json.NewEncoder(rw).Encode(protocol.Lease{Job: admittedJob(w.t, id, r.Header.Get(protocol.EpochHeader), &deadline, fixtureRequest), Token: "lease-" + id})
	case strings.HasSuffix(path, "/source"):
		rw.Write([]byte("source"))
	case strings.HasSuffix(path, "/stage"):
		var stage protocol.Stage
		json.NewDecoder(r.Body).Decode(&stage)
		if stage.State == model.Finalizing && w.finalizing[id].IsZero() {
			w.finalizing[id] = time.Now()
		}
		if stage.Held {
			if w.failHeld > 0 {
				w.failHeld--
				w.events = append(w.events, "held refused "+id)
				rw.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.heldAcked[id] = true
			w.events = append(w.events, "held "+id)
		}
		rw.WriteHeader(http.StatusNoContent)
	case strings.HasSuffix(path, "/complete") && w.window != 0 && !w.heldAcked[id] && time.Since(w.finalizing[id]) > w.window:
		w.events = append(w.events, "gone "+id)
		rw.WriteHeader(http.StatusGone)
	case strings.HasSuffix(path, "/complete"):
		var completion protocol.Completion
		json.NewDecoder(r.Body).Decode(&completion)
		w.complete[id] = completion.Result
		w.events = append(w.events, "complete "+id)
		rw.WriteHeader(http.StatusNoContent)
	case strings.HasSuffix(path, "/heartbeat"):
		json.NewEncoder(rw).Encode(protocol.Heartbeat{Deadline: time.Now().Add(time.Minute)})
	default:
		rw.WriteHeader(http.StatusNoContent)
	}
}

func (w *holdWorld) executor() *fakeExecutor {
	return &fakeExecutor{
		recover: func(context.Context) error {
			w.mu.Lock()
			defer w.mu.Unlock()
			if w.live != 0 {
				w.t.Error("Recover while a job executes")
			}
			if !w.held {
				return nil
			}
			w.events = append(w.events, "recover")
			err := w.recoverErr
			w.recoverErr = nil
			return err
		},
		execute: func(ctx context.Context, job model.Job, _ worker.Source, r io.Reader, sink worker.Sink) (worker.Result, error) {
			io.ReadAll(r)
			w.mu.Lock()
			w.live++
			gate := w.gates[job.ID]
			w.mu.Unlock()
			w.started <- job.ID
			select {
			case <-gate:
			case <-ctx.Done():
			}
			// Fails once the lease's context has ended (shutdown).
			_ = sink.Stage(model.Finalizing)
			result := worker.Result{State: model.Succeeded, CleanupOK: true, StartedAt: time.Now(), FinishedAt: time.Now(), Concurrency: &worker.Concurrency{Lane: 1, MaxLanes: 2, Attribution: worker.AttributionLineage, IdleVerdict: worker.IdleNotRequired}}
			w.mu.Lock()
			w.live--
			if job.ID == "j_held" {
				result.Concurrency.IdleVerdict, result.Concurrency.UnattributedResidue = worker.IdleDeferred, 1
				w.held = true
			}
			w.mu.Unlock()
			return result, ctx.Err()
		},
	}
}

// run starts a two-lane client against w.
func (w *holdWorld) run(ctx context.Context) (<-chan error, *Client) {
	w.t.Helper()
	cfg, _ := unixController(w.t, w)
	cfg.MaxConcurrentJobs = 2
	client, err := NewWithChecks(cfg, w.executor(), testChecks)
	if err != nil {
		w.t.Fatal(err)
	}
	w.t.Cleanup(func() { client.Close() })
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	return done, client
}

func before(events []string, a, b string) bool {
	i, j := slices.Index(events, a), slices.Index(events, b)
	return i >= 0 && j >= 0 && i < j
}

// A job that ends beside another with unattributed residue left is held:
// its completion waits, and no lease is asked for, until the other lane has
// ended and the idle Recover gives the verdict. Clean: the job completes with
// its result (idle verdict clean). Not clean: its cleanup is unverified, it
// fails and the epoch is replaced. The job's deadline passes during the hold
// without changing its result (Studio v0.1.47, 2026-11-12: a passing
// unit_test failed for residue beside the other lane).
func TestHeldCompletionWaitsForIdleCheck(t *testing.T) {
	for name, recoverErr := range map[string]error{"clean": nil, "contaminated": worker.ErrContamination} {
		t.Run(name, func(t *testing.T) {
			w := newHoldWorld(t, "j_held", "j_sib", "j_later")
			w.recoverErr = recoverErr
			w.deadlines["j_held"] = time.Now().Add(2 * time.Second)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			done, _ := w.run(ctx)
			<-w.started
			<-w.started
			close(w.gates["j_held"])
			w.wait(ctx, "held j_held")
			// Polls pass, and the held job's deadline, while the sibling runs.
			time.Sleep(3 * time.Second)
			if events := w.snapshot(); slices.Contains(events, "complete j_held") || slices.Contains(events, "lease j_later") || slices.Contains(events, "recover") {
				t.Fatalf("held completion did not wait for the sibling: %v", events)
			}
			close(w.gates["j_sib"])
			w.wait(ctx, "complete j_held")
			w.wait(ctx, "lease j_later")
			close(w.gates["j_later"])
			w.wait(ctx, "complete j_later")
			cancel()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			events := w.snapshot()
			if !before(events, "complete j_sib", "recover") || !before(events, "recover", "complete j_held") || !before(events, "complete j_held", "lease j_later") {
				t.Fatalf("hold order: %v", events)
			}
			w.mu.Lock()
			defer w.mu.Unlock()
			result := w.complete["j_held"]
			if recoverErr == nil && (result.State != model.Succeeded || !result.CleanupOK || result.Reason != "" || result.Concurrency.IdleVerdict != worker.IdleClean || result.Concurrency.UnattributedResidue != 1) {
				t.Fatalf("held completion after a clean idle check: %+v", result)
			}
			if recoverErr != nil && (result.State != model.Failed || result.CleanupOK || !strings.Contains(result.Reason, "idle check") || result.Concurrency.IdleVerdict != worker.IdleDeferred || len(slices.Compact(slices.Clone(w.epochs))) < 2) {
				t.Fatalf("held completion after a failed idle check: %+v epochs %v", result, w.epochs)
			}
		})
	}
}

// A worker stopping while a completion is held still gives it the idle
// verdict, once the other lane has ended, and delivers it.
func TestHeldCompletionSettlesAtShutdown(t *testing.T) {
	w := newHoldWorld(t, "j_held", "j_sib")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	runCtx, stop := context.WithCancel(ctx)
	done, _ := w.run(runCtx)
	<-w.started
	<-w.started
	close(w.gates["j_held"])
	w.wait(ctx, "held j_held")
	stop()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatalf("Run did not return: %v", w.snapshot())
	}
	events := w.snapshot()
	if !before(events, "complete j_sib", "recover") || !before(events, "recover", "complete j_held") {
		t.Fatalf("shutdown hold order: %v", events)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if result := w.complete["j_held"]; result.State != model.Succeeded || !result.CleanupOK || result.Concurrency.IdleVerdict != worker.IdleClean {
		t.Fatalf("held completion at shutdown: %+v", result)
	}
	if errors.Is(context.Cause(runCtx), context.DeadlineExceeded) {
		t.Fatal("test deadline")
	}
}

// The held stage is what lets a held lease outlast the controller's
// finalizing window; a first request that fails is resent until the
// controller records it, so a sibling running longer than that window does
// not cost the held job its result.
func TestHeldStageRetriedUntilRecorded(t *testing.T) {
	w := newHoldWorld(t, "j_held", "j_sib")
	w.failHeld, w.window = 1, 1500*time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	done, _ := w.run(ctx)
	<-w.started
	<-w.started
	close(w.gates["j_held"])
	w.wait(ctx, "held refused j_held")
	// The sibling outlasts the finalizing window.
	time.Sleep(3 * time.Second)
	close(w.gates["j_sib"])
	w.wait(ctx, "complete j_sib")
	for !slices.Contains(w.snapshot(), "complete j_held") && !slices.Contains(w.snapshot(), "gone j_held") {
		select {
		case <-ctx.Done():
			t.Fatalf("held completion never delivered: %v", w.snapshot())
		case <-time.After(20 * time.Millisecond):
		}
	}
	cancel()
	<-done
	events := w.snapshot()
	if !before(events, "held refused j_held", "held j_held") || !slices.Contains(events, "complete j_held") {
		t.Fatalf("held stage not resent until recorded: %v", events)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if result := w.complete["j_held"]; result.State != model.Succeeded || !result.CleanupOK || result.Concurrency.IdleVerdict != worker.IdleClean {
		t.Fatalf("held completion: %+v", result)
	}
}

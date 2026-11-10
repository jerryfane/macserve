package workerclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/protocol"
	"github.com/jerryfane/macserve/internal/worker"
)

// laneController is a fake controller handing out the queued job IDs, one
// per /next, recording the traffic.
type laneController struct {
	t        *testing.T
	mu       sync.Mutex
	queue    []string
	events   []string
	running  [][]string
	epochs   []string
	lanes    []int
	complete map[string]worker.Result
	// conflicts is how many registrations of an epoch after the first are
	// refused with 409, as while the controller still holds a lease of the
	// earlier epoch.
	conflicts int
}

func (f *laneController) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, protocol.Prefix)
	switch {
	case path == "/register":
		var reg protocol.Registration
		json.NewDecoder(r.Body).Decode(&reg)
		f.events = append(f.events, "register")
		f.epochs = append(f.epochs, reg.Epoch)
		f.lanes = append(f.lanes, reg.Lanes)
		if reg.Epoch != f.epochs[0] && f.conflicts > 0 {
			f.conflicts--
			w.WriteHeader(http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case path == "/next":
		var next protocol.NextRequest
		if err := json.NewDecoder(r.Body).Decode(&next); err != nil {
			f.t.Error(err)
		}
		f.running = append(f.running, next.Running)
		if len(f.queue) == 0 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		id := f.queue[0]
		f.queue = f.queue[1:]
		f.events = append(f.events, "lease "+id)
		deadline := time.Now().Add(time.Minute)
		json.NewEncoder(w).Encode(protocol.Lease{Job: admittedJob(f.t, id, r.Header.Get(protocol.EpochHeader), &deadline, fixtureRequest), Token: "lease-" + id})
	case strings.HasSuffix(path, "/source"):
		w.Write([]byte("source"))
	case strings.HasSuffix(path, "/complete"):
		var completion protocol.Completion
		json.NewDecoder(r.Body).Decode(&completion)
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/jobs/"), "/complete")
		f.complete[id] = completion.Result
		f.events = append(f.events, "complete "+id)
		w.WriteHeader(http.StatusNoContent)
	case strings.HasSuffix(path, "/heartbeat"):
		json.NewEncoder(w).Encode(protocol.Heartbeat{Deadline: time.Now().Add(time.Minute)})
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (f *laneController) snapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.events)
}

// laneExecutor runs each job until its gate closes, recording Recover calls
// and how many jobs executed at once.
type laneExecutor struct {
	fakeExecutor
	mu        sync.Mutex
	gates     map[string]chan struct{}
	cleanup   map[string]bool
	live, max int
	recovers  int
	started   chan string
}

func newLaneExecutor(ids ...string) *laneExecutor {
	e := &laneExecutor{gates: map[string]chan struct{}{}, cleanup: map[string]bool{}, started: make(chan string, 8)}
	for _, id := range ids {
		e.gates[id] = make(chan struct{})
		e.cleanup[id] = true
	}
	e.fakeExecutor.recover = func(context.Context) error {
		e.mu.Lock()
		defer e.mu.Unlock()
		if e.live != 0 {
			panic("Recover while a job executes")
		}
		e.recovers++
		return nil
	}
	e.fakeExecutor.execute = func(ctx context.Context, job model.Job, _ worker.Source, r io.Reader, _ worker.Sink) (worker.Result, error) {
		io.ReadAll(r)
		e.mu.Lock()
		e.live++
		e.max = max(e.max, e.live)
		gate := e.gates[job.ID]
		ok := e.cleanup[job.ID]
		e.mu.Unlock()
		e.started <- job.ID
		select {
		case <-gate:
		case <-ctx.Done():
		}
		e.mu.Lock()
		e.live--
		e.mu.Unlock()
		return worker.Result{State: model.Succeeded, CleanupOK: ok, StartedAt: time.Now(), FinishedAt: time.Now()}, nil
	}
	return e
}

// Two lanes execute two leases at once under one epoch: the second /next
// names the running job, Recover never runs beside a job, and the
// registration announces the lanes.
func TestClientRunsLeasesConcurrently(t *testing.T) {
	controller := &laneController{t: t, queue: []string{"j_one", "j_two"}, complete: map[string]worker.Result{}}
	cfg, _ := unixController(t, controller)
	cfg.MaxConcurrentJobs = 2
	engine := newLaneExecutor("j_one", "j_two")
	client, err := NewWithChecks(cfg, engine, testChecks)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	for range 2 {
		select {
		case <-engine.started:
		case <-ctx.Done():
			t.Fatalf("both leases did not run at once: %v", controller.snapshot())
		}
	}
	close(engine.gates["j_one"])
	close(engine.gates["j_two"])
	for deadline := time.Now().Add(10 * time.Second); len(controller.snapshot()) < 5 && time.Now().Before(deadline); {
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if engine.max != 2 {
		t.Fatalf("max concurrent executions %d", engine.max)
	}
	if len(controller.lanes) == 0 || controller.lanes[0] != 2 || slices.Compact(slices.Clone(controller.epochs))[0] != controller.epochs[len(controller.epochs)-1] {
		t.Fatalf("registration lanes %v epochs %v", controller.lanes, controller.epochs)
	}
	if len(controller.running) < 2 || len(controller.running[0]) != 0 || !slices.Equal(controller.running[1], []string{"j_one"}) {
		t.Fatalf("/next running lists %v", controller.running)
	}
	for _, id := range []string{"j_one", "j_two"} {
		if result, ok := controller.complete[id]; !ok || result.State != model.Succeeded {
			t.Fatalf("job %s completion %+v (events %v)", id, result, controller.events)
		}
	}
}

// A lane whose cleanup is unverified drains the client: no lease is asked
// for while its sibling runs, and a new epoch registers only after the
// sibling ends and Recover runs at idle. A registration the controller
// refuses with 409 (it still holds a lease of the earlier epoch) is retried:
// the quiescent worker does not exit.
func TestClientDrainsAfterUnverifiedLaneCleanup(t *testing.T) {
	controller := &laneController{t: t, queue: []string{"j_bad", "j_good", "j_later"}, complete: map[string]worker.Result{}, conflicts: 2}
	cfg, _ := unixController(t, controller)
	cfg.MaxConcurrentJobs = 2
	engine := newLaneExecutor("j_bad", "j_good", "j_later")
	engine.cleanup["j_bad"] = false
	close(engine.gates["j_later"])
	client, err := NewWithChecks(cfg, engine, testChecks)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	<-engine.started
	<-engine.started
	close(engine.gates["j_bad"])
	// Several polls pass while the sibling still runs: no lease is claimed.
	time.Sleep(2500 * time.Millisecond)
	if events := controller.snapshot(); slices.Contains(events, "lease j_later") {
		t.Fatalf("lease claimed while draining: %v", events)
	}
	engine.mu.Lock()
	recovers := engine.recovers
	engine.mu.Unlock()
	close(engine.gates["j_good"])
	select {
	case id := <-engine.started:
		if id != "j_later" {
			t.Fatalf("started %s", id)
		}
	case <-ctx.Done():
		t.Fatalf("worker did not resume after the idle check: %v", controller.snapshot())
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if engine.recovers <= recovers {
		t.Fatal("no idle Recover before resuming")
	}
	if len(controller.epochs) < 4 || controller.epochs[0] == controller.epochs[len(controller.epochs)-1] || controller.conflicts != 0 {
		t.Fatalf("epoch not rotated after the drain and refused registrations: %v", controller.epochs)
	}
	if controller.complete["j_bad"].State != model.Failed || controller.complete["j_good"].State != model.Succeeded {
		t.Fatalf("completions %+v", controller.complete)
	}
}

// Completions saved by concurrent lanes, and the single file of a worker
// from before lanes, are all delivered at startup, each acknowledged
// separately.
func TestClientDeliversEveryPendingCompletion(t *testing.T) {
	controller := &laneController{t: t, complete: map[string]worker.Result{}}
	cfg, _ := unixController(t, controller)
	cfg.MaxConcurrentJobs = 2
	engine := newLaneExecutor()
	client, err := NewWithChecks(cfg, engine, testChecks)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for _, id := range []string{"j_a", "j_b"} {
		if err := client.savePending(pending{Epoch: "e", Lease: protocol.Lease{Job: model.Job{ID: id}, Token: "t"}, Result: worker.Result{State: model.Failed}}); err != nil {
			t.Fatal(err)
		}
	}
	legacy, _ := json.Marshal(pending{Epoch: "e", Lease: protocol.Lease{Job: model.Job{ID: "j_old"}, Token: "t"}, Result: worker.Result{State: model.Failed}})
	if err := os.WriteFile(filepath.Join(cfg.Root, legacyPending), legacy, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	engine.fakeExecutor.recover = func(context.Context) error { cancel(); return context.Canceled }
	if err := client.Run(ctx); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"j_a", "j_b", "j_old"} {
		if _, ok := controller.complete[id]; !ok {
			t.Fatalf("pending %s not delivered", id)
		}
	}
	entries, _ := os.ReadDir(cfg.Root)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "pending") {
			t.Fatalf("acknowledged completion kept: %s", entry.Name())
		}
	}
}

package workerclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/protocol"
	"github.com/jerryfane/macserve/internal/worker"
)

// stallController is a fake controller of lease j_test. While stalled, its
// heartbeat, logs and stage requests wait for the stall to end, then take
// effect, as a controller on an overloaded host does; the worker may have
// given up on them by then. It records logs as the controller does: a seq
// once, a seq-less chunk always.
type stallController struct {
	mu         sync.Mutex
	stallUntil time.Time
	released   chan struct{}
	logStatus  int
	logs       strings.Builder
	lastSeq    int64
	logPosts   int
	resent     int
	stages     []model.State
	beats      int
	completed  chan worker.Result
}

func newStallController(t *testing.T) (*stallController, Config) {
	f := &stallController{released: make(chan struct{}), completed: make(chan worker.Result, 1)}
	t.Cleanup(func() { close(f.released) })
	cfg, _ := unixController(t, f)
	return f, cfg
}

func (f *stallController) stall(until time.Time) {
	f.mu.Lock()
	f.stallUntil = until
	f.mu.Unlock()
}

func (f *stallController) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, protocol.Prefix+"/jobs/j_test")
	switch path {
	case "/heartbeat", "/logs", "/stage":
		f.mu.Lock()
		until := f.stallUntil
		f.mu.Unlock()
		select {
		case <-time.After(time.Until(until)):
		case <-f.released:
			return
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch path {
	case "/source":
		w.Write([]byte("source"))
	case "/heartbeat":
		f.beats++
		json.NewEncoder(w).Encode(protocol.Heartbeat{Deadline: time.Now().Add(time.Hour)})
	case "/logs":
		f.logPosts++
		if f.logStatus != 0 {
			w.WriteHeader(f.logStatus)
			return
		}
		var chunk struct {
			Stream string `json:"stream"`
			Data   []byte `json:"data"`
			Seq    int64  `json:"seq"`
		}
		if err := json.NewDecoder(r.Body).Decode(&chunk); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch {
		case chunk.Seq == 0:
		case chunk.Seq <= f.lastSeq:
			f.resent++
			w.WriteHeader(http.StatusNoContent)
			return
		case chunk.Seq > f.lastSeq+1:
			w.WriteHeader(http.StatusConflict)
			return
		default:
			f.lastSeq = chunk.Seq
		}
		f.logs.Write(chunk.Data)
		w.WriteHeader(http.StatusNoContent)
	case "/stage":
		var stage protocol.Stage
		if err := json.NewDecoder(r.Body).Decode(&stage); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if n := len(f.stages); n == 0 || f.stages[n-1] != stage.State {
			f.stages = append(f.stages, stage.State)
		}
		w.WriteHeader(http.StatusNoContent)
	case "/complete":
		var got protocol.Completion
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		select {
		case f.completed <- got.Result:
		default:
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func executeStallLease(t *testing.T, cfg Config, engine *fakeExecutor) {
	t.Helper()
	client, err := NewWithChecks(cfg, engine, testChecks)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	deadline := time.Now().Add(5 * time.Minute)
	lease := protocol.Lease{Job: admittedJob(t, "j_test", client.epoch, &deadline, fixtureRequest), Token: "lease"}
	if _, err := client.execute(context.Background(), lease); err != nil {
		t.Fatal(err)
	}
}

func (f *stallController) result(t *testing.T) worker.Result {
	t.Helper()
	select {
	case result := <-f.completed:
		return result
	default:
		t.Fatal("no completion delivered")
		return worker.Result{}
	}
}

// A 15 s stall of the controller's heartbeat, logs and stage answers, longer
// than the worker's request timeout, does not end the job: the worker
// retries each until the lease window would end, holds the output meanwhile,
// and every line reaches the controller once, in order, though the stalled
// requests the worker gave up on took effect late (#174).
func TestControllerStallWithinLeaseWindowKeepsJob(t *testing.T) {
	t.Parallel()
	f, cfg := newStallController(t)
	var want strings.Builder
	engine := &fakeExecutor{execute: func(ctx context.Context, _ model.Job, _ worker.Source, r io.Reader, sink worker.Sink) (worker.Result, error) {
		if _, err := io.ReadAll(r); err != nil {
			return worker.Result{}, err
		}
		f.stall(time.Now().Add(15 * time.Second))
		line := func(i int) error {
			text := fmt.Sprintf("line %d\n", i)
			want.WriteString(text)
			return sink.Log("stdout", text)
		}
		for i := range 20 {
			if err := line(i); err != nil {
				return worker.Result{}, err
			}
			time.Sleep(100 * time.Millisecond)
		}
		if err := sink.Stage(model.Running); err != nil {
			return worker.Result{}, err
		}
		for i := 20; i < 40; i++ {
			if err := line(i); err != nil {
				return worker.Result{}, err
			}
		}
		if err := sink.Stage(model.Finalizing); err != nil {
			return worker.Result{}, err
		}
		if ctx.Err() != nil {
			return worker.Result{State: model.Cancelled, CleanupOK: true}, context.Cause(ctx)
		}
		return worker.Result{State: model.Succeeded, CleanupOK: true}, nil
	}}
	started := time.Now()
	executeStallLease(t, cfg, engine)
	if elapsed := time.Since(started); elapsed < 15*time.Second {
		t.Fatalf("job ended after %s, before the stall did", elapsed)
	}
	result := f.result(t)
	f.mu.Lock()
	defer f.mu.Unlock()
	if result.State != model.Succeeded {
		t.Fatalf("job ended %s (%s) on a stall within the lease window", result.State, result.Reason)
	}
	if got := f.logs.String(); got != want.String() {
		t.Fatalf("controller logs:\n%q\nwant\n%q", got, want.String())
	}
	if f.resent == 0 || f.beats == 0 {
		t.Fatalf("stall exercised no resent chunk (%d) or heartbeat (%d)", f.resent, f.beats)
	}
	if strings.Join(stateNames(f.stages), ",") != "running,finalizing" {
		t.Fatalf("stages %v", f.stages)
	}
}

func stateNames(states []model.State) []string {
	names := make([]string, len(states))
	for i, state := range states {
		names[i] = string(state)
	}
	return names
}

// leaseWindow is the controller's default HeartbeatTimeout.
const leaseWindow = 30 * time.Second

// A stall longer than the controller's lease window ends the job, after the
// worker retried for most of the window and never after the controller
// expired the lease (leaseWindow after it offered it).
func TestControllerStallPastLeaseWindowEndsJob(t *testing.T) {
	t.Parallel()
	f, cfg := newStallController(t)
	f.stall(time.Now().Add(time.Hour))
	ended := make(chan time.Time, 1)
	engine := &fakeExecutor{execute: func(ctx context.Context, _ model.Job, _ worker.Source, r io.Reader, sink worker.Sink) (worker.Result, error) {
		io.ReadAll(r)
		select {
		case <-ctx.Done():
			ended <- time.Now()
		case <-time.After(2 * leaseWindow):
		}
		return worker.Result{State: model.Cancelled, CleanupOK: true}, ctx.Err()
	}}
	offered := time.Now()
	executeStallLease(t, cfg, engine)
	result := f.result(t)
	select {
	case at := <-ended:
		if waited := at.Sub(offered); waited < 15*time.Second || waited > leaseWindow {
			t.Fatalf("job ended %s after the lease was offered; want within (15s, %s]", waited, leaseWindow)
		}
	default:
		t.Fatal("job was not cancelled on a stall past the lease window")
	}
	if result.State == model.Succeeded || !strings.Contains(result.Reason, "controller heartbeat") {
		t.Fatalf("result %s %q", result.State, result.Reason)
	}
}

// A refusal of the job's output (413: the controller's log limit) ends the
// job at once, without a retry.
func TestLogLimitRefusalEndsJobAtOnce(t *testing.T) {
	t.Parallel()
	f, cfg := newStallController(t)
	f.mu.Lock()
	f.logStatus = http.StatusRequestEntityTooLarge
	f.mu.Unlock()
	var waited time.Duration
	engine := &fakeExecutor{execute: func(ctx context.Context, _ model.Job, _ worker.Source, r io.Reader, sink worker.Sink) (worker.Result, error) {
		io.ReadAll(r)
		logged := time.Now()
		sink.Log("stdout", "too much\n")
		select {
		case <-ctx.Done():
		case <-time.After(10 * time.Second):
		}
		waited = time.Since(logged)
		return worker.Result{State: model.Cancelled, CleanupOK: true}, ctx.Err()
	}}
	executeStallLease(t, cfg, engine)
	result := f.result(t)
	if waited > time.Second {
		t.Fatalf("job ended %s after the refused log", waited)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.logPosts != 1 || result.State != model.Cancelled || !strings.Contains(result.Reason, "413") {
		t.Fatalf("log posts %d, result %s %q", f.logPosts, result.State, result.Reason)
	}
}

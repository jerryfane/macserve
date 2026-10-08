package workerclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/protocol"
	"github.com/jerryfane/macserve/internal/worker"
)

func TestUncertainPendingCompletionReplaysBeforeRecoveryWithoutRegistration(t *testing.T) {
	for _, accepted := range []bool{false, true} {
		t.Run(map[bool]string{false: "delivery-error", true: "delivered"}[accepted], func(t *testing.T) {
			var mu sync.Mutex
			var requests []string
			cfg, _ := unixController(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				requests = append(requests, r.URL.Path)
				mu.Unlock()
				if r.URL.Path != protocol.Prefix+"/jobs/uncertain/complete" {
					t.Error("registered or claimed before quiescence")
				}
				if r.Header.Get(protocol.EpochHeader) != "original-epoch" || r.Header.Get(protocol.LeaseHeader) != "original-lease" {
					t.Error("replay changed lease authority")
				}
				if accepted {
					w.WriteHeader(http.StatusNoContent)
				} else {
					w.WriteHeader(http.StatusServiceUnavailable)
				}
			}))
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			recovered := false
			executor := &fakeExecutor{recover: func(context.Context) error {
				recovered = true
				cancel()
				return worker.ErrContamination
			}}
			client, err := New(cfg, executor)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			saved := pending{Epoch: "original-epoch", Lease: protocol.Lease{Job: model.Job{ID: "uncertain"}, Token: "original-lease"}, Result: worker.Result{State: model.Failed, CleanupOK: false}}
			if err := client.savePending(saved); err != nil {
				t.Fatal(err)
			}
			err = client.Run(ctx)
			if accepted && (err != nil || !recovered) {
				t.Fatalf("recovery cancellation did not exit cleanly: recovered=%v err=%v", recovered, err)
			}
			if !accepted {
				var status *HTTPError
				if !errors.As(err, &status) || status.Status != 503 || recovered {
					t.Fatalf("delivery error lost or recovery ran before replay: recovered=%v err=%v", recovered, err)
				}
			}
			mu.Lock()
			if len(requests) != 1 || requests[0] != protocol.Prefix+"/jobs/uncertain/complete" {
				t.Errorf("unexpected startup traffic: %v", requests)
			}
			mu.Unlock()
			_, pendingErr := os.Stat(filepath.Join(cfg.Root, "pending.json"))
			if accepted {
				if !os.IsNotExist(pendingErr) || len(executor.removed) != 1 {
					t.Fatalf("acknowledged pending state not removed: %v", pendingErr)
				}
			} else if pendingErr != nil || len(executor.removed) != 0 {
				t.Fatalf("undelivered evidence removed: %v", pendingErr)
			}
		})
	}
}

func TestAdmissionFailureRecoversAndRegistersFreshEpochBeforeNextLease(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var mu sync.Mutex
	var events []string
	var epochs []string
	claims, recoveries, executions := 0, 0, 0
	cfg, _ := unixController(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case protocol.Prefix + "/register":
			events = append(events, "register")
			var registration protocol.Registration
			if err := json.NewDecoder(r.Body).Decode(&registration); err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if !registration.Quiescent || registration.Epoch != r.Header.Get(protocol.EpochHeader) {
				t.Error("registration did not acknowledge verified quiescence")
			}
			epochs = append(epochs, registration.Epoch)
			w.WriteHeader(http.StatusNoContent)
		case protocol.Prefix + "/next":
			events = append(events, "next")
			claims++
			if claims == 1 {
				deadline := time.Now().Add(time.Minute)
				json.NewEncoder(w).Encode(protocol.Lease{Job: model.Job{ID: "admission", WorkerEpoch: r.Header.Get(protocol.EpochHeader), State: model.Preparing, Deadline: &deadline}, Token: "lease"})
				return
			}
			cancel()
			w.WriteHeader(http.StatusNoContent)
		case protocol.Prefix + "/jobs/admission/source":
			events = append(events, "source")
			w.Write([]byte("source"))
		case protocol.Prefix + "/jobs/admission/complete":
			events = append(events, "complete")
			var result worker.Result
			if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
				t.Error(err)
			}
			if result.State != model.Failed || result.CleanupOK {
				t.Errorf("admission failure falsely claimed cleanup: %+v", result)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	engine := &fakeExecutor{
		recover: func(context.Context) error {
			mu.Lock()
			defer mu.Unlock()
			recoveries++
			events = append(events, "recover")
			if recoveries == 2 {
				return errors.New("temporary cleanup inspection failure")
			}
			return nil
		},
		execute: func(context.Context, model.Job, worker.Source, io.Reader, worker.Sink) (worker.Result, error) {
			mu.Lock()
			defer mu.Unlock()
			executions++
			events = append(events, "execute")
			return worker.Result{State: model.Failed, CleanupOK: false}, context.DeadlineExceeded
		},
	}
	client, err := New(cfg, engine)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Run(ctx); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	want := []string{"recover", "register", "next", "source", "execute", "complete", "recover", "recover", "register", "next"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("unsafe recovery ordering: got %v, want %v", events, want)
	}
	if len(epochs) != 2 || epochs[0] == epochs[1] || executions != 1 {
		t.Fatalf("failed-cleanup epoch reused or job replayed: epochs=%v executions=%d", epochs, executions)
	}
	if _, err := os.Stat(filepath.Join(cfg.Root, "pending.json")); !os.IsNotExist(err) {
		t.Fatalf("acknowledged failed completion retained: %v", err)
	}
	if len(engine.removed) != 1 || engine.removed[0] != "admission" {
		t.Fatalf("acknowledged export not removed: %v", engine.removed)
	}
}

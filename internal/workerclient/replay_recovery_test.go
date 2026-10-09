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

func TestAdmissionRefusalPreservesQueueUntilNextAdmittingPoll(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var mu sync.Mutex
	var events []string
	queued := true
	claims, recoveries, executions, completions := 0, 0, 0, 0
	var root string
	checkStatus := func(state, reason string) {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(root, "admission-status.json"))
		if err != nil {
			t.Error(err)
			return
		}
		var status admissionStatus
		if err := json.Unmarshal(data, &status); err != nil {
			t.Error(err)
			return
		}
		if status.State != state || status.Reason != reason || status.CheckedAt.IsZero() {
			t.Errorf("unexpected admission status: %+v", status)
		}
	}
	cfg, _ := unixController(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case protocol.Prefix + "/register":
			events = append(events, "register")
			checkStatus("admitting", "")
			w.WriteHeader(http.StatusNoContent)
		case protocol.Prefix + "/next":
			events = append(events, "next")
			claims++
			queued = false
			deadline := time.Now().Add(time.Minute)
			json.NewEncoder(w).Encode(protocol.Lease{Job: model.Job{ID: "admission", WorkerEpoch: r.Header.Get(protocol.EpochHeader), State: model.Preparing, Deadline: &deadline}, Token: "lease"})
		case protocol.Prefix + "/jobs/admission/source":
			events = append(events, "source")
			w.Write([]byte("source"))
		case protocol.Prefix + "/jobs/admission/complete":
			events = append(events, "complete")
			completions++
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	root = cfg.Root
	refusal := errors.New("GUI baseline process disappeared; worker-reset required")
	engine := &fakeExecutor{
		recover: func(context.Context) error {
			mu.Lock()
			defer mu.Unlock()
			recoveries++
			events = append(events, "recover")
			if recoveries == 5 {
				cancel()
				return context.Canceled
			}
			if claims != 0 || executions != 0 || completions != 0 || !queued {
				t.Error("admission refusal consumed queued work")
			}
			if recoveries > 1 {
				checkStatus("not_admitting", refusal.Error())
			}
			if _, err := os.Stat(filepath.Join(root, "admission-quarantine.json")); !os.IsNotExist(err) {
				t.Errorf("non-contamination refusal created marker: %v", err)
			}
			if recoveries <= 3 {
				return refusal
			}
			return nil
		},
		execute: func(context.Context, model.Job, worker.Source, io.Reader, worker.Sink) (worker.Result, error) {
			mu.Lock()
			defer mu.Unlock()
			executions++
			events = append(events, "execute")
			return worker.Result{State: model.Succeeded, CleanupOK: true}, nil
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
	want := []string{"recover", "recover", "recover", "recover", "register", "next", "source", "execute", "complete", "recover"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("unsafe pre-claim ordering: got %v, want %v", events, want)
	}
	if queued || claims != 1 || executions != 1 || completions != 1 {
		t.Fatalf("recovered admission did not resume work: queued=%v claims=%d executions=%d completions=%d", queued, claims, executions, completions)
	}
}

func TestAdmissionStatusWriteFailurePreventsClaims(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cfg, _ := unixController(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("status write failure allowed request: %s", r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	}))
	// A directory cannot be atomically replaced by the status file.
	if err := os.Mkdir(filepath.Join(cfg.Root, "admission-status.json"), 0700); err != nil {
		t.Fatal(err)
	}
	recoveries := 0
	client, err := New(cfg, &fakeExecutor{recover: func(context.Context) error {
		recoveries++
		if recoveries == 3 {
			cancel()
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if recoveries != 3 {
		t.Fatalf("status write failure did not retry ordinary polling: %d", recoveries)
	}
}

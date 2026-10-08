package workerclient

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"

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
			quarantined := errors.New("GUI baseline changed; administrator reconciliation required")
			executor := &fakeExecutor{recoverErr: quarantined}
			client, err := New(cfg, executor)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			saved := pending{Epoch: "original-epoch", Lease: protocol.Lease{Job: model.Job{ID: "uncertain"}, Token: "original-lease"}, Result: worker.Result{State: model.Failed, CleanupOK: false}}
			if err := client.savePending(saved); err != nil {
				t.Fatal(err)
			}
			err = client.Run(context.Background())
			if accepted && !errors.Is(err, quarantined) {
				t.Fatalf("recovery quarantine lost: %v", err)
			}
			if !accepted {
				var status *HTTPError
				if !errors.As(err, &status) || status.Status != 503 {
					t.Fatalf("delivery error lost: %v", err)
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

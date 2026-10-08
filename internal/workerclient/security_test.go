package workerclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/protocol"
	"github.com/jerryfane/macserve/internal/worker"
)

func TestProtectedBrokerConfigurationSeparatesIdentityAndStorage(t *testing.T) {
	base := Config{Socket: "/service/controller.sock", ControllerUID: 503, OwnerUID: 501, JobUID: 502, JobGID: 20, Root: "/service/control", ExportRoot: "/service/exports", WorkspaceRoot: "/service/workspaces", HelperPath: "/service/bin/macserve", BaselinePath: "/service/control/gui-baseline.json"}
	for name, mutate := range map[string]func(*Config){
		"missing-job":        func(c *Config) { c.JobUID = 0 },
		"owner-job":          func(c *Config) { c.JobUID = c.OwnerUID },
		"controller-job":     func(c *Config) { c.JobUID = c.ControllerUID },
		"root-controller":    func(c *Config) { c.ControllerUID = 0 },
		"missing-owner":      func(c *Config) { c.OwnerUID = 0 },
		"missing-baseline":   func(c *Config) { c.BaselinePath = "" },
		"control-under-job":  func(c *Config) { c.Root = filepath.Join(c.WorkspaceRoot, "control") },
		"job-under-control":  func(c *Config) { c.WorkspaceRoot = filepath.Join(c.Root, "workspaces") },
		"exports-under-job":  func(c *Config) { c.ExportRoot = filepath.Join(c.WorkspaceRoot, "exports") },
		"helper-under-job":   func(c *Config) { c.HelperPath = filepath.Join(c.WorkspaceRoot, "macserve") },
		"baseline-under-job": func(c *Config) { c.BaselinePath = filepath.Join(c.WorkspaceRoot, "baseline.json") },
		"socket-under-job":   func(c *Config) { c.Socket = filepath.Join(c.WorkspaceRoot, "controller.sock") },
	} {
		t.Run(name, func(t *testing.T) {
			c := base
			mutate(&c)
			if _, err := normalize(c); err == nil {
				t.Fatal("unsafe protected broker configuration accepted")
			}
		})
	}
	if _, err := normalize(base); err != nil {
		t.Fatal(err)
	}
}

func TestSourceTransferFailureCannotInventSuccessfulCleanup(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		t.Run(map[bool]string{false: "quiescent", true: "residual-process"}[uncertain], func(t *testing.T) {
			completed := make(chan worker.Result, 1)
			cfg, _ := unixController(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case protocol.Prefix + "/jobs/j_source/source":
					w.WriteHeader(http.StatusServiceUnavailable)
				case protocol.Prefix + "/jobs/j_source/complete":
					var result worker.Result
					if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
						t.Error(err)
						w.WriteHeader(400)
						return
					}
					completed <- result
					w.WriteHeader(http.StatusNoContent)
				default:
					t.Errorf("unexpected request %s", r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			engine := &fakeExecutor{execute: func(context.Context, model.Job, worker.Source, io.Reader, worker.Sink) (worker.Result, error) {
				t.Fatal("recipe ran without source")
				return worker.Result{}, nil
			}}
			if uncertain {
				engine.recoverErr = errors.New("job UID still has an escaped process")
			}
			client, err := New(cfg, engine)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			deadline := time.Now().Add(time.Minute)
			lease := protocol.Lease{Job: model.Job{ID: "j_source", WorkerEpoch: client.epoch, State: model.Preparing, Deadline: &deadline}, Token: "lease"}
			err = client.execute(context.Background(), lease)
			if (err != nil) != uncertain {
				t.Fatalf("cleanup continuation decision: %v", err)
			}
			result := <-completed
			if result.State != model.Failed || result.CleanupOK == uncertain {
				t.Fatalf("false source-failure cleanup receipt: %+v", result)
			}
		})
	}
}

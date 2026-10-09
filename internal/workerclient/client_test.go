package workerclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/protocol"
	"github.com/jerryfane/macserve/internal/worker"
)

type fakeExecutor struct {
	execute    func(context.Context, model.Job, worker.Source, io.Reader, worker.Sink) (worker.Result, error)
	artifacts  map[string]string
	removed    []string
	recoverErr error
	recover    func(context.Context) error
}

func (e *fakeExecutor) Recover(ctx context.Context) error {
	if e.recover != nil {
		return e.recover(ctx)
	}
	return e.recoverErr
}
func (e *fakeExecutor) Execute(ctx context.Context, job model.Job, source worker.Source, r io.Reader, sink worker.Sink) (worker.Result, error) {
	return e.execute(ctx, job, source, r, sink)
}
func (e *fakeExecutor) ArtifactPath(job, id string) (string, error) {
	path, ok := e.artifacts[id]
	if !ok {
		return "", os.ErrNotExist
	}
	return path, nil
}
func (e *fakeExecutor) RemoveExport(id string) error { e.removed = append(e.removed, id); return nil }

func unixController(t *testing.T, handler http.Handler) (Config, func()) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("worker transport requires a non-root peer")
	}
	dir, err := os.MkdirTemp("", "ms-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "controller.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	root := filepath.Join(dir, "worker")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	return Config{Socket: socket, ControllerUID: uint32(os.Geteuid()), OwnerUID: uint32(os.Geteuid()) + 20000, JobUID: uint32(os.Geteuid()) + 10000, JobGID: 502, Root: root, ExportRoot: filepath.Join(dir, "exports"), WorkspaceRoot: filepath.Join(dir, "workspaces"), HelperPath: filepath.Join(dir, "macserve"), BaselinePath: filepath.Join(root, "gui-baseline.json"), PollSeconds: 1, HeartbeatSeconds: 1, RequestTimeoutSeconds: 2}, func() { server.Close() }
}

func TestWrongControllerPeerCannotRegister(t *testing.T) {
	var mu sync.Mutex
	requests := 0
	cfg, _ := unixController(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	cfg.ControllerUID++
	client, err := New(cfg, &fakeExecutor{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := client.json(ctx, http.MethodPost, "/register", client.epoch, "", protocol.Registration{}, nil); err == nil {
		t.Fatal("wrong UID accepted")
	}
	mu.Lock()
	defer mu.Unlock()
	if requests != 0 {
		t.Fatal("unauthenticated peer received protocol request")
	}
}

func TestHeartbeatCancellationCompletesWithoutAnotherExecution(t *testing.T) {
	var result worker.Result
	var mu sync.Mutex
	completed := make(chan struct{})
	cfg, _ := unixController(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case protocol.Prefix + "/jobs/j_test/source":
			w.Write([]byte("source"))
		case protocol.Prefix + "/jobs/j_test/heartbeat":
			json.NewEncoder(w).Encode(protocol.Heartbeat{Cancel: true, Deadline: time.Now().Add(time.Minute)})
		case protocol.Prefix + "/jobs/j_test/complete":
			var got worker.Result
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			mu.Lock()
			result = got
			mu.Unlock()
			close(completed)
			w.WriteHeader(204)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	cancelObserved := false
	engine := &fakeExecutor{execute: func(ctx context.Context, _ model.Job, _ worker.Source, r io.Reader, _ worker.Sink) (worker.Result, error) {
		if _, err := io.ReadAll(r); err != nil {
			t.Error(err)
		}
		<-ctx.Done()
		cancelObserved = true
		return worker.Result{State: model.Cancelled, CleanupOK: true}, ctx.Err()
	}}
	client, err := New(cfg, engine)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	deadline := time.Now().Add(10 * time.Second)
	lease := protocol.Lease{Job: model.Job{ID: "j_test", WorkerEpoch: client.epoch, State: model.Preparing, Deadline: &deadline}, Token: "lease"}
	if _, err := client.execute(context.Background(), lease); err != nil {
		t.Fatal(err)
	}
	select {
	case <-completed:
	default:
		t.Fatal("cancelled result was not delivered")
	}
	mu.Lock()
	defer mu.Unlock()
	if !cancelObserved || result.State != model.Cancelled || !result.CleanupOK {
		t.Fatalf("cancel outcome: %+v", result)
	}
	if len(engine.removed) != 1 || engine.removed[0] != "j_test" {
		t.Fatal("acknowledged export was not cleaned")
	}
}

func TestCompletionRetryDoesNotRerunJob(t *testing.T) {
	content := []byte("actual evidence bytes\n")
	digest := sha256.Sum256(content)
	id := hex.EncodeToString(digest[:])
	var mu sync.Mutex
	uploads, completions := 0, 0
	var transferred []byte
	cfg, _ := unixController(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case protocol.Prefix + "/jobs/j_retry/source":
			w.Write([]byte("source"))
		case protocol.Prefix + "/jobs/j_retry/artifacts/" + id:
			data, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
			}
			mu.Lock()
			uploads++
			transferred = data
			mu.Unlock()
			w.WriteHeader(204)
		case protocol.Prefix + "/jobs/j_retry/complete":
			mu.Lock()
			completions++
			n := completions
			mu.Unlock()
			if n == 1 {
				w.WriteHeader(503)
			} else {
				w.WriteHeader(204)
			}
		default:
			w.WriteHeader(404)
		}
	}))
	path := filepath.Join(cfg.Root, "artifact")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	executions := 0
	engine := &fakeExecutor{artifacts: map[string]string{id: path}, execute: func(context.Context, model.Job, worker.Source, io.Reader, worker.Sink) (worker.Result, error) {
		executions++
		return worker.Result{State: model.Succeeded, CleanupOK: true, Artifacts: []evidence.Artifact{{ID: id, Name: "evidence.txt", SHA256: id, SizeBytes: int64(len(content)), ExpiresAt: time.Now().Add(time.Hour)}}}, nil
	}}
	client, err := New(cfg, engine)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Minute)
	lease := protocol.Lease{Job: model.Job{ID: "j_retry", WorkerEpoch: client.epoch, State: model.Preparing, Deadline: &deadline}, Token: "lease"}
	if _, err := client.execute(context.Background(), lease); err == nil {
		t.Fatal("failed completion acknowledged")
	}
	client.Close()
	if len(engine.removed) != 0 {
		t.Fatal("unacknowledged export removed")
	}
	client, err = New(cfg, engine)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	saved, err := client.loadPending()
	if err != nil || saved == nil {
		t.Fatalf("completion was not durable: %v", err)
	}
	if saved.Epoch != lease.Job.WorkerEpoch {
		t.Fatal("recovery lost execution epoch")
	}
	if err := client.deliver(context.Background(), *saved); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(cfg.Root, "pending.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("acknowledged completion retained: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if executions != 1 || uploads != 2 || completions != 2 || !bytes.Equal(transferred, content) {
		t.Fatalf("bad replay: executes=%d uploads=%d completions=%d bytes=%q", executions, uploads, completions, transferred)
	}
}

func TestRecoveryFailureRetriesWithoutRegistrationUntilCancellation(t *testing.T) {
	cfg, _ := unixController(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("registered before recovery succeeded")
		w.WriteHeader(204)
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	attempts := 0
	client, err := New(cfg, &fakeExecutor{recover: func(context.Context) error {
		attempts++
		if attempts == 2 {
			cancel()
			return context.Canceled
		}
		return errors.New("temporary census command failure")
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Run(ctx); err != nil {
		t.Fatalf("cancellation did not exit cleanly: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("recovery did not retry: attempts=%d", attempts)
	}
}

func TestWorkerConfigRejectsUntrustedFieldsAndPaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "worker.json")
	for _, body := range []string{
		`{"socket":"relative","controller_uid":123,"root":"/example/worker","export_root":"/example/export"}`,
		`{"socket":"/example/socket","controller_uid":0,"root":"/example/worker","export_root":"/example/export"}`,
		`{"socket":"/example/socket","controller_uid":123,"root":"/example/worker","export_root":"/example/export","token":"forbidden"}`,
		`{"socket":"/example/socket","controller_uid":123,"root":"/example/worker","export_root":"/example/export"} {}`,
	} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(path); err == nil {
			t.Fatalf("accepted invalid config %s", body)
		}
	}
}

package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/worker"
	"github.com/jerryfane/macserve/internal/workerclient"
)

type emptyLogExecutor struct {
	file         string
	acknowledged chan struct{}
}

func (e *emptyLogExecutor) Recover(context.Context) error               { return nil }
func (e *emptyLogExecutor) ArtifactPath(string, string) (string, error) { return e.file, nil }
func (e *emptyLogExecutor) RemoveExport(string) error                   { close(e.acknowledged); return nil }
func (e *emptyLogExecutor) VerifiedTree(string) string                  { return "" }
func (e *emptyLogExecutor) Execute(ctx context.Context, job model.Job, source worker.Source, input io.Reader, sink worker.Sink) (worker.Result, error) {
	if err := sink.Stage(model.Running); err != nil {
		return worker.Result{}, err
	}
	if err := sink.Stage(model.Finalizing); err != nil {
		return worker.Result{}, err
	}
	digest := sha256.Sum256(nil)
	id := hex.EncodeToString(digest[:])
	zero := 0
	result := worker.Result{State: model.Succeeded, CleanupOK: true, ExitCode: &zero, StartedAt: *job.StartedAt, FinishedAt: *job.StartedAt, Source: source, Observation: worker.Observation{Xcode: job.Profile.Xcode, Architecture: "arm64", SDKVersion: "18.5", SDKBuild: "22F77", SwiftVersion: "6.2", OSVersion: "26.0", OSBuild: "25A1"}}
	for _, name := range []string{"evidence/stdout.log", "evidence/stderr.log"} {
		result.Artifacts = append(result.Artifacts, evidence.Artifact{ID: id, SHA256: id, Name: name, MediaType: "application/octet-stream", ExpiresAt: job.StartedAt.Add(7 * 24 * time.Hour)})
	}
	return result, nil
}

func TestWorkerClientCompletesWithEmptyLogArtifacts(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("controller identity must be non-root")
	}
	f := newRuntime(t)
	runUnix(t, f.controller)
	job := f.enqueue(t, "empty-log-job", model.Build)
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "control"), 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "empty")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	engine := &emptyLogExecutor{file: file, acknowledged: make(chan struct{})}
	config := workerclient.Config{Root: filepath.Join(root, "control"), ExportRoot: filepath.Join(root, "exports"), WorkspaceRoot: filepath.Join(root, "workspaces"), HelperPath: filepath.Join(root, "helper"), BaselinePath: filepath.Join(root, "baseline.json"), PersistencePath: filepath.Join(root, "reviewed-persistence.json"), JobUID: uint32(os.Geteuid()) + 1000, JobGID: uint32(os.Getegid()) + 1000, OwnerUID: uint32(os.Geteuid()) + 2000, Socket: f.controller.options.Socket, ControllerUID: uint32(os.Geteuid()), PollSeconds: 1, HeartbeatSeconds: 1}
	writeLeaseAuthority(t, &config, root, runtimeAdmission(model.Build).Profile)
	// The test's non-root files stand in for the root-owned registry,
	// qualification record and seal key.
	client, err := workerclient.NewWithChecks(config, engine, workerclient.Checks{RootConfig: func(string) error { return nil }, ReadPrivateKey: os.ReadFile})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	select {
	case <-engine.acknowledged:
	case err := <-done:
		t.Fatalf("empty log delivery failed: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	saved, err := f.db.Get(context.Background(), job.ID)
	if err != nil || saved.State != model.Succeeded || !saved.CleanupOK {
		t.Fatalf("completion not committed: %+v %v", saved, err)
	}
	sum := sha256.Sum256(nil)
	sealed, metadata, err := f.controller.Artifact(context.Background(), job.ID, hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatal(err)
	}
	defer sealed.Close()
	data, err := io.ReadAll(sealed)
	if err != nil || len(data) != 0 || metadata.SizeBytes != 0 {
		t.Fatalf("empty evidence lost: %q %+v %v", data, metadata, err)
	}
}

// writeLeaseAuthority writes the worker's root registry of profile, a
// qualification record of exactly it and a seal key, and names them.
func writeLeaseAuthority(t *testing.T, config *workerclient.Config, dir string, profile model.Profile) {
	t.Helper()
	registry, err := profiles.New([]model.Profile{profile}, nil)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, value any) string {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	config.ProfilesFile = write("profiles.json", map[string]any{"profiles": []model.Profile{profile}})
	config.QualificationFile = write("qualification.json", map[string]any{"schema": 4, "profiles": registry.Digests()})
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	config.SealKeyFile = filepath.Join(dir, "seal-key.pem")
	if err := os.WriteFile(config.SealKeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	config.SealKeyID = "macserve-worker-test"
}

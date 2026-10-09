package controller

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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/protocol"
	"github.com/jerryfane/macserve/internal/source"
	"github.com/jerryfane/macserve/internal/store"
	"github.com/jerryfane/macserve/internal/worker"
)

type fakeSource struct {
	directory string
	release   <-chan struct{}
	started   chan struct{}
}

func (f *fakeSource) Prepare(ctx context.Context, job model.Job) (source.Descriptor, error) {
	if f.started != nil {
		close(f.started)
	}
	if f.release != nil {
		select {
		case <-ctx.Done():
			return source.Descriptor{}, ctx.Err()
		case <-f.release:
		}
	}
	data := []byte("deterministic controller source")
	filename := filepath.Join(f.directory, job.ID+".tar")
	if err := os.WriteFile(filename, data, 0600); err != nil {
		return source.Descriptor{}, err
	}
	digest := sha256.Sum256(data)
	return source.Descriptor{Path: filename, Source: worker.Source{Commit: job.Request.SHA, Tree: strings.Repeat("b", 40), SHA256: hex.EncodeToString(digest[:]), SizeBytes: int64(len(data))}}, nil
}
func (f *fakeSource) Remove(id string) error {
	err := os.Remove(filepath.Join(f.directory, id+".tar"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

type runtimeFixture struct {
	controller *Controller
	db         *store.Store
	now        time.Time
	offset     atomic.Int64
	blocked    atomic.Bool
	source     *fakeSource
}

func newRuntime(t *testing.T) *runtimeFixture {
	t.Helper()
	root := t.TempDir()
	socketDir, err := os.MkdirTemp("", "ms-c-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(socketDir) })
	db, err := store.Open(filepath.Join(root, "database", "queue.sqlite"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	f := &runtimeFixture{db: db, now: time.Now().UTC(), source: &fakeSource{directory: root}}
	uid := uint32(os.Geteuid())
	if uid == 0 {
		uid = 1
	}
	c, err := New(Options{Root: filepath.Join(root, "controller"), Socket: filepath.Join(socketDir, "worker.sock"), Store: db, BrokerUID: uid, Source: f.source, Now: func() time.Time { return f.now.Add(time.Duration(f.offset.Load())) }, Gate: func(context.Context) (GateState, error) { return GateState{Ready: !f.blocked.Load()}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	f.controller = c
	t.Cleanup(func() { c.Close() })
	return f
}

func runtimeAdmission(kind model.Kind) model.Admission {
	profile := model.Profile{ID: "approved", Version: 1, Repo: "example-org/example-app", Kind: kind, Xcode: model.Xcode{Version: "27.0", Build: "27A100"}, DeveloperDir: "/Applications/ExampleToolchain.app/Contents/Developer", WorkDir: ".", Run: model.Command{Executable: "/usr/bin/true"}, DefaultTimeoutSeconds: 600, MaxTimeoutSeconds: 600, MemoryLimitMiB: 512}
	if kind != model.Build {
		profile.Simulator = &model.Simulator{Runtime: "com.apple.CoreSimulator.SimRuntime.iOS-18-5", RuntimeBuild: "22F77", DeviceType: "com.apple.CoreSimulator.SimDeviceType.Example"}
		profile.RequiredTests = []string{"ExampleTests/testApproved"}
	}
	data, _ := json.Marshal(profile)
	digest := sha256.Sum256(data)
	return model.Admission{Request: model.Request{Repo: profile.Repo, SHA: strings.Repeat("a", 40), Kind: kind, Profile: profile.ID, Xcode: profile.Xcode, Simulator: profile.Simulator, TimeoutSeconds: 600}, Profile: profile, ProfileDigest: hex.EncodeToString(digest[:])}
}
func (f *runtimeFixture) enqueue(t *testing.T, key string, kind model.Kind) model.Job {
	t.Helper()
	job, _, err := f.db.Enqueue(context.Background(), "owner", key, runtimeAdmission(kind), f.now)
	if err != nil {
		t.Fatal(err)
	}
	return job
}
func (f *runtimeFixture) lease(t *testing.T, kind model.Kind) protocol.Lease {
	t.Helper()
	f.enqueue(t, "job", kind)
	if err := f.controller.register(context.Background(), protocol.Registration{Epoch: "epoch-a", Quiescent: true}); err != nil {
		t.Fatal(err)
	}
	lease, err := f.controller.next(context.Background(), "epoch-a")
	if err != nil || lease != nil {
		t.Fatalf("preparation admission: %v %v", lease, err)
	}
	f.controller.prep.Wait()
	lease, err = f.controller.next(context.Background(), "epoch-a")
	if err != nil || lease == nil {
		t.Fatalf("prepared lease: %v %v", lease, err)
	}
	return *lease
}
func (f *runtimeFixture) artifact(t *testing.T, job model.Job, name string, data []byte) evidence.Artifact {
	t.Helper()
	digest := sha256.Sum256(data)
	id := hex.EncodeToString(digest[:])
	a := evidence.Artifact{ID: id, SHA256: id, Name: name, MediaType: "application/octet-stream", SizeBytes: int64(len(data)), ExpiresAt: f.now.Add(7 * 24 * time.Hour)}
	if err := f.controller.putArtifact(context.Background(), job, a, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	return a
}
func (f *runtimeFixture) result(t *testing.T, lease protocol.Lease) worker.Result {
	t.Helper()
	zero := 0
	return worker.Result{State: model.Succeeded, CleanupOK: true, ExitCode: &zero, StartedAt: f.now, FinishedAt: f.now, Source: lease.Source, Observation: worker.Observation{Xcode: lease.Job.Profile.Xcode, Architecture: "arm64", SDKVersion: "18.5", SDKBuild: "22F77", SwiftVersion: "6.2", OSVersion: "26.0", OSBuild: "25A1", RuntimeVersion: "18.5", RuntimeBuild: "22F77", DeviceUDID: "device-fixture"}, Artifacts: []evidence.Artifact{f.artifact(t, lease.Job, "evidence/stdout.log", nil), f.artifact(t, lease.Job, "evidence/stderr.log", nil)}}
}

func unixClient(t *testing.T, c *Controller) *http.Client {
	t.Helper()
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", c.options.Socket)
	}}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 3 * time.Second}
}
func request(t *testing.T, client *http.Client, method, route, epoch, lease string, value any) (int, []byte) {
	t.Helper()
	var body io.Reader
	if value != nil {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, "http://controller"+protocol.Prefix+route, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(protocol.EpochHeader, epoch)
	req.Header.Set(protocol.LeaseHeader, lease)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, data
}
func runUnix(t *testing.T, c *Controller) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("unix", c.options.Socket, 20*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("Unix controller did not listen")
}

func TestUnixPeerBoundaryAsyncDrainAndEpochFencing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("successful peer fixture requires a non-root UID")
	}
	f := newRuntime(t)
	c := f.controller
	release := make(chan struct{})
	f.source.release = release
	f.source.started = make(chan struct{})
	job := f.enqueue(t, "first", model.Build)
	runUnix(t, c)
	client := unixClient(t, c)
	if status, _ := request(t, client, "POST", "/register", "epoch-a", "", protocol.Registration{Epoch: "epoch-a", Quiescent: true}); status != 204 {
		t.Fatalf("register %d", status)
	}
	if status, _ := request(t, client, "POST", "/next", "epoch-a", "", struct{}{}); status != 204 {
		t.Fatalf("async preparation status %d", status)
	}
	<-f.source.started
	if _, err := f.db.Pause(context.Background(), "benchmark", "drain", f.now); err != nil {
		t.Fatal(err)
	}
	close(release)
	c.prep.Wait()
	f.blocked.Store(true)
	status, raw := request(t, client, "POST", "/next", "epoch-a", "", struct{}{})
	if status != 200 {
		t.Fatalf("draining active preparation withheld: %d", status)
	}
	var lease protocol.Lease
	if err := json.Unmarshal(raw, &lease); err != nil {
		t.Fatal(err)
	}
	if lease.Job.ID != job.ID || lease.Token == "" {
		t.Fatalf("wrong lease: %+v", lease)
	}
	if status, _ := request(t, client, "POST", "/register", "epoch-b", "", protocol.Registration{Epoch: "epoch-b", Quiescent: true}); status != 409 {
		t.Fatalf("replacement stole active lease: %d", status)
	}
	if status, _ := request(t, client, "POST", "/jobs/"+job.ID+"/stage", "epoch-a", lease.Token, protocol.Stage{State: model.Running}); status != 204 {
		t.Fatalf("running stage %d", status)
	}
	if status, _ := request(t, client, "POST", "/next", "epoch-a", "", struct{}{}); status != 204 {
		t.Fatalf("running lease replayed: %d", status)
	}
	f.offset.Store(int64(31 * time.Second))
	c.checkActive(context.Background())
	state, err := f.db.ServiceState(context.Background())
	if err != nil || !state.Quarantined || !state.Paused {
		t.Fatalf("heartbeat quarantine lost: %+v %v", state, err)
	}
	if status, _ := request(t, client, "POST", "/jobs/"+job.ID+"/heartbeat", "epoch-a", lease.Token, struct{}{}); status != 410 {
		t.Fatalf("stale heartbeat %d", status)
	}
	if status, _ := request(t, client, "POST", "/register", "epoch-a", "", protocol.Registration{Epoch: "epoch-a", Quiescent: true}); status != 410 {
		t.Fatalf("invalid epoch returned: %d", status)
	}
	if status, _ := request(t, client, "POST", "/register", "epoch-b", "", protocol.Registration{Epoch: "epoch-b", Quiescent: true}); status != 204 {
		t.Fatalf("fresh quiescent registration %d", status)
	}
	state, _ = f.db.ServiceState(context.Background())
	if state.Quarantined || !state.Paused {
		t.Fatalf("registration cleared manual pause: %+v", state)
	}
}

func TestUnixKernelUIDMismatchCannotRegister(t *testing.T) {
	f := newRuntime(t)
	f.controller.options.BrokerUID = uint32(os.Geteuid() + 1)
	runUnix(t, f.controller)
	client := unixClient(t, f.controller)
	if status, _ := request(t, client, "POST", "/register", "epoch-a", "", protocol.Registration{Epoch: "epoch-a", Quiescent: true}); status != 403 {
		t.Fatalf("unauthorized kernel peer status %d", status)
	}
	if f.controller.epoch != "" {
		t.Fatal("untrusted peer changed epoch")
	}
}

func TestCompletionReparsesTestsAndRejectsForgedSummary(t *testing.T) {
	for _, outcome := range []string{"Passed", "Failed"} {
		t.Run(outcome, func(t *testing.T) {
			f := newRuntime(t)
			lease := f.lease(t, model.UnitTest)
			result := f.result(t, lease)
			report := []byte(`{"testPlanConfigurations":[],"devices":[],"testNodes":[{"nodeType":"Test Case","name":"testApproved","nodeIdentifier":"ExampleTests/testApproved","result":"` + outcome + `"}]}`)
			result.Artifacts = append(result.Artifacts, f.artifact(t, lease.Job, "evidence/tests.json", report), f.artifact(t, lease.Job, "results.xcresult.tar.gz", []byte("sealed result fixture")))
			result.Summary = &evidence.Summary{ParseStatus: "parsed", Tests: 999, Passed: 999}
			if err := f.controller.complete(context.Background(), lease.Job, result); err != nil {
				t.Fatal(err)
			}
			job, err := f.db.Get(context.Background(), lease.Job.ID)
			if err != nil {
				t.Fatal(err)
			}
			var saved Completion
			if err := json.Unmarshal(job.Result, &saved); err != nil {
				t.Fatal(err)
			}
			want := model.Succeeded
			failures := 0
			if outcome == "Failed" {
				want = model.Failed
				failures = 1
			}
			if job.State != want || saved.Result.Summary == nil || saved.Result.Summary.Tests != 1 || saved.Result.Summary.Failed != failures {
				t.Fatalf("unverified summary accepted: %+v %+v", job, saved.Result.Summary)
			}
			if err := f.controller.complete(context.Background(), lease.Job, result); err != nil {
				t.Fatalf("identical completion retry: %v", err)
			}
			result.Reason = "different completion"
			if err := f.controller.complete(context.Background(), lease.Job, result); !errors.Is(err, store.ErrConflict) {
				t.Fatalf("changed replay: %v", err)
			}
		})
	}
}

func TestArtifactIntegrityAliasesExpiryAndQuiescentAcknowledgment(t *testing.T) {
	f := newRuntime(t)
	lease := f.lease(t, model.Build)
	result := f.result(t, lease)
	if result.Artifacts[0].ID != result.Artifacts[1].ID {
		t.Fatal("fixture must exercise duplicate digest aliases")
	}
	a := result.Artifacts[0]
	if err := f.controller.putArtifact(context.Background(), lease.Job, a, strings.NewReader("wrong")); !errors.Is(err, evidence.ErrArtifact) {
		t.Fatalf("corrupted retry accepted: %v", err)
	}
	if err := f.controller.complete(context.Background(), lease.Job, result); err != nil {
		t.Fatal(err)
	}
	status, err := f.controller.Status(context.Background())
	if err != nil || status.Quiescent {
		t.Fatalf("unacknowledged completion reported quiet: %+v %v", status, err)
	}
	if _, err := f.db.Pause(context.Background(), "benchmark", "drain", f.now); err != nil {
		t.Fatal(err)
	}
	if lease, err := f.controller.next(context.Background(), "epoch-a"); lease != nil || err != nil {
		t.Fatalf("paused acknowledgment: %v %v", lease, err)
	}
	status, err = f.controller.Status(context.Background())
	if err != nil || !status.Quiescent {
		t.Fatalf("export acknowledgment not quiet: %+v %v", status, err)
	}
	file, metadata, err := f.controller.Artifact(context.Background(), lease.Job.ID, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	if metadata.Name != "evidence/stdout.log" {
		t.Fatalf("unstable alias metadata: %+v", metadata)
	}
	if _, _, err := f.controller.Artifact(context.Background(), lease.Job.ID, "../controller.lock"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("path-shaped artifact ID accepted: %v", err)
	}
	if _, err := f.controller.Receipt(context.Background(), lease.Job.ID); !errors.Is(err, ErrNotReady) {
		t.Fatalf("unsigned completion exposed receipt: %v", err)
	}
	f.offset.Store(int64(8 * 24 * time.Hour))
	if _, _, err := f.controller.Artifact(context.Background(), lease.Job.ID, a.ID); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired artifact returned: %v", err)
	}
	if err := f.controller.sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.controller.options.Root, "artifacts", lease.Job.ID, a.ID)); err != nil {
		t.Fatalf("benchmark pause allowed background GC: %v", err)
	}
	if _, err := f.db.Resume(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := f.controller.sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.controller.options.Root, "artifacts", lease.Job.ID, a.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retained expired artifact: %v", err)
	}
}

func TestCancellationWinsSealRaceAndCleanupFailureQuarantines(t *testing.T) {
	for _, cleanup := range []bool{true, false} {
		t.Run(map[bool]string{true: "cancel", false: "uncertain-cleanup"}[cleanup], func(t *testing.T) {
			f := newRuntime(t)
			lease := f.lease(t, model.Build)
			result := f.result(t, lease)
			result.CleanupOK = cleanup
			f.controller.options.Seal = func(ctx context.Context, job model.Job, value worker.Result) (json.RawMessage, error) {
				if value.State == model.Succeeded {
					if _, err := f.db.Cancel(ctx, job.ID, "operator cancellation", f.now); err != nil {
						return nil, err
					}
				}
				return json.Marshal(struct {
					State model.State `json:"state"`
				}{value.State})
			}
			if err := f.controller.complete(context.Background(), lease.Job, result); err != nil {
				t.Fatal(err)
			}
			job, _ := f.db.Get(context.Background(), lease.Job.ID)
			service, _ := f.db.ServiceState(context.Background())
			want := model.Cancelled
			if !cleanup {
				want = model.Failed
			}
			if job.State != want || service.Quarantined == cleanup {
				t.Fatalf("completion race: %+v %+v", job, service)
			}
			raw, err := f.controller.Receipt(context.Background(), job.ID)
			if err != nil {
				t.Fatal(err)
			}
			var receipt struct {
				State model.State `json:"state"`
			}
			if err := json.Unmarshal(raw, &receipt); err != nil {
				t.Fatal(err)
			}
			if receipt.State != want {
				t.Fatalf("stale success receipt retained: %s", raw)
			}
		})
	}
}

func TestExclusiveRecoveryAndShutdownFenceDeliveredWork(t *testing.T) {
	f := newRuntime(t)
	lease := f.lease(t, model.Build)
	if other, err := New(f.controller.options); err == nil {
		other.Close()
		t.Fatal("second controller acquired live root")
	}
	job, _ := f.db.Get(context.Background(), lease.Job.ID)
	if job.State != model.Preparing {
		t.Fatalf("failed lock attempt recovered live job: %s", job.State)
	}
	if err := f.controller.Close(); err != nil {
		t.Fatal(err)
	}
	job, _ = f.db.Get(context.Background(), lease.Job.ID)
	service, _ := f.db.ServiceState(context.Background())
	if job.State != model.Interrupted || !service.Quarantined {
		t.Fatalf("shutdown did not fence lease: %+v %+v", job, service)
	}
	reopened, err := New(f.controller.options)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.register(context.Background(), protocol.Registration{Epoch: "epoch-a", Quiescent: true}); !errors.Is(err, store.ErrLease) {
		t.Fatalf("old epoch survived restart: %v", err)
	}
	if err := reopened.register(context.Background(), protocol.Registration{Epoch: "epoch-b", Quiescent: true}); err != nil {
		t.Fatal(err)
	}
}

func TestPreparationOutlivesPollAndDoesNotStartHeartbeatClock(t *testing.T) {
	f := newRuntime(t)
	release := make(chan struct{})
	f.source.release = release
	f.source.started = make(chan struct{})
	job := f.enqueue(t, "preparing", model.Build)
	if err := f.controller.register(context.Background(), protocol.Registration{Epoch: "epoch-a", Quiescent: true}); err != nil {
		t.Fatal(err)
	}
	poll, cancel := context.WithCancel(context.Background())
	if lease, err := f.controller.next(poll, "epoch-a"); lease != nil || err != nil {
		t.Fatalf("claim: %v %v", lease, err)
	}
	<-f.source.started
	cancel()
	f.offset.Store(int64(time.Minute))
	f.controller.checkActive(context.Background())
	persisted, err := f.db.Get(context.Background(), job.ID)
	if err != nil || persisted.State != model.Preparing {
		t.Fatalf("poll cancellation/undelivered heartbeat killed export: %+v %v", persisted, err)
	}
	close(release)
	f.controller.prep.Wait()
	lease, err := f.controller.next(context.Background(), "epoch-a")
	if err != nil || lease == nil || lease.Job.ID != job.ID {
		t.Fatalf("export did not survive polling: %v %v", lease, err)
	}
}

func TestPreparationCancellationReleasesOnlyAfterExporterStops(t *testing.T) {
	f := newRuntime(t)
	f.source.release = make(chan struct{})
	f.source.started = make(chan struct{})
	job := f.enqueue(t, "preparing", model.Build)
	if err := f.controller.register(context.Background(), protocol.Registration{Epoch: "epoch-a", Quiescent: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.controller.next(context.Background(), "epoch-a"); err != nil {
		t.Fatal(err)
	}
	<-f.source.started
	if _, err := f.db.Cancel(context.Background(), job.ID, "operator", f.now); err != nil {
		t.Fatal(err)
	}
	f.controller.checkActive(context.Background())
	f.controller.prep.Wait()
	persisted, _ := f.db.Get(context.Background(), job.ID)
	service, _ := f.db.ServiceState(context.Background())
	if persisted.State != model.Cancelled || !persisted.CleanupOK || service.Quarantined {
		t.Fatalf("pre-worker cancellation incorrectly quarantined: %+v %+v", persisted, service)
	}
}

func TestIdleReadinessExpiresWithoutLosingKnownQuiescence(t *testing.T) {
	f := newRuntime(t)
	if err := f.controller.register(context.Background(), protocol.Registration{Epoch: "epoch-a", Quiescent: true}); err != nil {
		t.Fatal(err)
	}
	f.offset.Store(int64(31 * time.Second))
	status, err := f.controller.Status(context.Background())
	if err != nil || status.WorkerReady || !status.Quiescent {
		t.Fatalf("idle readiness did not expire: %+v %v", status, err)
	}
	if _, err := f.controller.next(context.Background(), "epoch-a"); err != nil {
		t.Fatal(err)
	}
	status, err = f.controller.Status(context.Background())
	if err != nil || !status.WorkerReady {
		t.Fatalf("live poll did not restore readiness: %+v %v", status, err)
	}
}

func TestUnverifiedSuccessPredicatesAreDurableFailures(t *testing.T) {
	for _, mutation := range []string{"source", "toolchain", "missing-log", "stored-bytes", "deadline"} {
		t.Run(mutation, func(t *testing.T) {
			f := newRuntime(t)
			lease := f.lease(t, model.Build)
			result := f.result(t, lease)
			switch mutation {
			case "source":
				result.Source.Tree = strings.Repeat("c", 40)
			case "toolchain":
				result.Observation.Xcode.Build = "unapproved"
			case "missing-log":
				result.Artifacts = result.Artifacts[:1]
			case "stored-bytes":
				if err := os.WriteFile(filepath.Join(f.controller.options.Root, "artifacts", lease.Job.ID, result.Artifacts[0].ID), []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "deadline":
				f.offset.Store(int64(601 * time.Second))
			}
			if err := f.controller.complete(context.Background(), lease.Job, result); err != nil {
				t.Fatal(err)
			}
			persisted, _ := f.db.Get(context.Background(), lease.Job.ID)
			want := model.Failed
			if mutation == "deadline" {
				want = model.TimedOut
			}
			if persisted.State != want {
				t.Fatalf("%s accepted: %+v", mutation, persisted)
			}
		})
	}
}

func TestArtifactPoolEvictsOldestTerminalBytesNotActiveOrMetadata(t *testing.T) {
	f := newRuntime(t)
	first := f.lease(t, model.Build)
	result := f.result(t, first)
	old := f.artifact(t, first.Job, "old.bin", []byte("123456"))
	result.Artifacts = append(result.Artifacts, old)
	if err := f.controller.complete(context.Background(), first.Job, result); err != nil {
		t.Fatal(err)
	}
	f.offset.Store(int64(time.Second))
	f.enqueue(t, "second", model.Build)
	if _, err := f.controller.next(context.Background(), "epoch-a"); err != nil {
		t.Fatal(err)
	}
	f.controller.prep.Wait()
	second, err := f.controller.next(context.Background(), "epoch-a")
	if err != nil || second == nil {
		t.Fatalf("second lease: %v %v", second, err)
	}
	active := f.artifact(t, second.Job, "active.bin", []byte("abcdefgh"))
	alias := active
	alias.Name = "same-bytes.bin"
	if err := f.controller.putArtifact(context.Background(), second.Job, alias, strings.NewReader("abcdefgh")); err != nil {
		t.Fatal(err)
	}
	f.controller.evidenceMu.Lock()
	err = f.controller.trimPool(context.Background(), 0, 8)
	f.controller.evidenceMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.controller.Artifact(context.Background(), first.Job.ID, old.ID); !errors.Is(err, ErrExpired) {
		t.Fatalf("evicted bytes not expired: %v", err)
	}
	persisted, err := f.db.Get(context.Background(), first.Job.ID)
	if err != nil || persisted.State != model.Succeeded || len(persisted.Result) == 0 {
		t.Fatalf("pool evicted terminal metadata: %+v %v", persisted, err)
	}
	if info, err := os.Stat(filepath.Join(f.controller.options.Root, "artifacts", second.Job.ID, active.ID)); err != nil || info.Size() != 8 {
		t.Fatalf("pool evicted active bytes: %v %v", info, err)
	}
}

func TestStartupRecoveryInterruptsPersistedLeaseBeforeRegistration(t *testing.T) {
	f := newRuntime(t)
	if err := f.controller.Close(); err != nil {
		t.Fatal(err)
	}
	job := f.enqueue(t, "interrupted", model.Build)
	claimed, err := f.db.Claim(context.Background(), "crashed-epoch", f.now)
	if err != nil || claimed.ID != job.ID {
		t.Fatalf("persisted claim: %v %v", claimed, err)
	}
	recovered, err := New(f.controller.options)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	persisted, _ := f.db.Get(context.Background(), job.ID)
	service, _ := f.db.ServiceState(context.Background())
	if persisted.State != model.Interrupted || !service.Quarantined {
		t.Fatalf("startup resumed uncertain work: %+v %+v", persisted, service)
	}
	if err := recovered.register(context.Background(), protocol.Registration{Epoch: "crashed-epoch", Quiescent: true}); !errors.Is(err, store.ErrLease) {
		t.Fatalf("recovered old epoch: %v", err)
	}
	if err := recovered.register(context.Background(), protocol.Registration{Epoch: "recovered-epoch", Quiescent: true}); err != nil {
		t.Fatal(err)
	}
}

func TestDeadlineQuarantinesEvenWhenWorkerKeepsHeartbeating(t *testing.T) {
	f := newRuntime(t)
	lease := f.lease(t, model.Build)
	f.offset.Store(int64(600*time.Second + f.controller.options.CleanupTimeout + f.controller.options.DeliveryTimeout + f.controller.options.HeartbeatTimeout + time.Second))
	f.controller.mu.Lock()
	f.controller.active.heartbeat = f.controller.options.Now()
	f.controller.mu.Unlock()
	f.controller.checkActive(context.Background())
	persisted, _ := f.db.Get(context.Background(), lease.Job.ID)
	service, _ := f.db.ServiceState(context.Background())
	if persisted.State != model.TimedOut || !service.Quarantined {
		t.Fatalf("heartbeat bypassed execution deadline: %+v %+v", persisted, service)
	}
}

func TestArtifactGetterRejectsSymlinkSubstitution(t *testing.T) {
	f := newRuntime(t)
	lease := f.lease(t, model.Build)
	result := f.result(t, lease)
	if err := f.controller.complete(context.Background(), lease.Job, result); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(target, []byte("not an artifact"), 0600); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(f.controller.options.Root, "artifacts", lease.Job.ID, result.Artifacts[0].ID)
	if err := os.Remove(name); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, name); err != nil {
		t.Fatal(err)
	}
	file, _, err := f.controller.Artifact(context.Background(), lease.Job.ID, result.Artifacts[0].ID)
	if err == nil {
		file.Close()
		t.Fatal("symlink exported a file outside sealed storage")
	}
}

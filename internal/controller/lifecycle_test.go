package controller

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/protocol"
	"github.com/jerryfane/macserve/internal/source"
	"github.com/jerryfane/macserve/internal/store"
)

func lifecycleRequest(t *testing.T, c *Controller, lease protocol.Lease, route string, value any) int {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, protocol.Prefix+"/jobs/"+lease.Job.ID+route, bytes.NewReader(data))
	r = r.WithContext(context.WithValue(r.Context(), peerKey{}, true))
	r.Header.Set(protocol.EpochHeader, lease.Job.WorkerEpoch)
	r.Header.Set(protocol.LeaseHeader, lease.Token)
	w := httptest.NewRecorder()
	c.handler().ServeHTTP(w, r)
	return w.Code
}

func TestCleanupAndDeliveryRetainTerminalEvidence(t *testing.T) {
	for _, cause := range []string{"cancel", "deadline", "finalizing"} {
		t.Run(cause, func(t *testing.T) {
			f := newRuntime(t)
			c := f.controller
			c.options.HeartbeatTimeout = 100 * time.Millisecond
			c.options.CleanupTimeout = 2 * time.Second
			c.options.DeliveryTimeout = 2 * time.Second
			lease := f.lease(t, model.Build)
			start := time.Second
			want := model.Cancelled
			if cause == "deadline" {
				start = lease.Job.Deadline.Sub(f.now)
				want = model.TimedOut
			}
			f.offset.Store(int64(start))
			switch cause {
			case "cancel":
				if _, err := f.db.Cancel(context.Background(), lease.Job.ID, "operator", c.options.Now()); err != nil {
					t.Fatal(err)
				}
			case "finalizing":
				want = model.Succeeded
				if status := lifecycleRequest(t, c, lease, "/stage", protocol.Stage{State: model.Finalizing}); status != http.StatusNoContent {
					t.Fatalf("finalizing stage: %d", status)
				}
			}
			c.checkActive(context.Background())
			// No heartbeats during two seconds of cleanup and most of delivery.
			// This is far beyond the ordinary lost-worker threshold.
			f.offset.Store(int64(start + 3900*time.Millisecond))
			c.checkActive(context.Background())
			job, err := f.db.Get(context.Background(), lease.Job.ID)
			if err != nil || job.State.Terminal() {
				t.Fatalf("live cleanup/delivery fenced: %+v %v", job, err)
			}
			result := f.result(t, lease)
			result.FinishedAt = c.options.Now()
			proof := f.artifact(t, lease.Job, "cleanup.log", []byte("bounded cleanup proof"))
			result.Artifacts = append(result.Artifacts, proof)
			if err := c.complete(context.Background(), lease.Job, result); err != nil {
				t.Fatal(err)
			}
			job, err = f.db.Get(context.Background(), lease.Job.ID)
			if err != nil || job.State != want || !job.CleanupOK {
				t.Fatalf("terminal state: %+v %v", job, err)
			}
			var saved Completion
			if err := json.Unmarshal(job.Result, &saved); err != nil {
				t.Fatal(err)
			}
			if saved.Result.State != want || saved.Result.Artifacts[len(saved.Result.Artifacts)-1].SHA256 != proof.SHA256 {
				t.Fatalf("terminal evidence was discarded: %+v", saved)
			}
			file, _, err := c.Artifact(context.Background(), job.ID, proof.ID)
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(file)
			file.Close()
			if err != nil || string(data) != "bounded cleanup proof" {
				t.Fatalf("cleanup artifact: %q %v", data, err)
			}
			service, err := f.db.ServiceState(context.Background())
			if err != nil || service.Quarantined {
				t.Fatalf("completed cleanup quarantined: %+v %v", service, err)
			}
		})
	}
}

func TestFinalizingHeartbeatsCannotExtendBound(t *testing.T) {
	f := newRuntime(t)
	c := f.controller
	c.options.CleanupTimeout = time.Second
	c.options.DeliveryTimeout = time.Second
	c.options.HeartbeatTimeout = 100 * time.Millisecond
	lease := f.lease(t, model.Build)
	for _, elapsed := range []time.Duration{0, time.Second, 2101 * time.Millisecond} {
		f.offset.Store(int64(elapsed))
		if status := lifecycleRequest(t, c, lease, "/stage", protocol.Stage{State: model.Finalizing}); status != http.StatusNoContent {
			t.Fatalf("stage status %d", status)
		}
		if status := lifecycleRequest(t, c, lease, "/heartbeat", struct{}{}); status != http.StatusOK {
			t.Fatalf("heartbeat status %d", status)
		}
		c.checkActive(context.Background())
	}
	job, err := f.db.Get(context.Background(), lease.Job.ID)
	service, stateErr := f.db.ServiceState(context.Background())
	if err != nil || stateErr != nil || job.State != model.Interrupted || !service.Quarantined {
		t.Fatalf("finalization extended forever: %+v %+v %v %v", job, service, err, stateErr)
	}
}

func TestSourceTransferHasIndependentBoundedWriteBudget(t *testing.T) {
	for _, expires := range []bool{false, true} {
		t.Run(fmt.Sprintf("expires=%t", expires), func(t *testing.T) {
			f := newRuntime(t)
			c := f.controller
			c.options.BrokerUID = uint32(os.Geteuid())
			c.requestTimeout = 20 * time.Millisecond
			lease := f.lease(t, model.Build)
			data := bytes.Repeat([]byte("source transfer bytes\n"), 1<<19)
			if err := os.WriteFile(c.active.source.Path, data, 0600); err != nil {
				t.Fatal(err)
			}
			c.options.SourceTimeout = 3 * time.Second
			c.options.HeartbeatTimeout = 10 * time.Millisecond
			if expires {
				c.options.SourceTimeout = 30 * time.Millisecond
			}
			runUnix(t, c)
			conn, err := net.Dial("unix", c.options.Socket)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := fmt.Fprintf(conn, "GET %s/jobs/%s/source HTTP/1.1\r\nHost: controller\r\n%s: %s\r\n%s: %s\r\nConnection: close\r\n\r\n", protocol.Prefix, lease.Job.ID, protocol.EpochHeader, lease.Job.WorkerEpoch, protocol.LeaseHeader, lease.Token); err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReader(conn)
			response, err := http.ReadResponse(reader, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatalf("source status %d", response.StatusCode)
			}
			// Larger than the socket send buffer: the server must still be writing
			// after the ordinary RPC deadline, without any minute-long sleep.
			time.Sleep(100 * time.Millisecond)
			received, readErr := io.ReadAll(response.Body)
			if expires {
				if readErr == nil || len(received) == len(data) {
					t.Fatalf("source budget did not bound stalled transfer: bytes=%d err=%v", len(received), readErr)
				}
			} else if readErr != nil || sha256.Sum256(received) != sha256.Sum256(data) {
				t.Fatalf("ordinary RPC deadline truncated source: bytes=%d err=%v", len(received), readErr)
			}
		})
	}
}

type retrySource struct {
	*fakeSource
	fail         atomic.Bool
	calls        atomic.Int64
	prepareFails bool
}

func (s *retrySource) Prepare(ctx context.Context, job model.Job) (source.Descriptor, error) {
	descriptor, err := s.fakeSource.Prepare(ctx, job)
	if err == nil && s.prepareFails {
		err = errors.New("source verification failed")
	}
	return descriptor, err
}

func (s *retrySource) Remove(id string) error {
	s.calls.Add(1)
	if s.fail.Load() {
		return errors.New("protected cleanup refused")
	}
	return s.fakeSource.Remove(id)
}

func TestSourceCleanupDebtSurvivesRegistrationAndRestart(t *testing.T) {
	f := newRuntime(t)
	c := f.controller
	provider := &retrySource{fakeSource: f.source}
	provider.fail.Store(true)
	c.options.Source = provider
	lease := f.lease(t, model.Build)
	service, err := f.db.ServiceState(context.Background())
	if err != nil || service.Quarantined {
		t.Fatalf("active source intent blocked its own lease: %+v %v", service, err)
	}
	result := f.result(t, lease)
	if err := c.complete(context.Background(), lease.Job, result); err != nil {
		t.Fatal(err)
	}
	completed, err := f.db.Get(context.Background(), lease.Job.ID)
	if err != nil || completed.State != model.Succeeded || !completed.CleanupOK {
		t.Fatalf("controller debt rewrote worker evidence: %+v %v", completed, err)
	}
	if err := c.register(context.Background(), protocol.Registration{Epoch: "epoch-b", Quiescent: true}); err != nil {
		t.Fatal(err)
	}
	service, err = f.db.ServiceState(context.Background())
	if err != nil || !service.Quarantined {
		t.Fatalf("registration cleared source debt: %+v %v", service, err)
	}
	f.enqueue(t, "waiting", model.Build)
	if _, err := f.db.Claim(context.Background(), "epoch-b", f.now); !errors.Is(err, store.ErrNoJob) {
		t.Fatalf("source debt allowed direct claim: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(c.options)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if provider.calls.Load() != 2 {
		t.Fatalf("restart did not retry terminal source export: %d", provider.calls.Load())
	}
	service, err = f.db.ServiceState(context.Background())
	if err != nil || !service.Quarantined {
		t.Fatalf("restart lost source debt: %+v %v", service, err)
	}
	provider.fail.Store(false)
	if err := reopened.sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	service, err = f.db.ServiceState(context.Background())
	if err != nil || service.Quarantined {
		t.Fatalf("successful retry retained controller quarantine: %+v %v", service, err)
	}
	if _, err := os.Stat(filepath.Join(f.source.directory, lease.Job.ID+".tar")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("source export was not removed: %v", err)
	}
	after, err := f.db.Get(context.Background(), lease.Job.ID)
	if err != nil || !bytes.Equal(after.Result, completed.Result) || after.State != completed.State || after.CleanupOK != completed.CleanupOK {
		t.Fatalf("cleanup retry rewrote terminal evidence: %+v %v", after, err)
	}
}

func TestPreparationCleanupFailureRetiresEpochWithoutWorkerDebt(t *testing.T) {
	f := newRuntime(t)
	provider := &retrySource{fakeSource: f.source, prepareFails: true}
	provider.fail.Store(true)
	c := f.controller
	c.options.Source = provider
	job := f.enqueue(t, "preparation", model.Build)
	if err := c.register(context.Background(), protocol.Registration{Epoch: "epoch-a", Quiescent: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.next(context.Background(), "epoch-a"); err != nil {
		t.Fatal(err)
	}
	c.prep.Wait()
	if _, err := c.next(context.Background(), "epoch-a"); !errors.Is(err, store.ErrLease) {
		t.Fatalf("uncertain preparation epoch kept polling: %v", err)
	}
	if err := c.register(context.Background(), protocol.Registration{Epoch: "epoch-a", Quiescent: true}); !errors.Is(err, store.ErrLease) {
		t.Fatalf("uncertain preparation epoch re-registered: %v", err)
	}
	provider.fail.Store(false)
	if err := c.sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	service, err := f.db.ServiceState(context.Background())
	if err != nil || service.Quarantined {
		t.Fatalf("controller cleanup left spurious worker debt: %+v %v", service, err)
	}
	persisted, err := f.db.Get(context.Background(), job.ID)
	if err != nil || persisted.State != model.Failed || persisted.CleanupOK {
		t.Fatalf("cleanup retry rewrote preparation history: %+v %v", persisted, err)
	}
}

func TestSourceRecoveryCannotClearWorkerUncertainty(t *testing.T) {
	f := newRuntime(t)
	provider := &retrySource{fakeSource: f.source}
	provider.fail.Store(true)
	f.controller.options.Source = provider
	lease := f.lease(t, model.Build)
	result := f.result(t, lease)
	result.CleanupOK = false
	if err := f.controller.complete(context.Background(), lease.Job, result); err != nil {
		t.Fatal(err)
	}
	provider.fail.Store(false)
	if err := f.controller.sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	service, err := f.db.ServiceState(context.Background())
	if err != nil || !service.Quarantined {
		t.Fatalf("source retry acknowledged worker processes: %+v %v", service, err)
	}
	if err := f.controller.register(context.Background(), protocol.Registration{Epoch: "epoch-b", Quiescent: true}); err != nil {
		t.Fatal(err)
	}
	service, err = f.db.ServiceState(context.Background())
	if err != nil || service.Quarantined {
		t.Fatalf("independent worker recovery failed: %+v %v", service, err)
	}
}

func TestRetentionReclaimsUnderDiskPressureButHonorsOwnerPause(t *testing.T) {
	for _, pause := range []string{"none", "service", "marker", "unknown"} {
		t.Run(pause, func(t *testing.T) {
			f := newRuntime(t)
			lease := f.lease(t, model.Build)
			result := f.result(t, lease)
			if err := f.controller.complete(context.Background(), lease.Job, result); err != nil {
				t.Fatal(err)
			}
			f.offset.Store(int64(8 * 24 * time.Hour))
			blockers := []string{"disk_emergency"}
			switch pause {
			case "service":
				if _, err := f.db.Pause(context.Background(), "owner benchmark", "drain", f.controller.options.Now()); err != nil {
					t.Fatal(err)
				}
			case "marker":
				blockers = append(blockers, "owner_pause")
			case "unknown":
				blockers = append(blockers, "isolation_unavailable")
			}
			f.controller.options.Gate = func(context.Context) (GateState, error) {
				return GateState{Blockers: blockers, CancelActive: true}, nil
			}
			if err := f.controller.sweep(context.Background()); err != nil {
				t.Fatal(err)
			}
			_, err := os.Stat(filepath.Join(f.controller.options.Root, "artifacts", lease.Job.ID, result.Artifacts[0].ID))
			if pause == "none" && !errors.Is(err, os.ErrNotExist) || pause != "none" && err != nil {
				t.Fatalf("retention under %s: %v", pause, err)
			}
		})
	}
}

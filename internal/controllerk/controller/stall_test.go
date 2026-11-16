package controller

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/protocol"
	"modernc.org/sqlite"
)

// storeHold, while set, is where a test's stall_hold() trigger function
// blocks the store connection that runs it: it signals entered, then waits
// for release.
var storeHold struct {
	entered chan struct{}
	release chan struct{}
}

func init() {
	sqlite.MustRegisterScalarFunction("stall_hold", 0, func(*sqlite.FunctionContext, []driver.Value) (driver.Value, error) {
		close(storeHold.entered)
		<-storeHold.release
		return nil, nil
	})
}

// holdStore makes f's store connection hold an open write transaction (a log
// append whose trigger blocks) until the returned release is called or the
// test ends.
func holdStore(t *testing.T, f *laneFixture, lease protocol.Lease) (release func()) {
	t.Helper()
	path := filepath.Join(filepath.Dir(f.controller.options.Root), "database", "queue.sqlite")
	other, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := other.Exec("CREATE TRIGGER stall_hold AFTER INSERT ON logs WHEN CAST(NEW.text AS TEXT)='hold' BEGIN SELECT stall_hold(); END"); err != nil {
		t.Fatal(err)
	}
	storeHold.entered, storeHold.release = make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := f.db.AppendLog(context.Background(), lease.Job.ID, lease.Token, "stdout", "hold", f.now)
		done <- err
	}()
	select {
	case <-storeHold.entered:
	case err := <-done:
		t.Fatalf("store hold did not block: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("store hold never started")
	}
	released := false
	release = func() {
		if !released {
			released = true
			close(storeHold.release)
			if err := <-done; err != nil {
				t.Errorf("held append: %v", err)
			}
		}
	}
	t.Cleanup(release)
	return release
}

// promptHeartbeat sends one heartbeat of lease and requires a 200 reply
// within a second.
func promptHeartbeat(t *testing.T, c *Controller, lease protocol.Lease) protocol.Heartbeat {
	t.Helper()
	type reply struct {
		code  int
		value protocol.Heartbeat
		err   error
	}
	replies := make(chan reply, 1)
	go func() {
		r := httptest.NewRequest(http.MethodPost, protocol.Prefix+"/jobs/"+lease.Job.ID+"/heartbeat", strings.NewReader("{}"))
		r = r.WithContext(context.WithValue(r.Context(), peerKey{}, true))
		r.Header.Set(protocol.EpochHeader, lease.Job.WorkerEpoch)
		r.Header.Set(protocol.LeaseHeader, lease.Token)
		w := httptest.NewRecorder()
		c.handler().ServeHTTP(w, r)
		var value protocol.Heartbeat
		err := json.Unmarshal(w.Body.Bytes(), &value)
		replies <- reply{w.Code, value, err}
	}()
	select {
	case got := <-replies:
		if got.code != http.StatusOK || got.err != nil {
			t.Fatalf("heartbeat of %s while the store was held: %d %v", lease.Job.ID, got.code, got.err)
		}
		return got.value
	case <-time.After(time.Second):
		t.Fatalf("heartbeat of %s did not answer within 1s while the store was held", lease.Job.ID)
		return protocol.Heartbeat{}
	}
}

// While another goroutine holds the store's single connection in a write
// transaction for well over 10 s, every heartbeat still answers within a
// second: a live lease is renewed without cancel, and a cancellation
// requested before the hold (and seen by a monitor tick) is still delivered
// (#167).
func TestHeartbeatAnswersWhileStoreHeld(t *testing.T) {
	f := newLanes(t, 2)
	f.enqueue(t, "live", model.Build)
	f.enqueue(t, "cancelled", model.Build)
	f.register(t, "epoch-a", 2)
	live := f.start(t, "epoch-a")
	cancelled := f.start(t, "epoch-a", live.Job.ID)
	if _, err := f.db.Cancel(context.Background(), cancelled.Job.ID, "client cancel", model.CancelReason{Source: model.CancelClient, Principal: "owner"}, f.now); err != nil {
		t.Fatal(err)
	}
	f.controller.checkActive(context.Background())
	release := holdStore(t, f, live)
	held := time.Now()
	for time.Since(held) < 11*time.Second {
		if beat := promptHeartbeat(t, f.controller, live); beat.Cancel || beat.Deadline.IsZero() {
			t.Fatalf("live lease heartbeat during hold: %+v", beat)
		}
		if beat := promptHeartbeat(t, f.controller, cancelled); !beat.Cancel {
			t.Fatalf("cancel requested before the hold was not delivered: %+v", beat)
		}
		time.Sleep(time.Second)
	}
	release()
	// The store answers again: the heartbeat reads the job's record.
	if beat := pulse(t, f.controller, cancelled); !beat.Cancel {
		t.Fatalf("cancel after hold: %+v", beat)
	}
	if code := lifecycleRequest(t, f.controller, live, "/heartbeat", struct{}{}); code != http.StatusOK {
		t.Fatalf("live heartbeat after hold %d", code)
	}
}

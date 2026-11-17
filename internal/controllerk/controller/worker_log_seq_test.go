package controller

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/protocol"
)

// workerLogServer serves c's worker socket handler over HTTP as the
// authenticated worker peer. While lose is set, a /logs request is handled
// in full (committed) but its answer never reaches the client: the server
// waits until the client gives up.
func workerLogServer(t *testing.T, c *Controller, lose *atomic.Bool) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), peerKey{}, true))
		if lose.Load() && strings.HasSuffix(r.URL.Path, "/logs") {
			c.handler().ServeHTTP(httptest.NewRecorder(), r)
			<-r.Context().Done()
			return
		}
		c.handler().ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	return server.URL
}

// postLog sends body as the worker's /logs request of lease, with the
// worker's 10 s request timeout shortened; status 0 is a request that timed
// out.
func postLog(t *testing.T, url string, lease protocol.Lease, body string) int {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, url+protocol.Prefix+"/jobs/"+lease.Job.ID+"/logs", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set(protocol.EpochHeader, lease.Job.WorkerEpoch)
	r.Header.Set(protocol.LeaseHeader, lease.Token)
	resp, err := (&http.Client{Timeout: time.Second}).Do(r)
	if err != nil {
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}

// workerLogText is the job's recorded output, in order.
func workerLogText(t *testing.T, f *laneFixture, lease protocol.Lease) string {
	t.Helper()
	records, _, _, err := f.db.Logs(context.Background(), lease.Job.ID, 0, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	var text bytes.Buffer
	for _, record := range records {
		text.WriteString(record.Text)
	}
	return text.String()
}

// A /logs request that commits but whose answer the worker never gets (its
// request timed out) is resent with the same seq: the controller answers it
// as accepted and records the bytes once (#174).
func TestWorkerLogResentAfterLostAnswerIsRecordedOnce(t *testing.T) {
	f := newLanes(t, 1)
	f.enqueue(t, "job", model.Build)
	f.register(t, "epoch-a", 1)
	lease := f.start(t, "epoch-a")
	var lose atomic.Bool
	lose.Store(true)
	url := workerLogServer(t, f.controller, &lose)
	first := `{"stream":"stdout","data":"b25lCg==","seq":1}` // "one\n"
	if code := postLog(t, url, lease, first); code != 0 {
		t.Fatalf("answer of the lost request reached the worker: %d", code)
	}
	lose.Store(false)
	if code := postLog(t, url, lease, first); code != http.StatusNoContent {
		t.Fatalf("resent seq 1 = %d, want 204", code)
	}
	if code := postLog(t, url, lease, `{"stream":"stdout","data":"dHdvCg==","seq":2}`); code != http.StatusNoContent {
		t.Fatalf("seq 2 = %d, want 204", code)
	}
	if got := workerLogText(t, f, lease); got != "one\ntwo\n" {
		t.Fatalf("recorded logs = %q, want %q", got, "one\ntwo\n")
	}
}

// A seq past the next one is refused (409: output between them was lost)
// and appends nothing; a seq-less log, as a worker from before seq sends,
// still appends unconditionally.
func TestWorkerLogGapRefusedAndSeqlessAppends(t *testing.T) {
	f := newLanes(t, 1)
	f.enqueue(t, "job", model.Build)
	f.register(t, "epoch-a", 1)
	lease := f.start(t, "epoch-a")
	url := workerLogServer(t, f.controller, new(atomic.Bool))
	if code := postLog(t, url, lease, `{"stream":"stdout","data":"b25lCg==","seq":1}`); code != http.StatusNoContent {
		t.Fatalf("seq 1 = %d", code)
	}
	if code := postLog(t, url, lease, `{"stream":"stdout","data":"bG9zdAo=","seq":3}`); code != http.StatusConflict {
		t.Fatalf("gap seq 3 = %d, want 409", code)
	}
	for range 2 {
		if code := postLog(t, url, lease, `{"stream":"stderr","data":"b2xkCg=="}`); code != http.StatusNoContent {
			t.Fatalf("seq-less log = %d", code)
		}
	}
	if got := workerLogText(t, f, lease); got != "one\nold\nold\n" {
		t.Fatalf("recorded logs = %q", got)
	}
}

// A lease offered again (the worker did not get the first answer) starts its
// heartbeat window anew: the worker counts the window from when it asked for
// the lease it received, so the controller never expires it first (#174).
func TestReofferedLeaseRenewsHeartbeatWindow(t *testing.T) {
	f := newLanes(t, 1)
	f.enqueue(t, "job", model.Build)
	f.register(t, "epoch-a", 1)
	f.claim(t, "epoch-a")
	first := f.offer(t, "epoch-a")
	timeout := f.controller.options.HeartbeatTimeout
	f.offset.Store(int64(timeout - time.Second))
	if again := f.offer(t, "epoch-a"); again.Job.ID != first.Job.ID || again.Token != first.Token {
		t.Fatalf("re-offer %s, want %s", again.Job.ID, first.Job.ID)
	}
	f.offset.Store(int64(2*timeout - 2*time.Second))
	f.controller.checkActive(context.Background())
	if job := f.job(t, first.Job.ID); job.State != model.Preparing {
		t.Fatalf("re-offered lease within its window: %s %q", job.State, job.Reason)
	}
	f.offset.Store(int64(2*timeout + time.Second))
	f.controller.checkActive(context.Background())
	if job := f.job(t, first.Job.ID); job.State != model.Interrupted {
		t.Fatalf("re-offered lease past its window: %s %q", job.State, job.Reason)
	}
}

package api

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
)

// A client cancel records the cancelling principal; the cause, like a
// controller-recorded one, appears in the job view and the job list, and a job
// never cancelled has none.
func TestCancelReasonInJobViewAndList(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	queued := f.submit(t, "cancel-me")
	w := perform(f.handler, "POST", "/v1/jobs/"+queued.ID+"/cancel", testToken, "", `{"reason":"superseded by a new push"}`)
	if w.Code != 200 {
		t.Fatalf("cancel %d: %s", w.Code, w.Body.String())
	}
	client := map[string]any{"source": "client", "principal": "coordinator", "at": testTime.Format(time.RFC3339), "detail": "superseded by a new push"}
	if got := decodeView(t, w.Body.Bytes())["cancel_reason"]; !reflect.DeepEqual(got, client) {
		t.Fatalf("cancel response cause: %v", got)
	}

	f.submit(t, "active")
	active, err := f.db.Claim(ctx, "api-test", testTime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Cancel(ctx, active.ID, "host readiness requires cancellation", model.CancelReason{Source: model.CancelHostReadiness, Blockers: []string{"isolation_unavailable", "host_memory_pressure"}}, testTime.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	readiness := map[string]any{"source": "host_readiness", "blockers": []any{"isolation_unavailable", "host_memory_pressure"}, "at": testTime.Add(time.Second).Format(time.RFC3339)}
	untouched := f.submit(t, "untouched")

	want := map[string]any{queued.ID: client, active.ID: readiness, untouched.ID: nil}
	for id, cause := range want {
		w = perform(f.handler, "GET", "/v1/jobs/"+id, testToken, "", "")
		if got, ok := decodeView(t, w.Body.Bytes())["cancel_reason"]; w.Code != 200 || ok != (cause != nil) || cause != nil && !reflect.DeepEqual(got, cause) {
			t.Fatalf("GET %s %d cause: %v", id, w.Code, got)
		}
	}
	w = perform(f.handler, "GET", "/v1/jobs", testToken, "", "")
	var list struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || w.Code != 200 || len(list.Items) != len(want) {
		t.Fatalf("list %d: %s %v", w.Code, w.Body.String(), err)
	}
	for _, item := range list.Items {
		cause := want[item["id"].(string)]
		if got, ok := item["cancel_reason"]; ok != (cause != nil) || cause != nil && !reflect.DeepEqual(got, cause) {
			t.Fatalf("listed %s cause: %v", item["id"], got)
		}
	}
}

func decodeView(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var view map[string]any
	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatalf("job view %s: %v", body, err)
	}
	return view
}

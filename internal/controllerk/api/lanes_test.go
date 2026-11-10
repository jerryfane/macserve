package api

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/jerryfane/macserve/internal/controllerk/controller"
	"github.com/jerryfane/macserve/internal/health"
)

// Agents learn the configured concurrency from capabilities, an administrator
// sees every active job, and a claimed job shows its lane.
func TestLanesReportedByCapabilitiesAdminStateAndJob(t *testing.T) {
	f := setup(t)
	job := f.submit(t, "first")
	claimed, err := f.db.Claim(context.Background(), "epoch", testTime, 2)
	if err != nil || claimed.ID != job.ID {
		t.Fatalf("claim: %+v %v", claimed, err)
	}
	f.options.Status = func(ctx context.Context) (controller.Status, error) {
		s, err := f.db.ServiceState(ctx)
		return controller.Status{Service: s, MaxConcurrentJobs: 2, ActiveJobs: []string{job.ID, "j_other"}, Gate: health.GateState{Ready: true, Blockers: []string{}}}, err
	}
	h, err := New(f.options)
	if err != nil {
		t.Fatal(err)
	}
	w := perform(h, "GET", "/v1/capabilities", testToken, "", "")
	var capabilities struct {
		MaxConcurrentJobs int `json:"max_concurrent_jobs"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &capabilities); w.Code != 200 || err != nil || capabilities.MaxConcurrentJobs != 2 {
		t.Fatalf("capabilities: %d %s", w.Code, w.Body.String())
	}
	w = perform(h, "GET", "/v1/admin/state", testToken, "", "")
	var state struct {
		ActiveJobs        []string `json:"active_jobs"`
		MaxConcurrentJobs int      `json:"max_concurrent_jobs"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &state); w.Code != 200 || err != nil || !slices.Equal(state.ActiveJobs, []string{job.ID, "j_other"}) || state.MaxConcurrentJobs != 2 {
		t.Fatalf("admin state: %d %s", w.Code, w.Body.String())
	}
	w = perform(h, "PUT", "/v1/admin/pause", testToken, "", `{"reason":"benchmark","mode":"drain"}`)
	state.ActiveJobs = nil
	if err := json.Unmarshal(w.Body.Bytes(), &state); w.Code != 200 || err != nil || !slices.Equal(state.ActiveJobs, []string{job.ID, "j_other"}) {
		t.Fatalf("pause: %d %s", w.Code, w.Body.String())
	}
	w = perform(h, "GET", "/v1/jobs/"+job.ID, testToken, "", "")
	var view struct {
		Lane int `json:"lane"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &view); w.Code != 200 || err != nil || view.Lane != 1 {
		t.Fatalf("job view: %d %s", w.Code, w.Body.String())
	}
}

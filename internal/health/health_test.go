package health

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func readyGuard(t *testing.T) (*Guard, *Health, *int64) {
	t.Helper()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	digest := strings.Repeat("a", 64)
	g, err := NewGuard(GuardOptions{Root: "/service/data", HealthFile: "/service/config/health.json", JobUID: 502, OwnerUID: 501, Profiles: map[string]string{"unit": digest}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	h := &Health{Schema: 3, JobUID: 502, BoundaryReceiptSHA256: digest, BoundaryValidated: true, CheckedAt: now, ExpiresAt: now.Add(30 * time.Second), AccountedBytes: 10 << 30, QualifiedProfiles: map[string]string{"unit": digest}}
	h.PersistenceValid = true
	h.PersistenceLastVerified = now
	free := int64(200 << 30)
	g.readHealth = func(string) (Health, error) { return *h, nil }
	g.freeBytes = func(string) (int64, error) { return free, nil }
	return g, h, &free
}
func TestSchema3HealthAdmitsWithoutInterfaceBinding(t *testing.T) {
	g, _, _ := readyGuard(t)
	state, err := g.Check(context.Background())
	if err != nil || !state.Ready || state.CancelActive || len(state.Blockers) != 0 {
		t.Fatalf("fresh qualified health refused: %+v %v", state, err)
	}
}
func TestReadinessRequiresCurrentQualifiedBoundary(t *testing.T) {
	for _, scenario := range []string{"stale", "future", "expiry", "unsigned qualification", "schema 1", "schema 2", "wrong worker", "invalid receipt", "profile changed", "unreadable"} {
		t.Run(scenario, func(t *testing.T) {
			g, h, _ := readyGuard(t)
			switch scenario {
			case "stale":
				h.CheckedAt = h.CheckedAt.Add(-time.Minute)
			case "future":
				h.CheckedAt = h.CheckedAt.Add(time.Minute)
			case "expiry":
				h.ExpiresAt = h.CheckedAt
			case "unsigned qualification":
				h.BoundaryValidated = false
			case "schema 1":
				h.Schema = 1
			case "schema 2":
				h.Schema = 2
			case "wrong worker":
				h.JobUID = 503
			case "invalid receipt":
				h.BoundaryReceiptSHA256 = ""
			case "profile changed":
				h.QualifiedProfiles["unit"] = strings.Repeat("b", 64)
			case "unreadable":
				g.readHealth = func(string) (Health, error) { return Health{}, errors.New("denied") }
			}
			state, err := g.Check(context.Background())
			if err != nil || state.Ready || !state.CancelActive {
				t.Fatalf("unsafe boundary admitted: %+v %v", state, err)
			}
		})
	}
}
func TestPersistenceAttestationPausesAdmission(t *testing.T) {
	for _, scenario := range []string{"missing", "revoked", "review", "future"} {
		t.Run(scenario, func(t *testing.T) {
			g, h, _ := readyGuard(t)
			switch scenario {
			case "missing":
				h.PersistenceLastVerified = time.Time{}
			case "revoked":
				h.PersistenceValid = false
			case "review":
				h.PersistenceNeedsReview = true
			case "future":
				h.PersistenceLastVerified = h.CheckedAt.Add(time.Minute)
			}
			state, err := g.Check(context.Background())
			if err != nil || state.Ready || state.CancelActive {
				t.Fatalf("attestation must pause admission without cancelling a job: %+v %v", state, err)
			}
		})
	}
}

// A worker that keeps refusing admission because a child of a tolerated launch
// persists is reported in admin state, without cancelling work.
func TestAdmissionInconclusiveHealthBlocksWithReason(t *testing.T) {
	g, h, _ := readyGuard(t)
	h.AdmissionInconclusive = "a child process of a tolerated launchd service outlived the admission wait; retry admission"
	state, err := g.Check(context.Background())
	if err != nil || state.Ready || state.CancelActive || len(state.Blockers) != 1 || state.Blockers[0] != "worker_admission_inconclusive" {
		t.Fatalf("inconclusive admission not reported: %+v %v", state, err)
	}
	h.AdmissionInconclusive = ""
	if state, err := g.Check(context.Background()); err != nil || !state.Ready {
		t.Fatalf("cleared record still blocks: %+v %v", state, err)
	}
}
func TestDiskReservationAndEmergencyHaveDifferentCancellationSemantics(t *testing.T) {
	g, h, free := readyGuard(t)
	for _, tc := range []struct {
		free, used    int64
		ready, cancel bool
	}{{150 << 30, 50 << 30, true, false}, {(150 << 30) - 1, 50 << 30, false, false}, {100 << 30, 50 << 30, false, false}, {(100 << 30) - 1, 50 << 30, false, true}, {200 << 30, 51 << 30, false, false}, {200 << 30, 81 << 30, false, true}} {
		*free = tc.free
		h.AccountedBytes = tc.used
		state, err := g.Check(context.Background())
		if err != nil || state.Ready != tc.ready || state.CancelActive != tc.cancel {
			t.Fatalf("free=%d used=%d: %+v %v", tc.free, tc.used, state, err)
		}
	}
}

// The service budget is 50 + 30·lanes GiB (170 GiB at four lanes, 230 at
// six), and the last lane is claimed only with 120 + 30·lanes GiB free and at
// most 50 GiB accounted. Seven lanes is refused.
func TestDiskBudgetAtFourAndSixLanes(t *testing.T) {
	for _, tc := range []struct {
		lanes        int
		budget, free int64
	}{{4, 170 << 30, 240 << 30}, {6, 230 << 30, 300 << 30}} {
		g, h, free := readyGuard(t)
		options := g.options
		options.Lanes = tc.lanes
		configured, err := NewGuard(options)
		if err != nil {
			t.Fatalf("%d lanes refused: %v", tc.lanes, err)
		}
		configured.readHealth, configured.freeBytes = g.readHealth, g.freeBytes
		if got := ServiceBudget(tc.lanes); got != tc.budget {
			t.Fatalf("%d lanes: budget %d GiB", tc.lanes, got>>30)
		}
		check := func(freeBytes, used int64) GateState {
			*free, h.AccountedBytes = freeBytes, used
			state, err := configured.Check(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			return state
		}
		if state := check(tc.free, tc.budget-JobReservationBytes); !state.Ready {
			t.Fatalf("%d lanes: one reservation left refused: %+v", tc.lanes, state)
		}
		if state := check(tc.free, tc.budget-JobReservationBytes+1); state.Ready || state.CancelActive {
			t.Fatalf("%d lanes: no reservation left: %+v", tc.lanes, state)
		}
		if state := check(tc.free, tc.budget+1); !state.CancelActive {
			t.Fatalf("%d lanes: over budget did not cancel: %+v", tc.lanes, state)
		}
		last := tc.lanes - 1
		if state := check(tc.free, 50<<30); !AdmitsAnother(state, last, tc.lanes) {
			t.Fatalf("%d lanes: last lane refused at %d GiB free, 50 GiB accounted", tc.lanes, tc.free>>30)
		}
		if state := check(tc.free-1, 50<<30); AdmitsAnother(state, last, tc.lanes) {
			t.Fatalf("%d lanes: last lane admitted below %d GiB free", tc.lanes, tc.free>>30)
		}
		if state := check(tc.free, 50<<30+1); AdmitsAnother(state, last, tc.lanes) {
			t.Fatalf("%d lanes: last lane admitted above 50 GiB accounted", tc.lanes)
		}
	}
	g, _, _ := readyGuard(t)
	options := g.options
	options.Lanes = 7
	if _, err := NewGuard(options); err == nil {
		t.Fatal("seven lanes accepted")
	}
}
func TestOwnerPauseDoesNotCancelDrainingWork(t *testing.T) {
	g, h, _ := readyGuard(t)
	g.options.PauseFile = "/service/control/pause"
	g.pause = func(string, uint32) (bool, error) { return true, nil }
	state, err := g.Check(context.Background())
	if err != nil || state.Ready || state.CancelActive {
		t.Fatalf("pause did not drain: %+v %v", state, err)
	}
	g.options.PauseFile = ""
	h.MemoryPressure = true
	state, err = g.Check(context.Background())
	if err != nil || state.Ready || state.CancelActive {
		t.Fatalf("memory pressure did not stop admission: %+v %v", state, err)
	}
}

// withProbeFailures sets the published probe_failures count the way the
// controller reads it, from the record's JSON.
func withProbeFailures(t *testing.T, h *Health, failures int) {
	t.Helper()
	if err := json.Unmarshal([]byte(`{"probe_failures":`+strconv.Itoa(failures)+`}`), h); err != nil {
		t.Fatal(err)
	}
}

// Maintenance republishes the last valid health with the count of probes that
// failed without evidence since (#53). Each blocks admission; none cancels
// active work while that health is in force: its expiry does. Two lanes
// booting simulators made three probes in a row time out 9 s before the
// last valid health expired, and the third cancelled both jobs although the
// next probe passed (Studio v0.1.47, 2026-11-12 12:28Z).
func TestProbeFailuresBlockAdmissionOnly(t *testing.T) {
	for failures, cancel := range map[int]bool{1: false, 2: false, 3: false, 4: false} {
		g, h, _ := readyGuard(t)
		withProbeFailures(t, h, failures)
		state, err := g.Check(context.Background())
		if err != nil || state.Ready || state.CancelActive != cancel || state.CapacityOnly || !reflect.DeepEqual(state.Blockers, []string{"maintenance_probe_failed"}) {
			t.Fatalf("%d failed probes: %+v %v", failures, state, err)
		}
		// The controller names the count in its log and the cancel reason.
		if data, _ := json.Marshal(state); !strings.Contains(string(data), `"probe_failures":`+strconv.Itoa(failures)) {
			t.Fatalf("%d failed probes: gate state %s lacks the count", failures, data)
		}
	}
	g, h, _ := readyGuard(t)
	withProbeFailures(t, h, -1)
	if state, err := g.Check(context.Background()); err != nil || state.Ready || !state.CancelActive {
		t.Fatalf("negative probe failure count admitted: %+v %v", state, err)
	}
}

// Guard (passes before #53 by design): the count never extends health. A
// republished last valid health is judged on its own timestamps, so once it
// expires or goes stale (a maintenance daemon that stopped publishing) active
// work is cancelled whatever the count; a finding published with it still
// cancels at once.
func TestProbeFailuresNeverOutliveLastValidHealth(t *testing.T) {
	for name, edit := range map[string]func(*Health){
		"expired": func(h *Health) { h.ExpiresAt = h.CheckedAt },
		"stale": func(h *Health) {
			h.CheckedAt = h.CheckedAt.Add(-time.Minute)
			h.ExpiresAt = h.CheckedAt.Add(30 * time.Second)
		},
		"invalid":         func(h *Health) { h.BoundaryValidated = false },
		"profile changed": func(h *Health) { h.QualifiedProfiles = map[string]string{"unit": strings.Repeat("b", 64)} },
	} {
		g, h, _ := readyGuard(t)
		withProbeFailures(t, h, 1)
		edit(h)
		if state, err := g.Check(context.Background()); err != nil || state.Ready || !state.CancelActive {
			t.Fatalf("%s health with one failed probe kept work: %+v %v", name, state, err)
		}
	}
}

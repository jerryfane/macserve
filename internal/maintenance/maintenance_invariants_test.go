package maintenance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/health"
)

// This file is class B in BOUNDARY.json. It pins the invariants that health
// timing and the run loop (run.go, timing.go) must keep whatever their
// tuning: a published record never outlives the controller's acceptance
// window, an inconclusive probe never refreshes or fabricates valid facts,
// never admits and never carries them past the probe outage bound, and no
// boundary fact can be dropped from Evaluate.

// controllerAcceptance is the lifetime bound in internal/controller/guards.go.
const controllerAcceptance = 45 * time.Second

func TestMaintenanceInvariantsHealthLifetime(t *testing.T) {
	if healthLifetime <= 0 || healthLifetime > controllerAcceptance {
		t.Fatalf("healthLifetime %v outside (0, %v]", healthLifetime, controllerAcceptance)
	}
	now, q, e, o := approvedFixture()
	h, err := Evaluate(now, q, e, o)
	if err != nil || !h.BoundaryValidated {
		t.Fatalf("approved fixture: %+v %v", h, err)
	}
	if !h.CheckedAt.Equal(now) || h.ExpiresAt.Sub(h.CheckedAt) != healthLifetime {
		t.Fatalf("published lifetime %v, want %v from %v", h.ExpiresAt.Sub(h.CheckedAt), healthLifetime, now)
	}
}

func TestMaintenanceInvariantsKeepLastValid(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	valid := health.Health{BoundaryValidated: true, CheckedAt: now.Add(-10 * time.Second), ExpiresAt: now.Add(30 * time.Second)}
	inconclusive := []error{
		context.DeadlineExceeded,
		fmt.Errorf("census: %w", context.DeadlineExceeded),
		fmt.Errorf("census: %w", errAcceptedMountChanged),
	}
	findings := []error{
		nil,
		context.Canceled,
		errors.New("context deadline exceeded"),
		errors.New(errAcceptedMountChanged.Error()),
		errors.New("GUI baseline process changed"),
		fmt.Errorf("persistence: %w", errors.New("inspection_unavailable")),
	}
	for _, err := range inconclusive {
		if !keepLastValid(err, valid, now) {
			t.Errorf("%v: inconclusive probe replaced valid health", err)
		}
		for name, last := range map[string]health.Health{
			"none":         {},
			"invalid":      {ExpiresAt: valid.ExpiresAt, CheckedAt: valid.CheckedAt},
			"zero expires": {BoundaryValidated: true, CheckedAt: now},
			"from future":  {BoundaryValidated: true, CheckedAt: now.Add(time.Second), ExpiresAt: now.Add(41 * time.Second)},
		} {
			if keepLastValid(err, last, now) {
				t.Errorf("%v: kept %s health", err, name)
			}
		}
	}
	for _, err := range findings {
		if keepLastValid(err, valid, now) {
			t.Errorf("%v: finding kept last valid health", err)
		}
	}
}

// A record published while probes fail without evidence carries the last
// valid health's facts exactly (last_valid_at names their check), blocks
// admission without cancelling, has its own lifetime within the acceptance
// window, never expires after the end of the probe outage bound, and is
// replaced by invalid health once that bound has passed.
func TestMaintenanceInvariantsCarriedRecord(t *testing.T) {
	start, q, e, o := approvedFixture()
	last, err := Evaluate(start, q, e, o)
	if err != nil {
		t.Fatal(err)
	}
	facts := func(h health.Health) map[string]any {
		data, _ := json.Marshal(h)
		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	want := facts(last)
	var r probeRecord
	r.publication(last, nil, start)
	for at := 10 * time.Second; at <= documentedProbeOutage+time.Minute; at += 10 * time.Second {
		now := start.Add(at)
		h := r.publication(health.Health{}, context.DeadlineExceeded, now)
		if at >= documentedProbeOutage {
			if h.BoundaryValidated {
				t.Fatalf("+%v: facts carried past the probe outage bound", at)
			}
			continue
		}
		got := facts(h)
		if got["last_valid_at"] != want["checked_at"] || !h.CheckedAt.Equal(now) || h.ProbeFailures != int(at/(10*time.Second)) {
			t.Fatalf("+%v: carried record %v, want checked now with last_valid_at %v", at, got, want["checked_at"])
		}
		for _, k := range []string{"checked_at", "expires_at", "probe_failures", "last_valid_at"} {
			delete(got, k)
		}
		kept := maps.Clone(want)
		delete(kept, "checked_at")
		delete(kept, "expires_at")
		if !reflect.DeepEqual(got, kept) {
			t.Fatalf("+%v: carried facts %v, want %v", at, got, kept)
		}
		if life := h.ExpiresAt.Sub(h.CheckedAt); life <= 0 || life > healthLifetime || h.ExpiresAt.After(last.CheckedAt.Add(documentedProbeOutage)) {
			t.Fatalf("+%v: carried record expires %v", at, h.ExpiresAt)
		}
		var names []string
		for _, b := range health.HealthBlockers(h, now, o.JobUID, o.Profiles, 1) {
			names = append(names, b.Name)
			if b.Cancel {
				t.Fatalf("+%v: carried record cancels (%s)", at, b.Name)
			}
		}
		if !reflect.DeepEqual(names, []string{"maintenance_probe_failed"}) {
			t.Fatalf("+%v: carried record blockers %v", at, names)
		}
	}
}

// TestMaintenanceInvariantsEvaluateRequiresEveryFact removes one boundary
// fact at a time from the approved fixture; each removal must publish
// invalid health within the acceptance window.
func TestMaintenanceInvariantsEvaluateRequiresEveryFact(t *testing.T) {
	removals := map[string]func(*Qualification, *BoundaryEvidence, *Observation){
		"persistence not valid":    func(_ *Qualification, _ *BoundaryEvidence, o *Observation) { o.Persistence.Valid = false },
		"persistence needs review": func(_ *Qualification, _ *BoundaryEvidence, o *Observation) { o.Persistence.NeedsReview = true },
		"persistence revoked": func(_ *Qualification, _ *BoundaryEvidence, o *Observation) {
			o.Persistence.RevokedAt = o.Persistence.LastVerified
		},
		"persistence never verified": func(_ *Qualification, _ *BoundaryEvidence, o *Observation) { o.Persistence.LastVerified = time.Time{} },
		"identity":                   func(_ *Qualification, _ *BoundaryEvidence, o *Observation) { o.IdentityValid = false },
		"baseline":                   func(_ *Qualification, _ *BoundaryEvidence, o *Observation) { o.BaselineValid = false },
		"console":                    func(_ *Qualification, _ *BoundaryEvidence, o *Observation) { o.ConsoleAdmissible = false },
		"accounting":                 func(_ *Qualification, _ *BoundaryEvidence, o *Observation) { o.AccountedBytes = -1 },
		"boot":                       func(_ *Qualification, _ *BoundaryEvidence, o *Observation) { o.Boot = "" },
		"baseline digest":            func(_ *Qualification, _ *BoundaryEvidence, o *Observation) { o.BaselineSHA256 = "" },
		"evidence digest":            func(_ *Qualification, _ *BoundaryEvidence, o *Observation) { o.BoundaryEvidenceSHA256 = "" },
		"live coexistence":           func(_ *Qualification, _ *BoundaryEvidence, o *Observation) { o.Coexistence = nil },
		"recorded coexistence":       func(_ *Qualification, e *BoundaryEvidence, _ *Observation) { e.Coexistence = nil },
		"profiles":                   func(_ *Qualification, _ *BoundaryEvidence, o *Observation) { o.Profiles = nil },
		"job uid":                    func(_ *Qualification, _ *BoundaryEvidence, o *Observation) { o.JobUID = 0 },
		"qualification schema":       func(q *Qualification, _ *BoundaryEvidence, _ *Observation) { q.Schema = 0 },
		"approval time":              func(q *Qualification, _ *BoundaryEvidence, _ *Observation) { q.ApprovedAt = time.Time{} },
		"evidence schema":            func(_ *Qualification, e *BoundaryEvidence, _ *Observation) { e.Schema = 0 },
		"evidence boot":              func(_ *Qualification, e *BoundaryEvidence, _ *Observation) { e.Boot = "" },
	}
	for _, category := range Categories {
		removals["probe "+category] = func(_ *Qualification, e *BoundaryEvidence, _ *Observation) {
			kept := e.Probes[:0]
			for _, p := range e.Probes {
				if p.Category != category {
					kept = append(kept, p)
				}
			}
			e.Probes = kept
		}
	}
	for name, remove := range removals {
		t.Run(name, func(t *testing.T) {
			now, q, e, o := approvedFixture()
			remove(&q, &e, &o)
			h, err := Evaluate(now, q, e, o)
			if err == nil || h.BoundaryValidated || h.AccountedBytes != -1 || !h.MemoryPressure {
				t.Fatalf("health without %s: %+v %v", name, h, err)
			}
			if h.ExpiresAt.Sub(h.CheckedAt) > controllerAcceptance {
				t.Fatalf("invalid health lifetime %v", h.ExpiresAt.Sub(h.CheckedAt))
			}
		})
	}
}

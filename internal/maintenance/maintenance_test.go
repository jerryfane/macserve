package maintenance

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func approvedFixture() (time.Time, Qualification, BoundaryEvidence, Observation) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	d := digest([]byte("approved"))
	o := Observation{JobUID: 550, Boot: d, InterfacesSHA256: d, BaselineSHA256: d, BoundaryEvidenceSHA256: d, Profiles: map[string]string{"build": d}, IdentityValid: true, BaselineValid: true, AccountedBytes: 1234}
	q := Qualification{Schema: 2, ApprovedAt: now, JobUID: o.JobUID, Boot: d, InterfacesSHA256: d, BaselineSHA256: d, BoundaryEvidenceSHA256: d, Profiles: map[string]string{"build": d}}
	e := BoundaryEvidence{Schema: 2, RecordedAt: now.Add(-time.Minute), JobUID: o.JobUID, Boot: d}
	before := CoexistenceState{RecordedAt: now.Add(-2 * time.Minute), MainRulesStatus: "available", MainRulesSHA256: d}
	after := before
	after.RecordedAt = e.RecordedAt
	current := after
	current.RecordedAt = now
	o.Coexistence = &current
	e.Coexistence = &CoexistenceEvidence{Before: before, After: after}
	e.Probes = append(e.Probes, Probe{Category: "network_reachability", ArtifactSHA256: d, Status: "not enforced in phase 1"})
	for _, category := range []string{"unix_socket_boundary", "owner_unaffected", "fast_switch", "reboot", "tool_profiles", "owner_home_denial"} {
		e.Probes = append(e.Probes, Probe{Category: category, ArtifactSHA256: d, Status: "passed", Attempts: 3, AuthorizedControlSuccesses: 3})
	}
	return now, q, e, o
}
func TestQualificationInvalidatesChangedLiveFacts(t *testing.T) {
	mutations := map[string]func(*Observation){
		"boot":             func(o *Observation) { o.Boot = digest([]byte("new boot")) },
		"interfaces":       func(o *Observation) { o.InterfacesSHA256 = digest([]byte("new address")) },
		"baseline":         func(o *Observation) { o.BaselineSHA256 = digest([]byte("new baseline")) },
		"evidence":         func(o *Observation) { o.BoundaryEvidenceSHA256 = digest([]byte("new evidence")) },
		"profile":          func(o *Observation) { o.Profiles["build"] = digest([]byte("new recipe")) },
		"identity":         func(o *Observation) { o.IdentityValid = false },
		"baseline invalid": func(o *Observation) { o.BaselineValid = false },
		"accounting":       func(o *Observation) { o.AccountedBytes = -1 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			now, q, e, o := approvedFixture()
			h, err := Evaluate(now, q, e, o)
			if err != nil || !h.BoundaryValidated || h.AccountedBytes != 1234 {
				t.Fatalf("valid approval: %+v %v", h, err)
			}
			mutate(&o)
			h, err = Evaluate(now, q, e, o)
			if err == nil || h.BoundaryValidated || h.AccountedBytes != -1 || !h.MemoryPressure {
				t.Fatalf("uncertain observation published success: %+v %v", h, err)
			}
		})
	}
}
func TestQualificationRefusesPostApprovalServiceRestart(t *testing.T) {
	now, q, evidence, observation := approvedFixture()
	for _, state := range []*CoexistenceState{&evidence.Coexistence.Before, &evidence.Coexistence.After, observation.Coexistence} {
		state.Services = []ServicePID{{Label: "com.example.guest-router", PID: 123}}
	}
	if _, err := Evaluate(now, q, evidence, observation); err != nil {
		t.Fatal(err)
	}
	observation.Coexistence.Services[0].PID = 124
	health, err := Evaluate(now, q, evidence, observation)
	if err == nil || health.BoundaryValidated || health.AccountedBytes != -1 {
		t.Fatalf("restarted peer retained qualified health: %+v %v", health, err)
	}
}
func TestEvidenceRequiresActualProbeAttestationFields(t *testing.T) {
	for name, mutate := range map[string]func(*BoundaryEvidence){
		"missing category":          func(e *BoundaryEvidence) { e.Probes = e.Probes[1:] },
		"duplicate":                 func(e *BoundaryEvidence) { e.Probes = append(e.Probes, e.Probes[0]) },
		"wrong boot":                func(e *BoundaryEvidence) { e.Boot = digest([]byte("old")) },
		"future record":             func(e *BoundaryEvidence) { e.RecordedAt = e.RecordedAt.Add(time.Hour) },
		"socket failed":             func(e *BoundaryEvidence) { e.Probes[1].Status = "failed" },
		"network enforcement claim": func(e *BoundaryEvidence) { e.Probes[0].Status = "passed" },
	} {
		t.Run(name, func(t *testing.T) {
			now, q, e, o := approvedFixture()
			mutate(&e)
			h, err := Evaluate(now, q, e, o)
			if err == nil || h.BoundaryValidated {
				t.Fatal("invalid evidence admitted")
			}
		})
	}
}

func TestOwnerHomeDenialRequiredForQualification(t *testing.T) {
	for _, mode := range []string{"missing", "readable", "no-owner-control", "failed", "denied"} {
		t.Run(mode, func(t *testing.T) {
			now, q, e, o := approvedFixture()
			probe := &e.Probes[len(e.Probes)-1]
			switch mode {
			case "missing":
				e.Probes = e.Probes[:len(e.Probes)-1]
			case "readable":
				probe.CanaryReceipts = 1
			case "no-owner-control":
				probe.AuthorizedControlSuccesses = 0
			case "failed":
				probe.Status = "failed"
			}
			h, err := Evaluate(now, q, e, o)
			if (err == nil) != (mode == "denied") || h.BoundaryValidated != (mode == "denied") {
				t.Fatalf("owner home %s: health=%+v error=%v", mode, h, err)
			}
		})
	}
}
func TestMutableAccountingDoesNotFollowLinksOrDoubleCountRoots(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(root, "Library")
	if err = os.Mkdir(nested, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(nested, "cache"), make([]byte, 8192), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink("/nonexistent-outside-accounted-tree", filepath.Join(nested, "outside")); err != nil {
		t.Fatal(err)
	}
	before, err := accountBytes(context.Background(), []string{root})
	if err != nil {
		t.Fatal(err)
	}
	after, err := accountBytes(context.Background(), []string{root, nested})
	if err != nil || after != before || after < 8192 {
		t.Fatalf("overlap count %d %d: %v", before, after, err)
	}
	if _, err = accountBytes(context.Background(), []string{filepath.Join(nested, "outside")}); err == nil {
		t.Fatal("symlink mutable root accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if n, err := accountBytes(ctx, []string{root}); err == nil || n != -1 {
		t.Fatalf("canceled census trusted: %d %v", n, err)
	}
}
func TestInspectRejectsUnloadedConfigWithoutHostProbes(t *testing.T) {
	if _, err := Inspect(context.Background(), Config{}); err == nil {
		t.Fatal("unloaded config admitted")
	}
}

func TestHealthDoesNotGateOnCurrentPFOrNetworkOutcome(t *testing.T) {
	for _, status := range []string{"available", "unavailable"} {
		now, q, e, o := approvedFixture()
		o.Coexistence.MainRulesStatus = status
		o.Coexistence.MainRulesSHA256 = ""
		if status == "available" {
			o.Coexistence.MainRulesSHA256 = digest([]byte("changed since qualification"))
		}
		e.Probes[0].CanaryReceipts = 20
		h, err := Evaluate(now, q, e, o)
		if err != nil || !h.BoundaryValidated || h.Schema != 2 {
			t.Fatalf("informational facts gated health: %+v %v", h, err)
		}
	}
}

func TestOldQualificationSchemasRejected(t *testing.T) {
	for _, qualification := range []bool{false, true} {
		now, q, e, o := approvedFixture()
		if qualification {
			q.Schema = 1
		} else {
			e.Schema = 1
		}
		if h, err := Evaluate(now, q, e, o); err == nil || h.BoundaryValidated {
			t.Fatal("old schema admitted")
		}
	}
}

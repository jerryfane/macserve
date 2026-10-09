package qualification

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/maintenance"
	"github.com/jerryfane/macserve/internal/pfctl"
)

func firewallState(at time.Time) maintenance.CoexistenceState {
	d := strings.Repeat("a", 64)
	return maintenance.CoexistenceState{RecordedAt: at, MainRulesSHA256: d,
		Anchors:  []maintenance.AnchorRulesDigest{{Path: "com.apple/guest-router", FilterSHA256: d, TranslationSHA256: d}},
		Services: []maintenance.ServicePID{{Label: "com.example.guest-router", PID: 123}}}
}

func TestFirewallStepPreservesEvidenceAndRefusesDrift(t *testing.T) {
	for _, scenario := range []string{"unchanged", "main", "peer-filter", "peer-translation", "service-restart", "load-error", "after-error"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
			before, after := firewallState(now), firewallState(now.Add(time.Second))
			switch scenario {
			case "main":
				after.MainRulesSHA256 = strings.Repeat("b", 64)
			case "peer-filter":
				after.Anchors[0].FilterSHA256 = strings.Repeat("b", 64)
			case "peer-translation":
				after.Anchors[0].TranslationSHA256 = strings.Repeat("b", 64)
			case "service-restart":
				after.Services[0].PID++
			}
			observations, loads := 0, 0
			observe := func(context.Context) (maintenance.CoexistenceState, error) {
				observations++
				if observations == 1 {
					return before, nil
				}
				if scenario == "after-error" {
					return after, errors.New("observer failed")
				}
				return after, nil
			}
			load := func(_ context.Context, path string) (pfctl.Output, error) {
				loads++
				// This durable baseline must exist before any mutation is possible.
				raw, err := os.ReadFile(filepath.Join(dir, "firewall-before.json"))
				if err != nil {
					t.Fatal(err)
				}
				var saved maintenance.CoexistenceState
				if err := decode(raw, &saved); err != nil {
					t.Fatal(err)
				}
				if saved.MainRulesSHA256 != before.MainRulesSHA256 || saved.Services[0].PID != 123 {
					t.Fatal("wrong pre-mutation baseline")
				}
				if path != filepath.Join(dir, firewallPolicyFile) {
					t.Fatalf("wrong load source: %s", path)
				}
				if scenario == "load-error" {
					return pfctl.Output{Stderr: "load refused"}, errors.New("load refused")
				}
				return pfctl.Output{}, nil
			}
			step, raw, err := runFirewallStep(context.Background(), dir, maintenance.DefaultPFAnchor, strings.Repeat("c", 64), observe, load)
			if (err == nil) != (scenario == "unchanged") {
				t.Fatalf("unexpected result: %v", err)
			}
			if loads != 1 || observations != 2 {
				t.Fatalf("loads=%d observations=%d: missing after-capture or attempted rollback", loads, observations)
			}
			preserved, err := os.ReadFile(filepath.Join(dir, firewallStepFile))
			if err != nil {
				t.Fatal(err)
			}
			if string(preserved) != string(raw) {
				t.Fatal("step artifact not preserved exactly")
			}
			var record firewallStepRecord
			if err := decode(raw, &record); err != nil {
				t.Fatal(err)
			}
			if (record.Error == "") != (scenario == "unchanged") {
				t.Fatalf("wrong recorded outcome: %q", record.Error)
			}
			if !step.AfterQualification.RecordedAt.IsZero() {
				t.Fatal("firewall step fabricated post-qualification evidence")
			}
			if scenario == "unchanged" {
				current := maintenance.Observation{PFAnchor: step.OwnedAnchor, PolicySHA256: step.PolicySHA256}
				final := firewallState(now.Add(2 * time.Second))
				current.Coexistence = &final
				completed, err := finalizeCoexistence(step, current)
				if err != nil || completed.AfterQualification.Services[0].PID != 123 {
					t.Fatalf("finalization: %v", err)
				}
				final.Services[0].PID++
				if _, err := finalizeCoexistence(step, current); err == nil {
					t.Fatal("post-qualification service restart accepted")
				}
			}
		})
	}
}

func TestFirewallStepNeverLoadsWithoutDurableBaseline(t *testing.T) {
	for _, scenario := range []string{"observation-error", "invalid-state", "existing-baseline"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			if scenario == "existing-baseline" {
				if err := os.WriteFile(filepath.Join(dir, "firewall-before.json"), []byte("preserve me"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			observe := func(context.Context) (maintenance.CoexistenceState, error) {
				if scenario == "observation-error" {
					return maintenance.CoexistenceState{}, errors.New("unavailable")
				}
				if scenario == "invalid-state" {
					return maintenance.CoexistenceState{}, nil
				}
				return firewallState(time.Now()), nil
			}
			_, _, err := runFirewallStep(context.Background(), dir, maintenance.DefaultPFAnchor, strings.Repeat("a", 64), observe,
				func(context.Context, string) (pfctl.Output, error) {
					t.Fatal("loaded without durable baseline")
					return pfctl.Output{}, nil
				})
			if err == nil {
				t.Fatal("unsafe firewall step accepted")
			}
		})
	}
}

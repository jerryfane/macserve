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
	o := Observation{JobUID: 550, Boot: d, InterfacesSHA256: d, PolicySHA256: d, RootRulesSHA256: d, AnchorRulesSHA256: d, BaselineSHA256: d, BoundaryEvidenceSHA256: d, Profiles: map[string]string{"build": d}, PFEnabled: true, LoopbackFiltered: true, IdentityValid: true, BaselineValid: true, AccountedBytes: 1234}
	q := Qualification{Schema: 1, ApprovedAt: now, JobUID: o.JobUID, Boot: d, InterfacesSHA256: d, PolicySHA256: d, RootRulesSHA256: d, AnchorRulesSHA256: d, BaselineSHA256: d, BoundaryEvidenceSHA256: d, Profiles: map[string]string{"build": d}}
	e := BoundaryEvidence{Schema: 1, RecordedAt: now.Add(-time.Minute), JobUID: o.JobUID, Boot: d}
	for _, category := range []string{"tcp_denial", "udp_denial", "approved_allow", "delegated_boundary", "unix_socket_boundary", "owner_unaffected", "fast_switch", "reboot", "tool_profiles", "owner_home_denial"} {
		e.Probes = append(e.Probes, Probe{Category: category, ArtifactSHA256: d, Passed: true, Attempts: 3, PFHitDelta: 3, AuthorizedControlSuccesses: 3})
	}
	return now, q, e, o
}
func TestQualificationInvalidatesChangedLiveFacts(t *testing.T) {
	mutations := map[string]func(*Observation){"boot": func(o *Observation) { o.Boot = digest([]byte("new boot")) }, "interfaces": func(o *Observation) { o.InterfacesSHA256 = digest([]byte("new address")) }, "policy": func(o *Observation) { o.PolicySHA256 = digest([]byte("new policy")) }, "root rules": func(o *Observation) { o.RootRulesSHA256 = digest([]byte("new root")) }, "anchor": func(o *Observation) { o.AnchorRulesSHA256 = digest([]byte("new anchor")) }, "baseline": func(o *Observation) { o.BaselineSHA256 = digest([]byte("new baseline")) }, "evidence": func(o *Observation) { o.BoundaryEvidenceSHA256 = digest([]byte("new evidence")) }, "profile": func(o *Observation) { o.Profiles["build"] = digest([]byte("new recipe")) }, "PF disabled": func(o *Observation) { o.PFEnabled = false }, "skip loopback": func(o *Observation) { o.LoopbackFiltered = false }, "lost baseline": func(o *Observation) { o.BaselineValid = false }, "accounting unavailable": func(o *Observation) { o.AccountedBytes = -1 }}
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
func TestEvidenceRequiresActualProbeAttestationFields(t *testing.T) {
	for name, mutate := range map[string]func(*BoundaryEvidence){"UDP received": func(e *BoundaryEvidence) { e.Probes[1].CanaryReceipts = 1 }, "no deny hits": func(e *BoundaryEvidence) { e.Probes[0].PFHitDelta = 0 }, "offline control": func(e *BoundaryEvidence) { e.Probes[1].AuthorizedControlSuccesses = 0 }, "missing category": func(e *BoundaryEvidence) { e.Probes = e.Probes[1:] }, "duplicate": func(e *BoundaryEvidence) { e.Probes = append(e.Probes, e.Probes[0]) }, "wrong boot": func(e *BoundaryEvidence) { e.Boot = digest([]byte("old")) }, "future record": func(e *BoundaryEvidence) { e.RecordedAt = e.RecordedAt.Add(time.Hour) }} {
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
				probe.Passed = false
			}
			h, err := Evaluate(now, q, e, o)
			if (err == nil) != (mode == "denied") || h.BoundaryValidated != (mode == "denied") {
				t.Fatalf("owner home %s: health=%+v error=%v", mode, h, err)
			}
		})
	}
}
func TestPFUnsupportedAndSkipOutputNeverAccepted(t *testing.T) {
	for _, out := range []string{"", "lo0 (skip)\n", "lo0\nother\n", "lo0 (unknown)\n"} {
		if loopbackFiltered(out) {
			t.Fatalf("accepted %q", out)
		}
	}
	if !loopbackFiltered("lo0\n") {
		t.Fatal("supported filtered loopback rejected")
	}
	for _, out := range []string{"Status: Disabled for 1 day Debug: Urgent\n", "Status: Enabled\n", ""} {
		if pfEnabled(out) {
			t.Fatalf("accepted %q", out)
		}
	}
	if !pfEnabled("Status: Enabled for 0 days 00:01:00 Debug: Urgent\n") {
		t.Fatal("supported enabled status rejected")
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

package setup

import (
	"strings"
	"testing"
	"time"
)

var (
	boot1  = Boot{Time: "{ sec = 1000, usec = 0 }", SessionUUID: "11111111-1111-1111-1111-111111111111"}
	boot2  = Boot{Time: "{ sec = 2000, usec = 0 }", SessionUUID: "22222222-2222-2222-2222-222222222222"}
	digest = strings.Repeat("a", 64)
	t0     = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
)

func mustStep(t *testing.T, l *Ledger, s Step, boot Boot) {
	t.Helper()
	if err := l.Begin(s, boot, t0); err != nil {
		t.Fatalf("begin %s: %v", s, err)
	}
	if err := l.Complete(s, boot, map[string]string{"input": digest}, t0); err != nil {
		t.Fatalf("complete %s: %v", s, err)
	}
}

// ledgerAt returns a ledger with every step before s done.
func ledgerAt(t *testing.T, s Step) *Ledger {
	t.Helper()
	l := NewLedger("jdoe", 501, t0)
	for _, step := range Steps {
		if step == s {
			return l
		}
		switch step {
		case StepReboot:
			if err := l.Begin(step, boot1, t0); err != nil {
				t.Fatal(err)
			}
			if err := l.Complete(step, boot2, nil, t0); err != nil {
				t.Fatal(err)
			}
		case StepRound2:
			mustStep(t, l, step, boot2)
		case StepApproveAndStart:
			if err := l.Begin(step, boot2, t0); err != nil {
				t.Fatal(err)
			}
			if err := l.Approve(digest, boot2, t0); err != nil {
				t.Fatal(err)
			}
			if err := l.Complete(step, boot2, nil, t0); err != nil {
				t.Fatal(err)
			}
		default:
			mustStep(t, l, step, boot1)
		}
	}
	return l
}

func TestGitHubPrecedesInstallAndRound1(t *testing.T) {
	index := map[Step]int{}
	for i, s := range Steps {
		index[s] = i
	}
	if index[StepPreflight] != 0 || index[StepGitHub] != 1 || index[StepGitHub] > index[StepInstall] || index[StepInstall] > index[StepRound1] ||
		index[StepRound1] > index[StepReboot] || index[StepReboot] > index[StepRound2] || index[StepRound2] > index[StepApproveAndStart] ||
		index[StepApproveAndStart] > index[StepFirstBuild] || len(Steps) != 10 {
		t.Fatalf("step order %v", Steps)
	}
	for _, s := range Steps {
		if StepSummaries[s] == "" {
			t.Errorf("step %s has no summary", s)
		}
	}
	l := ledgerAt(t, StepGitHub)
	for _, s := range []Step{StepInstall, StepRound1} {
		if err := l.Begin(s, boot1, t0); err == nil {
			t.Errorf("%s began before github", s)
		}
	}
}

func TestFailedStepBlocksLaterSteps(t *testing.T) {
	l := ledgerAt(t, StepInstall)
	if err := l.Begin(StepInstall, boot1, t0); err != nil {
		t.Fatal(err)
	}
	if err := l.Fail(StepInstall, "deploy-install failed partway", t0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := l.Next(); err == nil || !strings.Contains(err.Error(), "install failed") {
		t.Fatalf("Next after failure: %v", err)
	}
	for _, s := range Steps {
		if err := l.Begin(s, boot1, t0); err == nil {
			t.Errorf("%s began after a failed step", s)
		}
	}
	if err := l.Complete(StepInstall, boot1, nil, t0); err == nil {
		t.Error("failed step completed")
	}
	data, err := l.Encode()
	if err != nil {
		t.Fatal(err)
	}
	resumed, err := DecodeLedger(data)
	if err != nil {
		t.Fatal(err)
	}
	if r, failed := resumed.Failed(); !failed || r.Step != StepInstall {
		t.Fatal("failure lost across encode/decode")
	}
}

func TestResumeAfterRestart(t *testing.T) {
	l := ledgerAt(t, StepReboot)
	if err := l.Begin(StepReboot, boot1, t0); err != nil {
		t.Fatal(err)
	}
	data, err := l.Encode()
	if err != nil {
		t.Fatal(err)
	}
	// The host restarts; a new process decodes the same bytes.
	resumed, err := DecodeLedger(data)
	if err != nil {
		t.Fatal(err)
	}
	next, done, err := resumed.Next()
	if err != nil || done || next.Step != StepReboot || next.Status != StatusRunning {
		t.Fatalf("resume point %+v %v %v", next, done, err)
	}
	if err := resumed.Begin(StepReboot, boot2, t0); err == nil {
		t.Fatal("interrupted step restarted implicitly")
	}
	if err := resumed.Complete(StepReboot, boot1, nil, t0); err == nil {
		t.Fatal("reboot completed without a restart")
	}
	if err := resumed.Complete(StepReboot, boot2, nil, t0); err != nil {
		t.Fatal(err)
	}
	if next, _, _ := resumed.Next(); next.Step != StepRound2 {
		t.Fatalf("after reboot next is %s", next.Step)
	}
	if string(data) == "" || resumed.Records[0].Inputs["input"] != digest {
		t.Fatal("input digests lost across encode/decode")
	}
}

func TestRound2RequiresDifferentBoot(t *testing.T) {
	l := ledgerAt(t, StepRound2)
	if err := l.Begin(StepRound2, boot1, t0); err == nil {
		t.Fatal("round 2 began in round 1's boot")
	}
	half := Boot{Time: boot2.Time, SessionUUID: boot1.SessionUUID}
	if err := l.Begin(StepRound2, half, t0); err == nil {
		t.Fatal("round 2 began when only one boot identifier changed")
	}
	if err := l.Begin(StepRound2, boot2, t0); err != nil {
		t.Fatal(err)
	}
	if err := l.Complete(StepRound2, boot1, nil, t0); err == nil {
		t.Fatal("round 2 completed in another boot than it began in")
	}
}

// forged builds a ledger through every step with all boots set to boot,
// bypassing Begin/Complete, and encodes it without validation.
func forged(t *testing.T, boot Boot, edit func(*Ledger)) []byte {
	t.Helper()
	l := NewLedger("jdoe", 501, t0)
	for i := range l.Records {
		b, f, at := boot, boot, t0
		l.Records[i] = Record{Step: Steps[i], Status: StatusDone, Started: &at, Finished: &at, Boot: &b, FinishBoot: &f}
	}
	l.Approval = &Approval{At: t0, SummarySHA256: digest, Boot: boot}
	edit(l)
	data, err := l.encode()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestDecodeLedgerRechecksBootRules(t *testing.T) {
	valid := forged(t, boot2, func(l *Ledger) {
		for i := range 6 {
			l.Records[i].Boot, l.Records[i].FinishBoot = &boot1, &boot1
		}
		l.Records[6].Boot = &boot1
	})
	if _, err := DecodeLedger(valid); err != nil {
		t.Fatalf("consistent forged ledger refused: %v", err)
	}
	for name, data := range map[string][]byte{
		"same boot throughout": forged(t, boot1, func(*Ledger) {}),
		"round 2 in round 1 boot": forged(t, boot2, func(l *Ledger) {
			l.Records[5].Boot, l.Records[5].FinishBoot = &boot2, &boot2
			l.Records[6].Boot = &boot1
		}),
		"step finished in another boot": forged(t, boot2, func(l *Ledger) {
			l.Records[6].Boot = &boot1
			for i := range 6 {
				l.Records[i].Boot, l.Records[i].FinishBoot = &boot1, &boot1
			}
			l.Records[9].Boot = &boot1
		}),
		"approval from another boot": forged(t, boot2, func(l *Ledger) {
			for i := range 6 {
				l.Records[i].Boot, l.Records[i].FinishBoot = &boot1, &boot1
			}
			l.Records[6].Boot = &boot1
			l.Approval.Boot = boot1
		}),
		"done without approval": forged(t, boot2, func(l *Ledger) {
			for i := range 6 {
				l.Records[i].Boot, l.Records[i].FinishBoot = &boot1, &boot1
			}
			l.Records[6].Boot = &boot1
			l.Approval = nil
		}),
		"owner with control character": forged(t, boot2, func(l *Ledger) { l.Owner = "jdoe\n" }),
		"system owner uid":             forged(t, boot2, func(l *Ledger) { l.OwnerUID = 0 }),
		"boot with control character": forged(t, boot2, func(l *Ledger) {
			bad := Boot{Time: "1\x1b[2J", SessionUUID: "x"}
			l.Records[0].Boot = &bad
		}),
	} {
		if _, err := DecodeLedger(data); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDecodeLedgerRequiresCanonicalForm(t *testing.T) {
	good, err := ledgerAt(t, StepTools).Encode()
	if err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(string) string{
		"duplicate key": func(s string) string {
			return strings.Replace(s, `"owner": "jdoe",`, `"owner": "mallory", "owner": "jdoe",`, 1)
		},
		"case variant": func(s string) string { return strings.Replace(s, `"owner": "jdoe"`, `"OWNER": "jdoe"`, 1) },
		"reordered": func(s string) string {
			return strings.Replace(s, `"schema": 1,`+"\n  \"owner\": \"jdoe\",", `"owner": "jdoe",`+"\n  \"schema\": 1,", 1)
		},
		"compact":        func(s string) string { return strings.ReplaceAll(s, "\n  ", "\n ") },
		"no final line":  func(s string) string { return strings.TrimSuffix(s, "\n") },
		"escaped letter": func(s string) string { return strings.Replace(s, `"owner": "jdoe"`, `"owner": "j\u0064oe"`, 1) },
	} {
		bad := edit(string(good))
		if bad == string(good) {
			t.Fatalf("%s: edit did not apply", name)
		}
		if _, err := DecodeLedger([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	l := ledgerAt(t, StepTools)
	if err := l.Begin(StepTools, boot1, t0); err != nil {
		t.Fatal(err)
	}
	if err := l.Fail(StepTools, "xcodebuild failed\n\x1b[2J", t0); err == nil {
		t.Fatal("failure reason with control characters accepted")
	}
}

func TestStartRefusedBeforeApprove(t *testing.T) {
	l := ledgerAt(t, StepRound2)
	if err := l.AuthorizeStart(boot2); err == nil {
		t.Fatal("start authorized before round 2")
	}
	if err := l.Approve(digest, boot2, t0); err == nil {
		t.Fatal("approval accepted before round 2")
	}
	mustStep(t, l, StepRound2, boot2)
	if err := l.Approve(digest, boot2, t0); err == nil {
		t.Fatal("approval accepted before approve-and-start began")
	}
	if err := l.Begin(StepApproveAndStart, boot2, t0); err != nil {
		t.Fatal(err)
	}
	if err := l.AuthorizeStart(boot2); err == nil || !strings.Contains(err.Error(), "approve") {
		t.Fatalf("start authorized without approval: %v", err)
	}
	if err := l.Complete(StepApproveAndStart, boot2, nil, t0); err == nil {
		t.Fatal("approve-and-start completed without approval")
	}
	if err := l.Approve("not-a-digest", boot2, t0); err == nil {
		t.Fatal("malformed approval accepted")
	}
	if err := l.Approve(digest, boot1, t0); err == nil {
		t.Fatal("approval accepted from another boot")
	}
	if err := l.Approve(digest, boot2, t0); err != nil {
		t.Fatal(err)
	}
	if err := l.AuthorizeStart(boot1); err == nil {
		t.Fatal("approval from another boot authorized start")
	}
	if err := l.AuthorizeStart(boot2); err != nil {
		t.Fatal(err)
	}
	if err := l.Complete(StepApproveAndStart, boot2, nil, t0); err != nil {
		t.Fatal(err)
	}
	if err := l.AuthorizeStart(boot2); err == nil {
		t.Fatal("start authorized after approve-and-start finished")
	}
}

// TestMethodsRecheckInvariantsInMemory: the mutating methods do not rely
// on DecodeLedger having validated the ledger.
func TestMethodsRecheckInvariantsInMemory(t *testing.T) {
	// A failed step and a running later step: Complete must refuse.
	l := ledgerAt(t, StepTools)
	if err := l.Begin(StepTools, boot1, t0); err != nil {
		t.Fatal(err)
	}
	at := t0
	l.Records[2].Status, l.Records[2].Error, l.Records[2].FinishBoot = StatusFailed, "forged", nil
	if err := l.Complete(StepTools, boot1, nil, t0); err == nil {
		t.Error("step completed while an earlier step failed")
	}
	if err := l.Fail(StepTools, "x", t0); err != nil {
		t.Fatal(err)
	}
	if err := l.Fail(StepTools, "again", t0); err == nil {
		t.Error("Fail on a failed step accepted")
	}
	if err := NewLedger("jdoe", 501, t0).Fail(StepPreflight, "x", t0); err == nil {
		t.Error("Fail on a pending step accepted")
	}

	// approve-and-start running while round 2 is still pending.
	l = ledgerAt(t, StepRound2)
	b := boot2
	l.Records[8] = Record{Step: StepApproveAndStart, Status: StatusRunning, Started: &at, Boot: &b}
	if err := l.Approve(digest, boot2, t0); err == nil {
		t.Error("approval accepted while round 2 is pending")
	}

	// An approval from another boot cannot complete approve-and-start.
	l = ledgerAt(t, StepApproveAndStart)
	if err := l.Begin(StepApproveAndStart, boot2, t0); err != nil {
		t.Fatal(err)
	}
	l.Approval = &Approval{At: t0, SummarySHA256: digest, Boot: boot1}
	if err := l.Complete(StepApproveAndStart, boot2, nil, t0); err == nil {
		t.Error("approve-and-start completed with an approval from another boot")
	}
}

func TestDecodeLedgerRejectsForgedRecords(t *testing.T) {
	consistent := func(l *Ledger) {
		for i := range 6 {
			l.Records[i].Boot, l.Records[i].FinishBoot = &boot1, &boot1
		}
		l.Records[6].Boot = &boot1
	}
	at := t0
	for name, data := range map[string][]byte{
		"done after running": forged(t, boot2, func(l *Ledger) {
			consistent(l)
			l.Records[3].Status, l.Records[3].Finished, l.Records[3].FinishBoot = StatusRunning, nil, nil
		}),
		"two running": forged(t, boot2, func(l *Ledger) {
			consistent(l)
			for _, i := range []int{3, 4} {
				l.Records[i].Status, l.Records[i].Finished, l.Records[i].FinishBoot = StatusRunning, nil, nil
			}
			for i := 5; i < 10; i++ {
				l.Records[i] = Record{Step: Steps[i], Status: StatusPending}
			}
			l.Approval = nil
		}),
		"pending with state": forged(t, boot2, func(l *Ledger) {
			consistent(l)
			for i := 3; i < 10; i++ {
				l.Records[i] = Record{Step: Steps[i], Status: StatusPending}
			}
			l.Records[9].Started = &at
			l.Approval = nil
		}),
		"bad input digest": forged(t, boot2, func(l *Ledger) {
			consistent(l)
			l.Records[0].Inputs = map[string]string{"deploy.env": "abc"}
		}),
		"approval before approve-and-start": forged(t, boot2, func(l *Ledger) {
			consistent(l)
			l.Records[8], l.Records[9] = Record{Step: Steps[8], Status: StatusPending}, Record{Step: Steps[9], Status: StatusPending}
		}),
	} {
		if _, err := DecodeLedger(data); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := DecodeLedger(make([]byte, MaxLedger+1)); err == nil || !strings.Contains(err.Error(), "oversized") {
		t.Errorf("oversized ledger: %v", err)
	}
}

func TestCompleteRejectsMalformedInputDigests(t *testing.T) {
	l := NewLedger("jdoe", 501, t0)
	if err := l.Begin(StepPreflight, boot1, t0); err != nil {
		t.Fatal(err)
	}
	for _, inputs := range []map[string]string{{"deploy.env": "abc"}, {"Bad Name": digest}, {"": digest}} {
		if err := l.Complete(StepPreflight, boot1, inputs, t0); err == nil {
			t.Errorf("inputs %v accepted", inputs)
		}
	}
	if err := l.Begin(StepGitHub, Boot{}, t0); err == nil {
		t.Error("step began out of order")
	}
}

func TestDecodeLedgerRejectsInconsistentState(t *testing.T) {
	good, err := ledgerAt(t, StepTools).Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeLedger(good); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(string) string{
		"unknown field": func(s string) string { return strings.Replace(s, `"schema": 1`, `"schema": 1, "extra": true`, 1) },
		"schema":        func(s string) string { return strings.Replace(s, `"schema": 1`, `"schema": 2`, 1) },
		"trailing data": func(s string) string { return s + "{}" },
		"done after gap": func(s string) string {
			return strings.Replace(s, `"step": "github",`+"\n      \"status\": \"done\"", `"step": "github",`+"\n      \"status\": \"pending\"", 1)
		},
		"renamed step": func(s string) string { return strings.Replace(s, `"step": "install"`, `"step": "installs"`, 1) },
		"bad status":   func(s string) string { return strings.Replace(s, `"status": "pending"`, `"status": "skipped"`, 1) },
		"no owner":     func(s string) string { return strings.Replace(s, `"owner": "jdoe"`, `"owner": ""`, 1) },
	} {
		bad := edit(string(good))
		if bad == string(good) {
			t.Fatalf("%s: edit did not apply", name)
		}
		if _, err := DecodeLedger([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := DecodeLedger(nil); err == nil {
		t.Error("empty ledger accepted")
	}
}

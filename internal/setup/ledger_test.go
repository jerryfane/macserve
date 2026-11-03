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
	// A ledger whose reboot record was forged into the round-1 boot is
	// still refused: round 2 compares against round 1's own boot.
	l.Records[6].Boot = &boot1
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

package worker

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// Agents that keep vanishing before verification never quarantine:
// admission gives up after maxUnsettledSnapshots inconclusively.
func TestAdmissionRefusesWithoutQuarantineWhileProcessesKeepVanishing(t *testing.T) {
	s, _, rows := appleWorld()
	// Odd calls are the census snapshot, even calls its re-check.
	s.sample = vanishingSampler(rows, func(call int) bool { return call%2 == 1 })
	err := s.observeQuiet(context.Background())
	if !errors.Is(err, errAdmissionUnsettled) || errors.Is(err, ErrContamination) {
		t.Fatalf("unsettled admission: %v", err)
	}
}

// A contamination refusal names each refused process and why every rule
// refused it, bounded, in the error and the quarantine record; the reason
// that leaves the host carries only the count.
func TestContaminationListsRefusedProcessesAndPublicReasonIsShort(t *testing.T) {
	s, agents, rows := appleWorld()
	evil := "/Users/macservejob/bin/agent"
	for i := range 12 {
		pid := 500 + i
		agents.procs[pid] = agentProcess{start: "70:0", uid: testJobUID, ppid: 1, executable: evil, program: evil, argv: evil}
		rows = append(rows, sample(pid, "70:0"))
	}
	quietScope(s, rows)
	err := s.observeQuiet(context.Background())
	if !errors.Is(err, ErrContamination) {
		t.Fatalf("residual processes admitted: %v", err)
	}
	text := err.Error()
	for _, want := range []string{"processes outside audited GUI baseline: 12 unexpected process(es)", "pid=500 start=70:0 ppid=1 exe=\"" + evil + "\"", "apple: not a platform binary", "developer-tool: not a platform binary", "+4 more"} {
		if !strings.Contains(text, want) {
			t.Fatalf("contamination error lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "pid=508") || len(text) > 4096 {
		t.Fatalf("contamination error not bounded (%d bytes):\n%s", len(text), text)
	}
	public := PublicReason(errors.Join(ErrRecovery, err))
	if public != "worker requires recovery\njob-user contamination: 12 unexpected process(es); see host diagnostics" {
		t.Fatalf("public reason: %q", public)
	}

	runner := &scopeRunner{scope: s}
	engine := engineFixture(t, runner)
	recovered := engine.Recover(context.Background())
	if !errors.Is(recovered, ErrRecovery) || !errors.Is(recovered, ErrContamination) {
		t.Fatalf("recover: %v", recovered)
	}
	data, readErr := engine.root.ReadFile(quarantineRecord)
	var record QuarantineRecord
	if readErr != nil || json.Unmarshal(data, &record) != nil || !record.Quarantined || !strings.Contains(record.Reason, "pid=500") || record.RecordedAt.IsZero() {
		t.Fatalf("quarantine record %s: %v", data, readErr)
	}
}

func TestPublicReasonKeepsOtherErrors(t *testing.T) {
	plain := errors.Join(ErrRecovery, errors.New("simulator ownership unresolved"))
	if PublicReason(plain) != plain.Error() || PublicReason(nil) != "" {
		t.Fatal("non-contamination reason changed")
	}
	c := &contamination{what: "x", total: 1, entries: []string{"pid=9 exe=\"/Users/a\""}}
	for _, err := range []error{c, errors.Join(errors.New("cleanup"), c)} {
		if got := PublicReason(err); strings.Contains(got, "/Users") || !strings.Contains(got, "1 unexpected process(es)") {
			t.Fatalf("detail leaked: %q", got)
		}
	}
}

func TestLaunchdProgram(t *testing.T) {
	for raw, want := range map[string]string{
		cloudphotodProgram: "/System/Library/PrivateFrameworks/CloudPhotoLibrary.framework/Versions/A/Support/cloudphotod",
		aquaProgram:        "/System/Library/PrivateFrameworks/SkyLight.framework/Versions/A/Resources/AquaAppearanceHelper.app/Contents/MacOS/AquaAppearanceHelper",
		"/usr/libexec/x":   "/usr/libexec/x",
	} {
		if got, ok := launchdProgram(raw); !ok || got != want {
			t.Fatalf("%s: %q %v", raw, got, ok)
		}
	}
	for _, raw := range []string{"relative/x", "/System/./x", "/System/../Users/x", "/System/Library/a/..", ""} {
		if _, ok := launchdProgram(raw); ok {
			t.Fatalf("%q accepted", raw)
		}
	}
	if clean, _ := launchdProgram(cloudphotodProgram); !systemPath(clean) {
		t.Fatal("cleaned cloudphotod program is not a system path")
	}
}

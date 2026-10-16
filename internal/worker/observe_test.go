package worker

import "testing"

func TestMaintenanceBaselineAllowsActiveJobsButRejectsLostIdentity(t *testing.T) {
	b := GUIBaseline{JobUID: 550, Boot: "qualified", Processes: []ProcessIdentity{{PID: 100, Start: "boot:100"}}}
	baseline := processSample{pid: 100, uid: 550, start: "boot:100"}
	job := processSample{pid: 200, uid: 550, start: "boot:200"}
	if err := baselineAlive(b, []processSample{baseline, job}); err != nil {
		t.Fatalf("active job invalidates live baseline: %v", err)
	}
	for name, p := range map[string]processSample{"PID reused": {pid: 100, uid: 550, start: "boot:reused"}, "UID changed": {pid: 100, uid: 551, start: "boot:100"}, "zombie": {pid: 100, uid: 550, start: "boot:100", zombie: true}} {
		t.Run(name, func(t *testing.T) {
			if err := baselineAlive(b, []processSample{p, job}); err == nil {
				t.Fatal("lost baseline identity accepted")
			}
		})
	}
}

// Issue #27: a KeepAlive Apple helper (corespeechd) crashed itself mid-round and
// launchd restarted it under a new PID. The absent audited PID is recorded, not
// refused; the relaunched helper is an unaudited process and is ignored here.
func TestMaintenanceBaselineRecordsSelfExitedAuditedProcess(t *testing.T) {
	b := GUIBaseline{JobUID: 550, Boot: "qualified", Processes: []ProcessIdentity{{PID: 100, Start: "boot:100"}, {PID: 101, Start: "boot:101"}}}
	kept := processSample{pid: 100, uid: 550, start: "boot:100"}
	relaunched := processSample{pid: 300, uid: 550, start: "boot:300"}
	samples := []processSample{kept, relaunched}
	if err := baselineAlive(b, samples); err != nil {
		t.Fatalf("self-exited audited helper refused: %v", err)
	}
}

func TestMaintenanceBaselineExitedListsOnlyAbsentAuditedPIDs(t *testing.T) {
	b := GUIBaseline{JobUID: 550, Boot: "qualified", Processes: []ProcessIdentity{{PID: 100, Start: "boot:100"}, {PID: 101, Start: "boot:101"}}}
	samples := []processSample{{pid: 100, uid: 550, start: "boot:100"}, {pid: 300, uid: 550, start: "boot:300"}}
	exited := baselineExited(b, samples)
	if len(exited) != 1 || exited[0] != (ProcessIdentity{PID: 101, Start: "boot:101"}) {
		t.Fatalf("exited = %+v", exited)
	}
}

package worker

import (
	"context"
	"testing"
)

// observed runs the census ObserveGUIBaseline applies, without launchd agents.
func observed(b GUIBaseline, samples []processSample) error {
	scope := processScope{uid: int(b.JobUID), baseline: b}
	_, err := scope.residual(context.Background(), samples)
	return err
}

func TestMaintenanceBaselineAllowsActiveJobsButRejectsLostIdentity(t *testing.T) {
	b := GUIBaseline{JobUID: 550, Boot: "qualified", Processes: []ProcessIdentity{{PID: 100, Start: "boot:100"}}}
	baseline := processSample{pid: 100, uid: 550, start: "boot:100"}
	job := processSample{pid: 200, uid: 550, start: "boot:200"}
	if err := observed(b, []processSample{baseline, job}); err != nil {
		t.Fatalf("active job invalidates live baseline: %v", err)
	}
	for name, p := range map[string]processSample{"UID changed": {pid: 100, uid: 551, start: "boot:100"}, "zombie": {pid: 100, uid: 550, start: "boot:100", zombie: true}} {
		t.Run(name, func(t *testing.T) {
			if err := observed(b, []processSample{p, job}); err == nil {
				t.Fatal("lost baseline identity accepted")
			}
		})
	}
}

// macserve#108: the build host's PID counter wraps several times a day under
// job load, and the kernel then hands an exited audited process's PID number
// to an unrelated process: a root or other-user daemon, or a new job-UID
// process such as the CoreDevice helpers a simulator job starts. Health went
// invalid ("GUI baseline process changed") and cancelled the running job. A
// different start time is another process, never the audited one.
func TestMaintenanceBaselineToleratesRecycledAuditedPIDNumber(t *testing.T) {
	b := GUIBaseline{JobUID: 550, Boot: "qualified", Processes: []ProcessIdentity{{PID: 100, Start: "boot:100"}, {PID: 101, Start: "boot:101"}}}
	kept := processSample{pid: 101, uid: 550, start: "boot:101"}
	for name, holder := range map[string]processSample{
		"root daemon":         {pid: 100, uid: 0, start: "boot:wrapped"},
		"another user":        {pid: 100, uid: 501, start: "boot:wrapped"},
		"another user zombie": {pid: 100, uid: 501, start: "boot:wrapped", zombie: true},
		"job process":         {pid: 100, uid: 550, start: "boot:wrapped"},
		"job zombie":          {pid: 100, uid: 550, start: "boot:wrapped", zombie: true},
	} {
		t.Run(name, func(t *testing.T) {
			scope := processScope{uid: 550, baseline: b}
			c, err := scope.census(context.Background(), []processSample{kept, holder})
			if err != nil {
				t.Fatalf("recycled audited PID number refused: %v", err)
			}
			// The new holder is classified as any process: a live job-UID one is
			// residual (the job's), anything else is out of scope.
			wantResidual := holder.uid == 550 && !holder.zombie
			if got := len(c.residual) == 1 && c.residual[0] == holder; got != wantResidual || len(c.residual) > 1 {
				t.Fatalf("residual = %+v, want holder residual %v", c.residual, wantResidual)
			}
			if !c.unresolved {
				t.Fatal("the exited audited process was not left unresolved")
			}
			if exited := baselineExited(b, []processSample{kept, holder}); len(exited) != 1 || exited[0].PID != 100 {
				t.Fatalf("baseline_exited = %+v", exited)
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
	if err := observed(b, []processSample{kept, relaunched}); err != nil {
		t.Fatalf("self-exited audited helper refused: %v", err)
	}
}

func TestMaintenanceBaselineExitedListsAuditedIdentitiesNoLongerRunning(t *testing.T) {
	b := GUIBaseline{JobUID: 550, Boot: "qualified", Processes: []ProcessIdentity{{PID: 100, Start: "boot:100"}, {PID: 101, Start: "boot:101"}, {PID: 102, Start: "boot:102"}}}
	samples := []processSample{{pid: 100, uid: 550, start: "boot:100"}, {pid: 102, uid: 550, start: "boot:relaunched"}, {pid: 300, uid: 550, start: "boot:300"}}
	exited := baselineExited(b, samples)
	if len(exited) != 2 || exited[0] != (ProcessIdentity{PID: 101, Start: "boot:101"}) || exited[1] != (ProcessIdentity{PID: 102, Start: "boot:102"}) {
		t.Fatalf("exited = %+v", exited)
	}
}

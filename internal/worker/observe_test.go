package worker

import (
	"context"
	"errors"
	"maps"
	"testing"

	"github.com/jerryfane/macserve/internal/launchctlprint"
)

// observed runs the census ObserveGUIBaseline applies, without launchd agents.
func observed(b GUIBaseline, samples []processSample) error {
	scope := processScope{uid: int(b.JobUID), baseline: b, checkOnly: true}
	_, err := scope.residual(context.Background(), samples)
	return err
}

// countingAgents records which launchd and process inspections a census made.
type countingAgents struct {
	*fakeAgents
	calls map[string]int
}

func (c countingAgents) domain(ctx context.Context, target string) (launchctlprint.Domain, error) {
	c.calls["domain"]++
	return c.fakeAgents.domain(ctx, target)
}

func (c countingAgents) process(pid int) (agentProcess, error) {
	c.calls["process"]++
	return c.fakeAgents.process(pid)
}

func (c countingAgents) kernel(pid int) (agentProcess, error) {
	c.calls["kernel"]++
	return c.fakeAgents.kernel(pid)
}

func (c countingAgents) service(ctx context.Context, target string) (launchctlprint.Snapshot, error) {
	c.calls["service"]++
	return c.fakeAgents.service(ctx, target)
}

// macserve#215: under job load the maintenance GUI-baseline check spent its
// 30 s budget verifying every job process as a launchd relaunch or tolerated
// launch, one launchctl print each, although no outcome of that work can fail
// it; it timed out for over 10 minutes and health cancelled every running
// job. The maintenance census reads the job launchd domains only.
func TestMaintenanceBaselineInspectsNoJobProcess(t *testing.T) {
	const uid = 550
	gui, user := "gui/550", "user/550"
	b := GUIBaseline{JobUID: uid, Boot: "qualified", Launchd: &LaunchdEnvironment{GUI: map[string]string{}, User: map[string]string{}}, Processes: []ProcessIdentity{
		{PID: 100, Start: "boot:100", Service: LaunchdService{Domain: gui, Label: "com.apple.helper"}},
		{PID: 101, Start: "boot:101"},
	}}
	samples := []processSample{{pid: 101, uid: uid, start: "boot:101"}, {pid: 300, uid: uid, start: "boot:300"}, {pid: 301, uid: uid, start: "boot:301"}}
	agents := countingAgents{fakeAgents: newFakeAgents(), calls: map[string]int{}}
	agents.env[gui], agents.env[user] = map[string]string{}, map[string]string{}
	scope := processScope{uid: uid, baseline: b, agents: agents, checkOnly: true}
	if _, err := scope.census(context.Background(), samples); err != nil {
		t.Fatalf("maintenance census: %v", err)
	}
	if want := map[string]int{"domain": 2}; !maps.Equal(agents.calls, want) {
		t.Fatalf("inspections = %v, want %v", agents.calls, want)
	}
	agents.env[gui] = map[string]string{"DYLD_INSERT_LIBRARIES": "/tmp/x"}
	if _, err := scope.census(context.Background(), samples); !errors.Is(err, ErrContamination) {
		t.Fatalf("changed job launchd environment: %v", err)
	}
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

package worker

import "testing"

func TestMaintenanceBaselineAllowsActiveJobsButRejectsLostIdentity(t *testing.T) {
	b := GUIBaseline{JobUID: 550, Boot: "qualified", Processes: []ProcessIdentity{{PID: 100, Start: "boot:100"}}}
	baseline := processSample{pid: 100, uid: 550, start: "boot:100"}
	job := processSample{pid: 200, uid: 550, start: "boot:200"}
	if err := baselineAlive(b, []processSample{baseline, job}); err != nil {
		t.Fatalf("active job invalidates live baseline: %v", err)
	}
	for name, p := range map[string]processSample{"PID reused": {pid: 100, uid: 550, start: "boot:reused"}, "UID changed": {pid: 100, uid: 551, start: "boot:100"}, "zombie": {pid: 100, uid: 550, start: "boot:100", zombie: true}, "missing": job} {
		t.Run(name, func(t *testing.T) {
			if err := baselineAlive(b, []processSample{p}); err == nil {
				t.Fatal("lost baseline identity accepted")
			}
		})
	}
}

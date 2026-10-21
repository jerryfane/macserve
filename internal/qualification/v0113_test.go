package qualification

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/deploy"
)

func TestJobProbeOnlyThroughRootLauncher(t *testing.T) {
	err := probe(context.Background(), t.TempDir(), "job", t.TempDir()+"/out", 6202, 6202)
	if !errors.Is(err, errJobProbeLauncher) {
		t.Fatalf("job probe outside the launcher was not refused: %v", err)
	}
}

func TestJobReportNeedsProductionContext(t *testing.T) {
	now := time.Now().UTC().Add(-time.Minute)
	c := Challenge{Schema: schema, ID: strings.Repeat("a", 64), Created: now, Expires: now.Add(lifetime), Environment: deploy.Environment{JobUID: 502, JobGID: 20, OwnerUID: 501}}
	good := Report{Schema: schema, ChallengeSHA256: "h", Role: "job", Mode: jobProbeMode, UID: 502, AuditUID: 502, Groups: []int{20}, Started: now, Finished: now.Add(time.Second)}
	if err := checkReport(good, c, "h", "job"); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Report){
		"foreground job console": func(r *Report) { r.ConsoleUID = 502 },
		"full memberships":       func(r *Report) { r.Groups = []int{12, 20, 61} },
		"owner audit session":    func(r *Report) { r.AuditUID = 501 },
		"interactive mode":       func(r *Report) { r.Mode = ownerProbeMode },
		"previous report schema": func(r *Report) { r.Schema = 3 },
	} {
		t.Run(name, func(t *testing.T) {
			r := good
			mutate(&r)
			if checkReport(r, c, "h", "job") == nil {
				t.Fatal("report outside the production context accepted")
			}
		})
	}
	good.ConsoleUID = 0
	if err := checkReport(good, c, "h", "job"); err != nil {
		t.Fatalf("login-window console refused: %v", err)
	}
}

func TestRebootAndToolsAreMachineChecked(t *testing.T) {
	c, j, o, receipts := phaseOneFixture()
	c.Profiles = nil
	for name, facts := range map[string]sittingFacts{"no boot transition": {toolOK: true}, "tool recipes failed": {rebootOK: true}} {
		t.Run(name, func(t *testing.T) {
			v := Candidate{Categories: aggregate(c, j, o, receipts, facts)}
			if readyApproval(v) == nil {
				t.Fatal("approval admitted without machine evidence")
			}
		})
	}
	v := Candidate{Categories: aggregate(c, j, o, receipts, sittingFacts{rebootOK: true, toolOK: true})}
	if err := readyApproval(v); err != nil {
		t.Fatal(err)
	}
	if _, ok := v.Categories["fast_switch"]; ok {
		t.Fatal("fast_switch category still produced")
	}
}

func TestSessionIDIsTheOnlyLauncherInput(t *testing.T) {
	for _, id := range []string{"", "../x", "a/b", "-x", strings.Repeat("a", 65), "a.b"} {
		if _, err := SessionDirectory(id); err == nil {
			t.Errorf("session ID %q accepted", id)
		}
	}
	if dir, err := SessionDirectory("s2-v0113-round1"); err != nil || dir != "/Library/macserve/var/qualification/s2-v0113-round1" {
		t.Fatal(dir, err)
	}
}

func TestAnchorParametersDetectNarrowedChallenge(t *testing.T) {
	c := Challenge{TCP: []string{"127.0.0.1:1"}, PrivatePaths: []string{"/a", "/b"}, Socket: "/s"}
	a := anchorParameters(c)
	narrowed := c
	narrowed.PrivatePaths = []string{"/a"}
	if sameParameters(a, anchorParameters(narrowed)) {
		t.Fatal("narrowed private paths matched the anchor")
	}
	if !sameParameters(a, anchorParameters(c)) {
		t.Fatal("unchanged parameters differ")
	}
}

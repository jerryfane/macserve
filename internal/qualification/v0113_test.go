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
	good := Report{Schema: schema, ChallengeSHA256: "h", Role: "job", Mode: jobProbeMode, UID: 502, AuditUID: 502, AuditSession: 100010, Groups: []int{20}, Started: now, Finished: now.Add(time.Second)}
	if err := checkReport(good, c, "h", "job"); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Report){
		"foreground job console": func(r *Report) { r.ConsoleUID = 502 },
		"full memberships":       func(r *Report) { r.Groups = []int{12, 20, 61} },
		"default audit session":  func(r *Report) { r.AuditSession = 0 },
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

func TestLauncherProvenanceAcceptsOnlyJobAuditUserOrJobGUISession(t *testing.T) {
	const job, gui = 6202, int32(100010)
	for name, c := range map[string]struct {
		auid    uint32
		asid    int32
		session int32
		want    string
	}{
		"asuser sets job audit user":        {job, gui, gui, provenanceAuditUser},
		"asuser joins job GUI session only": {0, gui, gui, provenanceGUISession},
		"sudo from owner terminal":          {501, 100002, gui, ""},
		"root ssh":                          {0, 100500, gui, ""},
		"session unmeasured":                {0, gui, 0, ""},
		"default session":                   {0, 0, 0, ""},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := launcherProvenance(c.auid, c.asid, job, c.session)
			if got != c.want || (err == nil) != (c.want != "") {
				t.Fatalf("provenance %q err %v, want %q", got, err, c.want)
			}
		})
	}
}

func TestGUISessionMeasurementsMustAgree(t *testing.T) {
	if _, err := combineSessionASID(100010, 100011); err == nil {
		t.Fatal("disagreeing measurements accepted")
	}
	for _, c := range [][3]int32{{100010, 100010, 100010}, {100010, 0, 100010}, {0, 100010, 100010}} {
		if got, err := combineSessionASID(c[0], c[1]); err != nil || got != c[2] {
			t.Fatalf("%v: %d %v", c, got, err)
		}
	}
	if _, err := combineSessionASID(0, 0); err == nil {
		t.Fatal("unmeasured session accepted")
	}
}

func TestLaunchdSecurityContextParse(t *testing.T) {
	text := "gui/6202 = {\n\ttype = login\n\thandle = 100010\n\tsecurity context = {\n\t\tuid = 6202\n\t\tasid = 100010\n\t}\n\n\tservices = {\n\t\tasid = 7\n\t}\n}\n"
	if asid, err := parseSecurityContextASID(text, 6202); err != nil || asid != 100010 {
		t.Fatal(asid, err)
	}
	if _, err := parseSecurityContextASID(text, 501); err == nil {
		t.Fatal("security context of another uid accepted")
	}
	if _, err := parseSecurityContextASID("gui/6202 = {\n}\n", 6202); err == nil {
		t.Fatal("missing security context accepted")
	}
}

func TestLaunchRecordProvenanceIsRederived(t *testing.T) {
	l := JobProbeLaunch{LauncherAuditUID: 0, LauncherAuditSession: 100010, Provenance: provenanceGUISession, GUISession: guiSession{ASID: 100010}}
	if !launchProvenanceValid(l, 6202) {
		t.Fatal("valid GUI-session launch rejected")
	}
	l.GUISession.ASID = 100011
	if launchProvenanceValid(l, 6202) {
		t.Fatal("launch record with a foreign session accepted")
	}
	l = JobProbeLaunch{LauncherAuditUID: 501, LauncherAuditSession: 100002, Provenance: provenanceAuditUser}
	if launchProvenanceValid(l, 6202) {
		t.Fatal("owner sudo launch accepted")
	}
}

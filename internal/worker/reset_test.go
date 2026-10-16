package worker

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/launchctlprint"
)

const (
	loginwindowPath = "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow"
	dockPath        = "/System/Library/CoreServices/Dock.app/Contents/MacOS/Dock"
	finderPath      = "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"
	terminalPath    = "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal"
	teaLabel        = "com.apple.TrustEvaluationAgent"
	teaPath         = "/System/Library/PrivateFrameworks/TrustEvaluationAgent.framework/Versions/A/Resources/trustevaluationagent"
	helperPath      = "/System/Library/PrivateFrameworks/Helper.framework/helper"
)

var (
	teaTarget    = "user/" + strconv.Itoa(testJobUID) + "/" + teaLabel
	finderTarget = "gui/" + strconv.Itoa(testJobUID) + "/com.apple.Finder"
)

// The Mac Studio's trustevaluationagent: a Background-session LaunchAgent
// (LimitLoadToSessionType=Background, MachServices, no KeepAlive) that launchd
// runs in the job's user domain and starts again on demand.
func teaService() LaunchdService {
	return LaunchdService{Domain: "user", Label: teaLabel, Path: "/System/Library/LaunchAgents/" + teaLabel + ".plist", Executable: teaPath, LaunchSHA256: agentLaunch}
}

func finderService() LaunchdService {
	return LaunchdService{Domain: "gui", Label: "com.apple.Finder", Path: "/System/Library/LaunchAgents/com.apple.Finder.plist", Executable: finderPath, LaunchSHA256: agentLaunch}
}

// resetWorld is the job GUI session root sees at worker-reset: the anchors
// loginwindow (50), Dock (51), Finder (52, a KeepAlive gui LaunchAgent) and the
// administrator's Terminal (53) with its zsh (54); trustevaluationagent (60);
// a platform helper with no launchd record (61); an escaped job process (200)
// and an owner process (300). Killing a process launchd reports for a service
// relaunches it under a new PID (see host).
func resetWorld() (*processScope, *fakeAgents, *launchdHost) {
	agents := &fakeAgents{procs: map[int]agentProcess{}, reread: map[int]agentProcess{}, reads: map[int]int{}, services: map[string]launchctlprint.Snapshot{}, owners: map[int]int{}}
	for pid, path := range map[int]string{50: loginwindowPath, 51: dockPath, 53: terminalPath, 54: "/bin/zsh", 61: helperPath} {
		agents.procs[pid] = agentProcess{start: "1:" + strconv.Itoa(pid), uid: testJobUID, ppid: 1, executable: path, platform: true}
	}
	agents.run(52, "1:52", finderService(), "com.apple.Finder")
	agents.publish(finderTarget, 52, finderService().Path, "LaunchAgent")
	agents.run(60, "1:60", teaService(), teaLabel)
	agents.publish(teaTarget, 60, teaService().Path, "LaunchAgent")
	agents.procs[200] = agentProcess{start: "30:0", uid: testJobUID, ppid: 1, executable: "/bin/sleep", platform: true, launch: poisonedLaunch}
	scope := &processScope{uid: testJobUID, agents: agents, interval: time.Millisecond, grace: time.Millisecond}
	var rows []processSample
	for _, pid := range []int{50, 51, 52, 53, 54, 60, 61} {
		rows = append(rows, sample(pid, "1:"+strconv.Itoa(pid)))
	}
	rows = append(rows, sample(200, "30:0"), processSample{pid: 300, uid: 999, start: "owner"})
	return scope, agents, host(scope, agents, rows)
}

var resetSelection = []int{50, 51, 52, 53, 54, 60, 61}

func runReset(s *processScope, pids []int, cleanup func(context.Context) error) ([]ProcessIdentity, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	b, err := s.resetBaseline(ctx, pids, func() (string, error) { return "boot", nil }, cleanup)
	return b.Processes, err
}

func hasPID(processes []ProcessIdentity, pid int) bool {
	return slices.ContainsFunc(processes, func(p ProcessIdentity) bool { return p.PID == pid })
}

func TestResetAuditsSelectedProcessesAndRemovesOnlyOtherJobUIDs(t *testing.T) {
	s, _, h := resetWorld()
	got, err := runReset(s, resetSelection, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	want := []ProcessIdentity{{PID: 50, Start: "1:50"}, {PID: 51, Start: "1:51"}, {PID: 52, Start: "1:52", Service: finderService()}, {PID: 53, Start: "1:53"}, {PID: 54, Start: "1:54"}, {PID: 60, Start: "1:60", Service: teaService()}, {PID: 61, Start: "1:61"}}
	if !slices.Equal(got, want) {
		t.Fatalf("baseline = %+v, want %+v", got, want)
	}
	if !slices.Equal(h.signalled, []int{200}) || !slices.ContainsFunc(h.rows, func(p processSample) bool { return p.uid == 999 }) {
		t.Fatalf("reset targeted selected or foreign identity: signalled %v rows %+v", h.signalled, h.rows)
	}
}

// Mac Studio, v0.1.9: the selected trustevaluationagent exited during reset
// and launchd relaunched it; reset could not verify the relaunch and failed.
// Provenance is now recorded before cleanup, so the relaunch is verified and
// recorded in its place.
func TestResetKeepsVerifiedRelaunchOfSelectedHelper(t *testing.T) {
	s, _, h := resetWorld()
	got, err := runReset(s, resetSelection, func(context.Context) error { h.exit(60); return nil })
	if err != nil {
		t.Fatalf("reset = %v", err)
	}
	relaunch := ProcessIdentity{PID: 1001, Start: "1001:0", Service: teaService()}
	if !slices.Contains(got, relaunch) || hasPID(got, 60) {
		t.Fatalf("baseline = %+v, want relaunch %+v instead of 60", got, relaunch)
	}
	if !slices.Equal(h.signalled, []int{200}) {
		t.Fatalf("cleanup targets: %v", h.signalled)
	}
}

// A selected helper that exits during reset is dropped. A replacement that
// cannot be verified as launchd's relaunch is an unselected job process,
// terminated like any other.
func TestResetDropsSelectedHelperThatExits(t *testing.T) {
	for name, tc := range map[string]struct {
		replacement bool
		signalled   []int
	}{
		"no relaunch":                      {false, []int{200}},
		"relaunch that cannot be verified": {true, []int{200, 62}},
	} {
		t.Run(name, func(t *testing.T) {
			s, agents, h := resetWorld()
			got, err := runReset(s, resetSelection, func(context.Context) error {
				h.exit(61)
				if tc.replacement {
					agents.procs[62] = agentProcess{start: "40:0", uid: testJobUID, ppid: 1, executable: helperPath, platform: true}
					h.rows = append(h.rows, sample(62, "40:0"))
				}
				return nil
			})
			if err != nil {
				t.Fatalf("reset = %v", err)
			}
			if hasPID(got, 61) || hasPID(got, 62) || !hasPID(got, 60) {
				t.Fatalf("baseline = %+v", got)
			}
			slices.Sort(h.signalled)
			want := slices.Sorted(slices.Values(tc.signalled))
			if !slices.Equal(h.signalled, want) {
				t.Fatalf("cleanup targets: %v, want %v", h.signalled, want)
			}
		})
	}
}

// A requested PID already gone at reset start cannot be part of a baseline.
func TestResetDropsRequestedPIDAbsentAtStart(t *testing.T) {
	s, _, _ := resetWorld()
	got, err := runReset(s, append(slices.Clone(resetSelection), 70), func(context.Context) error { return nil })
	if err != nil || hasPID(got, 70) || len(got) != len(resetSelection) {
		t.Fatalf("reset = %+v, %v", got, err)
	}
}

// Guard: the GUI anchors must survive the reset unchanged, even when launchd
// verifiably relaunches one (Finder is KeepAlive).
func TestResetFailsWhenGUIAnchorExits(t *testing.T) {
	for name, pid := range map[string]int{"loginwindow": 50, "Finder relaunched by launchd": 52, "selected shell": 54} {
		t.Run(name, func(t *testing.T) {
			s, _, h := resetWorld()
			if _, err := runReset(s, resetSelection, func(context.Context) error { h.exit(pid); return nil }); err == nil {
				t.Fatal("reset accepted a changed GUI session")
			}
		})
	}
}

// Guard: survivors after termination still fail closed with the PR #28 F2
// classification: contamination when every audited process is accounted for,
// inconclusive (ErrCleanup) when a selected service's relaunch fails the rule.
func TestResetStillFailsClosedOnPersistentResidual(t *testing.T) {
	t.Run("job process survives termination", func(t *testing.T) {
		s, _, _ := resetWorld()
		s.signal = func(context.Context, processSample, syscall.Signal) error { return nil }
		if _, err := runReset(s, resetSelection, func(context.Context) error { return nil }); !errors.Is(err, ErrContamination) {
			t.Fatalf("reset = %v, want contamination", err)
		}
	})
	t.Run("relaunch after launchctl setenv keeps coming back", func(t *testing.T) {
		s, agents, h := resetWorld()
		_, err := runReset(s, resetSelection, func(context.Context) error {
			p := agents.procs[60]
			p.launch = poisonedLaunch
			agents.procs[60] = p
			h.exit(60)
			return nil
		})
		if !errors.Is(err, ErrCleanup) || errors.Is(err, ErrContamination) {
			t.Fatalf("reset = %v, want cleanup failure without contamination", err)
		}
	})
}

func TestResetRefusesUnsafeSelectionsBeforeCleanup(t *testing.T) {
	for name, pids := range map[string][]int{
		"empty":          nil,
		"duplicate":      append(slices.Clone(resetSelection), 50),
		"launchd":        append(slices.Clone(resetSelection), 1),
		"another UID":    append(slices.Clone(resetSelection), 300),
		"zombie":         append(slices.Clone(resetSelection), 62),
		"without Finder": {50, 51, 53, 54, 60},
	} {
		t.Run(name, func(t *testing.T) {
			s, _, h := resetWorld()
			h.rows = append(h.rows, processSample{pid: 62, uid: testJobUID, start: "40:0", zombie: true})
			_, err := runReset(s, pids, func(context.Context) error {
				t.Fatal("unsafe selection reached persistence cleanup")
				return nil
			})
			if err == nil || len(h.signalled) != 0 {
				t.Fatalf("unsafe audited selection accepted: %v signalled %v", err, h.signalled)
			}
		})
	}
}

// Guard: a selected PID taken over by another process, another UID or a
// zombie during reset is refused, never dropped or signalled.
func TestResetRejectsSelectedIdentityChangeDuringCleanup(t *testing.T) {
	for name, change := range map[string]func(*processSample){
		"reused":  func(p *processSample) { p.start = "reused-pid" },
		"foreign": func(p *processSample) { p.uid = 999 },
		"zombie":  func(p *processSample) { p.zombie = true },
	} {
		t.Run(name, func(t *testing.T) {
			s, agents, h := resetWorld()
			_, err := runReset(s, resetSelection, func(context.Context) error {
				delete(agents.procs, 61)
				i := slices.IndexFunc(h.rows, func(p processSample) bool { return p.pid == 61 })
				change(&h.rows[i])
				return nil
			})
			if err == nil || errors.Is(err, ErrContamination) || len(h.signalled) != 0 {
				t.Fatalf("reset = %v, signalled %v", err, h.signalled)
			}
		})
	}
}

package worker

import (
	"context"
	"errors"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/launchctlprint"
)

// realAgent runs pid as captured (UID 501): its root `launchctl print` and
// KERN_PROCARGS2, rebound to testJobUID and pid.
func realAgent(t *testing.T, agents *fakeAgents, pid int, start, executable, print, procargs string) LaunchdService {
	t.Helper()
	launch := launchFixture(t, "testdata/procargs2/"+procargs)
	agents.procs[pid] = agentProcess{start: start, uid: testJobUID, ppid: 1, executable: executable, platform: true, launch: launch.digest, program: launch.program, argv: launch.argv}
	text, err := os.ReadFile("../launchctlprint/testdata/" + print)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := launchctlprint.Parse(string(text))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(snapshot.Target, "/", 3)
	snapshot.Target, snapshot.PID = parts[0]+"/"+strconv.Itoa(testJobUID)+"/"+parts[2], pid
	agents.services[snapshot.Target] = snapshot
	return LaunchdService{Domain: parts[0], Label: parts[2], Path: snapshot.Path, Executable: executable, LaunchSHA256: launch.digest, InheritedSHA256: inheritedDigest(snapshot.Inherited)}
}

// realResetWorld is resetWorld with Finder (52) and trustevaluationagent (60)
// as captured.
func realResetWorld(t *testing.T) (*processScope, *fakeAgents, *launchdHost, LaunchdService) {
	s, agents, h := resetWorld()
	realAgent(t, agents, 52, "1:52", finderPath, "gui-finder.txt", "finder.bin")
	tea := realAgent(t, agents, 60, "1:60", teaPath, "user-trustevaluationagent.txt", "trustevaluationagent.bin")
	return s, agents, h, tea
}

func resetResult(s *processScope, pids []int, cleanup func(context.Context) error) (ResetResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return s.resetBaseline(ctx, pids, func() (string, error) { return "boot", nil }, cleanup)
}

// Mac Studio, v0.1.9: with trustevaluationagent excluded from the selection,
// reset terminated it, launchd started it again on demand (MachServices) and
// reset failed with contamination. Its provenance is now recorded before
// cleanup; the instance is still terminated and launchd's relaunch is kept.
func TestResetAdoptsLaunchdRespawnOfExcludedSystemAgent(t *testing.T) {
	s, _, h, tea := realResetWorld(t)
	result, err := resetResult(s, []int{50, 51, 52, 53, 54, 61}, func(context.Context) error { return nil })
	if err != nil {
		t.Fatalf("reset = %v", err)
	}
	relaunch := ProcessIdentity{PID: 1001, Start: "1001:0", Service: tea}
	if !slices.Equal(result.Adopted, []ProcessIdentity{relaunch}) || !slices.Contains(result.Processes, relaunch) {
		t.Fatalf("adopted %+v, baseline %+v", result.Adopted, result.Processes)
	}
	slices.Sort(h.signalled)
	if !slices.Equal(h.signalled, []int{60, 200}) {
		t.Fatalf("cleanup targets: %v", h.signalled)
	}
	if err := validateBaseline(result.GUIBaseline, testJobUID, "boot"); err != nil {
		t.Fatal(err)
	}
}

// An unselected system LaunchAgent that launchd starts on demand during reset
// is adopted only with launchd's record of the system plist, its program and
// the inherited environment launchctl prints for the selected agents of its
// domain. Anything else is terminated; launchd starting it again then fails
// reset closed. A `launchctl setenv` appears in launchd's record, never only in
// the process: its environment is not read.
func TestResetAdoptsOnlyCleanSystemLaunchAgentsStartedDuringReset(t *testing.T) {
	for name, tc := range map[string]struct {
		print   string
		mutate  func(*launchctlprint.Snapshot)
		adopted bool
	}{
		"clean on-demand launch": {"gui-corespeechd-session.txt", nil, true},
		"after launchctl setenv": {"gui-corespeechd-setenv.txt", nil, false},
		"job LaunchAgents plist copy": {"gui-corespeechd-session.txt", func(s *launchctlprint.Snapshot) {
			s.Path = "/Users/job/Library/LaunchAgents/com.apple.corespeechd.plist"
		}, false},
		"launchctl submit":              {"gui-corespeechd-session.txt", func(s *launchctlprint.Snapshot) { s.Path, s.Type = "(submitted by launchctl[7])", "Submitted" }, false},
		"program differs from record":   {"gui-corespeechd-session.txt", func(s *launchctlprint.Snapshot) { s.Program = "/bin/sh" }, false},
		"arguments differ from record":  {"gui-corespeechd-session.txt", func(s *launchctlprint.Snapshot) { s.Arguments = append(s.Arguments, "--debug") }, false},
		"inherited environment missing": {"gui-corespeechd-session.txt", func(s *launchctlprint.Snapshot) { s.Inherited = nil }, false},
	} {
		t.Run(name, func(t *testing.T) {
			s, agents, h, _ := realResetWorld(t)
			result, err := resetResult(s, resetSelection, func(context.Context) error {
				realAgent(t, agents, 400, "50:0", speechExecutable, tc.print, "corespeechd-session.bin")
				if tc.mutate != nil {
					snapshot := agents.services[speechAgentTarget]
					tc.mutate(&snapshot)
					agents.services[speechAgentTarget] = snapshot
				}
				h.rows = append(h.rows, sample(400, "50:0"))
				return nil
			})
			if tc.adopted {
				if err != nil || !hasPID(result.Adopted, 400) || !hasPID(result.Processes, 400) || slices.Contains(h.signalled, 400) {
					t.Fatalf("reset = %+v, %v; signalled %v", result, err, h.signalled)
				}
				return
			}
			if !slices.Contains(h.signalled, 400) || err == nil {
				t.Fatalf("unverifiable agent kept: %v; signalled %v", err, h.signalled)
			}
			if tc.mutate == nil && !errors.Is(err, ErrContamination) {
				t.Fatalf("reset = %v, want contamination", err)
			}
		})
	}
}

// The reset result records each way the baseline differs from the selection.
func TestResetResultRecordsWhatChanged(t *testing.T) {
	t.Run("dropped and relaunched", func(t *testing.T) {
		s, _, h := resetWorld()
		result, err := resetResult(s, append(slices.Clone(resetSelection), 70), func(context.Context) error {
			h.exit(61)
			h.exit(60)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		dropped := []DroppedProcess{{PID: 70, Reason: "absent at reset start"}, {PID: 61, Start: "1:61", Path: helperPath, Reason: "exited during reset; no launchd provenance to verify a relaunch"}}
		relaunched := []Relaunch{{Exited: ProcessIdentity{PID: 60, Start: "1:60", Service: teaService()}, Relaunch: ProcessIdentity{PID: 1001, Start: "1001:0", Service: teaService()}}}
		if !slices.Equal(result.Dropped, dropped) || !slices.Equal(result.Relaunched, relaunched) || len(result.Exited) != 0 || len(result.Adopted) != 0 {
			t.Fatalf("result = %+v", result)
		}
	})
	// A selected service that exits without a relaunch yet keeps its
	// provenance, so launchd's later on-demand relaunch is verified.
	t.Run("exited with provenance", func(t *testing.T) {
		s, agents, h := resetWorld()
		result, err := resetResult(s, resetSelection, func(context.Context) error {
			delete(agents.services, teaTarget)
			h.exit(60)
			return nil
		})
		exited := ProcessIdentity{PID: 60, Start: "1:60", Service: teaService()}
		if err != nil || !slices.Equal(result.Exited, []ProcessIdentity{exited}) || !slices.Contains(result.Processes, exited) || len(result.Dropped) != 0 {
			t.Fatalf("result = %+v, %v", result, err)
		}
	})
}

// The final reset audit (replacing v0.1.9's auditedBaseline census) takes two
// snapshots on one boot. Between them, a new unadoptable job process, a
// selected PID reused or moved to another UID, an unreadable snapshot or a
// changed boot refuses; a selected non-anchor helper that exits is dropped.
func TestResetAuditRequiresStableUIDStartAndBootCensus(t *testing.T) {
	for _, mode := range []string{"stable", "unlisted", "reused", "foreign", "disappeared", "boot", "unreadable"} {
		t.Run(mode, func(t *testing.T) {
			s, _, h := resetWorld()
			h.rows = slices.DeleteFunc(h.rows, func(p processSample) bool { return p.pid == 200 })
			var selected []ProcessIdentity
			for _, pid := range resetSelection {
				selected = append(selected, ProcessIdentity{PID: pid, Start: "1:" + strconv.Itoa(pid)})
			}
			s.baseline = GUIBaseline{JobUID: testJobUID, Boot: "boot", Processes: selected, Launchd: &LaunchdEnvironment{GUI: map[string]string{}, User: map[string]string{}}}
			anchors := map[int]string{50: "1:50", 51: "1:51", 52: "1:52", 53: "1:53", 54: "1:54"}
			calls, boots := 0, 0
			s.sample = func(context.Context) ([]processSample, error) {
				calls++
				rows := slices.Clone(h.rows)
				if calls == 2 {
					i := slices.IndexFunc(rows, func(p processSample) bool { return p.pid == 61 })
					switch mode {
					case "unlisted":
						rows = append(rows, sample(201, "extra"))
					case "reused":
						rows[i].start = "reused"
					case "foreign":
						rows[i].uid = 999
					case "disappeared":
						rows = slices.Delete(rows, i, i+1)
					case "unreadable":
						return nil, syscall.EPERM
					}
				}
				return rows, nil
			}
			boot := func() (string, error) {
				boots++
				if mode == "boot" {
					return "new", nil
				}
				return "boot", nil
			}
			result, err := s.auditReset(context.Background(), anchors, map[int]string{61: helperPath}, boot, "boot")
			switch mode {
			case "stable":
				if err != nil || !slices.Equal(result.Processes, selected) || calls != 2 || boots != 1 {
					t.Fatalf("stable census: %+v %v calls=%d boots=%d", result, err, calls, boots)
				}
			case "disappeared":
				if err != nil || hasPID(result.Processes, 61) || len(result.Dropped) != 1 || result.Dropped[0].PID != 61 {
					t.Fatalf("exited helper: %+v %v", result, err)
				}
			default:
				if err == nil {
					t.Fatal("changed census adopted")
				}
			}
		})
	}
}

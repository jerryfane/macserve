package worker

import (
	"context"
	"errors"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/launchctlprint"
)

// realAgent runs pid as captured on macOS 26.6 (one session, UID 501): its
// root `launchctl print` and KERN_PROCARGS2, rebound to testJobUID and pid.
func realAgent(t *testing.T, agents *fakeAgents, pid int, start, executable, print, procargs string) LaunchdService {
	t.Helper()
	launch := launchFixture(t, "testdata/procargs2/"+procargs)
	agents.procs[pid] = agentProcess{start: start, uid: testJobUID, ppid: 1, executable: executable, platform: true, label: launch.label, launch: launch.digest, program: launch.program, argv: launch.argv, env: launch.env}
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
	return LaunchdService{Domain: parts[0], Label: parts[2], Path: snapshot.Path, Executable: executable, LaunchSHA256: launch.digest}
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
// the domain environment of the selected agents. Anything else is terminated;
// launchd starting it again then fails reset closed.
func TestResetAdoptsOnlyCleanSystemLaunchAgentsStartedDuringReset(t *testing.T) {
	for name, tc := range map[string]struct {
		procargs string
		mutate   func(*launchctlprint.Snapshot)
		adopted  bool
	}{
		"clean on-demand launch": {"corespeechd-session.bin", nil, true},
		"after launchctl setenv": {"corespeechd-session-setenv.bin", nil, false},
		"job LaunchAgents plist copy": {"corespeechd-session.bin", func(s *launchctlprint.Snapshot) {
			s.Path = "/Users/job/Library/LaunchAgents/com.apple.corespeechd.plist"
		}, false},
		"launchctl submit":             {"corespeechd-session.bin", func(s *launchctlprint.Snapshot) { s.Path, s.Type = "(submitted by launchctl[7])", "Submitted" }, false},
		"program differs from record":  {"corespeechd-session.bin", func(s *launchctlprint.Snapshot) { s.Program = "/bin/sh" }, false},
		"arguments differ from record": {"corespeechd-session.bin", func(s *launchctlprint.Snapshot) { s.Arguments = append(s.Arguments, "--debug") }, false},
		"environment record missing":   {"corespeechd-session.bin", func(s *launchctlprint.Snapshot) { s.Environment = nil }, false},
	} {
		t.Run(name, func(t *testing.T) {
			s, agents, h, _ := realResetWorld(t)
			result, err := resetResult(s, resetSelection, func(context.Context) error {
				realAgent(t, agents, 400, "50:0", speechExecutable, "gui-corespeechd-session.txt", tc.procargs)
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

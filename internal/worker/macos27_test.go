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

	"github.com/jerryfane/macserve/internal/launchctlprint"
)

// procargsAgents is nativeAgents over captured bytes: kernel facts from a
// table, and process() adds what launchIdentity parses from the captured
// KERN_PROCARGS2, failing as nativeAgents does when the bytes do not parse.
type procargsAgents struct {
	*fakeAgents
	raw map[int][]byte
}

func (a procargsAgents) process(pid int) (agentProcess, error) {
	facts, err := a.kernel(pid)
	if err != nil {
		return agentProcess{}, err
	}
	launch, err := launchIdentity(a.raw[pid])
	if err != nil {
		return agentProcess{}, err
	}
	facts.launch, facts.program, facts.argv = launch.digest, launch.program, launch.argv
	return facts, nil
}

func capturedArgs(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/procargs2/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Mac Studio, macOS 27.0 (26A428), SIP enabled: KERN_PROCARGS2 of the GUI
// session's loginwindow, Dock and Finder ends after argv (no environment, no
// terminator) because they are CS_RESTRICT (csops 0x26017b01). v0.1.10 parsed
// it as part of anchor selection and refused every correct selection with
// "audited selection lacks the job GUI's running loginwindow".
func TestSelectAnchorsFromMacOS27ProcessArguments(t *testing.T) {
	agents := procargsAgents{fakeAgents: newFakeAgents(), raw: map[int][]byte{}}
	b := GUIBaseline{JobUID: testJobUID, Boot: "boot"}
	for pid, c := range map[int]struct{ path, file string }{
		50: {loginwindowPath, "macos27-loginwindow.bin"},
		51: {dockPath, "macos27-dock.bin"},
		52: {finderPath, "macos27-finder.bin"},
	} {
		start := "1:" + strconv.Itoa(pid)
		agents.procs[pid] = agentProcess{start: start, uid: testJobUID, ppid: 1, executable: c.path, platform: true}
		agents.raw[pid] = capturedArgs(t, c.file)
		b.Processes = append(b.Processes, ProcessIdentity{PID: pid, Start: start})
	}
	anchors, paths, err := selectAnchors(agents, b)
	if err != nil || len(anchors) != 3 || paths[50] != loginwindowPath || paths[51] != dockPath || paths[52] != finderPath {
		t.Fatalf("anchors = %v, paths = %v, err = %v", anchors, paths, err)
	}
}

// macos27Print returns a captured macOS 27.0 launchctl print, rebound to
// testJobUID and pid. trustevaluationagent was not running when captured;
// its run state is set as launchctl prints it for a running instance.
func macos27Print(t *testing.T, name string, pid int) launchctlprint.Snapshot {
	t.Helper()
	text, err := os.ReadFile("../launchctlprint/testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	print := strings.Replace(strings.Replace(string(text), "\tstate = not running\n", "\tstate = running\n", 1), "\truns = 188\n", "\truns = 189\n\tpid = 4242\n", 1)
	snapshot, err := launchctlprint.Parse(print)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(snapshot.Target, "/", 3)
	snapshot.Target, snapshot.PID = parts[0]+"/"+strconv.Itoa(testJobUID)+"/"+parts[2], pid
	return snapshot
}

// macos27World is resetWorld on the Mac Studio's macOS 27.0: Dock (51),
// Finder (52) and trustevaluationagent (60) run as launchctl printed them
// there, with KERN_PROCARGS2 that ends after argv (trustevaluationagent's is
// its macOS 26.6 capture cut after argv, which for Finder gives exactly the
// macOS 27.0 capture).
func macos27World(t *testing.T) (*processScope, procargsAgents, *launchdHost) {
	s, fake, h := resetWorld()
	agents := procargsAgents{fakeAgents: fake, raw: map[int][]byte{}}
	s.agents = agents
	for _, c := range []struct {
		pid              int
		path, print, raw string
	}{
		{51, dockPath, "macos27-gui-dock.txt", "macos27-dock.bin"},
		{52, finderPath, "macos27-gui-finder.txt", "macos27-finder.bin"},
		{60, teaPath, "macos27-user-trustevaluationagent.txt", "macos27-trustevaluationagent.bin"},
	} {
		agents.procs[c.pid] = agentProcess{start: "1:" + strconv.Itoa(c.pid), uid: testJobUID, ppid: 1, executable: c.path, platform: true}
		agents.raw[c.pid] = capturedArgs(t, c.raw)
		snapshot := macos27Print(t, c.print, c.pid)
		agents.services[snapshot.Target] = snapshot
	}
	agents.env["gui/"+strconv.Itoa(testJobUID)] = map[string]string{"SSH_AUTH_SOCK": "/var/run/com.apple.launchd.GWnys7uPgY/Listeners"}
	return s, agents, h
}

// The v0.1.10 Studio failure on macOS 27.0: the selected trustevaluationagent
// exits during reset and launchd starts it again. Its provenance comes from
// launchd's record and the argv-only launch identity, so the relaunch is kept.
func TestMacOS27ResetKeepsVerifiedRelaunchOfSelectedAgent(t *testing.T) {
	s, agents, h := macos27World(t)
	result, err := resetResult(s, resetSelection, func(context.Context) error {
		h.exit(60)
		agents.raw[h.next] = agents.raw[60]
		return nil
	})
	if err != nil {
		t.Fatalf("reset = %v", err)
	}
	if len(result.Relaunched) != 1 || result.Relaunched[0].Exited.PID != 60 || result.Relaunched[0].Relaunch.PID != h.next || result.Relaunched[0].Relaunch.Service.Label != teaLabel {
		t.Fatalf("result = %+v", result)
	}
	if err := validateBaseline(result.GUIBaseline, testJobUID, "boot"); err != nil {
		t.Fatal(err)
	}
}

// A job process whose KERN_PROCARGS2 also ends after argv (every system
// binary on a SIP-enabled macOS 27 host) still never passes as launchd's
// relaunch: identity comes from launchd's record of the SIP-protected plist.
func TestMacOS27JobProcessIsNotALaunchdRelaunch(t *testing.T) {
	submitted, err := os.ReadFile("../launchctlprint/testdata/macos27-gui-submitted.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := launchctlprint.Parse(string(submitted)); err == nil {
		t.Fatal("launchctl submit record parsed as a service")
	}
	for name, mutate := range map[string]func(procargsAgents, int){
		"job runs the Apple binary itself": func(a procargsAgents, pid int) {
			p := a.procs[pid]
			p.ppid = 200
			a.procs[pid] = p
		},
		"job LaunchAgents plist copy": func(a procargsAgents, pid int) {
			s := a.services[teaTarget]
			s.Path = "/Users/job/Library/LaunchAgents/" + teaLabel + ".plist"
			a.services[teaTarget] = s
		},
		"launchctl submit": func(a procargsAgents, _ int) {
			delete(a.services, teaTarget)
		},
		"launchctl setenv in the inherited environment": func(a procargsAgents, _ int) {
			s := a.services[teaTarget]
			s.Inherited = map[string]string{"PROBE_ENV": "poisoned"}
			a.services[teaTarget] = s
		},
		"other argv": func(a procargsAgents, pid int) {
			a.raw[pid] = capturedArgs(t, "macos27-loginwindow.bin")
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, agents, h := macos27World(t)
			s.baseline = describeServices(context.Background(), agents, testJobUID, GUIBaseline{JobUID: testJobUID, Boot: "boot", Processes: []ProcessIdentity{{PID: 52, Start: "1:52"}, {PID: 60, Start: "1:60"}}})
			if s.baseline.Processes[1].Service.Label != teaLabel {
				t.Fatalf("no provenance: %+v", s.baseline.Processes[1])
			}
			h.exit(60)
			pid := h.next
			agents.raw[pid] = agents.raw[60]
			mutate(agents, pid)
			if got := residualPIDs(t, s, h.rows); !slices.Contains(got, pid) {
				t.Fatalf("residual = %v; %d accepted as launchd's relaunch", got, pid)
			}
		})
	}
}

// `launchctl setenv` in the job's gui or user domain after reset reaches every
// later launch there and is contamination at every census: reset audit,
// cleanup, admission and health. An unreadable domain is inconclusive.
func TestLaunchdDomainEnvironmentChangeIsContamination(t *testing.T) {
	uid := strconv.Itoa(testJobUID)
	s, agents, h := macos27World(t)
	result, err := resetResult(s, resetSelection, func(context.Context) error { return nil })
	if err != nil || result.Launchd == nil || result.Launchd.GUI["SSH_AUTH_SOCK"] == "" || len(result.Launchd.User) != 0 {
		t.Fatalf("reset = %+v, %v", result.Launchd, err)
	}
	s.baseline = result.GUIBaseline
	if err := s.observeQuiet(context.Background()); err != nil {
		t.Fatalf("unchanged domain refused: %v", err)
	}
	for _, domain := range []string{"gui/" + uid, "user/" + uid} {
		saved := agents.env[domain]
		agents.env[domain] = map[string]string{"PROBE_ENV": "poisoned"}
		if err := s.observeQuiet(context.Background()); !errors.Is(err, ErrContamination) {
			t.Fatalf("%s setenv: admission = %v", domain, err)
		}
		if _, err := s.residual(context.Background(), h.rows); !errors.Is(err, ErrContamination) {
			t.Fatalf("%s setenv: census = %v", domain, err)
		}
		agents.env[domain] = saved
	}
	s.agents = failingDomains{agents}
	if err := s.observeQuiet(context.Background()); err == nil || errors.Is(err, ErrContamination) {
		t.Fatalf("unreadable domain: %v", err)
	}
}

type failingDomains struct{ procargsAgents }

func (failingDomains) domain(context.Context, string) (launchctlprint.Domain, error) {
	return launchctlprint.Domain{}, syscall.EPERM
}

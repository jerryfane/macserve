package worker

import (
	"context"
	"errors"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/launchctlprint"
)

// The macOS 27.0 developer-tool stack launchd brought back about 9 s after
// quiesce on the Mac Studio: CoreSimulatorService in user/<job>, its
// SimAudioProcessorService in pid/<CoreSimulatorService>, and the DeviceFS
// extension in the pid domain of fskit_agent (6397, audited here). DeviceFS
// is launchd's real print (launchctlprint testdata).
const (
	simFramework   = "/Library/Developer/PrivateFrameworks/CoreSimulator.framework/Versions/A"
	simLabel       = "com.apple.CoreSimulator.CoreSimulatorService"
	simBundle      = simFramework + "/XPCServices/" + simLabel + ".xpc"
	simProgram     = simBundle + "/Contents/MacOS/" + simLabel
	audioLabel     = "com.apple.CoreSimulator.SimAudioProcessorServices.SimAudioProcessorService"
	audioBundle    = simFramework + "/Resources/SimAudioProcessorServices.simdeviceio/Contents/XPCServices/SimAudioProcessorService.xpc"
	audioProgram   = audioBundle + "/Contents/MacOS/SimAudioProcessorService"
	fskitPID       = 6397
	deviceFSPID    = 67438
	deviceFSTarget = "pid/6397/com.apple.dt.CoreDevice.Extensions.DeviceFS.00000000-0000-0000-0000-000000000001"
	deviceFSID     = "com.apple.dt.CoreDevice.Extensions.DeviceFS"
	simPID         = 500
	audioPID       = 501
	mountPID       = 502
	jobTMPDIR      = "/var/folders/zz/zyxvpxvq6csfxvn_n0000000000000/T/"
)

func jobXPCEnvironment() map[string]string {
	return map[string]string{"HOME": "/Users/macservejob", "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "TMPDIR": jobTMPDIR}
}

func devtoolWorld(t *testing.T) (*processScope, *fakeAgents, []processSample) {
	t.Helper()
	agents := newFakeAgents()
	user := "user/" + strconv.Itoa(testJobUID)
	gui := "gui/" + strconv.Itoa(testJobUID)
	agents.disabled[gui] = map[string]string{"com.apple.Siri.agent": "disabled"}
	agents.xpcEnv = jobXPCEnvironment()
	agents.procs[100] = agentProcess{start: "10:0", uid: testJobUID, ppid: 1, executable: "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder", platform: true}
	agents.procs[fskitPID] = agentProcess{start: "10:1", uid: testJobUID, ppid: 1, executable: "/System/Library/Frameworks/FSKit.framework/Versions/A/Support/fskit_agent", platform: true}

	add := func(pid int, target, bundle, program, id, kind string, argv []string, inherited map[string]string) {
		agents.procs[pid] = agentProcess{start: "50:" + strconv.Itoa(pid), uid: testJobUID, ppid: 1, executable: program, platform: true, program: program, argv: joinArgs(argv)}
		var args []string
		if len(argv) > 1 {
			args = argv
		}
		agents.services[target] = launchctlprint.Snapshot{Target: target, State: "running", PID: pid, Path: bundle, Type: kind, BundleID: id, Program: program, Arguments: args, Inherited: inherited}
		agents.bundles[bundle] = [2]string{id, program[strings.LastIndex(program, "/")+1:]}
	}
	add(simPID, user+"/"+simLabel, simBundle, simProgram, simLabel, "XPCService", []string{simProgram}, nil)
	add(audioPID, "pid/"+strconv.Itoa(simPID)+"/"+audioLabel, audioBundle, audioProgram, audioLabel, "XPCService", []string{audioProgram}, jobXPCEnvironment())

	text, err := os.ReadFile("../launchctlprint/testdata/macos27-pid-devicefs.txt")
	if err != nil {
		t.Fatal(err)
	}
	devicefs, err := launchctlprint.Parse(string(text))
	if err != nil {
		t.Fatalf("DeviceFS fixture: %v", err)
	}
	devicefs.Target = deviceFSTarget
	agents.services[deviceFSTarget] = devicefs
	agents.procs[deviceFSPID] = agentProcess{start: "50:67438", uid: testJobUID, ppid: 1, executable: devicefs.Program, platform: true, program: devicefs.Program, argv: joinArgs(devicefs.Arguments)}
	agents.bundles[devicefs.Path] = [2]string{deviceFSID, "DeviceFS"}

	baseline := GUIBaseline{JobUID: testJobUID, Boot: "boot", Processes: []ProcessIdentity{
		{PID: 100, Start: "10:0"},
		{PID: fskitPID, Start: "10:1", Service: LaunchdService{Domain: "gui", Label: "com.apple.fskit.fskit_agent"}},
	}, Launchd: &LaunchdEnvironment{GUI: map[string]string{}, User: map[string]string{}}}
	scope := &processScope{uid: testJobUID, baseline: baseline, agents: agents, interval: time.Millisecond, grace: 5 * time.Millisecond}
	// The pid-domain children are listed before their owners: verification
	// repeats until no owner resolves.
	return scope, agents, []processSample{sample(100, "10:0"), sample(fskitPID, "10:1"), sample(audioPID, "50:501"), sample(deviceFSPID, "50:67438"), sample(simPID, "50:500")}
}

func pids(rows []processSample) []int {
	var out []int
	for _, p := range rows {
		out = append(out, p.pid)
	}
	slices.Sort(out)
	return out
}

// Field case: after quiesce launchd restarted CoreSimulatorService and its
// pid-domain services, and DeviceFS under fskit_agent; the next admission
// refused them as contamination.
func TestAdmissionAcceptsRespawnedDeveloperTools(t *testing.T) {
	s, _, rows := devtoolWorld(t)
	quietScope(s, rows)
	if err := s.observeQuiet(context.Background()); err != nil {
		t.Fatalf("developer-tool launches refused at admission: %v", err)
	}
	c, err := s.census(context.Background(), rows)
	if err != nil || len(c.residual) != 0 || !slices.Equal(pids(c.tolerated), []int{simPID, audioPID, deviceFSPID}) {
		t.Fatalf("census residual %v tolerated %v: %v", c.residual, c.tolerated, err)
	}
}

func TestQuiesceSignalsDeveloperToolsWithoutWaiting(t *testing.T) {
	s, agents, rows := devtoolWorld(t)
	// The fake host relaunches every signalled service at once under the same
	// target; a pid-domain service of the relaunched CoreSimulatorService
	// would name its exited owner, so it is left out here.
	delete(agents.services, "pid/"+strconv.Itoa(simPID)+"/"+audioLabel)
	rows = slices.DeleteFunc(rows, func(p processSample) bool { return p.pid == audioPID })
	h := host(s, agents, rows)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.quiesce(ctx); err != nil {
		t.Fatalf("respawning developer tools failed cleanup: %v", err)
	}
	if !slices.Contains(h.signalled, simPID) || !slices.Contains(h.signalled, deviceFSPID) {
		t.Fatalf("developer-tool launches not terminated: %v", h.signalled)
	}
}

// CoreDeviceService runs a short /sbin/mount when launchd restarts it. A
// residual that is a direct child of a tolerated launch is waited for, never
// tolerated, and refused without quarantine if it outlives the wait.
func TestAdmissionWaitsForChildOfToleratedLaunch(t *testing.T) {
	mount := func(s *processScope, agents *fakeAgents, rows []processSample, parent int) []processSample {
		agents.procs[mountPID] = agentProcess{start: "60:0", uid: testJobUID, ppid: parent, executable: "/sbin/mount", platform: true}
		return append(slices.Clone(rows), sample(mountPID, "60:0"))
	}
	t.Run("exits within the wait", func(t *testing.T) {
		s, agents, rows := devtoolWorld(t)
		with := mount(s, agents, rows, simPID)
		s.childWait = time.Second
		calls := 0
		s.sample = func(context.Context) ([]processSample, error) {
			if calls++; calls <= 3 {
				return slices.Clone(with), nil
			}
			return slices.Clone(rows), nil
		}
		if err := s.observeQuiet(context.Background()); err != nil {
			t.Fatalf("admission = %v", err)
		}
		if calls < 5 {
			t.Fatalf("admitted after %d snapshots", calls)
		}
	})
	t.Run("persists", func(t *testing.T) {
		s, agents, rows := devtoolWorld(t)
		quietScope(s, mount(s, agents, rows, simPID))
		s.childWait = 20 * time.Millisecond
		err := s.observeQuiet(context.Background())
		if !errors.Is(err, errToleratedChildPersists) || errors.Is(err, ErrContamination) {
			t.Fatalf("admission = %v", err)
		}
	})
	t.Run("child of an audited process", func(t *testing.T) {
		s, agents, rows := devtoolWorld(t)
		quietScope(s, mount(s, agents, rows, 100))
		s.childWait = time.Second
		if err := s.observeQuiet(context.Background()); !errors.Is(err, ErrContamination) {
			t.Fatalf("admission = %v", err)
		}
	})
	t.Run("beside another residual", func(t *testing.T) {
		s, agents, rows := devtoolWorld(t)
		with := mount(s, agents, rows, simPID)
		agents.procs[200] = agentProcess{start: "30:0", uid: testJobUID, ppid: 1, executable: "/bin/sleep", platform: true}
		quietScope(s, append(with, sample(200, "30:0")))
		s.childWait = time.Second
		if err := s.observeQuiet(context.Background()); !errors.Is(err, ErrContamination) {
			t.Fatalf("admission = %v", err)
		}
	})
}

// Everything launchd's record does not prove a developer-tool launch stays
// residual: admission refuses it as contamination.
func TestDeveloperToolLaunchRefusesUnproven(t *testing.T) {
	user := "user/" + strconv.Itoa(testJobUID)
	simTarget := user + "/" + simLabel
	snap := func(target string, f func(*launchctlprint.Snapshot)) func(*fakeAgents) {
		return func(a *fakeAgents) {
			s := a.services[target]
			s.Inherited = maps.Clone(s.Inherited)
			f(&s)
			a.services[target] = s
		}
	}
	proc := func(pid int, f func(*agentProcess)) func(*fakeAgents) {
		return func(a *fakeAgents) {
			p := a.procs[pid]
			f(&p)
			a.procs[pid] = p
		}
	}
	for name, c := range map[string]struct {
		pid    int
		mutate func(*fakeAgents)
	}{
		"binary copied into the job home": {simPID, func(a *fakeAgents) {
			home := "/Users/macservejob/Library/Developer" + strings.TrimPrefix(simBundle, "/Library/Developer")
			exe := home + "/Contents/MacOS/" + simLabel
			snap(simTarget, func(s *launchctlprint.Snapshot) { s.Path, s.Program = home, exe })(a)
			proc(simPID, func(p *agentProcess) { p.executable, p.program, p.argv = exe, exe, exe })(a)
			a.bundles[home] = [2]string{simLabel, simLabel}
		}},
		"Submitted":                            {simPID, snap(simTarget, func(s *launchctlprint.Snapshot) { s.Path, s.Type = "(submitted by launchctl[900])", "Submitted" })},
		"LaunchAgent type":                     {simPID, snap(simTarget, func(s *launchctlprint.Snapshot) { s.Type = "LaunchAgent" })},
		"executable chain writable by the job": {simPID, func(a *fakeAgents) { a.untrusted[simProgram] = true }},
		"bundle chain not root-owned":          {simPID, func(a *fakeAgents) { a.untrusted[simBundle] = true }},
		"Xcode bundle": {simPID, func(a *fakeAgents) {
			b := "/Applications/Xcode.app/Contents/Developer/Library/Xcode/XPCServices/x.xpc"
			exe := b + "/Contents/MacOS/x"
			snap(simTarget, func(s *launchctlprint.Snapshot) { s.Path, s.Program = b, exe })(a)
			proc(simPID, func(p *agentProcess) { p.executable, p.program, p.argv = exe, exe, exe })(a)
			a.bundles[b] = [2]string{simLabel, "x"}
		}},
		"disabled-table override": {simPID, func(a *fakeAgents) { a.disabled["gui/"+strconv.Itoa(testJobUID)][simLabel] = "enabled" }},
		"user-domain override of the original": {deviceFSPID, func(a *fakeAgents) {
			a.disabled[user] = map[string]string{deviceFSID: "disabled"}
		}},
		"unparsed override table": {simPID, func(a *fakeAgents) { a.incomplete[user] = true }},
		"unverified pid-domain owner": {deviceFSPID, func(a *fakeAgents) {
			s := a.services[deviceFSTarget]
			delete(a.services, deviceFSTarget)
			s.Target = "pid/200/com.apple.dt.CoreDevice.Extensions.DeviceFS.00000000-0000-0000-0000-000000000001"
			a.services[s.Target] = s
		}},
		"launchd bundle id differs from label": {simPID, snap(simTarget, func(s *launchctlprint.Snapshot) { s.BundleID = "com.apple.other" })},
		"Info.plist differs from launchd":      {simPID, func(a *fakeAgents) { a.bundles[simBundle] = [2]string{"com.apple.other", simLabel} }},
		"Info.plist executable differs":        {simPID, func(a *fakeAgents) { a.bundles[simBundle] = [2]string{simLabel, "other"} }},
		"instance suffix is not a UUID": {deviceFSPID, func(a *fakeAgents) {
			s := a.services[deviceFSTarget]
			delete(a.services, deviceFSTarget)
			s.Target = "pid/6397/" + deviceFSID + ".job"
			a.services[s.Target] = s
		}},
		"pid-domain env with a foreign HOME": {audioPID, snap("pid/500/"+audioLabel, func(s *launchctlprint.Snapshot) { s.Inherited["HOME"] = "/Users/jerry" })},
		"pid-domain env with a foreign TMPDIR": {deviceFSPID, snap(deviceFSTarget, func(s *launchctlprint.Snapshot) {
			s.Inherited["TMPDIR"] = "/var/folders/r4/g2h1rr8d4tn98sm4gs2bck6c0000gn/T/"
		})},
		"pid-domain env with an extra variable": {audioPID, snap("pid/500/"+audioLabel, func(s *launchctlprint.Snapshot) { s.Inherited["DYLD_INSERT_LIBRARIES"] = "/tmp/x" })},
		"user-domain setenv":                    {simPID, snap(simTarget, func(s *launchctlprint.Snapshot) { s.Inherited = map[string]string{"X": "1"} })},
		"exec argv differs from launchd":        {deviceFSPID, proc(deviceFSPID, func(p *agentProcess) { p.argv += "\x00--job" })},
		"executable is not the bundle's": {simPID, func(a *fakeAgents) {
			exe := simFramework + "/XPCServices/other"
			snap(simTarget, func(s *launchctlprint.Snapshot) { s.Program = exe })(a)
			proc(simPID, func(p *agentProcess) { p.executable, p.program, p.argv = exe, exe, exe })(a)
		}},
		"CoreSimulator volume launchd_sim": {simPID, func(a *fakeAgents) {
			b := "/Library/Developer/CoreSimulator/Volumes/iOS_23A1/Library/Developer/CoreSimulator/Profiles/Runtimes/iOS.simruntime/Contents/Resources/RuntimeRoot/sbin/launchd_sim.xpc"
			exe := b + "/Contents/MacOS/launchd_sim"
			snap(simTarget, func(s *launchctlprint.Snapshot) { s.Path, s.Program = b, exe })(a)
			proc(simPID, func(p *agentProcess) { p.executable, p.program, p.argv = exe, exe, exe })(a)
			a.bundles[b] = [2]string{simLabel, "launchd_sim"}
		}},
		"System volume": {simPID, func(a *fakeAgents) {
			b := "/System/Volumes/Data/Library/Developer/x.xpc"
			exe := b + "/Contents/MacOS/" + simLabel
			snap(simTarget, func(s *launchctlprint.Snapshot) { s.Path, s.Program = b, exe })(a)
			proc(simPID, func(p *agentProcess) { p.executable, p.program, p.argv = exe, exe, exe })(a)
			a.bundles[b] = [2]string{simLabel, simLabel}
		}},
		"not a platform binary":       {simPID, proc(simPID, func(p *agentProcess) { p.platform = false })},
		"not launched by launchd":     {simPID, proc(simPID, func(p *agentProcess) { p.ppid = 100 })},
		"launchd reports another PID": {simPID, snap(simTarget, func(s *launchctlprint.Snapshot) { s.PID = 999 })},
		"PID reused during verification": {simPID, func(a *fakeAgents) {
			p := a.procs[simPID]
			p.start = "51:0"
			a.reread[simPID] = p
		}},
	} {
		t.Run(name, func(t *testing.T) {
			s, agents, rows := devtoolWorld(t)
			c.mutate(agents)
			quietScope(s, rows)
			if err := s.observeQuiet(context.Background()); !errors.Is(err, ErrContamination) {
				t.Fatalf("admission = %v", err)
			}
			got, err := s.census(context.Background(), rows)
			if err != nil || !slices.ContainsFunc(got.residual, func(p processSample) bool { return p.pid == c.pid }) {
				t.Fatalf("census residual %v: %v", got.residual, err)
			}
		})
	}
}

// Reset keeps its own rule: developer-tool launches are residual there.
func TestDeveloperToolLaunchesStayResidualDuringReset(t *testing.T) {
	s, _, rows := devtoolWorld(t)
	s.adopt = &adoption{initial: map[int]string{}, terminate: map[int]string{}}
	c, err := s.census(context.Background(), rows)
	if err != nil || len(c.tolerated) != 0 || !slices.Contains(pids(c.residual), simPID) {
		t.Fatalf("census residual %v tolerated %v: %v", c.residual, c.tolerated, err)
	}
}

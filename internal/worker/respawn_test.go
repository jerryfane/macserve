package worker

import (
	"context"
	"errors"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/launchctlprint"
)

const (
	speechLabel      = "com.apple.corespeechd"
	speechPlist      = "/System/Library/LaunchAgents/com.apple.corespeechd.plist"
	speechExecutable = "/System/Library/PrivateFrameworks/CoreSpeech.framework/corespeechd"
	speechXPCLabel   = "com.apple.speech.localspeechrecognition"
	speechXPCBundle  = "/System/Library/Frameworks/Speech.framework/Versions/A/XPCServices/localspeechrecognition.xpc"
	agentLaunch      = "1111111111111111111111111111111111111111111111111111111111111111"
	xpcLaunch        = "2222222222222222222222222222222222222222222222222222222222222222"
	poisonedLaunch   = "3333333333333333333333333333333333333333333333333333333333333333"
)

// noInherited is the recorded inherited environment of a service launchctl
// prints none for.
var noInherited = inheritedDigest(nil)

func speechAgentService() LaunchdService {
	return LaunchdService{Domain: "gui", Label: speechLabel, Path: speechPlist, Executable: speechExecutable, LaunchSHA256: agentLaunch, InheritedSHA256: noInherited}
}

func speechXPCService(owner int) LaunchdService {
	return LaunchdService{Domain: "pid", Owner: owner, Label: speechXPCLabel, Path: speechXPCBundle, Executable: speechXPCBundle + "/Contents/MacOS/localspeechrecognition", LaunchSHA256: xpcLaunch, InheritedSHA256: noInherited}
}

// fakeAgents is the kernel and launchd as seen by root. reread, when set,
// replaces a PID's facts from the second read on (the binding re-read).
// Domain prints list the running services published under the domain, with
// the domain environment env holds for it.
// sip lists SIP-restricted files, plists the XML of launchd plists, and
// disabled each domain's `disabled services` table; incomplete marks a
// domain whose table did not parse completely.
type fakeAgents struct {
	procs      map[int]agentProcess
	reread     map[int]agentProcess
	reads      map[int]int
	services   map[string]launchctlprint.Snapshot
	env        map[string]map[string]string
	sip        map[string]bool
	plists     map[string]string
	disabled   map[string]map[string]string
	incomplete map[string]bool
	links      map[string]string
	untrusted  map[string]bool
	bundles    map[string][2]string
	xpcEnv     map[string]string
}

func newFakeAgents() *fakeAgents {
	return &fakeAgents{procs: map[int]agentProcess{}, reread: map[int]agentProcess{}, reads: map[int]int{}, services: map[string]launchctlprint.Snapshot{}, env: map[string]map[string]string{}, sip: map[string]bool{}, plists: map[string]string{}, disabled: map[string]map[string]string{}, incomplete: map[string]bool{}, links: map[string]string{}, untrusted: map[string]bool{}, bundles: map[string][2]string{}}
}

func (f *fakeAgents) restricted(path string) error {
	if !f.sip[path] {
		return errors.New("not SIP-restricted")
	}
	return nil
}

func (f *fakeAgents) restrictedDirectory(path string) error {
	if f.untrusted[path] || f.links[path] != "" {
		return errors.New("not a protected directory")
	}
	return f.restricted(path)
}

// resolve treats every path as canonical unless links names its target.
func (f *fakeAgents) resolve(path string) (string, error) {
	if target, ok := f.links[path]; ok {
		return target, nil
	}
	return path, nil
}

// toolchain fails for every path untrusted names (a chain that is not
// root-owned or is writable by the job).
func (f *fakeAgents) toolchain(path string, _ bool, _ int) error {
	if f.untrusted[path] {
		return errors.New("toolchain path writable by the job")
	}
	return nil
}

func (f *fakeAgents) bundleInfo(_ context.Context, bundle string) (string, string, error) {
	info, ok := f.bundles[bundle]
	if !ok {
		return "", "", syscall.ENOENT
	}
	return info[0], info[1], nil
}

func (f *fakeAgents) xpcEnvironment(context.Context, int) (map[string]string, error) {
	if f.xpcEnv == nil {
		return nil, errors.New("no job XPC environment")
	}
	return maps.Clone(f.xpcEnv), nil
}

func (f *fakeAgents) plist(_ context.Context, path string) ([]byte, error) {
	data, ok := f.plists[path]
	if !ok || !f.sip[path] {
		return nil, syscall.ENOENT
	}
	return []byte(data), nil
}

// kernel never carries launch arguments.
func (f *fakeAgents) kernel(pid int) (agentProcess, error) {
	p, ok := f.procs[pid]
	if !ok {
		return agentProcess{}, syscall.ESRCH
	}
	return agentProcess{start: p.start, uid: p.uid, ppid: p.ppid, executable: p.executable, platform: p.platform}, nil
}

func (f *fakeAgents) process(pid int) (agentProcess, error) {
	f.reads[pid]++
	if p, ok := f.reread[pid]; ok && f.reads[pid] > 1 {
		return p, nil
	}
	p, ok := f.procs[pid]
	if !ok {
		return agentProcess{}, syscall.ESRCH
	}
	return p, nil
}

func (f *fakeAgents) service(_ context.Context, target string) (launchctlprint.Snapshot, error) {
	s, ok := f.services[target]
	if !ok {
		return launchctlprint.Snapshot{}, syscall.ENOENT
	}
	return s, nil
}

func (f *fakeAgents) domain(_ context.Context, target string) (launchctlprint.Domain, error) {
	d := launchctlprint.Domain{Target: target, Environment: maps.Clone(f.env[target]), Services: map[int]string{}, Disabled: maps.Clone(f.disabled[target]), DisabledComplete: !f.incomplete[target]}
	listed := map[int]int{}
	for t, s := range f.services {
		if label, ok := strings.CutPrefix(t, target+"/"); ok && s.PID > 0 {
			d.Services[s.PID] = label
			listed[s.PID]++
		}
	}
	for pid, n := range listed {
		if n != 1 {
			delete(d.Services, pid)
		}
	}
	return d, nil
}

func (f *fakeAgents) run(pid int, start string, s LaunchdService) {
	f.procs[pid] = agentProcess{start: start, uid: testJobUID, ppid: 1, executable: s.Executable, platform: true, launch: s.LaunchSHA256}
}

func (f *fakeAgents) publish(target string, pid int, path, kind string) {
	f.services[target] = launchctlprint.Snapshot{Target: target, State: "running", PID: pid, Path: path, Type: kind}
}

func sample(pid int, start string) processSample {
	return processSample{pid: pid, group: pid, uid: testJobUID, start: start}
}

var (
	speechAgentTarget = "gui/" + strconv.Itoa(testJobUID) + "/" + speechLabel
	relaunchedXPC     = "pid/300/" + speechXPCLabel
)

// After corespeechd (100) crashed, launchd relaunched it as 300 and its XPC
// child (101, killed with it) came back as 301 in the new owner's domain. 102
// is another audited process that stayed up; 200 is an escaped job process.
func relaunchWorld() (*processScope, *fakeAgents, []processSample) {
	agents := newFakeAgents()
	agents.run(300, "20:0", speechAgentService())
	agents.run(301, "20:1", speechXPCService(100))
	agents.procs[200] = agentProcess{start: "30:0", uid: testJobUID, ppid: 1, executable: "/bin/sleep", platform: true, launch: poisonedLaunch}
	agents.publish(speechAgentTarget, 300, speechPlist, "LaunchAgent")
	agents.publish(relaunchedXPC, 301, speechXPCBundle, "XPCService")
	// The child is listed first: owners must still be resolved before children.
	baseline := GUIBaseline{JobUID: testJobUID, Boot: "boot", Processes: []ProcessIdentity{
		{PID: 101, Start: "10:1", Service: speechXPCService(100)},
		{PID: 100, Start: "10:0", Service: speechAgentService()},
		{PID: 102, Start: "10:2"},
	}}
	scope := &processScope{uid: testJobUID, baseline: baseline, agents: agents, interval: time.Millisecond, grace: time.Millisecond}
	return scope, agents, []processSample{sample(102, "10:2"), sample(300, "20:0"), sample(301, "20:1"), sample(200, "30:0")}
}

func residualPIDs(t *testing.T, s *processScope, samples []processSample) []int {
	t.Helper()
	residual, err := s.residual(context.Background(), samples)
	if err != nil {
		t.Fatal(err)
	}
	var pids []int
	for _, p := range residual {
		pids = append(pids, p.pid)
	}
	return pids
}

// Issue #27: a KeepAlive agent relaunched by launchd would otherwise be killed
// and relaunched forever, so quiesce never reaches two empty snapshots.
func TestQuiesceKeepsLaunchdRelaunchOfExitedAuditedAgent(t *testing.T) {
	s, _, rows := relaunchWorld()
	s.sample = func(context.Context) ([]processSample, error) { return slices.Clone(rows), nil }
	var signalled []int
	s.signal = func(_ context.Context, p processSample, _ syscall.Signal) error {
		signalled = append(signalled, p.pid)
		rows = slices.DeleteFunc(rows, func(row processSample) bool { return row.pid == p.pid })
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.quiesce(ctx); err != nil {
		t.Fatalf("verified relaunch blocked cleanup: %v", err)
	}
	if !slices.Equal(signalled, []int{200}) {
		t.Fatalf("cleanup targets: %v", signalled)
	}
}

// launchdHost runs a scope against mutable kernel rows. Killing a process that
// launchd reports for a service relaunches it (KeepAlive) under a new PID and
// start, as launchd does for corespeechd; any other process just exits.
type launchdHost struct {
	rows      []processSample
	agents    *fakeAgents
	next      int
	signalled []int
}

func host(s *processScope, agents *fakeAgents, rows []processSample) *launchdHost {
	h := &launchdHost{rows: rows, agents: agents, next: 1000}
	s.sample = func(context.Context) ([]processSample, error) { return slices.Clone(h.rows), nil }
	s.signal = func(_ context.Context, p processSample, _ syscall.Signal) error {
		h.signalled = append(h.signalled, p.pid)
		h.exit(p.pid)
		return nil
	}
	return h
}

// exit ends pid, signalled or on its own; launchd relaunches its service.
func (h *launchdHost) exit(pid int) {
	h.rows = slices.DeleteFunc(h.rows, func(row processSample) bool { return row.pid == pid })
	for target, svc := range h.agents.services {
		if svc.PID != pid {
			continue
		}
		h.next++
		facts := h.agents.procs[pid]
		facts.start = strconv.Itoa(h.next) + ":0"
		h.agents.procs[h.next] = facts
		svc.PID = h.next
		h.agents.services[target] = svc
		h.rows = append(h.rows, sample(h.next, facts.start))
	}
}

func quiesceOnce(s *processScope) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return s.quiesce(ctx)
}

// Review F1: an audited XPC service hosted by another pid-domain XPC service
// must verify whatever the baseline order, or launchd relaunches it forever.
func TestQuiesceResolvesNestedXPCOwnersInAnyBaselineOrder(t *testing.T) {
	s, agents, rows := relaunchWorld()
	nested := LaunchdService{Domain: "pid", Owner: 101, Label: "com.apple.speech.nested", Path: "/System/Library/PrivateFrameworks/Nested.framework/XPCServices/nested.xpc", Executable: "/System/Library/PrivateFrameworks/Nested.framework/XPCServices/nested.xpc/Contents/MacOS/nested", LaunchSHA256: xpcLaunch, InheritedSHA256: noInherited}
	s.baseline.Processes = append([]ProcessIdentity{{PID: 103, Start: "10:3", Service: nested}}, s.baseline.Processes...)
	agents.run(302, "20:2", nested)
	agents.publish("pid/301/"+nested.Label, 302, nested.Path, "XPCService")
	h := host(s, agents, append(rows, sample(302, "20:2")))
	if err := quiesceOnce(s); err != nil {
		t.Fatalf("nested XPC relaunch blocked cleanup: %v", err)
	}
	if !slices.Equal(h.signalled, []int{200}) {
		t.Fatalf("cleanup targets: %v", h.signalled)
	}
}

// Review F2: a survivor while an audited process is gone without a verified
// relaunch is inconclusive (it may be launchd's relaunch this host could not
// verify, e.g. under a v0.1.8 baseline without provenance). Cleanup and
// admission refuse without contamination, so no durable quarantine is written.
func TestUnverifiableRelaunchRefusesWithoutContamination(t *testing.T) {
	s, agents, rows := relaunchWorld()
	s.baseline.Processes[1].Service = LaunchdService{}
	host(s, agents, rows)
	err := quiesceOnce(s)
	if !errors.Is(err, ErrCleanup) || errors.Is(err, ErrContamination) {
		t.Fatalf("quiesce = %v, want cleanup failure without contamination", err)
	}
	err = s.observeQuiet(context.Background())
	if err == nil || errors.Is(err, ErrContamination) {
		t.Fatalf("admission = %v, want refusal without contamination", err)
	}
}

// Review F2 boundary: when every audited process is present or verifiably
// relaunched, a surviving job process (here a job's `launchctl submit`
// KeepAlive service) is contamination evidence, quarantined as in v0.1.8.
func TestSurvivingJobServiceIsContaminationWhenBaselineResolved(t *testing.T) {
	s, agents, rows := relaunchWorld()
	agents.publish("gui/"+strconv.Itoa(testJobUID)+"/job.sleep", 200, "(submitted by launchctl[7])", "Submitted")
	h := host(s, agents, rows)
	if err := quiesceOnce(s); !errors.Is(err, ErrContamination) {
		t.Fatalf("quiesce = %v, want contamination", err)
	}
	if slices.Contains(h.signalled, 300) || slices.Contains(h.signalled, 301) {
		t.Fatalf("verified relaunch signalled: %v", h.signalled)
	}
	if err := s.observeQuiet(context.Background()); !errors.Is(err, ErrContamination) {
		t.Fatalf("admission = %v, want contamination", err)
	}
}

// samePIDWorld relaunches corespeechd on its exited audited PID number 100.
func samePIDWorld(path, kind string) (*processScope, *fakeAgents, []processSample) {
	s, agents, _ := relaunchWorld()
	delete(agents.procs, 300)
	delete(agents.services, relaunchedXPC)
	agents.run(100, "20:0", speechAgentService())
	agents.publish(speechAgentTarget, 100, path, kind)
	agents.publish("pid/100/"+speechXPCLabel, 301, speechXPCBundle, "XPCService")
	return s, agents, []processSample{sample(102, "10:2"), sample(100, "20:0"), sample(301, "20:1"), sample(200, "30:0")}
}

// Review F3: launchd's verified relaunch landing on the exited audited PID
// number is a relaunch, not a changed baseline.
func TestQuiesceAcceptsVerifiedRelaunchOnAuditedPIDNumber(t *testing.T) {
	s, agents, rows := samePIDWorld(speechPlist, "LaunchAgent")
	h := host(s, agents, rows)
	if err := quiesceOnce(s); err != nil {
		t.Fatalf("same-PID relaunch blocked cleanup: %v", err)
	}
	if !slices.Equal(h.signalled, []int{200}) {
		t.Fatalf("cleanup targets: %v", h.signalled)
	}
}

// Any other new holder of an audited PID number is still a changed baseline,
// refused before anything is signalled.
func TestUnverifiedHolderOfAuditedPIDNumberStillRefuses(t *testing.T) {
	s, agents, rows := samePIDWorld("/Users/job/Library/LaunchAgents/com.apple.corespeechd.plist", "LaunchAgent")
	h := host(s, agents, rows)
	if err := quiesceOnce(s); err == nil || errors.Is(err, ErrContamination) || len(h.signalled) != 0 {
		t.Fatalf("quiesce = %v, signalled %v", err, h.signalled)
	}
	if _, err := s.residual(context.Background(), rows); err == nil {
		t.Fatal("unverified holder of an audited PID number accepted")
	}
}

// Every way a job can get launchd to run Apple code under its own UID, and
// every broken binding, leaves the process residual (terminated by quiesce).
func TestRelaunchRuleRefusesJobLaunchdServices(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*processScope, *fakeAgents, *[]processSample)
		want   []int
	}{
		"job LaunchAgent plist with the Apple label and binary": {func(_ *processScope, f *fakeAgents, _ *[]processSample) {
			f.publish(speechAgentTarget, 300, "/Users/job/Library/LaunchAgents/com.apple.corespeechd.plist", "LaunchAgent")
		}, []int{300, 301, 200}},
		"launchctl submit with the Apple label and binary": {func(_ *processScope, f *fakeAgents, _ *[]processSample) {
			f.publish(speechAgentTarget, 300, "(submitted by launchctl[6242])", "Submitted")
		}, []int{300, 301, 200}},
		"system plist path with another service type": {func(_ *processScope, f *fakeAgents, _ *[]processSample) {
			f.publish(speechAgentTarget, 300, speechPlist, "Submitted")
		}, []int{300, 301, 200}},
		"launchctl setenv changed the launch environment": {func(_ *processScope, f *fakeAgents, _ *[]processSample) {
			p := f.procs[300]
			p.launch = poisonedLaunch
			f.procs[300] = p
		}, []int{300, 301, 200}},
		"not a platform binary": {func(_ *processScope, f *fakeAgents, _ *[]processSample) {
			p := f.procs[300]
			p.platform = false
			f.procs[300] = p
		}, []int{300, 301, 200}},
		"another executable": {func(_ *processScope, f *fakeAgents, _ *[]processSample) {
			p := f.procs[300]
			p.executable = "/bin/sh"
			f.procs[300] = p
		}, []int{300, 301, 200}},
		"parent is a job process": {func(_ *processScope, f *fakeAgents, _ *[]processSample) {
			p := f.procs[300]
			p.ppid = 200
			f.procs[300] = p
		}, []int{300, 301, 200}},
		"UID changed during inspection": {func(_ *processScope, f *fakeAgents, _ *[]processSample) {
			p := f.procs[300]
			p.uid = 999
			f.procs[300] = p
		}, []int{300, 301, 200}},
		"launchd runs another PID for the label": {func(_ *processScope, f *fakeAgents, _ *[]processSample) {
			f.publish(speechAgentTarget, 999, speechPlist, "LaunchAgent")
		}, []int{300, 301, 200}},
		"launchctl answered for another target": {func(_ *processScope, f *fakeAgents, _ *[]processSample) {
			s := f.services[speechAgentTarget]
			s.Target = "gui/" + strconv.Itoa(testJobUID) + "/job.copy"
			f.services[speechAgentTarget] = s
		}, []int{300, 301, 200}},
		"PID reused during inspection": {func(_ *processScope, f *fakeAgents, _ *[]processSample) {
			p := f.procs[300]
			p.start = "25:0"
			f.reread[300] = p
		}, []int{300, 301, 200}},
		"PID reused after sampling": {func(_ *processScope, f *fakeAgents, _ *[]processSample) {
			p := f.procs[300]
			p.start = "25:0"
			f.procs[300] = p
		}, []int{300, 301, 200}},
		"started before the audited process": {func(_ *processScope, f *fakeAgents, rows *[]processSample) {
			p := f.procs[300]
			p.start = "5:0"
			f.procs[300] = p
			(*rows)[1].start = "5:0"
		}, []int{300, 301, 200}},
		"audited agent still running": {func(_ *processScope, _ *fakeAgents, rows *[]processSample) {
			*rows = append(*rows, sample(100, "10:0"))
		}, []int{300, 301, 200}},
		"no recorded launchd provenance": {func(s *processScope, _ *fakeAgents, _ *[]processSample) {
			s.baseline.Processes[1].Service = LaunchdService{}
		}, []int{300, 301, 200}},
		"XPC service outside the relaunched owner domain": {func(_ *processScope, f *fakeAgents, _ *[]processSample) {
			delete(f.services, relaunchedXPC)
			f.publish("pid/200/"+speechXPCLabel, 301, speechXPCBundle, "XPCService")
		}, []int{301, 200}},
	} {
		t.Run(name, func(t *testing.T) {
			s, agents, rows := relaunchWorld()
			tc.mutate(s, agents, &rows)
			if got := residualPIDs(t, s, rows); !slices.Equal(got, tc.want) {
				t.Fatalf("residual = %v, want %v", got, tc.want)
			}
		})
	}
	s, _, rows := relaunchWorld()
	if got := residualPIDs(t, s, rows); !slices.Equal(got, []int{200}) {
		t.Fatalf("verified relaunches = residual %v", got)
	}
}

// Reset records provenance only for verified system services: a job-owned
// launchd record running the same Apple binary gets none, and neither does a
// system record whose audited instance fails the relaunch rule itself.
func TestResetRecordsOnlySystemLaunchdProvenance(t *testing.T) {
	_, agents, _ := relaunchWorld()
	uid := strconv.Itoa(testJobUID)
	agents.run(100, "10:0", speechAgentService())
	agents.publish(speechAgentTarget, 100, speechPlist, "LaunchAgent")
	agents.run(101, "10:1", speechXPCService(100))
	agents.publish("pid/100/"+speechXPCLabel, 101, speechXPCBundle, "XPCService")
	agents.run(103, "10:3", speechAgentService())
	agents.publish("gui/"+uid+"/job.copy", 103, "/Users/job/Library/LaunchAgents/job.copy.plist", "LaunchAgent")
	agents.run(104, "10:4", speechAgentService())
	agents.publish("gui/"+uid+"/job.submit", 104, "(submitted by launchctl[7])", "Submitted")
	agents.run(105, "10:5", speechXPCService(500))
	agents.publish("pid/500/"+speechXPCLabel, 105, speechXPCBundle, "XPCService")
	tips := LaunchdService{Domain: "gui", Label: "com.apple.tipsd", Path: "/System/Library/LaunchAgents/com.apple.tipsd.plist", Executable: "/usr/libexec/tipsd", LaunchSHA256: agentLaunch, InheritedSHA256: noInherited}
	agents.run(106, "10:6", tips)
	agents.publish("gui/"+uid+"/"+tips.Label, 106, tips.Path, "Submitted")
	// Background-session LaunchAgents run in the user domain: the system plist
	// is provenance, a job plist with the same label and binary is not.
	agents.run(107, "10:7", teaService())
	agents.publish(teaTarget, 107, teaService().Path, "LaunchAgent")
	agents.run(108, "10:8", teaService())
	agents.publish("user/"+uid+"/job.background", 108, "/Users/job/Library/LaunchAgents/job.background.plist", "LaunchAgent")
	baseline := GUIBaseline{JobUID: testJobUID, Boot: "boot", Launchd: &LaunchdEnvironment{}}
	for _, pid := range []int{100, 101, 103, 104, 105, 106, 107, 108} {
		baseline.Processes = append(baseline.Processes, ProcessIdentity{PID: pid, Start: agents.procs[pid].start})
	}
	got := describeServices(context.Background(), agents, testJobUID, baseline)
	want := []LaunchdService{speechAgentService(), speechXPCService(100), {}, {}, {}, {}, teaService(), {}}
	for i, p := range got.Processes {
		if p.Service != want[i] {
			t.Errorf("pid %d provenance = %+v, want %+v", p.PID, p.Service, want[i])
		}
	}
	if err := validateBaseline(got, testJobUID, "boot"); err != nil {
		t.Fatal(err)
	}
}

func launchFixture(t *testing.T, path string) launchArguments {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	launch, err := launchIdentity(raw)
	if err != nil {
		t.Fatal(err)
	}
	return launch
}

// KERN_PROCARGS2 captured as UID 501: macOS 26.6 on a GitHub runner, where
// the environment follows argv, and macOS 27.0 on the SIP-enabled Mac Studio,
// where the kernel ends the buffer after argv for these CS_RESTRICT processes.
// The launch identity is the exec path and argv only, so both layouts give
// the same identity, and the environment (including a job's `launchctl
// setenv`) never enters it: launchd's record decides provenance.
func TestLaunchIdentityNeverReadsEnvironment(t *testing.T) {
	for name, want := range map[string][]string{
		"macos27-dock.bin":                 {dockPath, dockPath},
		"macos27-finder.bin":               {finderPath, finderPath},
		"macos27-loginwindow.bin":          {loginwindowPath, loginwindowPath, "console"},
		"macos27-trustevaluationagent.bin": {"/System/Library/PrivateFrameworks/TrustEvaluationAgent.framework/Resources/trustevaluationagent", "trustevaluationagent"},
	} {
		launch := launchFixture(t, "testdata/procargs2/"+name)
		if launch.program != want[0] || launch.argv != strings.Join(want[1:], "\x00") || !validLaunchDigest(launch.digest) {
			t.Errorf("%s: %+v", name, launch)
		}
	}
	if launchFixture(t, "testdata/procargs2/finder.bin") != launchFixture(t, "testdata/procargs2/macos27-finder.bin") {
		t.Error("Finder with and without its environment block has different launch identities")
	}
	audited := launchFixture(t, "testdata/procargs2/corespeechd-audited.bin")
	for _, name := range []string{"corespeechd-relaunched", "corespeechd-session", "corespeechd-session-setenv", "corespeechd-job-plist", "corespeechd-submitted"} {
		if launchFixture(t, "testdata/procargs2/"+name+".bin") != audited {
			t.Errorf("%s: launch identity depends on more than exec path and argv", name)
		}
	}
	raw, err := os.ReadFile("testdata/procargs2/macos27-loginwindow.bin")
	if err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string][]byte{
		"argv truncated": raw[:len(raw)-1],
		"argc too large": append([]byte{3, 0, 0, 0}, raw[4:]...),
		"argc zero":      append([]byte{0, 0, 0, 0}, raw[4:]...),
		"no exec path":   raw[:4],
	} {
		if _, err := launchIdentity(bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

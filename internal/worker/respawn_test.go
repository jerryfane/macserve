package worker

import (
	"context"
	"errors"
	"os"
	"slices"
	"strconv"
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

func speechAgentService() LaunchdService {
	return LaunchdService{Domain: "gui", Label: speechLabel, Path: speechPlist, Executable: speechExecutable, LaunchSHA256: agentLaunch}
}

func speechXPCService(owner int) LaunchdService {
	return LaunchdService{Domain: "pid", Owner: owner, Label: speechXPCLabel, Path: speechXPCBundle, Executable: speechXPCBundle + "/Contents/MacOS/localspeechrecognition", LaunchSHA256: xpcLaunch}
}

// fakeAgents is the kernel and launchd as seen by root. reread, when set,
// replaces a PID's facts from the second read on (the binding re-read).
type fakeAgents struct {
	procs    map[int]agentProcess
	reread   map[int]agentProcess
	reads    map[int]int
	services map[string]launchctlprint.Snapshot
	owners   map[int]int
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

func (f *fakeAgents) responsible(_ context.Context, pid int) (int, error) {
	if owner, ok := f.owners[pid]; ok {
		return owner, nil
	}
	return 0, syscall.ESRCH
}

func (f *fakeAgents) run(pid int, start string, s LaunchdService, label string) {
	f.procs[pid] = agentProcess{start: start, uid: testJobUID, ppid: 1, executable: s.Executable, platform: true, label: label, launch: s.LaunchSHA256}
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
	agents := &fakeAgents{procs: map[int]agentProcess{}, reread: map[int]agentProcess{}, reads: map[int]int{}, services: map[string]launchctlprint.Snapshot{}, owners: map[int]int{}}
	agents.run(300, "20:0", speechAgentService(), speechLabel)
	agents.run(301, "20:1", speechXPCService(100), speechXPCLabel)
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
		h.rows = slices.DeleteFunc(h.rows, func(row processSample) bool { return row.pid == p.pid })
		for target, svc := range agents.services {
			if svc.PID != p.pid {
				continue
			}
			h.next++
			facts := agents.procs[p.pid]
			facts.start = strconv.Itoa(h.next) + ":0"
			agents.procs[h.next] = facts
			svc.PID = h.next
			agents.services[target] = svc
			h.rows = append(h.rows, sample(h.next, facts.start))
		}
		return nil
	}
	return h
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
	nested := LaunchdService{Domain: "pid", Owner: 101, Label: "com.apple.speech.nested", Path: "/System/Library/PrivateFrameworks/Nested.framework/XPCServices/nested.xpc", Executable: "/System/Library/PrivateFrameworks/Nested.framework/XPCServices/nested.xpc/Contents/MacOS/nested", LaunchSHA256: xpcLaunch}
	s.baseline.Processes = append([]ProcessIdentity{{PID: 103, Start: "10:3", Service: nested}}, s.baseline.Processes...)
	agents.run(302, "20:2", nested, nested.Label)
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
	agents.run(100, "20:0", speechAgentService(), speechLabel)
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
	agents.run(100, "10:0", speechAgentService(), speechLabel)
	agents.publish(speechAgentTarget, 100, speechPlist, "LaunchAgent")
	agents.run(101, "10:1", speechXPCService(100), speechXPCLabel)
	agents.owners[101] = 100
	agents.publish("pid/100/"+speechXPCLabel, 101, speechXPCBundle, "XPCService")
	agents.run(103, "10:3", speechAgentService(), "job.copy")
	agents.publish("gui/"+uid+"/job.copy", 103, "/Users/job/Library/LaunchAgents/job.copy.plist", "LaunchAgent")
	agents.run(104, "10:4", speechAgentService(), "job.submit")
	agents.publish("gui/"+uid+"/job.submit", 104, "(submitted by launchctl[7])", "Submitted")
	agents.run(105, "10:5", speechXPCService(500), speechXPCLabel)
	agents.owners[105] = 500
	agents.publish("pid/500/"+speechXPCLabel, 105, speechXPCBundle, "XPCService")
	tips := LaunchdService{Domain: "gui", Label: "com.apple.tipsd", Path: "/System/Library/LaunchAgents/com.apple.tipsd.plist", Executable: "/usr/libexec/tipsd", LaunchSHA256: agentLaunch}
	agents.run(106, "10:6", tips, tips.Label)
	agents.publish("gui/"+uid+"/"+tips.Label, 106, tips.Path, "Submitted")
	baseline := GUIBaseline{JobUID: testJobUID, Boot: "boot"}
	for _, pid := range []int{100, 101, 103, 104, 105, 106} {
		baseline.Processes = append(baseline.Processes, ProcessIdentity{PID: pid, Start: agents.procs[pid].start})
	}
	got := describeServices(context.Background(), agents, testJobUID, baseline)
	want := []LaunchdService{speechAgentService(), speechXPCService(100), {}, {}, {}, {}}
	for i, p := range got.Processes {
		if p.Service != want[i] {
			t.Errorf("pid %d provenance = %+v, want %+v", p.PID, p.Service, want[i])
		}
	}
	if err := validateBaseline(got, testJobUID, "boot"); err != nil {
		t.Fatal(err)
	}
}

func procargs(t *testing.T, name string) (string, string) {
	t.Helper()
	raw, err := os.ReadFile("testdata/procargs2/" + name + ".bin")
	if err != nil {
		t.Fatal(err)
	}
	label, digest, err := launchIdentity(raw)
	if err != nil {
		t.Fatal(err)
	}
	return label, digest
}

// Captured KERN_PROCARGS2 from macOS 26.6 (GitHub runner, job UID 501).
func TestLaunchIdentityFromRealProcessArguments(t *testing.T) {
	label, audited := procargs(t, "corespeechd-audited")
	if label != speechLabel {
		t.Fatalf("label = %q", label)
	}
	if _, relaunched := procargs(t, "corespeechd-relaunched"); relaunched != audited {
		t.Fatal("launchd relaunch after SIGKILL changed the launch identity")
	}
	if _, submitted := procargs(t, "corespeechd-submitted"); submitted == audited {
		t.Fatal("launchctl submit launch identity matched the system agent")
	}
	// The job plist copy is indistinguishable here; its plist path is not.
	if _, copied := procargs(t, "corespeechd-job-plist"); copied != audited {
		t.Fatal("expected identical launch identity for an unmodified plist copy")
	}
	if _, kicked := procargs(t, "syncdefaultsd-kickstarted"); kicked == "" {
		t.Fatal("empty digest")
	} else if _, poisoned := procargs(t, "syncdefaultsd-setenv"); poisoned == kicked {
		t.Fatal("launchctl setenv did not change the launch identity")
	}
}

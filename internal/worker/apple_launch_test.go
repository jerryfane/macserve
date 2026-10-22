package worker

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/launchctlprint"
)

// The two agents launchd started in gui/6202 during the v0.1.13 field build,
// as launchctl print reports them on macOS 27.0. cloudpairing's plist is not
// named after its label.
const (
	heardLabel   = "com.apple.accessibility.heard"
	heardPlist   = "/System/Library/LaunchAgents/com.apple.accessibility.heard.plist"
	heardProgram = "/System/Library/PrivateFrameworks/HearingCore.framework/heard"
	pairLabel    = "com.apple.BTServer.cloudpairing"
	pairPlist    = "/System/Library/LaunchAgents/com.apple.cloudpaird.plist"
	pairProgram  = "/System/Library/CoreServices/audioaccessoryd"
	jobSocket    = "/private/var/run/com.apple.launchd.job/Listeners"
)

func agentPlistXML(label, keys string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>EnablePressuredExit</key>
	<true/>
	<key>Label</key>
	<string>` + label + `</string>
	<key>MachServices</key>
	<dict>
		<key>` + label + `</key>
		<true/>
	</dict>
` + keys + `</dict>
</plist>
`
}

// appleWorld is an audited job session (Finder-like 100) after a build made
// launchd start heard (400, Program only) and cloudpairing (401,
// ProgramArguments) in gui/<job>, with the domain environment recorded at
// reset.
func appleWorld() (*processScope, *fakeAgents, []processSample) {
	agents := newFakeAgents()
	gui := "gui/" + strconv.Itoa(testJobUID)
	agents.env[gui] = map[string]string{"SSH_AUTH_SOCK": jobSocket}
	agents.disabled[gui] = map[string]string{"com.apple.Siri.agent": "disabled"}
	agents.procs[100] = agentProcess{start: "10:0", uid: testJobUID, ppid: 1, executable: "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder", platform: true}
	for _, a := range []struct {
		pid               int
		label, path, prog string
		args              []string
		keys              string
	}{
		{400, heardLabel, heardPlist, heardProgram, nil, "\t<key>Program</key>\n\t<string>" + heardProgram + "</string>\n"},
		{401, pairLabel, pairPlist, pairProgram, []string{pairProgram, "-cloudpairing"}, "\t<key>ProgramArguments</key>\n\t<array>\n\t\t<string>" + pairProgram + "</string>\n\t\t<string>-cloudpairing</string>\n\t</array>\n"},
	} {
		argv := a.args
		if argv == nil {
			argv = []string{a.prog}
		}
		agents.procs[a.pid] = agentProcess{start: "40:" + strconv.Itoa(a.pid), uid: testJobUID, ppid: 1, executable: a.prog, platform: true, launch: agentLaunch, program: a.prog, argv: joinArgs(argv)}
		agents.services[gui+"/"+a.label] = launchctlprint.Snapshot{Target: gui + "/" + a.label, State: "running", PID: a.pid, Path: a.path, Type: "LaunchAgent", Program: a.prog, Arguments: a.args, Inherited: map[string]string{"SSH_AUTH_SOCK": jobSocket}}
		agents.sip[a.prog], agents.sip[a.path] = true, true
		agents.plists[a.path] = agentPlistXML(a.label, a.keys)
	}
	baseline := GUIBaseline{JobUID: testJobUID, Boot: "boot", Processes: []ProcessIdentity{{PID: 100, Start: "10:0"}}, Launchd: &LaunchdEnvironment{GUI: map[string]string{"SSH_AUTH_SOCK": jobSocket}}}
	scope := &processScope{uid: testJobUID, baseline: baseline, agents: agents, interval: time.Millisecond, grace: 5 * time.Millisecond}
	return scope, agents, []processSample{sample(100, "10:0"), sample(400, "40:400"), sample(401, "40:401")}
}

func joinArgs(argv []string) string {
	out := ""
	for i, a := range argv {
		if i > 0 {
			out += "\x00"
		}
		out += a
	}
	return out
}

func quietScope(s *processScope, rows []processSample) {
	s.sample = func(context.Context) ([]processSample, error) { return slices.Clone(rows), nil }
}

// v0.1.13 field failure: after a build, admission refused the next run with
// "job-user contamination observed: processes outside audited GUI baseline"
// for the Apple agents the build made launchd start.
func TestAdmissionAcceptsAppleDefinedLaunchesAfterBuild(t *testing.T) {
	s, _, rows := appleWorld()
	quietScope(s, rows)
	if err := s.observeQuiet(context.Background()); err != nil {
		t.Fatalf("Apple-defined launches refused at admission: %v", err)
	}
	if residual, err := s.residual(context.Background(), rows); err != nil || len(residual) != 0 {
		t.Fatalf("census residual %v: %v", residual, err)
	}
}

// heard respawns every second: quiesce signals each instance but must not wait
// for an absence launchd will not allow, nor call the survivor contamination.
func TestQuiesceSignalsRespawningAppleAgentWithoutContamination(t *testing.T) {
	s, agents, rows := appleWorld()
	h := host(s, agents, rows)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.quiesce(ctx); err != nil {
		t.Fatalf("respawning Apple agent failed cleanup: %v", err)
	}
	if len(h.signalled) < 2 || !slices.Contains(h.signalled, 401) {
		t.Fatalf("Apple-defined launches not terminated: %v", h.signalled)
	}
	if _, ok := agents.procs[h.signalled[0]]; !ok {
		t.Fatalf("signalled an unknown process: %v", h.signalled)
	}
}

// Everything launchd's record does not prove Apple-defined stays residual:
// admission refuses it as contamination.
func TestAppleLaunchRefusesUnprovenLaunches(t *testing.T) {
	gui := "gui/" + strconv.Itoa(testJobUID)
	target := gui + "/" + heardLabel
	edit := func(f func(*launchctlprint.Snapshot)) func(*fakeAgents) {
		return func(a *fakeAgents) {
			snap := a.services[target]
			snap.Inherited = maps.Clone(snap.Inherited)
			f(&snap)
			a.services[target] = snap
		}
	}
	proc := func(f func(*agentProcess)) func(*fakeAgents) {
		return func(a *fakeAgents) {
			p := a.procs[400]
			f(&p)
			a.procs[400] = p
		}
	}
	for name, mutate := range map[string]func(*fakeAgents){
		"job-submitted plist running an Apple binary": edit(func(s *launchctlprint.Snapshot) {
			s.Path, s.Type = "(submitted by launchctl[900])", "Submitted"
		}),
		"home plist under an Apple label": edit(func(s *launchctlprint.Snapshot) {
			s.Path = "/Users/macservejob/Library/LaunchAgents/" + heardLabel + ".plist"
		}),
		"non-SIP plist directory": edit(func(s *launchctlprint.Snapshot) {
			s.Path = "/Library/LaunchAgents/" + heardLabel + ".plist"
		}),
		"nested SIP plist path": edit(func(s *launchctlprint.Snapshot) {
			s.Path = "/System/Library/LaunchAgents/../LaunchAgents/" + heardLabel + ".plist"
		}),
		"launchctl enable override": func(a *fakeAgents) { a.disabled[gui][heardLabel] = "enabled" },
		"user-domain override": func(a *fakeAgents) {
			a.disabled["user/"+strconv.Itoa(testJobUID)] = map[string]string{heardLabel: "disabled"}
		},
		"unparsed override table": func(a *fakeAgents) { a.incomplete["user/"+strconv.Itoa(testJobUID)] = true },
		"launchctl setenv":        edit(func(s *launchctlprint.Snapshot) { s.Inherited["DYLD_INSERT_LIBRARIES"] = "/tmp/x" }),
		"launchd program differs from plist": func(a *fakeAgents) {
			other := "/usr/libexec/otheragent"
			a.sip[other] = true
			edit(func(s *launchctlprint.Snapshot) { s.Program = other })(a)
			proc(func(p *agentProcess) { p.executable, p.program, p.argv = other, other, other })(a)
		},
		"launchd argv differs from plist": func(a *fakeAgents) {
			edit(func(s *launchctlprint.Snapshot) { s.Arguments = []string{heardProgram, "--job"} })(a)
			proc(func(p *agentProcess) { p.argv = heardProgram + "\x00--job" })(a)
		},
		"exec argv differs from launchd":     proc(func(p *agentProcess) { p.argv = heardProgram + "\x00--job" }),
		"launchd program resolves elsewhere": func(a *fakeAgents) { a.links[heardProgram] = "/System/Library/Other/heard" },
		"non-SIP executable":                 func(a *fakeAgents) { a.sip[heardProgram] = false },
		"non-SIP plist file":                 func(a *fakeAgents) { a.sip[heardPlist] = false },
		"code runner": func(a *fakeAgents) {
			a.sip["/bin/zsh"] = true
			a.plists[heardPlist] = agentPlistXML(heardLabel, "\t<key>Program</key>\n\t<string>/bin/zsh</string>\n")
			edit(func(s *launchctlprint.Snapshot) { s.Program = "/bin/zsh" })(a)
			proc(func(p *agentProcess) { p.executable, p.program, p.argv = "/bin/zsh", "/bin/zsh", "/bin/zsh" })(a)
		},
		"disabled plist": func(a *fakeAgents) {
			a.plists[heardPlist] = agentPlistXML(heardLabel, "\t<key>Program</key>\n\t<string>"+heardProgram+"</string>\n\t<key>Disabled</key>\n\t<true/>\n")
		},
		"plist names another label": func(a *fakeAgents) {
			a.plists[heardPlist] = agentPlistXML("com.apple.other", "\t<key>Program</key>\n\t<string>"+heardProgram+"</string>\n")
		},
		"BundleProgram": func(a *fakeAgents) {
			a.plists[heardPlist] = agentPlistXML(heardLabel, "\t<key>Program</key>\n\t<string>"+heardProgram+"</string>\n\t<key>BundleProgram</key>\n\t<string>Contents/MacOS/x</string>\n")
		},
		"launchd reports another PID": edit(func(s *launchctlprint.Snapshot) { s.PID = 999 }),
		"not a platform binary":       proc(func(p *agentProcess) { p.platform = false }),
		"not launched by launchd":     proc(func(p *agentProcess) { p.ppid = 100 }),
		"PID reused during verification": func(a *fakeAgents) {
			p := a.procs[400]
			p.start = "41:0"
			a.reread[400] = p
		},
		"not in a job domain": func(a *fakeAgents) {
			snap := a.services[target]
			delete(a.services, target)
			snap.Target = "pid/100/" + heardLabel
			a.services[snap.Target] = snap
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, agents, rows := appleWorld()
			mutate(agents)
			quietScope(s, rows)
			if err := s.observeQuiet(context.Background()); !errors.Is(err, ErrContamination) {
				t.Fatalf("admission = %v", err)
			}
			c, err := s.census(context.Background(), rows)
			if err != nil || !slices.ContainsFunc(c.residual, func(p processSample) bool { return p.pid == 400 }) {
				t.Fatalf("census residual %v: %v", c.residual, err)
			}
		})
	}
}

// On macOS 27.0 launchd's program for com.apple.xtyped names fontd through
// ATS.framework's Support symlink; the kernel reports the resolved path.
func TestAppleLaunchThroughSystemFrameworkSymlink(t *testing.T) {
	s, agents, rows := appleWorld()
	resolved := "/System/Library/PrivateFrameworks/HearingCore.framework/Versions/A/heard"
	agents.links[heardProgram] = resolved
	agents.sip[resolved] = true
	p := agents.procs[400]
	p.executable = resolved
	agents.procs[400] = p
	c, err := s.census(context.Background(), rows)
	if err != nil || len(c.residual) != 0 || len(c.apple) != 2 {
		t.Fatalf("census residual %v apple %v: %v", c.residual, c.apple, err)
	}
}

// Spotlight starts mdworker_shared instances in the job's user domain while a
// build writes files (observed on macOS 27.0): label
// com.apple.mdworker.shared.<UUID>, launchd `original` com.apple.mdworker.shared.
func mdworkerWorld(t *testing.T, plistKeys string, original, suffix string) (*processScope, []processSample) {
	t.Helper()
	s, agents, rows := appleWorld()
	user := "user/" + strconv.Itoa(testJobUID)
	const base = "com.apple.mdworker.shared"
	const plist = "/System/Library/LaunchAgents/com.apple.mdworker.shared.plist"
	const prog = "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework/Versions/A/Support/mdworker_shared"
	argv := []string{prog, "-s", "mdworker", "-c", "MDSImporterWorker", "-m", base}
	label := base + "." + suffix
	agents.procs[500] = agentProcess{start: "50:0", uid: testJobUID, ppid: 1, executable: prog, platform: true, launch: agentLaunch, program: prog, argv: joinArgs(argv)}
	agents.services[user+"/"+label] = launchctlprint.Snapshot{Target: user + "/" + label, State: "running", PID: 500, Path: plist, Type: "LaunchAgent", Original: original, Program: prog, Arguments: argv}
	agents.sip[prog], agents.sip[plist] = true, true
	keys := "\t<key>ProgramArguments</key>\n\t<array>\n"
	for _, a := range argv {
		keys += "\t\t<string>" + a + "</string>\n"
	}
	agents.plists[plist] = agentPlistXML(base, keys+"\t</array>\n"+plistKeys)
	return s, append(rows, sample(500, "50:0"))
}

func TestAppleLaunchMultipleInstancesService(t *testing.T) {
	const uuid = "0F000000-0200-0000-0000-000000000000"
	s, rows := mdworkerWorld(t, "\t<key>MultipleInstances</key>\n\t<true/>\n", "com.apple.mdworker.shared", uuid)
	c, err := s.census(context.Background(), rows)
	if err != nil || len(c.residual) != 0 || len(c.apple) != 3 {
		t.Fatalf("census residual %v apple %v: %v", c.residual, c.apple, err)
	}
	for name, w := range map[string][3]string{
		"plist without MultipleInstances": {"", "com.apple.mdworker.shared", uuid},
		"instance of another original":    {"\t<key>MultipleInstances</key>\n\t<true/>\n", "com.apple.mdworker.single", uuid},
		"instance suffix not a UUID":      {"\t<key>MultipleInstances</key>\n\t<true/>\n", "com.apple.mdworker.shared", "job"},
		"instance label without original": {"\t<key>MultipleInstances</key>\n\t<true/>\n", "", uuid},
	} {
		s, rows := mdworkerWorld(t, w[0], w[1], w[2])
		c, err := s.census(context.Background(), rows)
		if err != nil || !slices.ContainsFunc(c.residual, func(p processSample) bool { return p.pid == 500 }) {
			t.Errorf("%s: residual %v apple %v: %v", name, c.residual, c.apple, err)
		}
	}
}

// Reset keeps its own rule (adoption); an Apple-defined launch is residual
// there and is terminated, so the reset audit sees the session it publishes.
func TestAppleLaunchesStayResidualDuringReset(t *testing.T) {
	s, _, rows := appleWorld()
	s.adopt = &adoption{initial: map[int]string{}, terminate: map[int]string{}, reference: map[string]string{}}
	c, err := s.census(context.Background(), rows)
	if err != nil || len(c.residual) != 2 || len(c.apple) != 0 {
		t.Fatalf("reset census residual %v apple %v: %v", c.residual, c.apple, err)
	}
}

// A verified Apple-defined launch that landed on an exited audited PID number
// is not a changed baseline.
func TestAppleLaunchOnReusedAuditedPID(t *testing.T) {
	s, _, rows := appleWorld()
	s.baseline.Processes = append(s.baseline.Processes, ProcessIdentity{PID: 400, Start: "9:0"})
	c, err := s.census(context.Background(), rows)
	if err != nil || len(c.residual) != 0 || len(c.apple) != 2 {
		t.Fatalf("census residual %v apple %v: %v", c.residual, c.apple, err)
	}
}

func TestAgentPlistProgramAndArguments(t *testing.T) {
	for name, c := range map[string]struct {
		keys    string
		program string
		argv    []string
	}{
		"program only":   {"<key>Program</key><string>/usr/libexec/a</string>", "/usr/libexec/a", []string{"/usr/libexec/a"}},
		"arguments only": {"<key>ProgramArguments</key><array><string>/usr/libexec/a</string><string>-x</string></array>", "/usr/libexec/a", []string{"/usr/libexec/a", "-x"}},
		"both":           {"<key>Program</key><string>/usr/libexec/a</string><key>ProgramArguments</key><array><string>a</string></array>", "/usr/libexec/a", []string{"a"}},
	} {
		program, argv, multiple, err := agentPlist([]byte(agentPlistXML("l", c.keys)), "l")
		if err != nil || program != c.program || !slices.Equal(argv, c.argv) || multiple {
			t.Errorf("%s: %q %q %v", name, program, argv, err)
		}
	}
	for name, keys := range map[string]string{
		"relative program":              "<key>ProgramArguments</key><array><string>a</string></array>",
		"no program":                    "",
		"duplicate key":                 "<key>Program</key><string>/a</string><key>Program</key><string>/b</string>",
		"non-string program":            "<key>Program</key><array><string>/a</string></array>",
		"non-boolean MultipleInstances": "<key>Program</key><string>/a</string><key>MultipleInstances</key><string>yes</string>",
		"non-boolean Disabled":          "<key>Program</key><string>/a</string><key>Disabled</key><string>no</string>",
	} {
		if _, _, _, err := agentPlist([]byte(agentPlistXML("l", keys)), "l"); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, _, _, err := agentPlist([]byte("bplist00"), "l"); err == nil {
		t.Error("binary plist parsed as XML")
	}
}

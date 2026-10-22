package worker

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"testing"

	"github.com/jerryfane/macserve/internal/launchctlprint"
	"github.com/jerryfane/macserve/internal/model"
)

// The two system LaunchAgents on macOS 27.0 whose Apple plists name their
// program with a redundant separator, which launchd execs verbatim
// (launchctl print and KERN_PROCARGS2 on the Mac Studio, 2026-10-22).
// AquaAppearanceHelper's plist is also not named after its label.
const (
	cloudphotodLabel   = "com.apple.cloudphotod"
	cloudphotodPlist   = "/System/Library/LaunchAgents/com.apple.cloudphotod.plist"
	cloudphotodProgram = "/System/Library/PrivateFrameworks/CloudPhotoLibrary.framework/Versions/A/Support//cloudphotod"
	aquaLabel          = "com.apple.AquaAppearanceHelper"
	aquaPlist          = "/System/Library/LaunchAgents/com.apple.AquaAppearanceHelper.agent.plist"
	aquaProgram        = "/System/Library/PrivateFrameworks/SkyLight.framework//Versions/A/Resources/AquaAppearanceHelper.app/Contents/MacOS/AquaAppearanceHelper"
)

// addRedundantSeparatorAgents makes launchd start cloudphotod (402: Program
// plus ProgramArguments [cloudphotod]) and AquaAppearanceHelper (403:
// ProgramArguments only) in gui/<job>, exactly as recorded on the host.
func addRedundantSeparatorAgents(agents *fakeAgents) []processSample {
	gui := "gui/" + strconv.Itoa(testJobUID)
	var rows []processSample
	for _, a := range []struct {
		pid               int
		label, path, prog string
		args              []string
		keys              string
	}{
		{402, cloudphotodLabel, cloudphotodPlist, cloudphotodProgram, []string{"cloudphotod"}, "\t<key>Program</key>\n\t<string>" + cloudphotodProgram + "</string>\n\t<key>ProgramArguments</key>\n\t<array>\n\t\t<string>cloudphotod</string>\n\t</array>\n"},
		{403, aquaLabel, aquaPlist, aquaProgram, []string{aquaProgram}, "\t<key>ProgramArguments</key>\n\t<array>\n\t\t<string>" + aquaProgram + "</string>\n\t</array>\n"},
	} {
		executable := filepath.Clean(a.prog)
		start := "50:" + strconv.Itoa(a.pid)
		agents.procs[a.pid] = agentProcess{start: start, uid: testJobUID, ppid: 1, executable: executable, platform: true, launch: agentLaunch, program: a.prog, argv: joinArgs(a.args)}
		agents.services[gui+"/"+a.label] = launchctlprint.Snapshot{Target: gui + "/" + a.label, State: "running", PID: a.pid, Path: a.path, Type: "LaunchAgent", Program: a.prog, Arguments: a.args, Inherited: map[string]string{"SSH_AUTH_SOCK": jobSocket}}
		agents.sip[executable], agents.sip[a.path] = true, true
		agents.plists[a.path] = agentPlistXML(a.label, a.keys)
		rows = append(rows, sample(a.pid, start))
	}
	return rows
}

// v0.1.14 field failure: launchd started cloudphotod in gui/<job> on an xpc
// event after worker-reset, and tool evidence was refused at Recover with
// "processes outside audited GUI baseline" before any recipe ran.
func TestAdmissionAcceptsAppleAgentsWithRedundantSeparators(t *testing.T) {
	s, agents, rows := appleWorld()
	rows = append(rows, addRedundantSeparatorAgents(agents)...)
	quietScope(s, rows)
	if err := s.observeQuiet(context.Background()); err != nil {
		t.Fatalf("Apple agents with a redundant separator refused: %v", err)
	}
}

// Cleaning launchd's program never launders a "." or ".." component, and the
// raw exec path must still be launchd's raw program.
func TestAppleLaunchRefusesDotComponentsAndCleanedExecPaths(t *testing.T) {
	for name, edit := range map[string]func(*fakeAgents){
		"dot-dot program": func(a *fakeAgents) {
			setCloudphotodProgram(a, "/System/Library/PrivateFrameworks/CloudPhotoLibrary.framework/Versions/A/Support/x/../cloudphotod")
		},
		"dot program": func(a *fakeAgents) {
			setCloudphotodProgram(a, "/System/Library/PrivateFrameworks/CloudPhotoLibrary.framework/Versions/A/Support/./cloudphotod")
		},
		"exec path cleaned": func(a *fakeAgents) {
			p := a.procs[402]
			p.program = filepath.Clean(cloudphotodProgram)
			a.procs[402] = p
		},
		"resolves elsewhere": func(a *fakeAgents) {
			a.links[cloudphotodProgram] = "/System/Library/PrivateFrameworks/Other.framework/cloudphotod"
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, agents, rows := appleWorld()
			rows = append(rows, addRedundantSeparatorAgents(agents)...)
			edit(agents)
			c, err := s.census(context.Background(), rows)
			if err != nil || len(c.residual) != 1 || c.residual[0].pid != 402 {
				t.Fatalf("residual %v: %v", c.residual, err)
			}
		})
	}
}

// Reset adoption and relaunch provenance accept a system LaunchAgent whose
// plist is not named after its label only when the SIP plist's own Label is
// that label.
func TestDescribeServiceBindsRenamedSystemPlistByLabel(t *testing.T) {
	_, agents, _ := appleWorld()
	addRedundantSeparatorAgents(agents)
	id := ProcessIdentity{PID: 403, Start: "50:403"}
	s, ok := describeService(context.Background(), agents, testJobUID, id, newServiceHints(agents, testJobUID, nil))
	if !ok || s.Path != aquaPlist || s.Label != aquaLabel || s.serviceType() != "LaunchAgent" {
		t.Fatalf("AquaAppearanceHelper provenance refused: %+v %v", s, ok)
	}
	agents.plists[aquaPlist] = agentPlistXML("com.apple.other", "")
	if _, ok := describeService(context.Background(), agents, testJobUID, id, newServiceHints(agents, testJobUID, nil)); ok {
		t.Fatal("plist defining another label accepted")
	}
}

// setCloudphotodProgram gives launchd, the plist and the kernel one program
// string, so only its components decide.
func setCloudphotodProgram(a *fakeAgents, program string) {
	target := "gui/" + strconv.Itoa(testJobUID) + "/" + cloudphotodLabel
	snapshot := a.services[target]
	snapshot.Program = program
	a.services[target] = snapshot
	p := a.procs[402]
	p.program = program
	a.procs[402] = p
	a.plists[cloudphotodPlist] = agentPlistXML(cloudphotodLabel, "\t<key>Program</key>\n\t<string>"+program+"</string>\n\t<key>ProgramArguments</key>\n\t<array>\n\t\t<string>cloudphotod</string>\n\t</array>\n")
}

// vanishingSampler lists the Apple agent 404, which never has kernel facts
// (it exited at once, like heard's 40 ms lives), in every snapshot for which
// present returns true.
func vanishingSampler(rows []processSample, present func(call int) bool) processSampler {
	var mu sync.Mutex
	calls := 0
	return func(context.Context) ([]processSample, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		out := slices.Clone(rows)
		if present(calls) {
			out = append(out, sample(404, "60:404"))
		}
		return out, nil
	}
}

// A process sampled alive that exits before its verification is not
// contamination: admission samples again.
func TestAdmissionResamplesWhenRefusedProcessVanishes(t *testing.T) {
	s, _, rows := appleWorld()
	s.sample = vanishingSampler(rows, func(call int) bool { return call == 1 })
	if err := s.observeQuiet(context.Background()); err != nil {
		t.Fatalf("vanished agent refused admission: %v", err)
	}
}

// scopeRunner runs jobs through fakeRunner but inspects admission and
// quiesce with a real process census over the fake host.
type scopeRunner struct {
	fakeRunner
	scope *processScope
}

func (r *scopeRunner) Admission(ctx context.Context) error { return r.scope.observeQuiet(ctx) }
func (r *scopeRunner) Quiesce(ctx context.Context) error   { return r.scope.quiesce(ctx) }

// The tool-evidence path end to end: a durable quarantine left by v0.1.13
// refuses until worker-reset clears it; launchd then starts cloudphotod and
// AquaAppearanceHelper after the reset, and heard lives for a moment during
// admission; a new engine's Recover admits and a recipe runs; a real
// residual process still quarantines.
func TestToolEvidencePathAfterResetWithNewSIPAgents(t *testing.T) {
	ctx := context.Background()
	s, agents, rows := appleWorld()
	baselineRows := rows[:1]
	s.signal = func(context.Context, processSample, syscall.Signal) error { return nil }
	s.sample = func(context.Context) ([]processSample, error) { return slices.Clone(baselineRows), nil }
	runner := &scopeRunner{scope: s}
	engine := engineFixture(t, runner)
	if err := os.WriteFile(filepath.Join(engine.options.Root, quarantineRecord), []byte(`{"quarantined":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := engine.Recover(ctx); !errors.Is(err, ErrRecovery) {
		t.Fatalf("stale v0.1.13 quarantine ignored: %v", err)
	}
	if err := engine.reset(ctx, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("reset: %v", err)
	}
	options := engine.options
	if err := engine.Close(); err != nil {
		t.Fatal(err)
	}

	after := append(slices.Clone(rows), addRedundantSeparatorAgents(agents)...)
	s.sample = vanishingSampler(after, func(call int) bool { return call == 1 })
	reopened, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.Recover(ctx); err != nil {
		t.Fatalf("tool-evidence Recover refused: %v", err)
	}
	job := fixtureJob(t, model.Build)
	source, archive := sourceFixture(t)
	if result, err := reopened.Execute(ctx, job, source, bytes.NewReader(archive), nil); err != nil || result.State != model.Succeeded {
		t.Fatalf("recipe after reset: %+v %v", result, err)
	}
	if _, err := reopened.root.Lstat(quarantineRecord); !os.IsNotExist(err) {
		t.Fatalf("worker quarantined: %v", err)
	}

	agents.procs[500] = agentProcess{start: "70:500", uid: testJobUID, ppid: 1, executable: "/Users/macservejob/bin/agent", program: "/Users/macservejob/bin/agent", argv: "/Users/macservejob/bin/agent"}
	s.sample = func(context.Context) ([]processSample, error) {
		return append(slices.Clone(after), sample(500, "70:500")), nil
	}
	if err := reopened.Recover(ctx); !errors.Is(err, ErrContamination) || !errors.Is(err, ErrRecovery) {
		t.Fatalf("residual process admitted: %v", err)
	}
	if _, err := reopened.root.Lstat(quarantineRecord); err != nil {
		t.Fatalf("contamination not quarantined: %v", err)
	}
}

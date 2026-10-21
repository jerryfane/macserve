package worker

import (
	"errors"
	"testing"
)

type policyAgents struct {
	nativeAgents
	facts map[int]agentProcess
}

func (a policyAgents) kernel(pid int) (agentProcess, error) {
	f, ok := a.facts[pid]
	if !ok {
		return agentProcess{}, errors.New("gone")
	}
	return f, nil
}

func TestBaselinePolicyRefusesCodeRunnersAndUnrestricted(t *testing.T) {
	sip := map[string]bool{"/usr/libexec/rapportd": true, "/System/Library/CoreServices/Dock.app/Contents/MacOS/Dock": true, "/bin/zsh": true}
	restricted := func(p string) error {
		if !sip[p] {
			return errors.New("not SIP-restricted")
		}
		return nil
	}
	b := GUIBaseline{JobUID: 600, Processes: []ProcessIdentity{{PID: 10, Start: "s"}, {PID: 11, Start: "s"}}}
	agents := policyAgents{facts: map[int]agentProcess{10: {start: "s", uid: 600, executable: "/usr/libexec/rapportd"}, 11: {start: "s", uid: 600, executable: "/System/Library/CoreServices/Dock.app/Contents/MacOS/Dock"}}}
	if err := checkBaselinePolicy(b, agents, restricted); err != nil {
		t.Fatal(err)
	}
	for name, exe := range map[string]string{"shell": "/bin/zsh", "terminal": "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", "job home binary": "/Users/job/agent"} {
		t.Run(name, func(t *testing.T) {
			bad := policyAgents{facts: map[int]agentProcess{10: {start: "s", uid: 600, executable: exe}, 11: agents.facts[11]}}
			if checkBaselinePolicy(b, bad, restricted) == nil {
				t.Fatalf("%s accepted in baseline", exe)
			}
		})
	}
	// An exited entry with launchd provenance is checked by its relaunch path.
	b.Processes = append(b.Processes, ProcessIdentity{PID: 12, Start: "s", Service: LaunchdService{Domain: "gui", Executable: "/Users/job/agent"}})
	if checkBaselinePolicy(b, agents, restricted) == nil {
		t.Fatal("exited entry relaunching a non-SIP executable accepted")
	}
}

func TestJobLoginwindowsByKernelFacts(t *testing.T) {
	samples := []processSample{{pid: 10, uid: 600, start: "s"}, {pid: 11, uid: 600, start: "s"}, {pid: 12, uid: 501, start: "s"}, {pid: 13, uid: 600, start: "s", zombie: true}}
	agents := policyAgents{facts: map[int]agentProcess{
		10: {start: "s", uid: 600, platform: true, executable: loginwindowExecutable},
		11: {start: "s", uid: 600, platform: false, executable: loginwindowExecutable},
		12: {start: "s", uid: 501, platform: true, executable: loginwindowExecutable},
		13: {start: "s", uid: 600, platform: true, executable: loginwindowExecutable},
	}}
	pids, err := jobLoginwindows(samples, agents, 600)
	if err != nil || len(pids) != 1 || pids[0] != 10 {
		t.Fatal(pids, err)
	}
	if _, err := jobLoginwindows(samples[2:3], agents, 600); err == nil {
		t.Fatal("missing job loginwindow accepted")
	}
}

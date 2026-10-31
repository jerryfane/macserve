package worker

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

const managedBundle = "/Library/Apple/System/Library/CoreServices/XProtect.app"

func managedAgentWorld() (*processScope, *fakeAgents, *launchdHost, LaunchdService) {
	s, a, h := resetWorld()
	h.exit(53)
	h.exit(54)
	service := LaunchdService{
		Domain: "gui", Label: "com.apple.XprotectFramework.PluginService",
		Path:         managedBundle + "/Contents/Resources/com.apple.XprotectFramework.PluginService.plist",
		Executable:   managedBundle + "/Contents/XPCServices/XProtectPluginService.xpc/Contents/MacOS/XProtectPluginService",
		LaunchSHA256: agentLaunch, InheritedSHA256: noInherited,
	}
	a.run(61, "1:61", service)
	p := a.procs[61]
	p.program, p.argv = service.Executable, service.Executable
	a.procs[61] = p
	target := service.target(testJobUID, 0)
	a.publish(target, 61, service.Path, "LaunchAgent")
	snapshot := a.services[target]
	snapshot.Program = service.Executable
	a.services[target] = snapshot
	a.plists[service.Path] = `<plist><dict><key>Label</key><string>` + service.Label + `</string><key>Program</key><string>` + service.Executable + `</string></dict></plist>`
	for _, leaf := range []string{service.Path, service.Executable} {
		a.sip[leaf] = true
		for dir := filepath.Dir(leaf); dir != "/Library"; dir = filepath.Dir(dir) {
			a.sip[dir] = true
		}
	}
	originalSignal := s.signal
	s.signal = func(ctx context.Context, p processSample, sig syscall.Signal) error {
		if p.pid == 61 || p.pid == 62 {
			return syscall.EPERM
		}
		return originalSignal(ctx, p, sig)
	}
	return s, a, h, service
}

func relaunchManagedAgent(a *fakeAgents, h *launchdHost, service LaunchdService) {
	p := a.procs[61]
	h.exit(61)
	delete(a.procs, 61)
	p.start = "40:62"
	a.procs[62] = p
	h.rows = append(h.rows, sample(62, p.start))
	target := service.target(testJobUID, 0)
	snapshot := a.services[target]
	snapshot.PID = 62
	a.services[target] = snapshot
}

func TestResetRetainsAuditedAppleManagedAgentAcrossRelaunch(t *testing.T) {
	s, a, h, service := managedAgentWorld()
	selected, err := runReset(s, []int{50, 51, 52, 60, 61}, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if i := slices.IndexFunc(selected, func(p ProcessIdentity) bool { return p.PID == 61 }); i < 0 || selected[i].Service != service {
		t.Fatalf("audited agent has no restart provenance: %+v", selected)
	}
	if !slices.Contains(h.signalled, 200) || slices.Contains(h.signalled, 300) {
		t.Fatalf("residual cleanup crossed UID boundary or missed job: %v", h.signalled)
	}
	relaunchManagedAgent(a, h, service)
	if err := quiesceOnce(s); err != nil {
		t.Fatalf("verified replacement was signalled or refused: %v", err)
	}
	if !slices.ContainsFunc(h.rows, func(p processSample) bool { return p.pid == 62 }) {
		t.Fatal("verified replacement was removed")
	}
}

func TestAuditedAppleManagedAgentRejectsChangedRelaunch(t *testing.T) {
	for _, change := range []string{"writable ancestor", "symlink ancestor", "unrestricted definition", "unrestricted executable", "changed plist label", "changed plist program", "disabled plist", "changed arguments", "changed inherited environment", "submitted service", "changed kernel identity"} {
		t.Run(change, func(t *testing.T) {
			s, a, h, service := managedAgentWorld()
			selected, err := runReset(s, []int{50, 51, 52, 60, 61}, func(context.Context) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			if i := slices.IndexFunc(selected, func(p ProcessIdentity) bool { return p.PID == 61 }); i < 0 || selected[i].Service != service {
				t.Fatal("fixture did not establish audited restart provenance")
			}
			relaunchManagedAgent(a, h, service)
			target := service.target(testJobUID, 0)
			snapshot := a.services[target]
			switch change {
			case "writable ancestor":
				a.untrusted["/Library/Apple"] = true
			case "symlink ancestor":
				a.links[managedBundle+"/Contents/XPCServices"] = "/Users/job/XPCServices"
			case "unrestricted definition":
				a.sip[service.Path] = false
			case "unrestricted executable":
				a.sip[service.Executable] = false
			case "changed plist label":
				a.plists[service.Path] = strings.ReplaceAll(a.plists[service.Path], service.Label, "com.apple.other")
			case "changed plist program":
				a.plists[service.Path] = strings.ReplaceAll(a.plists[service.Path], service.Executable, "/bin/sh")
			case "disabled plist":
				a.plists[service.Path] = strings.Replace(a.plists[service.Path], "</dict>", "<key>Disabled</key><true/></dict>", 1)
			case "changed arguments":
				snapshot.Arguments = []string{service.Executable, "--injected"}
			case "changed inherited environment":
				snapshot.Inherited = map[string]string{"DYLD_INSERT_LIBRARIES": "/Users/job/inject.dylib"}
			case "submitted service":
				snapshot.Type = "Submitted"
			case "changed kernel identity":
				p := a.procs[62]
				p.start = "41:62"
				a.reread[62] = p
			}
			a.services[target] = snapshot
			if err := quiesceOnce(s); !errors.Is(err, ErrCleanup) || !errors.Is(err, syscall.EPERM) {
				t.Fatalf("unverified replacement escaped guarded cleanup: %v", err)
			}
		})
	}
}

func TestUnselectedAppleManagedAgentStillRefusesSignalFailure(t *testing.T) {
	s, _, _, _ := managedAgentWorld()
	_, err := runReset(s, []int{50, 51, 52, 60}, func(context.Context) error { return nil })
	if !errors.Is(err, ErrCleanup) || !errors.Is(err, syscall.EPERM) {
		t.Fatalf("unselected agent must not be adopted or its signal error ignored: %v", err)
	}
}

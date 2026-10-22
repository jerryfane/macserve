package worker

import (
	"context"
	"maps"
	"slices"
	"strconv"
	"testing"

	"github.com/jerryfane/macserve/internal/launchctlprint"
)

// Apple services launchd started in the idle job session (gui/6202 on the Mac
// Studio, macOS 27.0) after the v0.1.14 round-1 worker-reset, in shapes
// recorded from their gui/501 twins with launchctl print and plutil.
const (
	rmOwnerPID     = 600
	rmOwnerLabel   = "com.apple.RemoteManagementAgent"
	subscriberPID  = 601
	subscriberID   = "com.apple.remotemanagement.SecuritySubscriber"
	subscriberXPC  = "/System/Library/PrivateFrameworks/RemoteManagement.framework/XPCServices/SecuritySubscriber.xpc"
	asConfigPID    = 602
	asConfigID     = "com.apple.AuthenticationServices.ASConfigurationSubscriber"
	asConfigXPC    = "/System/Library/PrivateFrameworks/RemoteManagement.framework/XPCServices/ASConfigurationSubscriber.xpc"
	safariPID      = 603
	safariID       = "com.apple.SafariShared.SafariConfigurationSubscriber"
	safariXPC      = "/System/Library/PrivateFrameworks/SafariFoundation.framework/Versions/A/XPCServices/SafariConfigurationSubscriber.xpc"
	safariCryptex  = "/System/Volumes/Preboot/Cryptexes/OS" + safariXPC
	keychainPID    = 604
	keychainLabel  = "com.apple.security.keychain-circle-notification"
	keychainPlist  = "/System/Library/LaunchAgents/com.apple.security.keychain-circle-notification.plist"
	keychainBinary = "/System/Library/CoreServices/Keychain Circle Notification.app/Contents/MacOS/Keychain Circle Notification"
	keychainFlag   = "\t<key>Disabled</key>\n\t<dict>\n\t\t<key>#IfFeatureFlagDisabled</key>\n\t\t<string>Security/EnableSecureObjectSync</string>\n\t\t<key>#Then</key>\n\t\t<true/>\n\t</dict>\n"
)

// postResetWorld is the devtool world with RemoteManagementAgent audited in
// gui/<job> (the recorded gui domain environment is launchd's
// SSH_AUTH_SOCK) and, launched after reset: three XPC services in its pid
// domain and the feature-flagged keychain-circle-notification LaunchAgent.
func postResetWorld(t *testing.T) (*processScope, *fakeAgents, []processSample) {
	s, agents, rows := devtoolWorld(t)
	gui := "gui/" + strconv.Itoa(testJobUID)
	s.baseline.Launchd.GUI = map[string]string{"SSH_AUTH_SOCK": jobSocket}
	agents.env[gui] = map[string]string{"SSH_AUTH_SOCK": jobSocket}
	ownerExe := "/System/Library/PrivateFrameworks/RemoteManagement.framework/RemoteManagementAgent"
	agents.procs[rmOwnerPID] = agentProcess{start: "10:600", uid: testJobUID, ppid: 1, executable: ownerExe, platform: true}
	agents.services[gui+"/"+rmOwnerLabel] = launchctlprint.Snapshot{Target: gui + "/" + rmOwnerLabel, State: "running", PID: rmOwnerPID, Path: "/System/Library/LaunchAgents/com.apple.RemoteManagementAgent.plist", Type: "LaunchAgent"}
	s.baseline.Processes = append(s.baseline.Processes, ProcessIdentity{PID: rmOwnerPID, Start: "10:600", Service: LaunchdService{Domain: "gui", Label: rmOwnerLabel}})
	inherited := maps.Clone(jobXPCEnvironment())
	inherited["SSH_AUTH_SOCK"] = jobSocket
	owner := "pid/" + strconv.Itoa(rmOwnerPID) + "/"
	for _, x := range []struct {
		pid           int
		id, bundle    string
		exe, exeName  string
		bundleExeName string
	}{
		{subscriberPID, subscriberID, subscriberXPC, subscriberXPC + "/Contents/MacOS/SecuritySubscriber", "SecuritySubscriber", "SecuritySubscriber"},
		{asConfigPID, asConfigID, asConfigXPC, asConfigXPC + "/Contents/MacOS/ASConfigurationSubscriber", "ASConfigurationSubscriber", ""},
		{safariPID, safariID, safariXPC, safariCryptex + "/Contents/MacOS/SafariConfigurationSubscriber", "SafariConfigurationSubscriber", "SafariConfigurationSubscriber"},
	} {
		program := x.bundle + "/Contents/MacOS/" + x.exeName
		agents.procs[x.pid] = agentProcess{start: "50:" + strconv.Itoa(x.pid), uid: testJobUID, ppid: 1, executable: x.exe, platform: true, program: program, argv: program}
		agents.services[owner+x.id] = launchctlprint.Snapshot{Target: owner + x.id, State: "running", PID: x.pid, Path: x.bundle, Type: "XPCService", BundleID: x.id, Program: program, Inherited: inherited}
		agents.bundles[x.bundle] = [2]string{x.id, x.bundleExeName}
		rows = append(rows, sample(x.pid, "50:"+strconv.Itoa(x.pid)))
	}
	agents.links[safariXPC] = safariCryptex
	agents.links[safariXPC+"/Contents/MacOS/SafariConfigurationSubscriber"] = safariCryptex + "/Contents/MacOS/SafariConfigurationSubscriber"
	agents.sip[safariCryptex+"/Contents/MacOS/SafariConfigurationSubscriber"] = true
	agents.sip[safariCryptex+"/Contents/Info.plist"] = true

	agents.procs[keychainPID] = agentProcess{start: "50:604", uid: testJobUID, ppid: 1, executable: keychainBinary, platform: true, launch: agentLaunch, program: keychainBinary, argv: keychainBinary}
	agents.services[gui+"/"+keychainLabel] = launchctlprint.Snapshot{Target: gui + "/" + keychainLabel, State: "running", PID: keychainPID, Path: keychainPlist, Type: "LaunchAgent", Program: keychainBinary, Arguments: []string{keychainBinary}, Inherited: map[string]string{"SSH_AUTH_SOCK": jobSocket}}
	agents.sip[keychainBinary], agents.sip[keychainPlist] = true, true
	agents.plists[keychainPlist] = agentPlistXML(keychainLabel, keychainFlag+"\t<key>ProgramArguments</key>\n\t<array>\n\t\t<string>"+keychainBinary+"</string>\n\t</array>\n")
	rows = append(rows, sample(rmOwnerPID, "10:600"), sample(keychainPID, "50:604"))
	return s, agents, rows
}

func TestAdmissionAcceptsPostResetAppleServices(t *testing.T) {
	s, _, rows := postResetWorld(t)
	c, err := s.census(context.Background(), rows)
	if err != nil || len(c.residual) != 0 {
		t.Fatalf("post-reset Apple services residual %v: %v", pids(c.residual), err)
	}
}

func TestPostResetRulesStayNarrow(t *testing.T) {
	owner := "pid/" + strconv.Itoa(rmOwnerPID) + "/"
	for name, tc := range map[string]struct {
		pid  int
		edit func(*fakeAgents)
	}{
		"extra pid-domain variable": {subscriberPID, func(a *fakeAgents) {
			s := a.services[owner+subscriberID]
			s.Inherited = maps.Clone(s.Inherited)
			s.Inherited["DYLD_INSERT_LIBRARIES"] = "/Users/macservejob/x.dylib"
			a.services[owner+subscriberID] = s
		}},
		"default executable mismatch": {asConfigPID, func(a *fakeAgents) { a.bundles[asConfigXPC] = [2]string{asConfigID, "Other"} }},
		"cryptex file not SIP":        {safariPID, func(a *fakeAgents) { delete(a.sip, safariCryptex+"/Contents/MacOS/SafariConfigurationSubscriber") }},
		"bundle outside cryptex":      {safariPID, func(a *fakeAgents) { a.links[safariXPC] = "/Users/macservejob/SafariConfigurationSubscriber.xpc" }},
		"literal Disabled": {keychainPID, func(a *fakeAgents) {
			a.plists[keychainPlist] = agentPlistXML(keychainLabel, "\t<key>Disabled</key>\n\t<true/>\n\t<key>ProgramArguments</key>\n\t<array>\n\t\t<string>"+keychainBinary+"</string>\n\t</array>\n")
		}},
		"unknown Disabled condition": {keychainPID, func(a *fakeAgents) {
			a.plists[keychainPlist] = agentPlistXML(keychainLabel, "\t<key>Disabled</key>\n\t<dict>\n\t\t<key>#IfOSVersion</key>\n\t\t<string>27</string>\n\t\t<key>#Then</key>\n\t\t<true/>\n\t</dict>\n\t<key>ProgramArguments</key>\n\t<array>\n\t\t<string>"+keychainBinary+"</string>\n\t</array>\n")
		}},
		"job enable override": {keychainPID, func(a *fakeAgents) {
			a.disabled["gui/"+strconv.Itoa(testJobUID)][keychainLabel] = "enabled"
		}},
	} {
		t.Run(name, func(t *testing.T) {
			s, agents, rows := postResetWorld(t)
			tc.edit(agents)
			c, err := s.census(context.Background(), rows)
			if err != nil || len(c.residual) != 1 || c.residual[0].pid != tc.pid {
				t.Fatalf("residual %v: %v", pids(c.residual), err)
			}
		})
	}
}

// Brief pid-domain services seen in the idle job session, in the bundle and
// Info.plist shapes read on the host (macOS 27.0): an app-extension
// (Extension type, .appex in /System/Applications) and an instance of a
// MultipleInstances XPC service (<original>.<UUID>).
func TestAdmissionAcceptsTransientPidDomainServices(t *testing.T) {
	s, agents, rows := postResetWorld(t)
	owner := "pid/" + strconv.Itoa(rmOwnerPID) + "/"
	inherited := maps.Clone(jobXPCEnvironment())
	inherited["SSH_AUTH_SOCK"] = jobSocket
	for _, x := range []struct {
		pid                     int
		label, original, bundle string
		name, kind              string
	}{
		{610, "com.apple.MailCacheDelete", "", "/System/Applications/Mail.app/Contents/PlugIns/MailCacheDelete.appex", "MailCacheDelete", "Extension"},
		{611, "com.apple.WorkflowKit.BackgroundShortcutRunner.D5CDB00E-16AB-4CDF-93C2-35A5093CB12B", "com.apple.WorkflowKit.BackgroundShortcutRunner", "/System/Library/PrivateFrameworks/WorkflowKit.framework/XPCServices/BackgroundShortcutRunner.xpc", "BackgroundShortcutRunner", "XPCService"},
	} {
		id := x.label
		if x.original != "" {
			id = x.original
		}
		program := x.bundle + "/Contents/MacOS/" + x.name
		agents.procs[x.pid] = agentProcess{start: "50:" + strconv.Itoa(x.pid), uid: testJobUID, ppid: 1, executable: program, platform: true, program: program, argv: program}
		agents.services[owner+x.label] = launchctlprint.Snapshot{Target: owner + x.label, State: "running", PID: x.pid, Path: x.bundle, Type: x.kind, BundleID: id, Original: x.original, Program: program, Inherited: inherited}
		agents.bundles[x.bundle] = [2]string{id, x.name}
		rows = append(rows, sample(x.pid, "50:"+strconv.Itoa(x.pid)))
	}
	c, err := s.census(context.Background(), rows)
	if err != nil || len(c.residual) != 0 {
		t.Fatalf("transient pid-domain services residual %v: %v", pids(c.residual), err)
	}
}

const (
	safariCacheBundle  = "/System/Volumes/Preboot/Cryptexes/App/System/Applications/Safari.app/Contents/PlugIns/CacheDeleteExtension.appex"
	safariCacheID      = "com.apple.Safari.CacheDeleteExtension"
	safariCacheProgram = safariCacheBundle + "/Contents/MacOS/CacheDeleteExtension"
)

// addSafariCacheDelete adds Safari's CacheDeleteExtension as launchd printed
// it in deleted's pid domain on the host (path in the App cryptex, type
// Extension), here under RemoteManagementAgent, a verified gui owner.
func addSafariCacheDelete(agents *fakeAgents) processSample {
	owner := "pid/" + strconv.Itoa(rmOwnerPID) + "/"
	inherited := maps.Clone(jobXPCEnvironment())
	inherited["SSH_AUTH_SOCK"] = jobSocket
	agents.procs[620] = agentProcess{start: "50:620", uid: testJobUID, ppid: 1, executable: safariCacheProgram, platform: true, program: safariCacheProgram, argv: safariCacheProgram}
	agents.services[owner+safariCacheID] = launchctlprint.Snapshot{Target: owner + safariCacheID, State: "running", PID: 620, Path: safariCacheBundle, Type: "Extension", BundleID: safariCacheID, Program: safariCacheProgram, Inherited: inherited}
	agents.bundles[safariCacheBundle] = [2]string{safariCacheID, "CacheDeleteExtension"}
	agents.sip[safariCacheProgram], agents.sip[safariCacheBundle+"/Contents/Info.plist"] = true, true
	return sample(620, "50:620")
}

func TestAdmissionAcceptsAppCryptexExtensionInVerifiedPidDomain(t *testing.T) {
	s, agents, rows := postResetWorld(t)
	rows = append(rows, addSafariCacheDelete(agents))
	if c, err := s.census(context.Background(), rows); err != nil || len(c.residual) != 0 {
		t.Fatalf("Safari CacheDeleteExtension residual %v: %v", pids(c.residual), err)
	}
	delete(agents.sip, safariCacheProgram)
	if c, err := s.census(context.Background(), rows); err != nil || len(c.residual) != 1 {
		t.Fatalf("non-SIP App-cryptex binary admitted: %v %v", pids(c.residual), err)
	}
}

// The App cryptex is never trusted for a gui-domain service.
func TestAppCryptexAgentInGuiDomainStaysResidual(t *testing.T) {
	s, agents, rows := postResetWorld(t)
	rows = append(rows, addSafariCacheDelete(agents))
	owner := "pid/" + strconv.Itoa(rmOwnerPID) + "/"
	gui := "gui/" + strconv.Itoa(testJobUID)
	snapshot := agents.services[owner+safariCacheID]
	delete(agents.services, owner+safariCacheID)
	snapshot.Target, snapshot.Type, snapshot.Inherited = gui+"/"+safariCacheID, "XPCService", map[string]string{"SSH_AUTH_SOCK": jobSocket}
	agents.services[snapshot.Target] = snapshot
	c, err := s.census(context.Background(), rows)
	if err != nil || len(c.residual) != 1 || c.residual[0].pid != 620 {
		t.Fatalf("App-cryptex gui service: residual %v: %v", pids(c.residual), err)
	}
}

// F2: a pid domain's owner environment never replaces the job account's.
func TestPidDomainEnvironmentRefusesReplacedAccountVariable(t *testing.T) {
	s, agents, rows := postResetWorld(t)
	gui := "gui/" + strconv.Itoa(testJobUID)
	s.baseline.Launchd.GUI = map[string]string{"SSH_AUTH_SOCK": jobSocket, "HOME": "/Users/macservejob"}
	agents.env[gui] = s.baseline.Launchd.GUI
	owner := "pid/" + strconv.Itoa(rmOwnerPID) + "/"
	snapshot := agents.services[owner+subscriberID]
	snapshot.Inherited = maps.Clone(snapshot.Inherited)
	agents.services[owner+subscriberID] = snapshot
	c, err := s.census(context.Background(), rows)
	if err != nil || !slices.Contains(pids(c.residual), subscriberPID) {
		t.Fatalf("replaced HOME accepted: residual %v: %v", pids(c.residual), err)
	}
}

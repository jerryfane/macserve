package launchctlprint

import (
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
)

func capture(t *testing.T, name string) string {
	t.Helper()
	text, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(text)
}

// Root-run `launchctl print gui/501/com.apple.corespeechd` and
// `launchctl print pid/359/com.apple.quicklook.QuickLookUIService` on macOS
// 26.6. Both print `domain = <domain> [<annotation>]`.
func TestParseRealAgentCaptures(t *testing.T) {
	for name, want := range map[string]Snapshot{
		"gui-corespeechd.txt": {Target: "gui/501/com.apple.corespeechd", State: "running", PID: 421},
		"pid-xpcservice.txt":  {Target: "pid/359/com.apple.quicklook.QuickLookUIService", State: "running", PID: 365},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := Parse(capture(t, name))
			if err != nil || got.Target != want.Target || got.State != want.State || got.PID != want.PID {
				t.Fatalf("Parse = %+v, %v", got, err)
			}
		})
	}
}

func TestParseRootServicePathAndType(t *testing.T) {
	text := capture(t, "gui-corespeechd.txt")
	got, err := Parse(text)
	if err != nil || got.Path != "/System/Library/LaunchAgents/com.apple.corespeechd.plist" || got.Type != "LaunchAgent" {
		t.Fatalf("Parse = %+v, %v", got, err)
	}
	refused := map[string]string{
		"second root path":   strings.Replace(text, "\ttype = LaunchAgent\n", "\ttype = LaunchAgent\n\tpath = /System/Library/LaunchAgents/x.plist\n", 1),
		"second root type":   strings.Replace(text, "\tstate = running\n", "\tstate = running\n\ttype = LaunchAgent\n", 1),
		"arrow root path":    strings.Replace(text, "\tpath = /System", "\tpath => /System", 1),
		"annotation opens":   strings.Replace(text, "[100002]", "[100002", 1),
		"annotation nests":   strings.Replace(text, "[100002]", "[[100002]]", 1),
		"annotation quoted":  strings.Replace(text, "[100002]", "[\"100002\"]", 1),
		"annotation trailer": strings.Replace(text, "[100002]", "[100002] }", 1),
	}
	for name, text := range refused {
		t.Run(name, func(t *testing.T) {
			if got, err := Parse(text); err == nil {
				t.Fatalf("ambiguous snapshot accepted: %+v", got)
			}
		})
	}
}

// Root-run prints from one macOS 26.6 session (UID 501). Finder's program is
// inferred (no arguments block); corespeechd was relaunched after the job ran
// `launchctl setenv PROBE_ENV poisoned`, which launchctl lists only under
// `inherited environment`.
func TestParseRootProgramArgumentsAndEnvironment(t *testing.T) {
	for name, want := range map[string]Snapshot{
		"user-trustevaluationagent.txt": {
			Program:     "/System/Library/PrivateFrameworks/TrustEvaluationAgent.framework/Resources/trustevaluationagent",
			Arguments:   []string{"trustevaluationagent"},
			Environment: map[string]string{"OSLogRateLimit": "64", "MallocSpaceEfficient": "1", "XPC_SERVICE_NAME": "com.apple.TrustEvaluationAgent"},
		},
		"gui-finder.txt": {
			Program:     "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder",
			Environment: map[string]string{"OSLogRateLimit": "64", "XPC_SERVICE_NAME": "com.apple.Finder"},
		},
		"gui-corespeechd-setenv.txt": {
			Program:     "/System/Library/PrivateFrameworks/CoreSpeech.framework/corespeechd",
			Arguments:   []string{"/System/Library/PrivateFrameworks/CoreSpeech.framework/corespeechd"},
			Environment: map[string]string{"OSLogRateLimit": "64", "MallocSpaceEfficient": "1", "XPC_SERVICE_NAME": "com.apple.corespeechd"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := Parse(capture(t, name))
			if err != nil || got.Program != want.Program || !slices.Equal(got.Arguments, want.Arguments) || !maps.Equal(got.Environment, want.Environment) {
				t.Fatalf("Parse = %+v, %v", got, err)
			}
		})
	}
	text := capture(t, "user-trustevaluationagent.txt")
	for name, edited := range map[string]string{
		"second root environment": strings.Replace(text, "\tdomain = ", "\tenvironment = {\n\t\tXPC_SERVICE_NAME => com.example\n\t}\n\tdomain = ", 1),
		"second root program":     strings.Replace(text, "\tdomain = ", "\tprogram = /tmp/x\n\tdomain = ", 1),
		"second root arguments":   strings.Replace(text, "\tdomain = ", "\targuments = {\n\t\tx\n\t}\n\tdomain = ", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := Parse(edited); err == nil {
				t.Fatalf("ambiguous snapshot accepted: %+v", got)
			}
		})
	}
	// An environment entry launchd would not print as a plain KEY => value
	// leaves no usable environment rather than a partial one.
	for name, edited := range map[string]string{
		"duplicate key":  strings.Replace(text, "\t\tOSLogRateLimit => 64\n", "\t\tOSLogRateLimit => 64\n\t\tOSLogRateLimit => 7\n", 1),
		"assignment":     strings.Replace(text, "\t\tOSLogRateLimit => 64\n", "\t\tOSLogRateLimit = 64\n", 1),
		"quoted value":   strings.Replace(text, "\t\tOSLogRateLimit => 64\n", "\t\tOSLogRateLimit => \"64\"\n", 1),
		"nested element": strings.Replace(text, "\t\tOSLogRateLimit => 64\n", "\t\tOSLogRateLimit => {\n\t\t}\n", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := Parse(edited); err != nil || got.Environment != nil || got.PID != 2499 {
				t.Fatalf("Parse = %+v, %v", got, err)
			}
		})
	}
}

// Root-run prints from the SIP-enabled Mac Studio, macOS 27.0 (26A428), UID
// 501. Service roots keep their 26.6 shape; the inherited environment is the
// gui domain's SSH_AUTH_SOCK. Domain prints were trimmed to Apple entries.
func TestParseMacOS27Captures(t *testing.T) {
	socket := map[string]string{"SSH_AUTH_SOCK": "/var/run/com.apple.launchd.GWnys7uPgY/Listeners"}
	for name, want := range map[string]Snapshot{
		"macos27-gui-finder.txt": {Target: "gui/501/com.apple.Finder", State: "running", PID: 16209, Path: "/System/Library/LaunchAgents/com.apple.Finder.plist", Type: "LaunchAgent", Program: "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder", Inherited: socket},
		"macos27-gui-dock.txt":   {Target: "gui/501/com.apple.Dock.agent", State: "running", PID: 16204, Path: "/System/Library/LaunchAgents/com.apple.Dock.plist", Type: "LaunchAgent", Program: "/System/Library/CoreServices/Dock.app/Contents/MacOS/Dock", Inherited: socket},
	} {
		got, err := Parse(capture(t, name))
		if err != nil || got.Target != want.Target || got.State != want.State || got.PID != want.PID || got.Path != want.Path || got.Type != want.Type || got.Program != want.Program || got.Arguments != nil || !maps.Equal(got.Inherited, want.Inherited) {
			t.Errorf("%s: Parse = %+v, %v", name, got, err)
		}
	}
	// A job's `launchctl submit` (path "(submitted by launchctl[N])", type
	// Submitted) and a service that is not running never parse.
	for _, name := range []string{"macos27-gui-submitted.txt", "macos27-user-trustevaluationagent.txt"} {
		if got, err := Parse(capture(t, name)); err == nil {
			t.Errorf("%s accepted: %+v", name, got)
		}
	}
	gui, err := ParseDomain(capture(t, "macos27-gui-domain.txt"))
	if err != nil || gui.Target != "gui/501" || !maps.Equal(gui.Environment, socket) || gui.Services[16209] != "com.apple.Finder" || gui.Services[16204] != "com.apple.Dock.agent" || slices.Contains(slices.Collect(maps.Keys(gui.Services)), 0) {
		t.Fatalf("ParseDomain = %+v, %v", gui, err)
	}
	user, err := ParseDomain(capture(t, "macos27-user-domain.txt"))
	if err != nil || user.Target != "user/501" || user.Environment != nil || user.Services[1084] != "com.apple.trustd.agent" {
		t.Fatalf("ParseDomain = %+v, %v", user, err)
	}
	text := capture(t, "macos27-gui-finder.txt")
	domain := capture(t, "macos27-gui-domain.txt")
	for name, edited := range map[string]string{
		"second inherited environment":  strings.Replace(text, "\tdomain = ", "\tinherited environment = {\n\t\tX => y\n\t}\n\tdomain = ", 1),
		"quoted inherited entry":        strings.Replace(text, "\t\tSSH_AUTH_SOCK => ", "\t\t\"SSH_AUTH_SOCK\" => ", 1),
		"inherited entry without arrow": strings.Replace(text, "\t\tSSH_AUTH_SOCK => ", "\t\tSSH_AUTH_SOCK = ", 1),
	} {
		if got, err := Parse(edited); err == nil {
			t.Errorf("%s accepted: %+v", name, got)
		}
	}
	for name, edited := range map[string]string{
		"second domain environment": strings.Replace(domain, "\tservices = {", "\tenvironment = {\n\t\tX => y\n\t}\n\tservices = {", 1),
		"quoted domain entry":       strings.Replace(domain, "\t\tSSH_AUTH_SOCK => ", "\t\t\"SSH_AUTH_SOCK\" => ", 1),
		"second services table":     strings.Replace(domain, "\tunmanaged processes = {", "\tservices = {\n\t}\n\tunmanaged processes = {", 1),
		"trailing output":           domain + "x\n",
	} {
		if got, err := ParseDomain(edited); err == nil {
			t.Errorf("%s accepted: %+v", name, got)
		}
	}
	twice := strings.Replace(domain, "\t\t   16204      - \tcom.apple.Dock.agent\n", "\t\t   16204      - \tcom.apple.Dock.agent\n\t\t   16204      - \tjob.copy\n", 1)
	if d, err := ParseDomain(twice); err != nil || d.Services[16204] != "" {
		t.Fatalf("PID listed twice kept a label: %+v, %v", d.Services, err)
	}
}

// v0.1.14: the `disabled services` table is the per-user override record an
// Apple-defined launch must not appear in (worker appleLaunch).
func TestParseDomainDisabledServices(t *testing.T) {
	domain := capture(t, "macos27-gui-domain.txt")
	d, err := ParseDomain(domain)
	if err != nil || !d.DisabledComplete || d.Disabled["com.apple.Siri.agent"] != "disabled" || len(d.Disabled) != 5 {
		t.Fatalf("disabled services = %v complete=%v, %v", d.Disabled, d.DisabledComplete, err)
	}
	enabled := strings.Replace(domain, "\t\t\"com.apple.Siri.agent\" => disabled\n", "\t\t\"com.apple.Siri.agent\" => disabled\n\t\t\"com.apple.heard\" => enabled\n", 1)
	if d, err := ParseDomain(enabled); err != nil || !d.DisabledComplete || d.Disabled["com.apple.heard"] != "enabled" {
		t.Fatalf("enabled override = %v, %v", d.Disabled, err)
	}
	for name, edited := range map[string]string{
		"unquoted label": strings.Replace(domain, "\t\t\"com.apple.Siri.agent\" => disabled", "\t\tcom.apple.Siri.agent => disabled", 1),
		"other state":    strings.Replace(domain, "\"com.apple.Siri.agent\" => disabled", "\"com.apple.Siri.agent\" => maybe", 1),
		"repeated label": strings.Replace(domain, "\t\t\"com.apple.Siri.agent\" => disabled\n", "\t\t\"com.apple.Siri.agent\" => disabled\n\t\t\"com.apple.Siri.agent\" => enabled\n", 1),
	} {
		if d, err := ParseDomain(edited); err != nil || d.DisabledComplete {
			t.Errorf("%s: complete=%v, %v", name, d.DisabledComplete, err)
		}
	}
	if d, err := ParseDomain(strings.Replace(domain, "\tdisabled services = {", "\tdisabled services = {\n\t}\n\tdisabled services = {", 1)); err == nil {
		t.Fatalf("second disabled services table accepted: %+v", d.Disabled)
	}
}

// launchd prints `original` for an instance of a MultipleInstances service
// (com.apple.mdworker.shared.<UUID> on macOS 27.0).
func TestParseOriginalLabel(t *testing.T) {
	finder := capture(t, "macos27-gui-finder.txt")
	head, rest, _ := strings.Cut(finder, "\n")
	instance := head + "\n\toriginal = com.apple.mdworker.shared\n" + rest
	if s, err := Parse(instance); err != nil || s.Original != "com.apple.mdworker.shared" {
		t.Fatalf("original = %q, %v", s.Original, err)
	}
	if s, err := Parse(finder); err != nil || s.Original != "" {
		t.Fatalf("service without original = %q, %v", s.Original, err)
	}
	twice := head + "\n\toriginal = a\n\toriginal = b\n" + rest
	if _, err := Parse(twice); err == nil {
		t.Fatal("second original label accepted")
	}
}

// The parser reports launchd's root type and path as printed, without pairing
// them: a record whose type is Submitted but whose path names a SIP
// LaunchAgents plist parses, so callers must check the type themselves.
func TestParseDoesNotPairTypeWithPath(t *testing.T) {
	dock := capture(t, "macos27-gui-dock.txt")
	forged := strings.Replace(dock, "\ttype = LaunchAgent\n", "\ttype = Submitted\n", 1)
	s, err := Parse(forged)
	if forged == dock || err != nil || s.Type != "Submitted" || s.Path != "/System/Library/LaunchAgents/com.apple.Dock.plist" {
		t.Fatalf("type %q path %q: %v", s.Type, s.Path, err)
	}
}

// macOS 27.0 developer-tool services launchd starts in the job's user domain
// and in pid domains while a build runs. DeviceFS (an Extension) carries a
// JSON argument that opens and closes on its own line.
func TestParseMacOS27DeveloperServices(t *testing.T) {
	for name, want := range map[string]Snapshot{
		"macos27-pid-devicefs.txt": {
			Target: "pid/6397/com.apple.dt.CoreDevice.Extensions.DeviceFS.00000000-0000-0000-0000-000000000001", PID: 67438, Type: "Extension",
			Original: "com.apple.dt.CoreDevice.Extensions.DeviceFS", BundleID: "com.apple.dt.CoreDevice.Extensions.DeviceFS",
			Path: "/Library/Developer/PrivateFrameworks/CoreDevice.framework/Versions/A/PrivateApplications/CoreDeviceExtensions.app/Contents/Extensions/DeviceFS.appex",
		},
		"macos27-pid-extensionkitservice.txt":   {Target: "pid/6397/com.apple.extensionkitservice", PID: 67437, Type: "XPCService", BundleID: "com.apple.extensionkitservice", Path: "/System/Library/Frameworks/ExtensionFoundation.framework/Versions/A/XPCServices/extensionkitservice.xpc"},
		"macos27-pid-simaudio.txt":              {Target: "pid/67431/com.apple.CoreSimulator.SimAudioProcessorServices.SimAudioProcessorService", PID: 67994, Type: "XPCService", BundleID: "com.apple.CoreSimulator.SimAudioProcessorServices.SimAudioProcessorService"},
		"macos27-user-coresimulatorservice.txt": {Target: "user/501/com.apple.CoreSimulator.CoreSimulatorService", PID: 67431, Type: "XPCService", BundleID: "com.apple.CoreSimulator.CoreSimulatorService"},
	} {
		s, err := Parse(capture(t, name))
		if err != nil || s.Target != want.Target || s.PID != want.PID || s.Type != want.Type || s.Original != want.Original || s.BundleID != want.BundleID || want.Path != "" && s.Path != want.Path {
			t.Errorf("%s: %+v, %v", name, s, err)
		}
		if name == "macos27-pid-devicefs.txt" && (len(s.Arguments) != 5 || s.Arguments[2] != `{"XPCService":{"Services":{"MainService":{}}}}`) {
			t.Errorf("DeviceFS arguments %q", s.Arguments)
		}
		if name != "macos27-user-coresimulatorservice.txt" && s.Inherited["HOME"] != "/Users/macservejob" {
			t.Errorf("%s inherited %v", name, s.Inherited)
		}
	}
}

func TestInlineBalancedArgumentCannotChangeNesting(t *testing.T) {
	for line, want := range map[string]bool{
		`{"a":{"b":[1,2]}}`: true,
		`[]`:                true,
		`{"a":"}{"}`:        true,
		`{`:                 false,
		`{"a":1}}`:          false,
		`{"a":1}{`:          false,
		`{"a":1} x`:         false,
		`{"a":"x}`:          false,
		`x{}`:               false,
		`{"a":[}`:           false,
	} {
		if inlineBalanced(line) != want {
			t.Errorf("inlineBalanced(%q) = %v", line, !want)
		}
	}
	devicefs := capture(t, "macos27-pid-devicefs.txt")
	forged := strings.Replace(devicefs, `{"XPCService":{"Services":{"MainService":{}}}}`, `{"XPCService":{`, 1)
	if _, err := Parse(forged); err == nil {
		t.Fatal("unbalanced argument line parsed")
	}
	// Outside the root arguments and environment, a one-line container is
	// still structure, never opaque text.
	forged = strings.Replace(devicefs, "\tinherited environment = {\n", "\tinherited environment = {\n\t\tX => {\"a\":1}\n", 1)
	if forged == devicefs {
		t.Fatal("fixture lacks inherited environment")
	}
	if _, err := Parse(forged); err == nil {
		t.Fatal("inline container accepted in inherited environment")
	}
	forged = strings.Replace(devicefs, "\tmanagedby_services = {\n", "\tmanagedby_services = {\n\t\t{\"a\":1}\n", 1)
	if _, err := Parse(forged); err == nil || forged == devicefs {
		t.Fatal("inline container accepted outside arguments")
	}
}

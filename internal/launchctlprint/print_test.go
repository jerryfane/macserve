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

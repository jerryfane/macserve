package launchctlprint

import (
	"os"
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

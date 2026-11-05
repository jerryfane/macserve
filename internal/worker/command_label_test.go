package worker

import (
	"strings"
	"testing"
)

func TestCommandLabelNamesSubcommandOnly(t *testing.T) {
	for args, want := range map[string]string{
		"simctl bootstatus D6C581BE-2B54-4AAB-ABAE-C2F295AB2761 -b": "xcrun simctl bootstatus",
		"--sdk iphonesimulator --show-sdk-version":                  "xcrun",
		"simctl list devices --json":                                "xcrun simctl list",
	} {
		if got := commandLabel(Command{Executable: "/usr/bin/xcrun", Args: strings.Fields(args)}); got != want {
			t.Errorf("commandLabel(%q) = %q, want %q", args, got, want)
		}
	}
}

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/onboarding"
)

func TestConnectGitHubRefusesBeforeContactingGitHub(t *testing.T) {
	original := connectGitHubHost
	t.Cleanup(func() { connectGitHubHost = original })
	for name, host := range map[string]onboarding.Host{
		"not root":          {Root: "/nonexistent/macserve", EUID: 501, SudoUID: "501"},
		"root without sudo": {Root: "/nonexistent/macserve", EUID: 0},
	} {
		connectGitHubHost = func() onboarding.Host { return host }
		var stdout, stderr bytes.Buffer
		if got := run([]string{"connect-github", "--profile", "p"}, &stdout, &stderr); got != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "sudo") {
			t.Errorf("%s: exit %d stdout %q stderr %q", name, got, stdout.String(), stderr.String())
		}
	}
}

func TestConnectGitHubUsage(t *testing.T) {
	for _, args := range [][]string{{"--bogus"}, {"extra"}} {
		var stdout, stderr bytes.Buffer
		if got := run(append([]string{"connect-github"}, args...), &stdout, &stderr); got != 2 {
			t.Errorf("%v: exit %d", args, got)
		}
	}
	var stdout, stderr bytes.Buffer
	if got := run([]string{"connect-github", "--help"}, &stdout, &stderr); got != 0 || !strings.Contains(stdout.String(), "Temporary until\n          PR-policy templates (O7)") {
		t.Fatalf("exit %d help %q", got, stdout.String())
	}
}

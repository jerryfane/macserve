package main

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/setup"
)

func TestOnboardingCommandsHelpExitZero(t *testing.T) {
	for _, name := range []string{"setup", "connect-github", "doctor", "build", "upgrade"} {
		for _, flag := range []string{"--help", "-h"} {
			var stdout, stderr bytes.Buffer
			if got := run([]string{name, flag}, &stdout, &stderr); got != 0 {
				t.Errorf("%s %s: exit %d, stderr %q", name, flag, got, stderr.String())
			}
			if !strings.HasPrefix(stdout.String(), "Usage: macserve "+name) || stderr.Len() != 0 {
				t.Errorf("%s %s: stdout %q stderr %q", name, flag, stdout.String(), stderr.String())
			}
		}
	}
}

func TestOnboardingShellsAreNotAvailable(t *testing.T) {
	for _, name := range []string{"connect-github", "doctor", "build", "upgrade"} {
		var stdout, stderr bytes.Buffer
		if got := run([]string{name}, &stdout, &stderr); got != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "not available in this release") {
			t.Errorf("%s: exit %d stdout %q stderr %q", name, got, stdout.String(), stderr.String())
		}
	}
}

func TestUsageListsOnboardingCommands(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := run([]string{"no-such-command"}, &stdout, &stderr); got != 2 {
		t.Fatalf("exit %d", got)
	}
	for _, want := range []string{"unknown command", "First-time setup:", "  setup ", "  connect-github ", "  doctor ", "  build ", "  upgrade ", "deploy-install"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("usage lacks %q:\n%s", want, stderr.String())
		}
	}
}

// fakeSetupHost is a healthy Mac. Every read is answered from memory.
func fakeSetupHost(t *testing.T, ran *int) setup.Probe {
	outputs := map[string]string{
		"/usr/bin/sw_vers -productVersion":                                       "26.1\n",
		"/usr/bin/sw_vers -buildVersion":                                         "25B78\n",
		"/usr/sbin/sysctl -n hw.optional.arm64":                                  "1\n",
		"/usr/bin/csrutil status":                                                "System Integrity Protection status: enabled.\n",
		"/usr/bin/fdesetup status":                                               "FileVault is Off.\n",
		"/usr/bin/xcode-select -p":                                               "/Applications/Xcode.app/Contents/Developer\n",
		"/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild -version": "Xcode 26.1\nBuild version 17B55\n",
	}
	return setup.Probe{
		GOOS: "darwin", UID: 501, EUID: 501, Environ: []string{"HOME=/Users/jdoe"},
		Run: func(_ context.Context, argv []string) (string, error) {
			*ran++
			if !setup.AllowedCommand(argv) {
				t.Errorf("setup --plan ran %q", argv)
			}
			if out, ok := outputs[strings.Join(argv, " ")]; ok {
				return out, nil
			}
			if argv[0] == "/usr/bin/dscl" {
				return "root 0\njdoe 501\n", nil
			}
			return "", errors.New("exit status 1")
		},
		Addrs: func() ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("100.101.102.103"), netip.MustParseAddr("192.168.1.20")}, nil
		},
		Lstat: func(path string) (setup.FileInfo, error) {
			if path == "/Users/jdoe" {
				return setup.FileInfo{Exists: true, Mode: fs.ModeDir | 0o700, UID: 501, GID: 20}, nil
			}
			return setup.FileInfo{}, nil
		},
		Owner: func() (setup.Account, error) {
			return setup.Account{Name: "jdoe", UID: 501, Home: "/Users/jdoe", GIDs: []uint32{20, 80}}, nil
		},
		AdminGID:  func() (uint32, error) { return 80, nil },
		PortInUse: func(context.Context, netip.AddrPort) bool { return false },
	}
}

func withSetupProbe(t *testing.T, p setup.Probe) {
	saved := setupProbe
	setupProbe = func() setup.Probe { return p }
	t.Cleanup(func() { setupProbe = saved })
}

func TestSetupPlanPrintsChecksAndEnvironment(t *testing.T) {
	ran := 0
	withSetupProbe(t, fakeSetupHost(t, &ran))
	var stdout, stderr bytes.Buffer
	if got := run([]string{"setup", "--plan", "--repository", "jdoe/myapp:987654321"}, &stdout, &stderr); got != 0 {
		t.Fatalf("exit %d\nstdout %s\nstderr %s", got, stdout.String(), stderr.String())
	}
	for _, want := range []string{"Nothing was written", "ok    host.sip", "ok    net.tailnet", "TAILNET_IP=100.101.102.103", "REPOSITORIES=jdoe/myapp:987654321", "JOB_UID=6202", "Result: ready"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("plan lacks %q:\n%s", want, stdout.String())
		}
	}
	if ran == 0 || stderr.Len() != 0 {
		t.Fatalf("ran %d stderr %q", ran, stderr.String())
	}
}

func TestSetupPlanBlockedExitsOne(t *testing.T) {
	ran := 0
	p := fakeSetupHost(t, &ran)
	p.Addrs = func() ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("192.168.1.20")}, nil }
	withSetupProbe(t, p)
	var stdout, stderr bytes.Buffer
	if got := run([]string{"setup", "--plan"}, &stdout, &stderr); got != 1 || !strings.Contains(stdout.String(), "fail  net.tailnet") || strings.Contains(stdout.String(), "Generated deploy.env") {
		t.Fatalf("exit %d\n%s", got, stdout.String())
	}
}

func TestSetupRefusesSudoAndApply(t *testing.T) {
	ran := 0
	p := fakeSetupHost(t, &ran)
	p.Environ = append(p.Environ, "SUDO_USER=jdoe", "SUDO_UID=501")
	withSetupProbe(t, p)
	var stdout, stderr bytes.Buffer
	if got := run([]string{"setup", "--plan"}, &stdout, &stderr); got != 2 || !strings.Contains(stderr.String(), "not with sudo") || ran != 0 {
		t.Fatalf("sudo: exit %d ran %d stderr %q", got, ran, stderr.String())
	}

	withSetupProbe(t, fakeSetupHost(t, &ran))
	for _, args := range [][]string{{"setup"}, {"setup", "--plan", "extra"}, {"setup", "--apply"}, {"setup", "--plan", "--job-real-name", " "}} {
		stdout.Reset()
		stderr.Reset()
		if got := run(args, &stdout, &stderr); got != 2 || stdout.Len() != 0 || ran != 0 {
			t.Errorf("%q: exit %d ran %d stdout %q", args, got, ran, stdout.String())
		}
	}
}

// TestSetupPlanOnThisHostChangesNothing runs the real system probe. On
// macOS it compares the local accounts and /Library/macserve before and
// after; elsewhere the plan stops at host.macos without probing.
func TestSetupPlanOnThisHostChangesNothing(t *testing.T) {
	probe := setup.SystemProbe()
	snapshot := func() string {
		var b strings.Builder
		if _, err := os.Lstat(setup.InstallRoot); err == nil {
			b.WriteString("install root present\n")
		}
		if runtime.GOOS == "darwin" {
			for _, path := range []string{"/Users", "/Groups"} {
				out, err := exec.Command("/usr/bin/dscl", ".", "-list", path).Output()
				if err != nil {
					t.Fatalf("dscl: %v", err)
				}
				b.Write(out)
			}
		}
		return b.String()
	}
	before := snapshot()
	var stdout, stderr bytes.Buffer
	got := run([]string{"setup", "--plan"}, &stdout, &stderr)
	want := []int{0, 1}
	if probe.Elevated() {
		want = []int{2}
	}
	if got != want[0] && (len(want) == 1 || got != want[1]) {
		t.Fatalf("exit %d, want %v\nstdout %s\nstderr %s", got, want, stdout.String(), stderr.String())
	}
	if !probe.Elevated() && !strings.HasPrefix(stdout.String(), "macserve setup --plan: read-only.") {
		t.Fatalf("stdout %s", stdout.String())
	}
	if runtime.GOOS != "darwin" && !probe.Elevated() && !strings.Contains(stdout.String(), "fail  host.macos") {
		t.Fatalf("non-macOS plan: %s", stdout.String())
	}
	if after := snapshot(); after != before {
		t.Fatalf("setup --plan changed host state:\nbefore %s\nafter %s", before, after)
	}
}

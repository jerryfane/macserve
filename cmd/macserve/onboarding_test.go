package main

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/setup"
	"github.com/jerryfane/macserve/internal/setup/plan"
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

// TestOnboardingHelpTakesNoArguments: only a lone --help prints help.
func TestOnboardingHelpTakesNoArguments(t *testing.T) {
	for _, name := range []string{"doctor", "build", "upgrade"} {
		var stdout, stderr bytes.Buffer
		if got := run([]string{name, "--help", "extra"}, &stdout, &stderr); got != 2 || stdout.Len() != 0 {
			t.Errorf("%s --help extra: exit %d stdout %q", name, got, stdout.String())
		}
	}
}

// TestOnboardingNamesDoNotShadowCommands: the hook runs only in the
// default branch, and no onboarding name equals an existing command.
func TestOnboardingNamesDoNotShadowCommands(t *testing.T) {
	for _, existing := range []string{"controller", "worker", "deploy-install", "qualify", "wait", "maintenance-observe", "worker-persistence", "worker-reset"} {
		if _, ok := onboardingCommand(existing); ok {
			t.Errorf("onboarding table shadows %s", existing)
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

// TestSetupDispatchesToRunSetup: checks/readonly proves runSetup read-only
// and lets onboardingCommand reach the table only on that basis.
func TestSetupDispatchesToRunSetup(t *testing.T) {
	var found bool
	for _, c := range onboardingCommands {
		if c.name == "setup" {
			found = reflect.ValueOf(c.run).Pointer() == reflect.ValueOf(runSetup).Pointer()
		}
	}
	if !found {
		t.Fatal(`the "setup" command does not run runSetup`)
	}
}

// fakeSetupHost is a healthy Mac. Every read is answered from memory.
func fakeSetupHost(t *testing.T, ran *int) plan.Probe {
	outputs := map[string]string{
		"/usr/bin/sw_vers -productVersion":                                       "26.1\n",
		"/usr/bin/sw_vers -buildVersion":                                         "25B78\n",
		"/usr/sbin/sysctl -n hw.optional.arm64":                                  "1\n",
		"/usr/bin/csrutil status":                                                "System Integrity Protection status: enabled.\n",
		"/usr/bin/fdesetup status":                                               "FileVault is Off.\n",
		"/usr/bin/xcode-select -p":                                               "/Applications/Xcode.app/Contents/Developer\n",
		"/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild -version": "Xcode 26.1\nBuild version 17B55\n",
	}
	return plan.Probe{
		GOOS: "darwin", UID: 501, EUID: 501, GID: 20, EGID: 20, Environ: []string{"HOME=/Users/jdoe"},
		Run: func(_ context.Context, argv []string) (string, error) {
			*ran++
			if !plan.AllowedCommand(argv) {
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
		Lstat: func(path string) (plan.FileInfo, error) {
			if path == "/Users/jdoe" {
				return plan.FileInfo{Exists: true, Mode: fs.ModeDir | 0o700, UID: 501, GID: 20, Nlink: 1}, nil
			}
			return plan.FileInfo{}, nil
		},
		Owner: func() (plan.Account, error) {
			return plan.Account{Name: "jdoe", UID: 501, Home: "/Users/jdoe", GIDs: []uint32{20, 80}}, nil
		},
		AdminGID:  func() (uint32, error) { return 80, nil },
		PortInUse: func(context.Context, netip.AddrPort) bool { return false },
	}
}

func TestSetupPlanPrintsChecksAndEnvironment(t *testing.T) {
	ran := 0
	var stdout, stderr bytes.Buffer
	if got := runSetupWith(fakeSetupHost(t, &ran), []string{"--plan", "--repository", "jdoe/myapp:987654321"}, &stdout, &stderr); got != 0 {
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
	var stdout, stderr bytes.Buffer
	if got := runSetupWith(p, []string{"--plan"}, &stdout, &stderr); got != 1 || !strings.Contains(stdout.String(), "fail  net.tailnet") || strings.Contains(stdout.String(), "Generated deploy.env") {
		t.Fatalf("exit %d\n%s", got, stdout.String())
	}
}

// TestSetupPlanBlocksInjectedFlags: values that would add deploy.env lines
// are reported as a failed check, and no environment is printed.
func TestSetupPlanBlocksInjectedFlags(t *testing.T) {
	for _, args := range [][]string{
		{"--plan", "--job-real-name", "macserve build\nCOEXISTING_SERVICES=com.example.agent"},
		{"--plan", "--job-real-name", "macserve build\rCOEXISTING_ANCHORS=x"},
		{"--plan", "--job-real-name", "a=b"},
		{"--plan", "--job-real-name", " "},
		{"--plan", "--job-real-name", ""},
		{"--plan", "--repository", "jdoe/myapp:1\nCOEXISTING_SERVICES=com.example.agent"},
		{"--plan", "--repository", "jdoe/myapp:1,jdoe/other:2"},
		{"--plan", "--repository", "jdoe/myapp"},
	} {
		ran := 0
		var stdout, stderr bytes.Buffer
		got := runSetupWith(fakeSetupHost(t, &ran), args, &stdout, &stderr)
		if got != 1 || !strings.Contains(stdout.String(), "fail  config.choices") || strings.Contains(stdout.String(), "Generated deploy.env") || strings.Contains(stdout.String(), "COEXISTING") {
			t.Errorf("%q: exit %d\n%s", args, got, stdout.String())
		}
	}
}

func TestSetupRefusesSudoAndApply(t *testing.T) {
	ran := 0
	p := fakeSetupHost(t, &ran)
	p.Environ = append(p.Environ, "SUDO_USER=jdoe", "SUDO_UID=501")
	var stdout, stderr bytes.Buffer
	if got := runSetupWith(p, []string{"--plan"}, &stdout, &stderr); got != 2 || !strings.Contains(stderr.String(), "not with sudo") || ran != 0 {
		t.Fatalf("sudo: exit %d ran %d stderr %q", got, ran, stderr.String())
	}
	for _, args := range [][]string{nil, {"--plan", "extra"}, {"--apply"}} {
		stdout.Reset()
		stderr.Reset()
		if got := runSetupWith(fakeSetupHost(t, &ran), args, &stdout, &stderr); got != 2 || stdout.Len() != 0 || ran != 0 {
			t.Errorf("%q: exit %d ran %d stdout %q", args, got, ran, stdout.String())
		}
	}
}

// TestSetupPlanOnThisHostChangesNothing runs the real command. On macOS it
// compares the local accounts and /Library/macserve before and after;
// elsewhere the plan stops at host.macos without probing.
func TestSetupPlanOnThisHostChangesNothing(t *testing.T) {
	probe := plan.SystemProbe()
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
	switch {
	case probe.Elevated():
		if got != 2 {
			t.Fatalf("elevated: exit %d", got)
		}
	case got != 0 && got != 1:
		t.Fatalf("exit %d\nstdout %s\nstderr %s", got, stdout.String(), stderr.String())
	case !strings.HasPrefix(stdout.String(), "macserve setup --plan: read-only."):
		t.Fatalf("stdout %s", stdout.String())
	case runtime.GOOS != "darwin" && !strings.Contains(stdout.String(), "fail  host.macos"):
		t.Fatalf("non-macOS plan: %s", stdout.String())
	}
	if after := snapshot(); after != before {
		t.Fatalf("setup --plan changed host state:\nbefore %s\nafter %s", before, after)
	}
}

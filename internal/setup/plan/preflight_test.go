package plan

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/deploy"
	"github.com/jerryfane/macserve/internal/setup"
)

type fakeHost struct {
	t       *testing.T
	outputs map[string]string
	files   map[string]FileInfo
	busy    map[uint16]bool
	addrs   []netip.Addr
	owner   Account
	admin   uint32
	calls   [][]string
	dials   []netip.AddrPort
}

func dsclKey(node, path, key string) string {
	return strings.Join([]string{"/usr/bin/dscl", node, "-list", path, key}, " ")
}

func newFakeHost(t *testing.T) *fakeHost {
	return &fakeHost{
		t: t,
		outputs: map[string]string{
			"/usr/bin/sw_vers -productVersion":                                       "26.1\n",
			"/usr/bin/sw_vers -buildVersion":                                         "25B78\n",
			"/usr/sbin/sysctl -n hw.optional.arm64":                                  "1\n",
			"/usr/bin/csrutil status":                                                "System Integrity Protection status: enabled.\n",
			"/usr/bin/fdesetup status":                                               "FileVault is On.\n",
			"/usr/bin/fdesetup supportsauthrestart":                                  "true\n",
			"/usr/bin/xcode-select -p":                                               "/Applications/Xcode.app/Contents/Developer\n",
			"/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild -version": "Xcode 26.1\nBuild version 17B55\n",
			dsclKey("/Search", "/Users", "UniqueID"):                                 "root 0\ndaemon 1\njdoe 501\n_www 70\n",
			dsclKey(".", "/Users", "UniqueID"):                                       "root 0\njdoe 501\n",
			dsclKey("/Search", "/Groups", "PrimaryGroupID"):                          "wheel 0\nstaff 20\nadmin 80\n",
			dsclKey(".", "/Groups", "PrimaryGroupID"):                                "wheel 0\nstaff 20\nadmin 80\n",
			dsclKey("/Search", "/Users", "PrimaryGroupID"):                           "root 0\njdoe 20\n",
			dsclKey(".", "/Users", "PrimaryGroupID"):                                 "root 0\njdoe 20\n",
		},
		files: map[string]FileInfo{
			"/Users/jdoe": {Exists: true, Mode: fs.ModeDir | 0o700, UID: 501, GID: 20, Nlink: 1},
		},
		busy: map[uint16]bool{},
		addrs: []netip.Addr{
			netip.MustParseAddr("127.0.0.1"),
			netip.MustParseAddr("::1"),
			netip.MustParseAddr("192.168.1.20"),
			netip.MustParseAddr("fe80::1%en0"),
			netip.MustParseAddr("100.101.102.103"),
			netip.MustParseAddr("fd7a:115c:a1e0::1234"),
		},
		owner: Account{Name: "jdoe", UID: 501, Home: "/Users/jdoe", GIDs: []uint32{20, 80}},
		admin: 80,
	}
}

func (h *fakeHost) probe() Probe {
	return Probe{
		GOOS: "darwin", UID: 501, EUID: 501, GID: 20, EGID: 20,
		Environ: []string{"HOME=/Users/jdoe", "PATH=/usr/bin:/bin"},
		Run: func(_ context.Context, argv []string) (string, error) {
			h.calls = append(h.calls, argv)
			if !AllowedCommand(argv) {
				h.t.Errorf("preflight ran a command outside the read-only list: %q", argv)
				return "", errors.New("refused")
			}
			out, ok := h.outputs[strings.Join(argv, " ")]
			if !ok {
				return "", errors.New("exit status 1")
			}
			return out, nil
		},
		Addrs:    func() ([]netip.Addr, error) { return h.addrs, nil },
		Lstat:    func(path string) (FileInfo, error) { return h.files[path], nil },
		Owner:    func() (Account, error) { return h.owner, nil },
		AdminGID: func() (uint32, error) { return h.admin, nil },
		PortInUse: func(_ context.Context, ap netip.AddrPort) bool {
			h.dials = append(h.dials, ap)
			return h.busy[ap.Port()]
		},
	}
}

func checkStatus(t *testing.T, plan Plan, id string) string {
	t.Helper()
	for _, c := range plan.Checks {
		if c.ID == id {
			return c.Status
		}
	}
	t.Fatalf("no check %s in %+v", id, plan.Checks)
	return ""
}

func TestPreflightHealthyHostGeneratesEnvironment(t *testing.T) {
	h := newFakeHost(t)
	plan := Preflight(context.Background(), h.probe(), DefaultChoices())
	if !plan.Ready() {
		t.Fatalf("plan not ready: %+v", plan.Checks)
	}
	if checkStatus(t, plan, "host.filevault") != Warn || !plan.AuthRestart {
		t.Fatalf("FileVault on with authrestart should warn: %+v", plan)
	}
	if bytes.Contains(plan.Environment, []byte("REPOSITORIES=")) {
		t.Fatalf("REPOSITORIES present before the GitHub step:\n%s", plan.Environment)
	}
	env, err := deploy.ParseEnvironment(append(bytes.Clone(plan.Environment), "REPOSITORIES=jdoe/myapp:987654321\n"...))
	if err != nil {
		t.Fatal(err)
	}
	if env.OwnerUser != "jdoe" || env.OwnerUID != 501 || env.ControllerUID != 6201 || env.JobUID != 6202 || env.JobRealName != "macserve build" ||
		env.TailnetIP != "100.101.102.103" || env.Port != 8443 || env.DeveloperDir != "/Applications/Xcode.app/Contents/Developer" {
		t.Fatalf("unexpected environment %+v", env)
	}
	if got := strings.Join(env.HostAddresses, ","); got != "100.101.102.103,192.168.1.20,fd7a:115c:a1e0::1234" {
		t.Fatalf("HOST_ADDRESSES = %s", got)
	}
	if want := []netip.AddrPort{netip.MustParseAddrPort("100.101.102.103:8443")}; !slices.Equal(h.dials, want) {
		t.Fatalf("dialled %v, want only %v", h.dials, want)
	}
	var out bytes.Buffer
	if err := WritePlan(&out, plan); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"read-only. Nothing was written", "JOB_UID=6202", "# REPOSITORIES is added in step 2", " 2. github", "10. first-build", "Result: ready"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("plan output lacks %q:\n%s", want, out.String())
		}
	}
}

// TestPreflightRunsOnlyReadOnlyCommands: the preflight asks only for
// allowed commands (the fake fails the test otherwise), and uses every one.
func TestPreflightRunsOnlyReadOnlyCommands(t *testing.T) {
	h := newFakeHost(t)
	c := DefaultChoices()
	c.Repository = "jdoe/myapp:987654321"
	Preflight(context.Background(), h.probe(), c)
	seen := map[string]bool{}
	for _, argv := range h.calls {
		seen[strings.Join(argv, " ")] = true
	}
	for _, c := range readOnlyCommands {
		if !seen[strings.Join(c, " ")] {
			t.Errorf("allowed command %q never used; remove it from the list", c)
		}
	}
	if len(seen) != len(readOnlyCommands)+1 {
		t.Errorf("ran %d distinct commands, want the %d fixed ones and xcodebuild -version", len(seen), len(readOnlyCommands))
	}
}

// TestReadOnlyCommandsGolden pins the command allowlist. A change here is
// a change to what `setup --plan` may run and needs review.
func TestReadOnlyCommandsGolden(t *testing.T) {
	golden := [][]string{
		{"/usr/bin/csrutil", "status"},
		{"/usr/bin/dscl", ".", "-list", "/Groups", "PrimaryGroupID"},
		{"/usr/bin/dscl", ".", "-list", "/Users", "PrimaryGroupID"},
		{"/usr/bin/dscl", ".", "-list", "/Users", "UniqueID"},
		{"/usr/bin/dscl", "/Search", "-list", "/Groups", "PrimaryGroupID"},
		{"/usr/bin/dscl", "/Search", "-list", "/Users", "PrimaryGroupID"},
		{"/usr/bin/dscl", "/Search", "-list", "/Users", "UniqueID"},
		{"/usr/bin/fdesetup", "status"},
		{"/usr/bin/fdesetup", "supportsauthrestart"},
		{"/usr/bin/sw_vers", "-buildVersion"},
		{"/usr/bin/sw_vers", "-productVersion"},
		{"/usr/bin/xcode-select", "-p"},
		{"/usr/sbin/sysctl", "-n", "hw.optional.arm64"},
	}
	if !slices.EqualFunc(readOnlyCommands, golden, slices.Equal) {
		t.Fatalf("readOnlyCommands changed:\n%q", readOnlyCommands)
	}
	if !slices.IsSortedFunc(readOnlyCommands, slices.Compare) {
		t.Fatal("readOnlyCommands is not sorted")
	}
	if xcodebuildSuffix != "/usr/bin/xcodebuild" || !slices.Equal(commandEnv, []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}) {
		t.Fatalf("runner constants changed: %q %q", xcodebuildSuffix, commandEnv)
	}
}

func TestAllowedCommandRefusesEverythingElse(t *testing.T) {
	for _, argv := range [][]string{
		nil,
		{},
		{"/usr/bin/fdesetup", "authrestart"},
		{"/usr/bin/fdesetup", "status", "-extended"},
		{"/usr/bin/dscl", ".", "-create", "/Users/macservejob"},
		{"/usr/bin/dscl", ".", "-list", "/Users"},
		{"sw_vers", "-productVersion"},
		{"/usr/bin/csrutil", "disable"},
		{"/usr/bin/xcode-select", "-s", "/Applications/Xcode.app"},
		{"/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild", "-license", "accept"},
		{"/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild", "-runFirstLaunch"},
		{"/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild", "-version", "-sdk"},
		{"/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild"},
		{"/Library/Developer/CommandLineTools/usr/bin/xcodebuild", "-version"},
		{"/tmp/evil.app/Contents/Developer/../../../bin/sh/usr/bin/xcodebuild", "-version"},
		{"/tmp/a.app/Contents/Developer/x/usr/bin/xcodebuild", "-version"},
		{"/tmp/x/../y.app/Contents/Developer/usr/bin/xcodebuild", "-version"},
		{"//Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild", "-version"},
		{"/Applications/Xcode.app/Contents/Developer/./usr/bin/xcodebuild", "-version"},
		{"/tmp/a;b.app/Contents/Developer/usr/bin/xcodebuild", "-version"},
		{"relative.app/Contents/Developer/usr/bin/xcodebuild", "-version"},
		{"/tmp/$(id).app/Contents/Developer/usr/bin/xcodebuild", "-version"},
		{"/tmp/a\n.app/Contents/Developer/usr/bin/xcodebuild", "-version"},
		{"/bin/sh", "-c", "true"},
		{"/usr/bin/touch", "/tmp/x"},
	} {
		if AllowedCommand(argv) {
			t.Errorf("AllowedCommand(%q) = true", argv)
		}
	}
	for _, ok := range [][]string{
		{"/Applications/Xcode-26.1.app/Contents/Developer/usr/bin/xcodebuild", "-version"},
		{"/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild", "-version"},
	} {
		if !AllowedCommand(ok) {
			t.Errorf("AllowedCommand(%q) = false", ok)
		}
	}
}

// TestCommandHardening pins how every allowed command is started: exactly
// the given absolute path and argv (never a PATH lookup), the fixed
// environment, cwd "/", no stdin, no extra files or process attributes, and
// bounded output.
func TestCommandHardening(t *testing.T) {
	for _, argv := range append(slices.Clone(readOnlyCommands), []string{"/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild", "-version"}) {
		cmd, out, err := command(context.Background(), argv)
		if err != nil {
			t.Fatal(err)
		}
		env := []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}
		if strings.HasSuffix(argv[0], "/xcodebuild") {
			env = append(env, "DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer")
		}
		if cmd.Path != argv[0] || !filepath.IsAbs(cmd.Path) || !slices.Equal(cmd.Args, argv) || cmd.Err != nil {
			t.Errorf("%q: path %q args %q err %v", argv, cmd.Path, cmd.Args, cmd.Err)
		}
		if !slices.Equal(cmd.Env, env) || cmd.Dir != "/" || cmd.Stdin != nil || cmd.ExtraFiles != nil || cmd.SysProcAttr != nil || cmd.WaitDelay != 0 {
			t.Errorf("%q: env %q dir %q stdin %v extra %v attr %v", argv, cmd.Env, cmd.Dir, cmd.Stdin, cmd.ExtraFiles, cmd.SysProcAttr)
		}
		stdout, okOut := cmd.Stdout.(*boundedBuffer)
		_, okErr := cmd.Stderr.(*boundedBuffer)
		if !okOut || !okErr || stdout != out || cmd.Stdout == cmd.Stderr {
			t.Errorf("%q: output is not bounded and separate", argv)
		}
	}
	var b boundedBuffer
	if _, err := b.Write(make([]byte, maxCommandOutput)); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Write([]byte{1}); err == nil || !b.over || b.buf.Len() != maxCommandOutput {
		t.Fatal("output bound not enforced")
	}
	if maxCommandOutput != 4<<20 || commandTimeout.Seconds() != 30 {
		t.Fatal("runner bounds changed")
	}
}

func TestSystemRunnerRefusesBeforeExecuting(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "marker")
	for _, argv := range [][]string{{"/usr/bin/touch", marker}, {"touch", marker}} {
		if _, err := runReadOnly(context.Background(), argv); err == nil || !strings.Contains(err.Error(), "refused") {
			t.Fatalf("runReadOnly(%q) = %v, want refusal", argv, err)
		}
	}
	if _, err := os.Lstat(marker); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("refused command ran: %v", err)
	}
}

// TestPortInUseDialsOnlyTheTarget: a listening port is in use; once closed
// (connection refused) it is free.
func TestPortInUseDialsOnlyTheTarget(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ap := netip.MustParseAddrPort(l.Addr().String())
	if !portInUse(context.Background(), ap) {
		t.Fatal("listening port reported free")
	}
	l.Close()
	if portInUse(context.Background(), ap) {
		t.Fatal("closed port reported in use")
	}
	// Any other failure (here: a cancelled dial) does not prove the port
	// free.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !portInUse(ctx, ap) {
		t.Fatal("failed dial reported the port free")
	}
}

func TestReadyNeedsEnvironment(t *testing.T) {
	if (Plan{Checks: []Check{{ID: "host.macos", Status: OK}}}).Ready() {
		t.Fatal("plan without an environment is ready")
	}
	if !(Plan{Checks: []Check{{ID: "host.macos", Status: Warn}}, Environment: []byte("X=1\n")}).Ready() {
		t.Fatal("plan with only warnings is not ready")
	}
	if (Plan{Checks: []Check{{ID: "a", Status: OK}, {ID: "b", Status: Fail}}, Environment: []byte("X=1\n")}).Ready() {
		t.Fatal("failed check ignored")
	}
}

func TestPreflightRefusesExistingInstallation(t *testing.T) {
	native := func(h *fakeHost) {
		for _, d := range []string{setup.InstallRoot, setup.InstallRoot + "/var", setup.LedgerDir} {
			h.files[d] = FileInfo{Exists: true, Mode: fs.ModeDir | 0o755, UID: 0, GID: 0, Nlink: 3}
		}
		h.files[setup.LedgerPath] = FileInfo{Exists: true, Mode: 0o600, UID: 0, GID: 0, Nlink: 1}
	}
	tests := []struct {
		name, want string
		mutate     func(*fakeHost)
	}{
		{"admin-managed", "managed by other tooling", func(h *fakeHost) {
			h.files[setup.InstallRoot] = FileInfo{Exists: true, Mode: fs.ModeDir | 0o755}
		}},
		{"native ledger", "native setup ledger exists", native},
		{"symlinked ledger", "managed by other tooling", func(h *fakeHost) {
			native(h)
			h.files[setup.LedgerPath] = FileInfo{Exists: true, Mode: fs.ModeSymlink | 0o600, UID: 0, Nlink: 1}
		}},
		{"user-owned ledger", "managed by other tooling", func(h *fakeHost) {
			native(h)
			h.files[setup.LedgerPath] = FileInfo{Exists: true, Mode: 0o600, UID: 501, Nlink: 1}
		}},
		{"install root is a symlink", "managed by other tooling", func(h *fakeHost) {
			native(h)
			h.files[setup.InstallRoot] = FileInfo{Exists: true, Mode: fs.ModeSymlink | 0o755, UID: 0, Nlink: 1}
		}},
		{"group-owned ledger", "managed by other tooling", func(h *fakeHost) {
			native(h)
			h.files[setup.LedgerPath] = FileInfo{Exists: true, Mode: 0o600, UID: 0, GID: 20, Nlink: 1}
		}},
		{"ledger is a directory", "managed by other tooling", func(h *fakeHost) {
			native(h)
			h.files[setup.LedgerPath] = FileInfo{Exists: true, Mode: fs.ModeDir | 0o600, UID: 0, Nlink: 1}
		}},
		{"user-owned var", "managed by other tooling", func(h *fakeHost) {
			native(h)
			h.files[setup.InstallRoot+"/var"] = FileInfo{Exists: true, Mode: fs.ModeDir | 0o755, UID: 501, Nlink: 3}
		}},
		{"hard-linked ledger", "managed by other tooling", func(h *fakeHost) {
			native(h)
			h.files[setup.LedgerPath] = FileInfo{Exists: true, Mode: 0o600, UID: 0, Nlink: 2}
		}},
		{"readable ledger", "managed by other tooling", func(h *fakeHost) {
			native(h)
			h.files[setup.LedgerPath] = FileInfo{Exists: true, Mode: 0o644, UID: 0, Nlink: 1}
		}},
		{"writable ledger dir", "managed by other tooling", func(h *fakeHost) {
			native(h)
			h.files[setup.LedgerDir] = FileInfo{Exists: true, Mode: fs.ModeDir | 0o777, UID: 0, Nlink: 2}
		}},
	}
	for _, test := range tests {
		h := newFakeHost(t)
		test.mutate(h)
		plan := Preflight(context.Background(), h.probe(), DefaultChoices())
		var detail string
		for _, c := range plan.Checks {
			if c.ID == "setup.existing" {
				detail = c.Detail
			}
		}
		if checkStatus(t, plan, "setup.existing") != Fail || plan.Ready() || !strings.Contains(detail, test.want) {
			t.Errorf("%s: %q ready %v", test.name, detail, plan.Ready())
		}
	}
}

func TestPreflightRefusesElevatedWithoutProbing(t *testing.T) {
	for _, mutate := range []func(*Probe){
		func(p *Probe) { p.UID, p.EUID = 0, 0 },
		func(p *Probe) { p.EUID = 0 },
		func(p *Probe) { p.UID = 0 },
		func(p *Probe) { p.EUID = 502 },
		func(p *Probe) { p.GID, p.EGID = 0, 0 },
		func(p *Probe) { p.EGID = 0 },
		func(p *Probe) { p.GID = 0 },
		func(p *Probe) { p.EGID = 80 },
		func(p *Probe) { p.Environ = append(p.Environ, "SUDO_USER=jdoe") },
		func(p *Probe) { p.Environ = append(p.Environ, "SUDO_COMMAND=/usr/local/bin/macserve") },
	} {
		h := newFakeHost(t)
		p := h.probe()
		mutate(&p)
		plan := Preflight(context.Background(), p, DefaultChoices())
		if !p.Elevated() || len(plan.Checks) != 1 || plan.Checks[0].ID != "host.user" || plan.Checks[0].Status != Fail || len(h.calls) != 0 || len(h.dials) != 0 {
			t.Fatalf("elevated preflight: checks %+v calls %q", plan.Checks, h.calls)
		}
	}
	if newFakeHost(t).probe().Elevated() {
		t.Fatal("ordinary user reported elevated")
	}
}

func TestPreflightOffMacOSProbesNothing(t *testing.T) {
	h := newFakeHost(t)
	p := h.probe()
	p.GOOS = "linux"
	plan := Preflight(context.Background(), p, DefaultChoices())
	if plan.Ready() || len(plan.Checks) != 1 || plan.Checks[0].ID != "host.macos" || len(h.calls) != 0 {
		t.Fatalf("linux preflight: %+v calls %q", plan.Checks, h.calls)
	}
}

func TestPreflightBlockingChecks(t *testing.T) {
	tests := []struct {
		id     string
		mutate func(*fakeHost)
	}{
		{"host.admin", func(h *fakeHost) { h.owner.GIDs = []uint32{20} }},
		{"host.macos", func(h *fakeHost) { delete(h.outputs, "/usr/bin/sw_vers -productVersion") }},
		{"host.arch", func(h *fakeHost) { delete(h.outputs, "/usr/sbin/sysctl -n hw.optional.arm64") }},
		{"host.arch", func(h *fakeHost) { h.outputs["/usr/sbin/sysctl -n hw.optional.arm64"] = "0\n" }},
		{"host.sip", func(h *fakeHost) {
			h.outputs["/usr/bin/csrutil status"] = "System Integrity Protection status: disabled.\n"
		}},
		{"host.sip", func(h *fakeHost) {
			h.outputs["/usr/bin/csrutil status"] = "System Integrity Protection status: enabled.\n\nConfiguration:\n\tKext Signing: disabled\n"
		}},
		{"xcode.developer_dir", func(h *fakeHost) {
			h.outputs["/usr/bin/xcode-select -p"] = "/Library/Developer/CommandLineTools\n"
		}},
		{"xcode.developer_dir", func(h *fakeHost) { delete(h.outputs, "/usr/bin/xcode-select -p") }},
		{"net.tailnet", func(h *fakeHost) { h.addrs = h.addrs[:4] }},
		{"owner.home", func(h *fakeHost) {
			h.files["/Users/jdoe"] = FileInfo{Exists: true, Mode: fs.ModeDir | 0o701, UID: 501, GID: 7000}
		}},
		{"owner.home", func(h *fakeHost) {
			// The macOS default: staff can list the home.
			h.files["/Users/jdoe"] = FileInfo{Exists: true, Mode: fs.ModeDir | 0o750, UID: 501, GID: 20}
		}},
		{"owner.home", func(h *fakeHost) {
			h.files["/Users/jdoe"] = FileInfo{Exists: true, Mode: fs.ModeSymlink | 0o700, UID: 501}
		}},
		{"owner.home", func(h *fakeHost) {
			h.files["/Users/jdoe"] = FileInfo{Exists: true, Mode: fs.ModeDir | 0o700, UID: 502}
		}},
		{"ids.accounts", func(h *fakeHost) {
			h.outputs[dsclKey("/Search", "/Users", "UniqueID")] += "macservejob 7001\n"
		}},
		{"ids.accounts", func(h *fakeHost) {
			h.outputs[dsclKey(".", "/Groups", "PrimaryGroupID")] += "odd record 3\n"
		}},
		{"ids.accounts", func(h *fakeHost) { delete(h.outputs, dsclKey(".", "/Users", "PrimaryGroupID")) }},
	}
	for _, test := range tests {
		h := newFakeHost(t)
		test.mutate(h)
		plan := Preflight(context.Background(), h.probe(), DefaultChoices())
		if got := checkStatus(t, plan, test.id); got != Fail || plan.Ready() {
			t.Errorf("%s: status %s ready %v, want fail and blocked", test.id, got, plan.Ready())
		}
	}
}

func TestPreflightWarningsDoNotBlock(t *testing.T) {
	h := newFakeHost(t)
	h.files["/Users/jdoe"] = FileInfo{Exists: true, Mode: fs.ModeDir | 0o750, UID: 501, GID: 7000}
	h.outputs["/usr/bin/fdesetup supportsauthrestart"] = "false\n"
	delete(h.outputs, "/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild -version")
	plan := Preflight(context.Background(), h.probe(), DefaultChoices())
	for _, id := range []string{"owner.home", "host.filevault", "xcode.version"} {
		if checkStatus(t, plan, id) != Warn {
			t.Errorf("%s should warn: %+v", id, plan.Checks)
		}
	}
	if !plan.Ready() || plan.AuthRestart || !plan.FileVaultOn {
		t.Fatalf("warnings blocked the plan: %+v", plan.Checks)
	}
	h = newFakeHost(t)
	h.outputs["/usr/bin/fdesetup status"] = "FileVault is Off.\n"
	h.outputs["/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild -version"] = "Xcode 26.1\nBuild version \x1b[2J\n"
	plan = Preflight(context.Background(), h.probe(), DefaultChoices())
	if checkStatus(t, plan, "host.filevault") != OK || plan.FileVaultOn || checkStatus(t, plan, "xcode.version") != Warn {
		t.Fatalf("FileVault off / hostile xcodebuild output: %+v", plan.Checks)
	}
}

func TestPreflightPicksNextFreePort(t *testing.T) {
	h := newFakeHost(t)
	h.busy[8443], h.busy[8444] = true, true
	plan := Preflight(context.Background(), h.probe(), DefaultChoices())
	if !bytes.Contains(plan.Environment, []byte("\nPORT=8445\nPROTECTED_PORTS=8445\n")) {
		t.Fatalf("port not moved:\n%s", plan.Environment)
	}
	for _, ap := range h.dials {
		if ap.Addr() != netip.MustParseAddr("100.101.102.103") {
			t.Fatalf("dialled %v outside the tailnet address", ap)
		}
	}
	h = newFakeHost(t)
	for p := uint16(DefaultPort); p < DefaultPort+portCandidates; p++ {
		h.busy[p] = true
	}
	plan = Preflight(context.Background(), h.probe(), DefaultChoices())
	if checkStatus(t, plan, "net.port") != Fail || plan.Ready() || len(h.dials) != portCandidates {
		t.Fatalf("all ports busy: %+v dials %d", plan.Checks, len(h.dials))
	}
}

// TestPreflightBlocksInjectedChoices: input that could add or change a
// deploy.env line blocks the plan and generates nothing.
func TestPreflightBlocksInjectedChoices(t *testing.T) {
	for name, mutate := range injectionChoices() {
		h := newFakeHost(t)
		c := DefaultChoices()
		mutate(&c)
		plan := Preflight(context.Background(), h.probe(), c)
		if checkStatus(t, plan, "config.choices") != Fail || plan.Ready() || plan.Environment != nil {
			t.Errorf("%s: accepted: %+v", name, plan.Checks)
		}
		var out bytes.Buffer
		if err := WritePlan(&out, plan); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out.String(), "COEXISTING") || strings.Contains(out.String(), "Generated deploy.env") {
			t.Errorf("%s: plan printed an environment:\n%s", name, out.String())
		}
	}
}

package setup

import (
	"bytes"
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/deploy"
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
}

func newFakeHost(t *testing.T) *fakeHost {
	dscl := func(node, path, key string) string {
		return strings.Join([]string{"/usr/bin/dscl", node, "-list", path, key}, " ")
	}
	h := &fakeHost{
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
			dscl("/Search", "/Users", "UniqueID"):                                    "root 0\ndaemon 1\njdoe 501\n_www 70\n",
			dscl(".", "/Users", "UniqueID"):                                          "root 0\njdoe 501\n",
			dscl("/Search", "/Groups", "PrimaryGroupID"):                             "wheel 0\nstaff 20\nadmin 80\n",
			dscl(".", "/Groups", "PrimaryGroupID"):                                   "wheel 0\nstaff 20\nadmin 80\n",
			dscl("/Search", "/Users", "PrimaryGroupID"):                              "root 0\njdoe 20\n",
			dscl(".", "/Users", "PrimaryGroupID"):                                    "root 0\njdoe 20\n",
		},
		files: map[string]FileInfo{
			"/Users/jdoe": {Exists: true, Mode: fs.ModeDir | 0o700, UID: 501, GID: 20},
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
	return h
}

func (h *fakeHost) probe() Probe {
	return Probe{
		GOOS: "darwin", UID: 501, EUID: 501, Environ: []string{"HOME=/Users/jdoe", "PATH=/usr/bin:/bin"},
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
		Addrs:     func() ([]netip.Addr, error) { return h.addrs, nil },
		Lstat:     func(path string) (FileInfo, error) { return h.files[path], nil },
		Owner:     func() (Account, error) { return h.owner, nil },
		AdminGID:  func() (uint32, error) { return h.admin, nil },
		PortInUse: func(_ context.Context, ap netip.AddrPort) bool { return h.busy[ap.Port()] },
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

// TestPreflightRunsOnlyReadOnlyCommands is half of the read-only proof: the
// preflight asks only for allowed commands (the fake fails the test
// otherwise), and the system runner refuses anything else before exec.
func TestPreflightRunsOnlyReadOnlyCommands(t *testing.T) {
	h := newFakeHost(t)
	Preflight(context.Background(), h.probe(), Choices{ControllerUser: "macservectl", JobUser: "macservejob", JobRealName: "macserve build", Repository: "jdoe/myapp:987654321"})
	if len(h.calls) == 0 {
		t.Fatal("no commands recorded")
	}
	seen := map[string]bool{}
	for _, argv := range h.calls {
		seen[strings.Join(argv, " ")] = true
	}
	for _, c := range readOnlyCommands {
		if !seen[strings.Join(c, " ")] {
			t.Errorf("allowed command %q never used; remove it from the list", c)
		}
	}
}

func TestAllowedCommandRefusesEverythingElse(t *testing.T) {
	for _, argv := range [][]string{
		nil,
		{"/usr/bin/fdesetup", "authrestart"},
		{"/usr/bin/fdesetup", "status", "-extended"},
		{"/usr/bin/dscl", ".", "-create", "/Users/macservejob"},
		{"/usr/bin/dscl", ".", "-list", "/Users"},
		{"sw_vers", "-productVersion"},
		{"/usr/bin/csrutil", "disable"},
		{"/usr/bin/xcode-select", "-s", "/Applications/Xcode.app"},
		{"/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild", "-license", "accept"},
		{"/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild", "-runFirstLaunch"},
		{"/Library/Developer/CommandLineTools/usr/bin/xcodebuild", "-version"},
		{"/tmp/evil.app/Contents/Developer/../../../bin/sh/usr/bin/xcodebuild", "-version"},
		{"relative.app/Contents/Developer/usr/bin/xcodebuild", "-version"},
		{"/bin/sh", "-c", "true"},
	} {
		if AllowedCommand(argv) {
			t.Errorf("AllowedCommand(%q) = true", argv)
		}
	}
	if !AllowedCommand([]string{"/Applications/Xcode-26.1.app/Contents/Developer/usr/bin/xcodebuild", "-version"}) {
		t.Error("xcodebuild -version in an Xcode app refused")
	}
}

func TestSystemRunnerRefusesBeforeExecuting(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "marker")
	if _, err := runReadOnly(context.Background(), []string{"/usr/bin/touch", marker}); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("runReadOnly(touch) = %v, want refusal", err)
	}
	if _, err := os.Lstat(marker); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("refused command ran: %v", err)
	}
}

// TestPlanCodeHasNoMutatingCalls is the other half of the read-only proof:
// the files the plan runs call no file, process or network API that can
// change host state, and exec only inside the allowlisted runner.
func TestPlanCodeHasNoMutatingCalls(t *testing.T) {
	allowed := map[string]map[string]bool{
		"os":      {"Lstat": true, "Getuid": true, "Geteuid": true, "Environ": true},
		"exec":    {"CommandContext": true},
		"net":     {"InterfaceAddrs": true, "IPNet": true, "Dialer": true},
		"syscall": {"Stat_t": true, "ECONNREFUSED": true},
		"user":    {"LookupId": true, "LookupGroup": true},
	}
	for _, name := range []string{"preflight.go", "env.go", "ledger.go"} {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		imports := map[string]string{}
		for _, spec := range file.Imports {
			path, _ := strconv.Unquote(spec.Path.Value)
			local := filepath.Base(path)
			if spec.Name != nil {
				local = spec.Name.Name
			}
			imports[local] = path
			switch path {
			case "os/signal", "unsafe", "golang.org/x/sys/unix", "net/http", "plugin":
				t.Errorf("%s imports %s", name, path)
			}
		}
		for _, decl := range file.Decls {
			fn, _ := decl.(*ast.FuncDecl)
			ast.Inspect(decl, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok || imports[pkg.Name] == "" {
					return true
				}
				names, guarded := allowed[pkg.Name]
				if !guarded {
					return true
				}
				if !names[sel.Sel.Name] {
					t.Errorf("%s: %s.%s is not allowed in plan code", fset.Position(sel.Pos()), pkg.Name, sel.Sel.Name)
				}
				if pkg.Name == "exec" && (fn == nil || fn.Name.Name != "runReadOnly") {
					t.Errorf("%s: exec outside runReadOnly", fset.Position(sel.Pos()))
				}
				return true
			})
		}
	}
}

func TestPreflightRefusesAdminManagedHost(t *testing.T) {
	h := newFakeHost(t)
	h.files[InstallRoot] = FileInfo{Exists: true, Mode: fs.ModeDir | 0o755}
	plan := Preflight(context.Background(), h.probe(), DefaultChoices())
	if checkStatus(t, plan, "setup.existing") != Fail || plan.Ready() || plan.ExistingSetup {
		t.Fatalf("admin-managed host accepted: %+v", plan.Checks)
	}
	h.files[LedgerPath] = FileInfo{Exists: true, Mode: 0o600, UID: 0}
	plan = Preflight(context.Background(), h.probe(), DefaultChoices())
	if checkStatus(t, plan, "setup.existing") != Warn || !plan.ExistingSetup {
		t.Fatalf("native ledger not recognised: %+v", plan.Checks)
	}
	h.files[LedgerPath] = FileInfo{Exists: true, Mode: fs.ModeSymlink | 0o777, UID: 501}
	plan = Preflight(context.Background(), h.probe(), DefaultChoices())
	if checkStatus(t, plan, "setup.existing") != Fail {
		t.Fatalf("symlinked, user-owned ledger accepted: %+v", plan.Checks)
	}
}

func TestPreflightRefusesRootAndSudoWithoutProbing(t *testing.T) {
	for _, mutate := range []func(*Probe){
		func(p *Probe) { p.UID, p.EUID = 0, 0 },
		func(p *Probe) { p.EUID = 0 },
		func(p *Probe) { p.Environ = append(p.Environ, "SUDO_USER=jdoe") },
	} {
		h := newFakeHost(t)
		p := h.probe()
		mutate(&p)
		plan := Preflight(context.Background(), p, DefaultChoices())
		if len(plan.Checks) != 1 || plan.Checks[0].ID != "host.user" || plan.Checks[0].Status != Fail || len(h.calls) != 0 {
			t.Fatalf("elevated preflight: checks %+v calls %q", plan.Checks, h.calls)
		}
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
		status string
		mutate func(*fakeHost)
	}{
		{"host.admin", Fail, func(h *fakeHost) { h.owner.GIDs = []uint32{20} }},
		{"host.arch", Fail, func(h *fakeHost) { delete(h.outputs, "/usr/sbin/sysctl -n hw.optional.arm64") }},
		{"host.sip", Fail, func(h *fakeHost) {
			h.outputs["/usr/bin/csrutil status"] = "System Integrity Protection status: disabled.\n"
		}},
		{"host.sip", Fail, func(h *fakeHost) {
			h.outputs["/usr/bin/csrutil status"] = "System Integrity Protection status: unknown (Custom Configuration).\n"
		}},
		{"xcode.developer_dir", Fail, func(h *fakeHost) {
			h.outputs["/usr/bin/xcode-select -p"] = "/Library/Developer/CommandLineTools\n"
		}},
		{"net.tailnet", Fail, func(h *fakeHost) { h.addrs = h.addrs[:4] }},
		{"owner.home", Fail, func(h *fakeHost) {
			h.files["/Users/jdoe"] = FileInfo{Exists: true, Mode: fs.ModeDir | 0o701, UID: 501, GID: 7000}
		}},
		{"owner.home", Fail, func(h *fakeHost) {
			// The macOS default: staff can list the home.
			h.files["/Users/jdoe"] = FileInfo{Exists: true, Mode: fs.ModeDir | 0o750, UID: 501, GID: 20}
		}},
		{"owner.home", Fail, func(h *fakeHost) {
			h.files["/Users/jdoe"] = FileInfo{Exists: true, Mode: fs.ModeSymlink | 0o700, UID: 501}
		}},
		{"ids.accounts", Fail, func(h *fakeHost) {
			h.outputs["/usr/bin/dscl /Search -list /Users UniqueID"] += "macservejob 7001\n"
		}},
		{"ids.accounts", Fail, func(h *fakeHost) {
			h.outputs["/usr/bin/dscl . -list /Groups PrimaryGroupID"] += "odd record 3\n"
		}},
	}
	for _, test := range tests {
		h := newFakeHost(t)
		test.mutate(h)
		plan := Preflight(context.Background(), h.probe(), DefaultChoices())
		if got := checkStatus(t, plan, test.id); got != test.status || plan.Ready() {
			t.Errorf("%s: status %s ready %v, want %s and blocked", test.id, got, plan.Ready(), test.status)
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
	if !plan.Ready() || plan.AuthRestart {
		t.Fatalf("warnings blocked the plan: %+v", plan.Checks)
	}
}

func TestPreflightPicksNextFreePort(t *testing.T) {
	h := newFakeHost(t)
	h.busy[8443], h.busy[8444] = true, true
	plan := Preflight(context.Background(), h.probe(), DefaultChoices())
	if !bytes.Contains(plan.Environment, []byte("\nPORT=8445\nPROTECTED_PORTS=8445\n")) {
		t.Fatalf("port not moved:\n%s", plan.Environment)
	}
	for p := uint16(DefaultPort); p < DefaultPort+portCandidates; p++ {
		h.busy[p] = true
	}
	plan = Preflight(context.Background(), h.probe(), DefaultChoices())
	if checkStatus(t, plan, "net.port") != Fail || plan.Ready() {
		t.Fatalf("all ports busy accepted: %+v", plan.Checks)
	}
}

func TestPreflightRejectsInvalidChoices(t *testing.T) {
	h := newFakeHost(t)
	c := DefaultChoices()
	c.Repository = "JDoe/MyApp:1"
	plan := Preflight(context.Background(), h.probe(), c)
	if checkStatus(t, plan, "config.environment") != Fail || plan.Ready() {
		t.Fatalf("invalid repository pin accepted: %+v", plan.Checks)
	}
}

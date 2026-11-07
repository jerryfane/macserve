package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jerryfane/macserve/assets"
	"github.com/jerryfane/macserve/internal/controllerconfig"
	"github.com/jerryfane/macserve/internal/deploy"
	"github.com/jerryfane/macserve/internal/onboarding"
)

const testToken = "API_BEARER_TOKEN=tok-0123456789abcdef"

// fakeHost is a Mac in a temporary directory: the helper's files live
// under top, root is the test user, and every command is recorded.
type fakeHost struct {
	t           *testing.T
	top         string
	h           *Helper
	terminal    bytes.Buffer
	installs    []deploy.Options
	installErr  error
	execs       [][]string
	execEnv     [][]string
	execCred    []*syscall.Credential
	execErr     error
	probes      [][]string
	fda         string // what the transient launchd job prints
	guiSession  bool
	console     uint32
	boot        Boot
	terminalErr error
	toolChecks  int
	// The qualification fakes (qualify_test.go): q stands in for every
	// Qualifier method; outputs records every Output command, loaded is
	// what launchctl has bootstrapped and fileVault is fdesetup status.
	q         *fakeQualifier
	outputs   [][]string
	loaded    map[string]bool
	fileVault string
}

func testEnv(owner Owner) string {
	return "CONTROLLER_USER=macservectl\nCONTROLLER_UID=6201\nCONTROLLER_GID=6201\nJOB_USER=macservejob\nJOB_UID=6202\nJOB_GID=6202\n" +
		"OWNER_USER=" + owner.Name + "\nOWNER_UID=" + itoa(owner.UID) + "\nTAILNET_IP=100.64.0.10\nPORT=8443\nPROTECTED_PORTS=8443\n" +
		"HOST_ADDRESSES=100.64.0.10\nDEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer\nREPOSITORIES=jdoe/myapp:4242\n"
}

// controllerBinary is the fixture release's macserve-controller.
const controllerBinary = "macserve-controller binary"

func itoa(u uint32) string { return strconv.FormatUint(uint64(u), 10) }

func newFakeHost(t *testing.T) *fakeHost {
	t.Helper()
	// A short directory: a Unix socket path is limited to 104 bytes on
	// macOS.
	top, err := os.MkdirTemp("", "ms")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(top) })
	if err := os.Chmod(top, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"private/var/root", "Library", "private/var/db"} {
		if err := os.MkdirAll(filepath.Join(top, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	exe := filepath.Join(top, "macserve-download")
	if err := os.WriteFile(exe, []byte("macserve binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The release's macserve-controller beside the downloaded macserve.
	if err := os.WriteFile(filepath.Join(top, "macserve-controller"), []byte(controllerBinary), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, name := range assets.DeployNames {
		files[name] = []byte("asset " + name)
	}
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	f := &fakeHost{t: t, top: top, fda: "granted\n", guiSession: true, boot: Boot{Time: "boot-time-1", SessionUUID: "11111111-1111-1111-1111-111111111111"}}
	f.console = 501
	f.h = &Helper{
		Store:            Store{Staging: filepath.Join(top, "private/var/root/.macserve-setup"), Ledger: filepath.Join(top, "Library/macserve/var/setup"), Top: top, RootUID: uid, RootGID: gid},
		Root:             filepath.Join(top, "Library/macserve"),
		Owner:            Owner{UID: 501, GID: 20, Name: "jdoe", Home: "/Users/jdoe"},
		SHA256:           digestHex([]byte("macserve binary")),
		ControllerSHA256: digestHex([]byte(controllerBinary)),
		Executable:       exe,
		Assets:           files,
		Install:          f.install,
		Exec: func(_ context.Context, c Cmd) error {
			f.execs = append(f.execs, c.Argv)
			f.execEnv = append(f.execEnv, c.Env)
			f.execCred = append(f.execCred, c.Credential)
			return f.execErr
		},
		Probe:         f.probe,
		ConsoleUID:    func() (uint32, error) { return f.console, nil },
		ToolCheck:     func(string, uint32) error { f.toolChecks++; return nil },
		Boot:          func() (Boot, error) { return f.boot, nil },
		Now:           func() time.Time { return time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC) },
		FDAWait:       2 * time.Second,
		TerminalCheck: func() error { return f.terminalErr },
	}
	f.h.Terminal = &f.terminal
	f.loaded, f.fileVault = map[string]bool{}, "FileVault is On."
	f.q = newFakeQualifier(f)
	f.h.Qualify, f.h.Output = f.q, f.output
	return f
}

// install stands in for deploy.Install: it checks the staged inputs and
// creates the installation deploy-install would (the parts setup reads).
func (f *fakeHost) install(o deploy.Options, stdout, _ io.Writer) error {
	f.installs = append(f.installs, o)
	if f.installErr != nil {
		return f.installErr
	}
	env, err := os.ReadFile(o.EnvironmentPath)
	if err != nil {
		return err
	}
	bin, err := os.ReadFile(o.BinaryPath)
	if err != nil {
		return err
	}
	if digestHex(bin) != o.SHA256 {
		return errors.New("binary digest")
	}
	controller, err := os.ReadFile(o.ControllerBinaryPath)
	if err != nil {
		return err
	}
	if digestHex(controller) != o.ControllerSHA256 {
		return errors.New("controller binary digest")
	}
	for _, name := range assets.DeployNames {
		if _, err := os.Stat(filepath.Join(o.AssetsPath, name)); err != nil {
			return err
		}
	}
	root := f.h.Root
	for _, dir := range []string{"config", "bin", "var/controller/secrets"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			return err
		}
	}
	write := func(name string, data []byte, mode fs.FileMode) {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, data, mode); err != nil {
			f.t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			f.t.Fatal(err)
		}
	}
	write("config/deploy.env", env, 0o644)
	write("bin/macserve", bin, 0o755)
	write("bin/macserve-controller", controller, 0o755)
	write("config/profiles.json", []byte("{\"profiles\":[]}\n"), 0o644)
	f.writeController(nil)
	_, err = io.WriteString(stdout, testToken+"\n")
	return err
}

func (f *fakeHost) controllerConfig() controllerconfig.Config {
	root := f.h.Root
	config := root + "/config"
	return controllerconfig.Config{
		Root: root + "/var/controller", Socket: root + "/var/controller/run/worker.sock", JobUID: 6202,
		ProfilesFile: config + "/profiles.json", Listen: "100.64.0.10:8443", AllowedNetworks: []string{"100.64.0.0/10", "fd7a:115c:a1e0::/48"},
		TLSCertificate: config + "/tls-cert.pem", TLSKey: root + "/var/controller/secrets/tls-key.pem", HealthFile: root + "/health/current.json",
		PauseFile: config + "/owner.pause", OwnerUID: 501,
		Receipt: controllerconfig.ReceiptConfig{KeyID: "k1", PrivateKeyFile: root + "/var/controller/secrets/receipt-key.pem", ServiceID: "svc", HostID: "host", Repositories: map[string]int64{"jdoe/myapp": 4242}},
	}
}

func (f *fakeHost) writeController(github *controllerconfig.GitHubConfig) {
	c := f.controllerConfig()
	c.GitHub = github
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		f.t.Fatal(err)
	}
	path := filepath.Join(f.h.Root, "config/controller.json")
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

// connectGitHub writes what connect-github leaves: the key and the github
// section.
func (f *fakeHost) connectGitHub() {
	key := filepath.Join(f.h.Root, "var/controller/secrets/github-app.pem")
	if err := os.WriteFile(key, []byte("pem"), 0o600); err != nil {
		f.t.Fatal(err)
	}
	e := onboarding.Enrollment{AppID: 77, InstallationID: 555, Repository: "jdoe/myapp", RepositoryID: 4242, AuthorIDs: []int64{1001}, BaseBranches: []string{"main"}, Profiles: []string{"myapp-build-v1"}}
	f.writeController(e.Section(key))
}

var plistString = regexp.MustCompile(`<key>StandardOutPath</key>\s*<string>([^<]+)</string>`)

// probe is a fake launchctl: bootstrap of the transient job "runs" it as
// launchd would, writing its output to StandardOutPath.
func (f *fakeHost) probe(_ context.Context, c Cmd) error {
	f.probes = append(f.probes, c.Argv)
	if !slices.Equal(c.Env, []string{FixedPath}) || c.Argv[0] != "/bin/launchctl" {
		f.t.Errorf("probe %q env %q", c.Argv, c.Env)
	}
	switch {
	case len(c.Argv) == 4 && c.Argv[1] == "bootstrap" && c.Argv[2] == "system":
		plist, err := os.ReadFile(c.Argv[3])
		if err != nil {
			return err
		}
		if !bytes.Contains(plist, []byte("<string>"+filepath.Join(f.h.Root, "bin/macserve")+"</string>\n\t\t<string>_fda-check</string>")) {
			f.t.Errorf("transient job does not run the installed _fda-check:\n%s", plist)
		}
		m := plistString.FindSubmatch(plist)
		if m == nil {
			return errors.New("no StandardOutPath")
		}
		return os.WriteFile(string(m[1]), []byte(f.fda), 0o644)
	case len(c.Argv) == 3 && c.Argv[1] == "bootout":
		return nil
	case len(c.Argv) == 3 && c.Argv[1] == "print" && c.Argv[2] == "gui/6202":
		if f.guiSession {
			return nil
		}
		return errors.New("exit status 113")
	}
	f.t.Errorf("unexpected launchctl %q", c.Argv)
	return errors.New("unexpected")
}

func (f *fakeHost) call(v Verb, env string) Response {
	f.t.Helper()
	return f.h.Handle(Request{Verb: v, Env: env})
}

func (f *fakeHost) mustDo(v Verb, env string) Response {
	f.t.Helper()
	r := f.call(v, env)
	if r.Error != "" || !r.Done {
		f.t.Fatalf("%s: %+v", v, r)
	}
	return r
}

func (f *fakeHost) ledger() *Ledger {
	f.t.Helper()
	l, _, err := f.h.Store.Load()
	if err != nil {
		f.t.Fatal(err)
	}
	return l
}

// through runs setup up to (not including) step s.
func (f *fakeHost) through(s Step) {
	f.t.Helper()
	order := map[Step]func(){
		StepPreflight:       func() { f.mustDo(VerbPreflight, testEnv(f.h.Owner)) },
		StepInstall:         func() { f.mustDo(VerbInstall, "") },
		StepGitHub:          func() { f.connectGitHub(); f.mustDo(VerbGitHub, "") },
		StepTools:           func() { f.mustDo(VerbTools, "") },
		StepOwnerActions:    func() { f.mustDo(VerbOwnerActions, "") },
		StepRound1:          func() { f.round(StepRound1) },
		StepReboot:          func() { f.restart() },
		StepRound2:          func() { f.round(StepRound2) },
		StepApproveAndStart: func() { f.approveAndStart() },
	}
	for _, step := range Steps {
		if step == s {
			return
		}
		if l, _, _ := f.h.Store.Load(); l != nil && l.record(step).Status == StatusDone {
			continue
		}
		order[step]()
	}
}

func TestStatusWithoutLedger(t *testing.T) {
	f := newFakeHost(t)
	if r := f.call(VerbStatus, ""); r.Error != "" || r.Ledger != nil {
		t.Fatalf("%+v", r)
	}
}

func TestPreflightCreatesStagedLedger(t *testing.T) {
	f := newFakeHost(t)
	r := f.mustDo(VerbPreflight, testEnv(f.h.Owner))
	l, err := r.DecodedLedger()
	if err != nil || l.record(StepPreflight).Status != StatusDone || l.Owner != "jdoe" || l.OwnerUID != 501 {
		t.Fatalf("ledger %+v %v", l, err)
	}
	if got := l.record(StepPreflight).Inputs["deploy.env"]; got != digestHex([]byte(testEnv(f.h.Owner))) {
		t.Errorf("deploy.env digest %q", got)
	}
	info, err := os.Lstat(filepath.Join(f.h.Store.Staging, ledgerName))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("staged ledger: %v %v", info, err)
	}
	if info, err := os.Lstat(f.h.Store.Staging); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("staging: %v %v", info, err)
	}
	if _, err := os.Lstat(f.h.Root); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("preflight created %s", f.h.Root)
	}
	if r := f.call(VerbPreflight, testEnv(f.h.Owner)); !strings.Contains(r.Error, "already recorded") {
		t.Errorf("second preflight: %+v", r)
	}
}

func TestPreflightRefusals(t *testing.T) {
	f := newFakeHost(t)
	other := testEnv(Owner{UID: 502, Name: "mallory"})
	noRepo := strings.Replace(testEnv(f.h.Owner), "REPOSITORIES=jdoe/myapp:4242\n", "", 1)
	for name, tc := range map[string]struct{ env, want string }{
		"other owner":   {other, "another owner"},
		"no repository": {noRepo, "REPOSITORIES"},
		"unparseable":   {"OWNER_UID=$(id -u)\n", "generated deploy.env"},
	} {
		if r := f.call(VerbPreflight, tc.env); !strings.Contains(r.Error, tc.want) {
			t.Errorf("%s: %+v", name, r)
		}
	}
	if f.ledger() != nil {
		t.Error("a refused preflight created a ledger")
	}
}

// TestPreflightRefusesAdminManagedHost (D12): /Library/macserve exists and
// there is no native ledger.
func TestPreflightRefusesAdminManagedHost(t *testing.T) {
	f := newFakeHost(t)
	if err := os.MkdirAll(f.h.Root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := f.h.CheckStart(); err == nil || !strings.Contains(err.Error(), "other tooling") {
		t.Errorf("CheckStart: %v", err)
	}
	if r := f.call(VerbPreflight, testEnv(f.h.Owner)); !strings.Contains(r.Error, "other tooling") {
		t.Errorf("preflight: %+v", r)
	}
}

func TestInstallUsesDeployInstallAndMovesLedger(t *testing.T) {
	f := newFakeHost(t)
	f.through(StepInstall)
	r := f.mustDo(VerbInstall, "")
	if len(f.installs) != 1 {
		t.Fatalf("deploy.Install called %d times", len(f.installs))
	}
	o := f.installs[0]
	want := deploy.Options{
		EnvironmentPath: filepath.Join(f.h.Store.Staging, "deploy.env"), BinaryPath: filepath.Join(f.h.Store.Staging, "macserve"),
		SHA256: f.h.SHA256, AssetsPath: filepath.Join(f.h.Store.Staging, "assets"), Apply: true,
		ControllerBinaryPath: filepath.Join(f.h.Store.Staging, "macserve-controller"), ControllerSHA256: f.h.ControllerSHA256,
	}
	if o != want {
		t.Errorf("options %+v, want %+v", o, want)
	}
	l, _ := r.DecodedLedger()
	rec := l.record(StepInstall)
	if rec.Status != StatusDone || rec.Inputs["macserve"] != f.h.SHA256 || rec.Inputs[ControllerInput] != f.h.ControllerSHA256 || rec.Inputs["deploy.env"] == "" || rec.Inputs["assets"] == "" {
		t.Errorf("install record %+v", rec)
	}
	if _, loc, err := f.h.Store.Load(); err != nil || loc != LedgerInstalled {
		t.Errorf("ledger location %v %v", loc, err)
	}
	for _, name := range []string{ledgerName, "deploy.env", "macserve", "assets"} {
		if _, err := os.Lstat(filepath.Join(f.h.Store.Staging, name)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("staged %s left behind: %v", name, err)
		}
	}
	if info, err := os.Lstat(f.h.Store.Ledger); err != nil || info.Mode().Perm() != 0o755 {
		t.Errorf("ledger dir %v %v", info, err)
	}
	// The one-time token goes back to the wizard only (for the keychain):
	// never to the terminal, the audit log, the ledger or any file.
	if r.Token != strings.TrimPrefix(testToken, tokenPrefix) {
		t.Errorf("response token %q", r.Token)
	}
	audit, _ := os.ReadFile(filepath.Join(f.h.Store.Staging, auditName))
	ledger, _ := os.ReadFile(filepath.Join(f.h.Store.Ledger, ledgerName))
	r.Token = ""
	resp, _ := json.Marshal(r)
	for name, data := range map[string][]byte{"audit": audit, "ledger": ledger, "response without token": resp, "terminal": f.terminal.Bytes()} {
		if bytes.Contains(data, []byte("tok-0123456789abcdef")) {
			t.Errorf("token in the %s", name)
		}
	}
	// Install never runs twice.
	if r := f.call(VerbInstall, ""); r.Error == "" || len(f.installs) != 1 {
		t.Errorf("second install: %+v", r)
	}
}

func TestInstallRefusals(t *testing.T) {
	t.Run("before preflight", func(t *testing.T) {
		f := newFakeHost(t)
		if r := f.call(VerbInstall, ""); !strings.Contains(r.Error, "no setup ledger") {
			t.Errorf("%+v", r)
		}
	})
	t.Run("binary digest", func(t *testing.T) {
		f := newFakeHost(t)
		f.through(StepInstall)
		f.h.SHA256 = strings.Repeat("0", 64)
		if r := f.call(VerbInstall, ""); !strings.Contains(r.Error, "expected SHA-256") || len(f.installs) != 0 {
			t.Errorf("%+v", r)
		}
		if f.ledger().record(StepInstall).Status != StatusPending {
			t.Error("install began")
		}
	})
	t.Run("staged env changed", func(t *testing.T) {
		f := newFakeHost(t)
		f.through(StepInstall)
		if err := f.h.Store.StageFile("deploy.env", []byte(strings.Replace(testEnv(f.h.Owner), "8443", "9443", -1))); err != nil {
			t.Fatal(err)
		}
		if r := f.call(VerbInstall, ""); !strings.Contains(r.Error, "not the one preflight recorded") || len(f.installs) != 0 {
			t.Errorf("%+v", r)
		}
	})
	t.Run("assets incomplete", func(t *testing.T) {
		f := newFakeHost(t)
		f.through(StepInstall)
		delete(f.h.Assets, "qualify.sh")
		if r := f.call(VerbInstall, ""); !strings.Contains(r.Error, "assets") || len(f.installs) != 0 {
			t.Errorf("%+v", r)
		}
	})
	t.Run("deploy-install fails", func(t *testing.T) {
		f := newFakeHost(t)
		f.through(StepInstall)
		f.installErr = errors.New("PARTIAL FAILURE: create-users failed; do not rerun")
		if r := f.call(VerbInstall, ""); !strings.Contains(r.Error, "PARTIAL FAILURE") {
			t.Errorf("%+v", r)
		}
		rec := f.ledger().record(StepInstall)
		if rec.Status != StatusFailed || !strings.Contains(rec.Error, "PARTIAL FAILURE") {
			t.Errorf("record %+v", rec)
		}
		f.installErr = nil
		for _, v := range []Verb{VerbInstall, VerbGitHub, VerbTools, VerbFDACheck, VerbJobLogin, VerbOwnerActions} {
			if r := f.call(v, ""); !strings.Contains(r.Error, "later steps are blocked") {
				t.Errorf("%s after failed install: %+v", v, r)
			}
		}
		if len(f.installs) != 1 {
			t.Errorf("deploy.Install reran")
		}
	})
	t.Run("interrupted", func(t *testing.T) {
		f := newFakeHost(t)
		f.through(StepInstall)
		l := f.ledger()
		if err := l.Begin(StepInstall, f.boot, f.h.Now()); err != nil {
			t.Fatal(err)
		}
		if err := f.h.Store.Save(l, LedgerStaged); err != nil {
			t.Fatal(err)
		}
		if r := f.call(VerbInstall, ""); !strings.Contains(r.Error, "interrupted") || len(f.installs) != 0 {
			t.Errorf("%+v", r)
		}
	})
}

func TestGitHubDetection(t *testing.T) {
	f := newFakeHost(t)
	f.through(StepGitHub)
	r := f.call(VerbGitHub, "")
	if r.Error != "" || r.Done || !strings.Contains(r.Detail, "no github section") {
		t.Fatalf("before connect-github: %+v", r)
	}
	if f.ledger().record(StepGitHub).Status != StatusPending {
		t.Error("github began before detection")
	}
	if r := f.call(VerbTools, ""); !strings.Contains(r.Error, "tools is not served") {
		t.Errorf("tools before github: %+v", r)
	}
	f.connectGitHub()
	r = f.mustDo(VerbGitHub, "")
	l, _ := r.DecodedLedger()
	if in := l.record(StepGitHub).Inputs; in["controller.json"] == "" || in["profiles.json"] == "" {
		t.Errorf("inputs %v", in)
	}
}

func TestToolsRunsXcodeSystemSteps(t *testing.T) {
	f := newFakeHost(t)
	f.through(StepTools)
	f.execErr = errors.New("exit status 1")
	if r := f.call(VerbTools, ""); !strings.Contains(r.Error, "run macserve setup again") {
		t.Fatalf("%+v", r)
	}
	if rec := f.ledger().record(StepTools); rec.Status != StatusRunning {
		t.Errorf("failed tools command: %+v", rec)
	}
	f.execErr, f.execs, f.execEnv, f.execCred, f.toolChecks = nil, nil, nil, nil, 0
	f.mustDo(VerbTools, "")
	xcodebuild := "/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild"
	want := [][]string{{xcodebuild, "-license", "accept"}, {xcodebuild, "-runFirstLaunch"}, {xcodebuild, "-downloadComponent", "MetalToolchain"}}
	if !slices.EqualFunc(f.execs, want, slices.Equal) {
		t.Errorf("ran %q", f.execs)
	}
	for i, env := range f.execEnv {
		home := "HOME=/private/var/root"
		if i == 2 {
			home = "HOME=/Users/jdoe"
		}
		if !slices.Equal(env, []string{FixedPath, "DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer", home, "LANG=C", "LC_ALL=C"}) {
			t.Errorf("env %d %q", i, env)
		}
	}
	// License and first launch write system locations and run as root;
	// the Metal toolchain download runs as the owner.
	for i, cred := range f.execCred {
		if (i == 2) != (cred != nil) || (cred != nil && (cred.Uid != 501 || cred.Gid != 20 || !slices.Equal(cred.Groups, []uint32{20}))) {
			t.Errorf("command %d credential %+v", i, cred)
		}
	}
	// The toolchain policy is checked before each command, not once.
	if f.toolChecks != 1+len(xcodeSystemSteps) {
		t.Errorf("toolchain checked %d times", f.toolChecks)
	}
}

func TestToolsRefusesUnprotectedXcode(t *testing.T) {
	f := newFakeHost(t)
	f.through(StepTools)
	f.h.ToolCheck = func(string, uint32) error { return errors.New("owner-writable") }
	if r := f.call(VerbTools, ""); !strings.Contains(r.Error, "not a protected toolchain") || len(f.execs) != 0 {
		t.Errorf("%+v", r)
	}
}

// TestFDACheckUsesLaunchdContext: the check is a transient launchd job of
// the installed binary; the helper never runs _fda-check itself, and the
// job is booted out and its files removed.
func TestFDACheckUsesLaunchdContext(t *testing.T) {
	f := newFakeHost(t)
	f.through(StepOwnerActions)
	f.execs = nil
	f.fda = "denied: open TCC.db: operation not permitted\n"
	r := f.call(VerbFDACheck, "")
	if r.Error != "" || r.Done || !strings.Contains(r.Detail, "not granted") {
		t.Fatalf("denied: %+v", r)
	}
	f.fda = "granted\n"
	f.probes = nil
	r = f.call(VerbFDACheck, "")
	if r.Error != "" || !r.Done {
		t.Fatalf("granted: %+v", r)
	}
	var verbs []string
	for _, argv := range f.probes {
		verbs = append(verbs, argv[1])
	}
	if !slices.Equal(verbs, []string{"bootout", "bootstrap", "bootout"}) {
		t.Errorf("launchctl sequence %q", verbs)
	}
	if len(f.execs) != 0 {
		t.Errorf("helper ran %q directly", f.execs)
	}
	for _, name := range []string{FDALabel + ".plist", fdaOut} {
		if _, err := os.Lstat(filepath.Join(f.h.Store.Staging, name)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s left behind", name)
		}
	}
	f.fda = "not-launchd: x\n"
	if r := f.call(VerbFDACheck, ""); !strings.Contains(r.Error, "unexpected") {
		t.Errorf("interactive output accepted: %+v", r)
	}
}

func TestFDACheckCommandRefusesInteractiveRun(t *testing.T) {
	var out bytes.Buffer
	opened := false
	open := func(string) (io.Closer, error) { opened = true; return io.NopCloser(nil), nil }
	if got := FDACheck(&out, 4242, open); got != 2 || opened || !strings.HasPrefix(out.String(), "not-launchd") {
		t.Errorf("interactive: %d %q opened=%v", got, out.String(), opened)
	}
	out.Reset()
	if got := FDACheck(&out, 1, func(p string) (io.Closer, error) {
		if p != TCCDatabase {
			t.Errorf("opened %s", p)
		}
		return io.NopCloser(nil), nil
	}); got != 0 || out.String() != "granted\n" {
		t.Errorf("granted: %d %q", got, out.String())
	}
	out.Reset()
	if got := FDACheck(&out, 1, func(string) (io.Closer, error) {
		return nil, &fs.PathError{Op: "open", Path: TCCDatabase, Err: fs.ErrPermission}
	}); got != 1 || !strings.HasPrefix(out.String(), "denied: ") {
		t.Errorf("denied: %d %q", got, out.String())
	}
}

func TestJobLoginDetection(t *testing.T) {
	f := newFakeHost(t)
	f.through(StepOwnerActions)
	for _, tc := range []struct {
		gui     bool
		console uint32
		done    bool
	}{{false, 501, false}, {true, 6202, false}, {true, 503, false}, {true, 501, true}, {true, 0, true}} {
		f.guiSession, f.console = tc.gui, tc.console
		r := f.call(VerbJobLogin, "")
		if r.Error != "" || r.Done != tc.done {
			t.Errorf("gui=%v console=%d: %+v", tc.gui, tc.console, r)
		}
	}
}

func TestOwnerActionsCompleteOnlyWhenBothDetected(t *testing.T) {
	f := newFakeHost(t)
	f.through(StepOwnerActions)
	f.fda = "denied\n"
	if r := f.call(VerbOwnerActions, ""); r.Error != "" || r.Done {
		t.Fatalf("fda denied: %+v", r)
	}
	f.fda, f.guiSession = "granted\n", false
	if r := f.call(VerbOwnerActions, ""); r.Error != "" || r.Done {
		t.Fatalf("no job session: %+v", r)
	}
	if rec := f.ledger().record(StepOwnerActions); rec.Status != StatusRunning {
		t.Errorf("record %+v", rec)
	}
	f.guiSession = true
	r := f.mustDo(VerbOwnerActions, "")
	l, _ := r.DecodedLedger()
	if l.record(StepOwnerActions).Inputs["macserve"] != f.h.SHA256 {
		t.Errorf("inputs %v", l.record(StepOwnerActions).Inputs)
	}
	next, _, _ := l.Next()
	if next.Step != StepRound1 {
		t.Errorf("next %s", next.Step)
	}
	// At round 1 only the job-login check and the round verbs are
	// served (verbSteps); every other verb is refused.
	var served []Verb
	for _, v := range Verbs[1:] {
		if slices.Contains(verbSteps[v], StepRound1) {
			served = append(served, v)
			continue
		}
		if r := f.call(v, testEnvIf(v, f.h.Owner)); r.Error == "" {
			t.Errorf("%s after owner-actions: %+v", v, r)
		}
	}
	if want := []Verb{VerbJobLogin, VerbRoundPrepare, VerbRoundBegin, VerbRoundJobProbe, VerbRoundCollect}; !slices.Equal(served, want) {
		t.Errorf("served at round 1: %v, want %v", served, want)
	}
}

func testEnvIf(v Verb, o Owner) string {
	if v == VerbPreflight {
		return testEnv(o)
	}
	return ""
}

func TestHelperRefusesAfterApproval(t *testing.T) {
	for _, name := range []string{"activation-anchor.json", "qualification.json"} {
		f := newFakeHost(t)
		f.through(StepTools)
		if err := os.WriteFile(filepath.Join(f.h.Root, "config", name), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := f.h.CheckStart(); err == nil || !strings.Contains(err.Error(), "approved") {
			t.Errorf("%s: CheckStart %v", name, err)
		}
		for _, v := range Verbs[1:] {
			if v == VerbUpgrade {
				continue // the setup helper never serves it (TestUpgradeVerbOnlyOnUpgradeHelper)
			}
			if r := f.call(v, testEnvIf(v, f.h.Owner)); !strings.Contains(r.Error, "approved") {
				t.Errorf("%s: %s %+v", name, v, r)
			}
		}
		if r := f.call(VerbStatus, ""); r.Error != "" || r.Ledger == nil {
			t.Errorf("%s: status %+v", name, r)
		}
	}
}

func TestHelperRefusesAnotherOwnersLedger(t *testing.T) {
	f := newFakeHost(t)
	f.through(StepInstall)
	f.h.Owner = Owner{UID: 502, Name: "mallory"}
	if err := f.h.CheckStart(); err == nil || !strings.Contains(err.Error(), "belongs to jdoe") {
		t.Errorf("CheckStart: %v", err)
	}
	for _, v := range Verbs {
		if r := f.call(v, testEnvIf(v, f.h.Owner)); !strings.Contains(r.Error, "belongs to jdoe") || r.Ledger != nil {
			t.Errorf("%s: %+v", v, r)
		}
	}
}

func TestDecodeRequestGrammar(t *testing.T) {
	for _, line := range []string{
		``, `{}`, `{"verb":"qualify"}`, `{"verb":"status","path":"/etc"}`, `{"verb":"status"} {"verb":"install"}`,
		`{"verb":"install","env":"X=1"}`, `{"verb":"preflight"}`, `{"verb":"STATUS"}`, `[]`, `{"verb":"status","argv":["/bin/sh"]}`,
		`{"verb":"status","Verb":"install"}`, `{"verb":"approve"}`, `{"verb":"round-begin","sha256":"AB"}`,
		`{"verb":"status","sha256":"` + strings.Repeat("a", 64) + `"}`, `{"verb":"approve","sha256":"` + strings.Repeat("A", 64) + `"}`,
		`{"verb":"upgrade"}`, `{"verb":"upgrade","sha256":"` + strings.Repeat("a", 64) + `","tag":"0.1.2"}`,
		`{"verb":"approve","sha256":"` + strings.Repeat("a", 64) + `","tag":"v0.1.2"}`, `{"verb":"status","proof":"{}"}`,
		`{"verb":"upgrade","sha256":"` + strings.Repeat("a", 64) + `","proof":"` + strings.Repeat("x", MaxCarryProof+1) + `"}`,
	} {
		if _, err := DecodeRequest([]byte(line)); err == nil {
			t.Errorf("accepted %s", line)
		}
	}
	if _, err := DecodeRequest(bytes.Repeat([]byte("x"), MaxRequest+1)); err == nil {
		t.Error("accepted oversized request")
	}
	for _, v := range Verbs {
		r := Request{Verb: v, Env: testEnvIf(v, Owner{UID: 501, Name: "jdoe"})}
		if v == VerbRoundBegin || v == VerbApprove || v == VerbUpgrade {
			r.SHA256 = strings.Repeat("a", 64)
		}
		line, _ := json.Marshal(r)
		if r, err := DecodeRequest(line); err != nil || r.Verb != v {
			t.Errorf("%s: %v", v, err)
		}
	}
}

func TestParseRootArgsAndSudoOwner(t *testing.T) {
	sha, ctl := strings.Repeat("a", 64), strings.Repeat("c", 64)
	if got, err := ParseRootArgs([]string{"--sha256", sha}); err != nil || got != (RootArgs{SHA256: sha}) {
		t.Errorf("valid: %+v %v", got, err)
	}
	if got, err := ParseRootArgs([]string{"--sha256", sha, "--controller-sha256", ctl}); err != nil || got != (RootArgs{SHA256: sha, ControllerSHA256: ctl}) {
		t.Errorf("valid install: %+v %v", got, err)
	}
	if got, err := ParseRootArgs([]string{"--upgrade", "--sha256", sha, "--controller-sha256", ctl}); err != nil || got != (RootArgs{SHA256: sha, ControllerSHA256: ctl, Upgrade: true}) {
		t.Errorf("valid upgrade: %+v %v", got, err)
	}
	for _, args := range [][]string{nil, {"--sha256"}, {"--sha256", strings.ToUpper(sha)}, {"--sha256", sha, "--ledger", "/tmp/x"}, {"--env", "/tmp/x"}, {"--sha256=" + sha}, {"--sha256", sha, "--upgrade"}, {"--upgrade"}, {"--upgrade", "--upgrade", "--sha256", sha, "--controller-sha256", ctl},
		{"--upgrade", "--sha256", sha}, {"--sha256", sha, "--controller-sha256"}, {"--sha256", sha, "--controller-sha256", strings.ToUpper(ctl)}, {"--controller-sha256", ctl, "--sha256", sha}, {"--sha256", sha, "--sha256", ctl}} {
		if _, err := ParseRootArgs(args); err == nil {
			t.Errorf("accepted %q", args)
		}
	}
	// The lookup accepts every uid, so only SudoOwner's own checks refuse.
	account := user.User{Gid: "20", Username: "jdoe", HomeDir: "/Users/jdoe"}
	lookup := func(uid string) (*user.User, error) {
		u := account
		u.Uid = uid
		return &u, nil
	}
	if o, err := SudoOwner("501", lookup); err != nil || o != (Owner{UID: 501, GID: 20, Name: "jdoe", Home: "/Users/jdoe"}) {
		t.Errorf("valid: %+v %v", o, err)
	}
	for _, uid := range []string{"", "0", "0501", "500", "abc", "-1", "+501", " 501", "4294967296"} {
		if _, err := SudoOwner(uid, lookup); err == nil {
			t.Errorf("accepted SUDO_UID %q", uid)
		}
	}
	for name, u := range map[string]user.User{
		"name":    {Gid: "20", Username: "Bad Name", HomeDir: "/Users/jdoe"},
		"gid":     {Gid: "020", Username: "jdoe", HomeDir: "/Users/jdoe"},
		"home":    {Gid: "20", Username: "jdoe", HomeDir: "Users/jdoe"},
		"unclean": {Gid: "20", Username: "jdoe", HomeDir: "/Users/../jdoe"},
		"nogid":   {Username: "jdoe", HomeDir: "/Users/jdoe"},
	} {
		account = u
		if _, err := SudoOwner("501", lookup); err == nil {
			t.Errorf("accepted account with bad %s", name)
		}
	}
	if _, err := SudoOwner("501", func(string) (*user.User, error) { return nil, errors.New("unknown") }); err == nil {
		t.Error("accepted an unknown SUDO_UID")
	}
}

func TestServeChecksPeerUIDAndAcceptsOneConnection(t *testing.T) {
	f := newFakeHost(t)
	dir, sockets := filepath.Join(f.top, "s"), f.h.Store
	f.h.Owner.UID = uint32(os.Getuid())
	ln, err := sockets.Listen(dir, f.h.Owner.UID)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(dir); err != nil || info.Mode().Perm() != 0o711 {
		t.Fatalf("socket dir %v %v", info, err)
	}
	if info, err := os.Lstat(filepath.Join(dir, SocketName)); err != nil || info.Mode().Perm() != 0o600 || info.Mode().Type() != fs.ModeSocket {
		t.Fatalf("socket %v %v", info, err)
	}
	done := make(chan error, 1)
	go func() { done <- f.h.Serve(ln, 5*time.Second) }()
	c, err := Dial(dir, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	if r, err := c.Call(Request{Verb: VerbStatus}); err != nil || r.Ledger != nil {
		t.Fatalf("status %+v %v", r, err)
	}
	if _, err := net.DialTimeout("unix", filepath.Join(dir, SocketName), time.Second); err == nil {
		t.Error("a second connection was accepted")
	}
	if _, err := c.conn.Write([]byte(`{"verb":"run","argv":["/bin/sh"]}` + "\n")); err != nil {
		t.Fatal(err)
	}
	reply, err := readLine(c.in, 1<<20)
	if err != nil || !bytes.Contains(reply, []byte("unknown field")) {
		t.Errorf("bad request reply %s %v", reply, err)
	}
	c.Close()
	if err := <-done; err != nil {
		t.Errorf("serve: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, SocketName)); !errors.Is(err, fs.ErrNotExist) {
		t.Error("socket left behind")
	}
}

func TestServeRefusesOtherPeerUID(t *testing.T) {
	f := newFakeHost(t)
	dir, sockets := filepath.Join(f.top, "s"), f.h.Store
	f.h.Owner.UID = uint32(os.Getuid()) + 1
	if err := f.h.Store.EnsureStaging(); err != nil {
		t.Fatal(err)
	}
	ln, err := sockets.Listen(dir, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- f.h.Serve(ln, 500*time.Millisecond) }()
	c, err := Dial(dir, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Call(Request{Verb: VerbStatus}); err == nil {
		t.Error("a connection from another uid was served")
	}
	if err := <-done; err == nil || !strings.Contains(err.Error(), "no connection") {
		t.Errorf("serve: %v", err)
	}
	audit, _ := os.ReadFile(filepath.Join(f.h.Store.Staging, auditName))
	if !bytes.Contains(audit, []byte(`"phase":"refused"`)) {
		t.Errorf("refusal not audited: %s", audit)
	}
}

func TestDialRefusesUntrustedDirectoryAndPeer(t *testing.T) {
	f := newFakeHost(t)
	dir, sockets := filepath.Join(f.top, "s"), f.h.Store
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := Dial(dir, uint32(os.Getuid())); err == nil || !strings.Contains(err.Error(), "group or other write") {
		t.Errorf("writable dir: %v", err)
	}
	if _, err := sockets.Listen(dir, uint32(os.Getuid())); err == nil {
		t.Error("Listen accepted a 0777 socket directory")
	}
	if err := os.Chmod(dir, 0o711); err != nil {
		t.Fatal(err)
	}
	ln, err := sockets.Listen(dir, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if _, err := Dial(dir, uint32(os.Getuid())+1); err == nil {
		t.Error("Dial accepted a socket not owned by the expected root uid")
	}
}

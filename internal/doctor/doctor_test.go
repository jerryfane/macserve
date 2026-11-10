package doctor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/deploy"
	"github.com/jerryfane/macserve/internal/health"
	"github.com/jerryfane/macserve/internal/setup"
	"github.com/jerryfane/macserve/internal/setup/plan"
)

var update = flag.Bool("update", false, "rewrite testdata golden files")

var now = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

const (
	binary     = "macserve release bytes"
	controller = "macserve-controller release bytes"
)

// controllerPlist is the controller plist deploy-install renders (only
// ProgramArguments matters to doctor).
func controllerPlist(args ...string) []byte {
	var b strings.Builder
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>org.macserve.controller</string>\n<key>ProgramArguments</key><array>")
	for _, a := range args {
		b.WriteString("<string>" + a + "</string>")
	}
	b.WriteString("</array>\n<key>Disabled</key><true/>\n<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>\n</dict></plist>\n")
	return []byte(b.String())
}

var env = []byte(`CONTROLLER_USER=macservectl
CONTROLLER_UID=610
CONTROLLER_GID=610
JOB_USER=macservebuild
JOB_UID=611
JOB_GID=611
OWNER_USER=jdoe
OWNER_UID=501
TAILNET_IP=100.64.0.10
PORT=8443
PROTECTED_PORTS=22,8443
HOST_ADDRESSES=127.0.0.1,::1,100.64.0.10
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
REPOSITORIES=jdoe/app:12345
KEYHOLDER_UID=499
KEYHOLDER_GID=499
KEYRPC_GID=498
`)

var boot = setup.Boot{Time: strings.Repeat("a", 64), SessionUUID: "11111111-2222-3333-4444-555555555555"}

// fakeHost is a healthy, fully set-up Mac seen as root.
type fakeHost struct {
	euid     int
	files    map[string][]byte
	fileErr  map[string]error
	stats    map[string]plan.FileInfo
	commands map[string]string // argv joined by " " -> stdout; absent = error
	addrs    []netip.Addr
	listen   bool
	fda      *bool
	github   error
}

func healthy(t *testing.T) *fakeHost {
	t.Helper()
	health, _ := json.Marshal(health.Health{
		Schema: 3, JobUID: 611, BoundaryReceiptSHA256: strings.Repeat("b", 64), BoundaryValidated: true,
		CheckedAt: now.Add(-10 * time.Second), ExpiresAt: now.Add(30 * time.Second), AccountedBytes: 10 << 30,
		PersistenceLastVerified: now.Add(-time.Minute), PersistenceValid: true,
	})
	l := setup.NewLedger("jdoe", 501, now.Add(-time.Hour))
	for i := range l.Records {
		l.Records[i].Status = setup.StatusDone
	}
	l.Records[1].Inputs = map[string]string{"macserve": sha256Hex([]byte(binary)), setup.ControllerInput: sha256Hex([]byte(controller))}
	l.Records[4].Inputs = map[string]string{"macserve": sha256Hex([]byte(binary))}
	l.Approval = &setup.Approval{SummarySHA256: strings.Repeat("c", 64), Boot: boot, At: now.Add(-time.Hour)}
	ledger, err := json.Marshal(l)
	if err != nil {
		t.Fatal(err)
	}
	h := &fakeHost{
		files: map[string][]byte{
			EnvFile: env, HealthFile: health, setup.LedgerPath: ledger, Binary: []byte(binary), Controller: []byte(controller),
			launchDaemons + "org.macserve.controller.plist": controllerPlist(Controller, "--config", Root+"/config/controller.json"),
			ProfilesFile: []byte(`{"profiles":[],"templates":[{"id":"org-ios-sim-build-v1","owners":["jdoe"],"xcode":{"version":"16.2","build":"16C5032a"}}]}`),
		},
		fileErr: map[string]error{},
		stats:   map[string]plan.FileInfo{},
		commands: map[string]string{
			"/usr/bin/sw_vers -productVersion":                                       "15.3\n",
			"/usr/sbin/sysctl -n hw.optional.arm64":                                  "1\n",
			"/usr/bin/csrutil status":                                                "System Integrity Protection status: enabled.\n",
			"/usr/bin/fdesetup status":                                               "FileVault is On.\n",
			"/usr/bin/fdesetup supportsauthrestart":                                  "true\n",
			"/usr/bin/xcode-select -p":                                               "/Applications/Xcode.app/Contents/Developer\n",
			"/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild -version": "Xcode 16.2\nBuild version 16C5032a\n",
			"/bin/launchctl print gui/611":                                           "gui/502 = {}\n",
			"/bin/launchctl print-disabled system":                                   "disabled services = {\n\t\"org.macserve.controller\" => enabled\n\t\"org.macserve.keyholder\" => enabled\n\t\"org.macserve.maintenance\" => enabled\n\t\"org.macserve.worker\" => enabled\n\t\"com.apple.ftpd\" => disabled\n}\n",
		},
		addrs:  []netip.Addr{netip.MustParseAddr("100.64.0.10")},
		listen: true,
	}
	for _, l := range Labels {
		h.commands["/bin/launchctl print system/"+l] = "system/" + l + " = {}\n"
	}
	dir := plan.FileInfo{Exists: true, Mode: fs.ModeDir | 0o755, Nlink: 3}
	file := plan.FileInfo{Exists: true, Mode: 0o644, Nlink: 1}
	for _, p := range protectedPaths {
		switch {
		case p.absent:
			h.stats[p.path] = plan.FileInfo{}
		case p.dir:
			h.stats[p.path] = dir
		case p.binary:
			h.stats[p.path] = plan.FileInfo{Exists: true, Mode: 0o755, Nlink: 1}
		default:
			h.stats[p.path] = file
		}
	}
	h.stats[SecretsDir] = plan.FileInfo{Exists: true, Mode: fs.ModeDir | 0o700, UID: 610, Nlink: 2}
	h.stats[KeyholderDir] = plan.FileInfo{Exists: true, Mode: fs.ModeDir | 0o700, UID: 499, Nlink: 6}
	h.stats[KeyholderSecrets] = plan.FileInfo{Exists: true, Mode: fs.ModeDir | 0o700, UID: 499, Nlink: 2}
	for _, l := range Labels {
		h.stats[launchDaemons+l+".plist"] = file
	}
	h.stats[Qualification], h.stats[Anchor] = file, file
	h.stats[Console] = plan.FileInfo{Exists: true, Mode: fs.ModeCharDevice | 0o600, UID: 501}
	granted := true
	h.fda = &granted
	return h
}

func (h *fakeHost) probe() Probe {
	p := Probe{
		GOOS: "darwin", EUID: h.euid,
		Run: func(_ context.Context, argv []string) (string, error) {
			if !AllowedCommand(argv) {
				return "", errors.New("refused")
			}
			out, ok := h.commands[strings.Join(argv, " ")]
			if !ok {
				return "", errors.New("failed")
			}
			return out, nil
		},
		ReadFile: func(path string, max int64) ([]byte, error) {
			if err := h.fileErr[path]; err != nil {
				return nil, err
			}
			data, ok := h.files[path]
			if !ok {
				return nil, fs.ErrNotExist
			}
			return data, nil
		},
		Lstat:     func(path string) (plan.FileInfo, error) { return h.stats[path], nil },
		Addrs:     func() ([]netip.Addr, error) { return h.addrs, nil },
		PortInUse: func(context.Context, netip.AddrPort) bool { return h.listen },
		Boot:      func() (setup.Boot, error) { return boot, nil },
		Now:       func() time.Time { return now },
	}
	if h.fda != nil {
		p.FDA = func() (bool, string, error) {
			if *h.fda {
				return true, "macserve has Full Disk Access in launchd context", nil
			}
			return false, "macserve lacks Full Disk Access in launchd context", nil
		}
		p.GitHub = func(context.Context) (string, error) {
			if h.github != nil {
				return "", h.github
			}
			return "App 1 is installed", nil
		}
	}
	return p
}

func checks(r Report) map[string]Check {
	m := map[string]Check{}
	for _, c := range r.Checks {
		m[c.ID] = c
	}
	return m
}

func TestHealthyHostPasses(t *testing.T) {
	r := Run(context.Background(), healthy(t).probe(), Options{})
	for _, c := range r.Checks {
		if c.Status != Pass {
			t.Errorf("%s: %s %q", c.ID, c.Status, c.Detail)
		}
	}
	if len(r.Checks) != len(IDs) || r.ExitCode() != 0 || !r.Root || !r.Live {
		t.Errorf("report %+v", r)
	}
}

// TestEachCheckFails breaks one thing at a time; exactly that check (and
// the listed related ones) changes.
func TestEachCheck(t *testing.T) {
	for _, tc := range []struct {
		id     string
		status Status
		edit   func(h *fakeHost)
	}{
		{"host.macos", Fail, func(h *fakeHost) { delete(h.commands, "/usr/bin/sw_vers -productVersion") }},
		{"host.arch", Fail, func(h *fakeHost) { h.commands["/usr/sbin/sysctl -n hw.optional.arm64"] = "0\n" }},
		{"host.sip", Fail, func(h *fakeHost) {
			h.commands["/usr/bin/csrutil status"] = "System Integrity Protection status: disabled.\n"
		}},
		{"host.sip", Unknown, func(h *fakeHost) { delete(h.commands, "/usr/bin/csrutil status") }},
		{"host.filevault", Warn, func(h *fakeHost) { h.commands["/usr/bin/fdesetup supportsauthrestart"] = "false\n" }},
		{"host.filevault", Unknown, func(h *fakeHost) { delete(h.commands, "/usr/bin/fdesetup status") }},
		{"xcode.pins", Fail, func(h *fakeHost) {
			h.commands["/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild -version"] = "Xcode 16.3\nBuild version 16E140\n"
		}},
		{"xcode.pins", Unknown, func(h *fakeHost) { h.euid = 501; h.fileErr[ProfilesFile] = fs.ErrPermission }},
		{"net.tailnet", Fail, func(h *fakeHost) { h.addrs = nil }},
		{"net.tailnet", Warn, func(h *fakeHost) { h.listen = false }},
		{"release.bytes", Fail, func(h *fakeHost) { h.files[Binary] = []byte("other bytes") }},
		{"release.bytes", Unknown, func(h *fakeHost) { h.euid = 501; h.fileErr[Binary] = fs.ErrPermission }},
		{"release.bytes", Fail, func(h *fakeHost) { h.files[Controller] = []byte("other controller") }},
		{"release.bytes", Fail, func(h *fakeHost) { delete(h.files, Controller) }},
		{"release.bytes", Fail, func(h *fakeHost) {
			// Signed bytes the inventory does not record.
			h.files[InstalledBinaries] = inventory(sha256Hex([]byte("signed")), sha256Hex([]byte(controller)))
		}},
		{"release.bytes", Pass, func(h *fakeHost) {
			// Signed bytes map to the recorded release digests.
			h.files[Binary], h.files[Controller] = []byte("signed macserve"), []byte("signed controller")
			h.files[InstalledBinaries] = inventory(sha256Hex([]byte("signed macserve")), sha256Hex([]byte("signed controller")))
		}},
		{"release.bytes", Pass, func(h *fakeHost) {
			// An installation from before the controller binary.
			delete(h.files, Controller)
			h.stats[Controller] = plan.FileInfo{}
			h.files[launchDaemons+"org.macserve.controller.plist"] = controllerPlist(Binary, "controller", "--config", Root+"/config/controller.json")
			h.setLedger(t, func(l *setup.Ledger) { delete(l.Records[1].Inputs, setup.ControllerInput) })
		}},
		{"fs.protect", Fail, func(h *fakeHost) { h.stats[Controller] = plan.FileInfo{Exists: true, Mode: 0o755, Nlink: 2} }},
		{"fs.protect", Fail, func(h *fakeHost) { h.stats[Controller] = plan.FileInfo{Exists: true, Mode: 0o755, Nlink: 1, GID: 20} }},
		{"fs.protect", Fail, func(h *fakeHost) { h.stats[Binary] = plan.FileInfo{Exists: true, Mode: 0o700, Nlink: 1} }},
		{"svc.state", Fail, func(h *fakeHost) {
			h.files[launchDaemons+"org.macserve.controller.plist"] = controllerPlist(Binary, "controller", "--config", Root+"/config/controller.json")
		}},
		{"fs.protect", Fail, func(h *fakeHost) { h.stats[EnvFile] = plan.FileInfo{Exists: true, Mode: 0o666, Nlink: 1} }},
		{"fs.protect", Fail, func(h *fakeHost) {
			h.stats[SecretsDir] = plan.FileInfo{Exists: true, Mode: fs.ModeDir | 0o755, UID: 610}
		}},
		// The controller holds no key but its TLS key.
		{"fs.protect", Fail, func(h *fakeHost) {
			h.stats[SecretsDir+"/receipt-key.pem"] = plan.FileInfo{Exists: true, Mode: 0o600, UID: 610, Nlink: 1}
		}},
		{"fs.protect", Fail, func(h *fakeHost) {
			h.stats[SecretsDir+"/github-app.pem"] = plan.FileInfo{Exists: true, Mode: 0o600, UID: 610, Nlink: 1}
		}},
		// The keyholder's state is the keyholder's alone.
		{"fs.protect", Fail, func(h *fakeHost) {
			h.stats[KeyholderSecrets] = plan.FileInfo{Exists: true, Mode: fs.ModeDir | 0o700, UID: 610, Nlink: 2}
		}},
		{"fs.protect", Fail, func(h *fakeHost) {
			h.stats[KeyholderDir] = plan.FileInfo{Exists: true, Mode: fs.ModeDir | 0o705, UID: 499, Nlink: 2}
		}},
		{"fs.protect", Fail, func(h *fakeHost) { h.stats[deploy.KeyholderConfigPath] = plan.FileInfo{} }},
		{"fs.protect", Fail, func(h *fakeHost) {
			h.stats[deploy.ReleaseScopePath] = plan.FileInfo{Exists: true, Mode: 0o644, UID: 499, Nlink: 1}
		}},
		{"fs.protect", Pass, func(h *fakeHost) { h.stats[deploy.ReleaseScopePath] = plan.FileInfo{} }},
		{"fs.protect", Fail, func(h *fakeHost) {
			h.files[EnvFile] = bytes.Replace(env, []byte("KEYHOLDER_UID=499\nKEYHOLDER_GID=499\nKEYRPC_GID=498\n"), nil, 1)
		}},
		{"tcc.fda", Fail, func(h *fakeHost) { *h.fda = false }},
		{"tcc.fda", Unknown, func(h *fakeHost) { h.fda = nil }},
		{"session.job", Fail, func(h *fakeHost) { delete(h.commands, "/bin/launchctl print gui/611") }},
		{"session.job", Fail, func(h *fakeHost) { h.stats[Console] = plan.FileInfo{Exists: true, UID: 611} }},
		{"persistence", Fail, func(h *fakeHost) { h.setHealth(t, func(x *health.Health) { x.PersistenceNeedsReview = true }) }},
		{"qual.state", Fail, func(h *fakeHost) { h.stats[Anchor] = plan.FileInfo{} }},
		{"qual.state", Warn, func(h *fakeHost) {
			h.setLedger(t, func(l *setup.Ledger) { l.Approval.Boot.SessionUUID = "99999999-2222-3333-4444-555555555555" })
		}},
		{"svc.state", Warn, func(h *fakeHost) {
			for _, l := range Labels {
				delete(h.commands, "/bin/launchctl print system/"+l)
			}
			h.commands["/bin/launchctl print-disabled system"] = "\"org.macserve.controller\" => disabled\n\"org.macserve.keyholder\" => disabled\n\"org.macserve.maintenance\" => disabled\n\"org.macserve.worker\" => disabled\n"
		}},
		{"svc.state", Fail, func(h *fakeHost) {
			h.commands["/bin/launchctl print-disabled system"] += "\"org.macserve.extra\" => enabled\n"
		}},
		{"svc.state", Fail, func(h *fakeHost) { delete(h.commands, "/bin/launchctl print system/org.macserve.worker") }},
		{"svc.state", Unknown, func(h *fakeHost) { delete(h.commands, "/bin/launchctl print-disabled system") }},
		{"health", Fail, func(h *fakeHost) {
			h.setHealth(t, func(x *health.Health) {
				x.CheckedAt = now.Add(-time.Minute)
				x.ExpiresAt = now.Add(-15 * time.Second)
			})
		}},
		{"health", Fail, func(h *fakeHost) { h.setHealth(t, func(x *health.Health) { x.MemoryPressure = true }) }},
		{"health", Unknown, func(h *fakeHost) { h.euid = 501; h.fileErr[HealthFile] = fs.ErrPermission }},
		{"github.app", Fail, func(h *fakeHost) { h.github = errors.New("installation 7 no longer grants jdoe/app") }},
		{"github.app", Unknown, func(h *fakeHost) { h.fda = nil }},
		{"disk", Fail, func(h *fakeHost) { h.setHealth(t, func(x *health.Health) { x.AccountedBytes = 81 << 30 }) }},
		{"disk", Warn, func(h *fakeHost) { h.setHealth(t, func(x *health.Health) { x.AccountedBytes = 60 << 30 }) }},
		{"setup.ledger", Fail, func(h *fakeHost) {
			h.setLedger(t, func(l *setup.Ledger) { l.Records[6].Status = setup.StatusFailed })
		}},
		{"setup.ledger", Warn, func(h *fakeHost) {
			h.setLedger(t, func(l *setup.Ledger) { l.Records[9].Status = setup.StatusPending })
		}},
		{"setup.ledger", Fail, func(h *fakeHost) { delete(h.files, setup.LedgerPath) }},
		{"setup.ledger", Unknown, func(h *fakeHost) { h.euid = 501; h.fileErr[setup.LedgerPath] = fs.ErrPermission }},
	} {
		h := healthy(t)
		tc.edit(h)
		r := Run(context.Background(), h.probe(), Options{})
		got := checks(r)[tc.id]
		if got.Status != tc.status {
			t.Errorf("%s want %s: got %s %q", tc.id, tc.status, got.Status, got.Detail)
		}
		if (got.Status == Fail || got.Status == Warn) && got.Fix == "" && tc.id != "host.macos" {
			t.Errorf("%s %s has no fix", tc.id, got.Status)
		}
		if want := map[bool]int{true: 1, false: 0}[r.Summary[Fail] > 0]; r.ExitCode() != want || tc.status == Fail && want != 1 {
			t.Errorf("%s %s: exit %d", tc.id, tc.status, r.ExitCode())
		}
	}
}

// inventory is an installed-binaries.json recording the signed on-disk
// digests of the fixture's release binaries.
func inventory(macserve, controllerDigest string) []byte {
	entry := func(release, installed, id string) map[string]string {
		return map[string]string{"release_sha256": release, "installed_sha256": installed, "identifier": id, "designated_requirement": "identifier " + id}
	}
	data, _ := json.Marshal(map[string]any{"schema": "macserve-installed-binaries/1", "binaries": map[string]any{
		"macserve":            entry(sha256Hex([]byte(binary)), macserve, "app.themartian.macserve"),
		"macserve-controller": entry(sha256Hex([]byte(controller)), controllerDigest, "app.themartian.macserve-controller"),
	}})
	return data
}

func (h *fakeHost) setHealth(t *testing.T, f func(*health.Health)) {
	var x health.Health
	if err := json.Unmarshal(h.files[HealthFile], &x); err != nil {
		t.Fatal(err)
	}
	f(&x)
	h.files[HealthFile], _ = json.Marshal(x)
}

func (h *fakeHost) setLedger(t *testing.T, f func(*setup.Ledger)) {
	var l setup.Ledger
	if err := json.Unmarshal(h.files[setup.LedgerPath], &l); err != nil {
		t.Fatal(err)
	}
	f(&l)
	h.files[setup.LedgerPath], _ = json.Marshal(l)
}

func TestReleaseDigestSources(t *testing.T) {
	h := healthy(t)
	sum := sha256Hex([]byte(binary))
	h.files["/tmp/SHA256SUMS"] = []byte(sum + "  macserve-darwin-arm64\n" + sha256Hex([]byte(controller)) + "  macserve-controller-darwin-arm64\n" + strings.Repeat("0", 64) + "  other\n")
	if c := checks(Run(context.Background(), h.probe(), Options{SHA256Sums: "/tmp/SHA256SUMS"}))["release.bytes"]; c.Status != Pass || !strings.Contains(c.Detail, "SHA256SUMS") {
		t.Errorf("sums: %+v", c)
	}
	// A release that publishes no controller does not match an
	// installation that has one.
	h.files["/tmp/SHA256SUMS"] = []byte(sum + "  macserve-darwin-arm64\n")
	if c := checks(Run(context.Background(), h.probe(), Options{SHA256Sums: "/tmp/SHA256SUMS"}))["release.bytes"]; c.Status != Fail {
		t.Errorf("sums without controller: %+v", c)
	}
	h.files["/tmp/SHA256SUMS"] = []byte(sum + "  macserve-darwin-arm64\n" + strings.Repeat("2", 64) + "  macserve-controller-darwin-arm64\n")
	if c := checks(Run(context.Background(), h.probe(), Options{SHA256Sums: "/tmp/SHA256SUMS"}))["release.bytes"]; c.Status != Fail || !strings.Contains(c.Detail, "controller") {
		t.Errorf("sums with another controller: %+v", c)
	}
	if c := checks(Run(context.Background(), h.probe(), Options{ReleaseSHA256: strings.Repeat("1", 64)}))["release.bytes"]; c.Status != Fail {
		t.Errorf("wrong digest: %+v", c)
	}
	h.files["/tmp/SHA256SUMS"] = []byte("garbage\n")
	if c := checks(Run(context.Background(), h.probe(), Options{SHA256Sums: "/tmp/SHA256SUMS"}))["release.bytes"]; c.Status != Fail {
		t.Errorf("bad sums: %+v", c)
	}
}

// TestNotDarwin: one failing check, the rest unknown.
func TestNotDarwin(t *testing.T) {
	p := healthy(t).probe()
	p.GOOS = "linux"
	r := Run(context.Background(), p, Options{})
	if r.Summary[Fail] != 1 || r.Summary[Unknown] != len(IDs)-1 || r.ExitCode() != 1 {
		t.Errorf("summary %v", r.Summary)
	}
}

// TestNoSecretsInOutput: details never carry file contents beyond the
// fixed facts, even when files hold secrets.
func TestNoSecretsInOutput(t *testing.T) {
	h := healthy(t)
	h.github = errors.New("installation 7 no longer grants jdoe/app")
	h.files[HealthFile] = []byte(`{"secret":"ghs_SECRET"`)
	data, err := Render(Run(context.Background(), h.probe(), Options{}), true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "SECRET") {
		t.Errorf("output leaks file contents:\n%s", data)
	}
}

// TestJSONGolden pins the --json schema for a non-root, non-live run.
func TestJSONGolden(t *testing.T) {
	h := healthy(t)
	h.euid, h.fda = 501, nil
	for _, p := range []string{setup.LedgerPath, HealthFile, Binary} {
		h.fileErr[p] = fs.ErrPermission
	}
	got, err := Render(Run(context.Background(), h.probe(), Options{}), true)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", "doctor.golden.json")
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("--json differs from %s (go test -update):\n%s", path, got)
	}
	text, _ := Render(Run(context.Background(), h.probe(), Options{}), false)
	if !strings.Contains(string(text), "Without sudo") || !strings.Contains(string(text), "fix: ") {
		t.Errorf("text:\n%s", text)
	}
}

func TestMode(t *testing.T) {
	for args, want := range map[string]string{"--live": ModeLive, "-live": ModeLive, "--json --live": ModeLive, "-live=false": "check", "--live=false": "check", "--live=true": "check", "--json": "check", "": "check", "live": "check", "---live": "check"} {
		if got := Mode(strings.Fields(args)); got != want {
			t.Errorf("Mode(%q) = %q", args, got)
		}
	}
}

func TestAllowedCommand(t *testing.T) {
	for _, argv := range [][]string{
		{"/bin/launchctl", "print", "gui/502"}, {"/bin/launchctl", "print-disabled", "system"},
		{"/bin/launchctl", "print", "system/org.macserve.worker"}, {"/usr/bin/csrutil", "status"},
	} {
		if !AllowedCommand(argv) {
			t.Errorf("refused %q", argv)
		}
	}
	for _, argv := range [][]string{
		{"/bin/launchctl", "bootout", "system/org.macserve.worker"}, {"/bin/launchctl", "print", "gui/0"},
		{"/bin/launchctl", "print", "system/com.other"}, {"launchctl", "print-disabled", "system"},
		{"/bin/launchctl", "print", "gui/502", "x"},
	} {
		if AllowedCommand(argv) {
			t.Errorf("allowed %q", argv)
		}
	}
}

// Doctor sizes the disk budget by the lanes the services actually run, by the
// runtime rule for lanes.json: an unsafe, unreadable or malformed override
// runs one lane (80 GiB budget, so 60 GiB accounted leaves no room), a safe
// one lowers, an absent one leaves controller.json's two lanes (110 GiB).
func TestDoctorLanesOverrideFollowsRuntimeRule(t *testing.T) {
	const override = Root + "/config/lanes.json"
	safe := plan.FileInfo{Exists: true, Mode: 0o644, Nlink: 1}
	dir := plan.FileInfo{Exists: true, Mode: fs.ModeDir | 0o755, Nlink: 3}
	for name, tc := range map[string]struct {
		info      plan.FileInfo
		body      string
		readErr   error
		ancestors map[string]plan.FileInfo
		want      Status
	}{
		// Runtime RootConfig also refuses an unsafe ancestor directory.
		"group-writable ancestor": {safe, `{"max_concurrent_jobs":2}`, nil, map[string]plan.FileInfo{"/Library": {Exists: true, Mode: fs.ModeDir | 0o775, Nlink: 3}}, Warn},
		"user-owned ancestor":     {safe, `{"max_concurrent_jobs":2}`, nil, map[string]plan.FileInfo{Root + "/config": {Exists: true, Mode: fs.ModeDir | 0o755, UID: 501, Nlink: 3}}, Warn},
		"symlinked ancestor":      {safe, `{"max_concurrent_jobs":2}`, nil, map[string]plan.FileInfo{Root: {Exists: true, Mode: fs.ModeSymlink | 0o755, Nlink: 1}}, Warn},
		"missing ancestor":        {safe, `{"max_concurrent_jobs":2}`, nil, map[string]plan.FileInfo{"/": {}}, Warn},
		"absent":                  {plan.FileInfo{}, "", nil, nil, Pass},
		"safe two":                {safe, `{"max_concurrent_jobs":2}`, nil, nil, Pass},
		"safe one":                {safe, `{"max_concurrent_jobs":1}`, nil, nil, Warn},
		"group writable":          {plan.FileInfo{Exists: true, Mode: 0o664, Nlink: 1}, `{"max_concurrent_jobs":2}`, nil, nil, Warn},
		"not root owned":          {plan.FileInfo{Exists: true, Mode: 0o644, UID: 501, Nlink: 1}, `{"max_concurrent_jobs":2}`, nil, nil, Warn},
		"symlink":                 {plan.FileInfo{Exists: true, Mode: fs.ModeSymlink | 0o644, Nlink: 1}, `{"max_concurrent_jobs":2}`, nil, nil, Warn},
		"unknown field":           {safe, `{"max_concurrent_jobs":2,"lanes":3}`, nil, nil, Warn},
		"unreadable":              {safe, "", fs.ErrPermission, nil, Warn},
		"above configured":        {safe, `{"max_concurrent_jobs":3}`, nil, nil, Pass},
	} {
		t.Run(name, func(t *testing.T) {
			h := healthy(t)
			h.files[Root+"/config/controller.json"] = []byte(`{"max_concurrent_jobs":2}`)
			h.setHealth(t, func(x *health.Health) { x.AccountedBytes = 60 << 30 })
			h.stats[override] = tc.info
			h.stats["/"], h.stats["/Library"] = dir, dir
			for path, info := range tc.ancestors {
				h.stats[path] = info
			}
			if tc.info.Exists && tc.readErr == nil {
				h.files[override] = []byte(tc.body)
			}
			if tc.readErr != nil {
				h.fileErr[override] = tc.readErr
			}
			if c := checks(Run(context.Background(), h.probe(), Options{}))["disk"]; c.Status != tc.want {
				t.Fatalf("disk %s (%s), want %s", c.Status, c.Detail, tc.want)
			}
		})
	}
}

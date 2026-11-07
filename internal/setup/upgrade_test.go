package setup

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/deploy"
	"github.com/jerryfane/macserve/internal/qualification"
)

// upgradeHost is a fake Mac that macserve setup approved and started, then
// stopped, with the upgrade helper running from a downloaded release
// v0.2.0 (the installed binary is v0.1.0).
type upgradeHost struct {
	*fakeHost
	procs     []Process
	quiescent int
	execErr   map[string]error
	carried   []string
	// failProcsAt makes that process listing (1-based) show a controller
	// process.
	failProcsAt, procCalls int
	// atReplace: owner.pause and the anchor existed when the replace ran
	// its stopped gate.
	atReplace []bool
}

const (
	newRelease    = "macserve binary release v0.2.0"
	newController = "macserve-controller binary release v0.2.0"
)

// fakeVersion stands in for ReleaseVersion: the installed test binary is
// v0.1.0, a downloaded one names its release.
func fakeVersion(b []byte) (string, error) {
	s := string(b)
	if s == "macserve binary" {
		return "v0.1.0", nil
	}
	if _, v, ok := strings.Cut(s, "release "); ok && ValidRelease(v) {
		return v, nil
	}
	return "", errors.New("not a release build")
}

func newUpgradeHost(t *testing.T) *upgradeHost {
	t.Helper()
	f := newQualifyHost(t)
	f.through(StepFirstBuild)
	f.loaded = map[string]bool{}
	u := &upgradeHost{fakeHost: f, execErr: map[string]error{}}
	// The downloaded release: macserve with its macserve-controller beside
	// it, as Homebrew installs them.
	dir := filepath.Join(f.top, "v0.2.0")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "macserve")
	writeRoot(t, exe, []byte(newRelease), 0o755)
	writeRoot(t, filepath.Join(dir, "macserve-controller"), []byte(newController), 0o755)
	f.h.Executable, f.h.SHA256, f.h.ControllerSHA256, f.h.Upgrade = exe, digestHex([]byte(newRelease)), digestHex([]byte(newController)), true
	f.h.Version = fakeVersion
	f.h.Processes = func() ([]Process, error) {
		u.procCalls++
		if u.procCalls == u.failProcsAt {
			_, err := os.Lstat(f.h.configPath("owner.pause"))
			_, anchor := os.Lstat(f.h.configPath("activation-anchor.json"))
			u.atReplace = []bool{err == nil, anchor == nil}
			return []Process{{PID: 3, UID: 6201, Executable: "/usr/bin/true"}}, nil
		}
		return slices.Clone(u.procs), nil
	}
	output := f.h.Output
	f.h.Output = func(ctx context.Context, c Cmd) ([]byte, int, error) {
		if len(c.Argv) > 1 && c.Argv[1] == "worker-quiescent" {
			f.outputs = append(f.outputs, c.Argv)
			return []byte("{}\n"), u.quiescent, nil
		}
		return output(ctx, c)
	}
	f.h.Exec = func(_ context.Context, c Cmd) error {
		f.execs = append(f.execs, c.Argv)
		name := c.Argv[1]
		switch {
		case c.Argv[0] == "/bin/launchctl" && slices.Contains(c.Argv, "--self-test"):
			name = "self-test"
		case c.Argv[0] == "/bin/launchctl":
			name = "job-probe"
		case name == "qualify":
			name = c.Argv[2]
		}
		u.carried = append(u.carried, name)
		if err := u.execErr[name]; err != nil {
			return err
		}
		if name == "carry" {
			writeRoot(t, f.h.configPath("activation-anchor.json"), []byte(`{"anchor":2}`), 0o644)
		}
		return nil
	}
	return u
}

func (u *upgradeHost) upgrade(r Request) Response {
	u.t.Helper()
	if r.Verb == "" {
		r.Verb = VerbUpgrade
	}
	if r.SHA256 == "" {
		r.SHA256 = u.h.SHA256
	}
	return u.h.Handle(r)
}

func (u *upgradeHost) installed() string {
	u.t.Helper()
	d, err := u.h.installedBinary()
	if err != nil {
		u.t.Fatal(err)
	}
	return d
}

func (u *upgradeHost) proof() string {
	p := qualification.CarryProof{
		Schema: 2, Kind: "release-carry-proof", ReleaseEffect: "QualificationCarried",
		From:                 qualification.CarryRelease{Tag: "v0.1.0", Commit: "c1", BinarySHA256: digestHex([]byte("macserve binary")), ControllerBinarySHA256: digestHex([]byte(controllerBinary))},
		To:                   qualification.CarryRelease{Tag: "v0.2.0", Commit: "c2", BinarySHA256: u.h.SHA256, ControllerBinarySHA256: u.h.ControllerSHA256},
		BoundaryManifestBlob: "b", ClassesPresent: []string{"T"},
		Changed: []qualification.CarryChange{{Path: "docs/install.md", Class: "T", Old: []string{"100644", "a"}, New: []string{"100644", "b"}}},
	}
	data, err := json.Marshal(p)
	if err != nil {
		u.t.Fatal(err)
	}
	return string(data)
}

// gui is a valid inventory with a live build-account GUI session.
func (u *upgradeHost) gui() []Process {
	return []Process{
		{PID: 1, UID: 0, Executable: "/sbin/launchd"},
		{PID: 9, UID: 6202, Executable: "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow"},
	}
}

// sums is the release's SHA256SUMS listing the binary and proof.
func (u *upgradeHost) sums(proof string) string {
	return u.h.SHA256 + "  " + ReleaseAsset + "\n" + u.h.ControllerSHA256 + "  " + ControllerReleaseAsset + "\n" + digestHex([]byte(proof)) + "  " + CarryProofAsset + "\n"
}

// carryRequest is an upgrade request with the release's proof and sums.
func (u *upgradeHost) carryRequest(carry bool) Request {
	if !carry {
		return Request{}
	}
	p := u.proof()
	return Request{Sums: u.sums(p), Proof: p}
}

// reproof edits the proof and lists the edited one in SHA256SUMS, so only
// the proof's content is wrong.
func (u *upgradeHost) reproof(r *Request, edit func(string) string) {
	r.Proof = edit(r.Proof)
	r.Sums = u.sums(r.Proof)
}

// dropApproval makes the ledger and the host unapproved.
func (u *upgradeHost) dropApproval() {
	l := u.ledger()
	for _, s := range []Step{StepApproveAndStart, StepFirstBuild} {
		l.Records[slices.Index(Steps, s)] = Record{Step: s, Status: StatusPending}
	}
	l.Approval = nil
	if err := u.h.Store.Save(l, LedgerInstalled); err != nil {
		u.t.Fatal(err)
	}
	for _, name := range ApprovedFiles[1:] {
		os.Remove(u.h.configPath(name))
	}
}

// wantLogoutGate: with the build account still logged in, setup counts no
// job login; once it is logged out, the gate clears and is recorded.
func (u *upgradeHost) wantLogoutGate() {
	u.t.Helper()
	u.h.Upgrade, u.h.Executable = false, u.h.installedPath()
	if r := u.h.Handle(Request{Verb: VerbJobLogin}); r.Done || !strings.Contains(r.Detail, "still logged in from the upgrade") {
		u.t.Fatalf("job login counted while the carry's session is live: %+v", r)
	}
	u.procs = u.gui()[:1]
	u.h.Handle(Request{Verb: VerbJobLogin})
	if u.ledger().JobLogoutPending() {
		u.t.Fatal("logout not recorded")
	}
}

// wantRequalified: the release is installed and recorded, the approval
// and anchor are gone, owner.pause is set and setup resumes at
// owner-actions.
func (u *upgradeHost) wantRequalified(abandoned string) {
	u.t.Helper()
	if got := u.installed(); got != u.h.SHA256 {
		u.t.Fatalf("installed %s, want %s", got, u.h.SHA256)
	}
	info, err := os.Lstat(u.h.installedPath())
	if err != nil || info.Mode().Perm() != 0o755 {
		u.t.Fatalf("installed binary mode %v %v", info, err)
	}
	l := u.ledger()
	if n := len(l.Releases); n != 1 || l.Releases[0].Effect != EffectRequalify || l.Releases[0].From != "v0.1.0" || l.Releases[0].To != "v0.2.0" {
		u.t.Fatalf("releases %+v", l.Releases)
	}
	if !strings.Contains(l.Releases[0].CarryAbandoned, abandoned) || (abandoned == "") != (l.Releases[0].CarryAbandoned == "") {
		u.t.Fatalf("carry abandoned %q, want %q", l.Releases[0].CarryAbandoned, abandoned)
	}
	if l.Approval != nil || l.InstalledBinary() != u.h.SHA256 || l.InstalledController() != u.h.ControllerSHA256 {
		u.t.Fatalf("approval %+v installed %s %s", l.Approval, l.InstalledBinary(), l.InstalledController())
	}
	if got := u.installedController(); got != u.h.ControllerSHA256 {
		u.t.Fatalf("installed controller %s, want %s", got, u.h.ControllerSHA256)
	}
	u.wantNext(StepOwnerActions)
	for _, s := range RequalifySteps {
		if u.status(s) != StatusPending {
			u.t.Fatalf("%s is %s after the upgrade", s, u.status(s))
		}
	}
	for _, name := range invalidatedFiles {
		if _, err := os.Lstat(filepath.Join(u.h.Root, name)); err == nil {
			u.t.Fatalf("%s survived the upgrade", name)
		}
	}
	if _, err := os.Lstat(u.h.configPath("owner.pause")); err != nil {
		u.t.Fatalf("owner.pause: %v", err)
	}
	if approved, _ := u.h.Approved(); approved {
		u.t.Fatal("still approved")
	}
}

func TestUpgradeFullRequalification(t *testing.T) {
	u := newUpgradeHost(t)
	os.Remove(u.h.configPath("owner.pause"))
	if err := u.h.CheckStart(); err != nil {
		t.Fatal(err)
	}
	r := u.upgrade(Request{Tag: "v0.2.0"})
	if r.Error != "" || !r.Done || !slices.Equal(r.Items, []string{EffectRequalify}) {
		t.Fatalf("upgrade %+v", r)
	}
	u.wantRequalified("")
	if data, _ := os.ReadFile(u.h.configPath("owner.pause")); string(data) != OwnerPauseUpgrade || !u.ledger().Releases[0].PauseWritten {
		t.Fatalf("owner.pause %q", data)
	}
	if len(u.carried) != 0 {
		t.Fatalf("carry verbs ran without a proof: %q", u.carried)
	}
	// The same release again is refused, and nothing changes.
	before := u.ledger()
	if r := u.upgrade(Request{}); !strings.Contains(r.Error, "already installed") {
		t.Fatalf("second upgrade %+v", r)
	}
	if after := u.ledger(); len(after.Releases) != len(before.Releases) {
		t.Fatal("ledger changed")
	}
	// macserve setup resumes as the installed new binary.
	u.h.Upgrade, u.h.Executable = false, u.h.installedPath()
	if err := u.h.CheckStart(); err != nil {
		t.Fatalf("setup helper after upgrade: %v", err)
	}
}

func TestUpgradeRefusals(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		prepare    func(u *upgradeHost)
	}{
		{"service loaded", "stop macserve's services", func(u *upgradeHost) { u.loaded["org.macserve.controller"] = true }},
		{"controller process", "still runs as the controller", func(u *upgradeHost) { u.procs = []Process{{PID: 9, UID: 6201, Executable: "/usr/bin/true"}} }},
		{"installed binary running", "still runs", func(u *upgradeHost) {
			u.procs = []Process{{PID: 9, UID: 0, Executable: u.h.installedPath()}}
		}},
		{"live job GUI console", "GUI session is live", func(u *upgradeHost) { u.console = 6202 }},
		{"live job loginwindow", "GUI session is live", func(u *upgradeHost) {
			u.procs = []Process{{PID: 9, UID: 6202, Executable: "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow"}}
		}},
		{"digest mismatch", "not the verified", func(u *upgradeHost) { writeRoot(u.t, u.h.Executable, []byte("tampered"), 0o755) }},
		{"request digest", "not this helper's", func(u *upgradeHost) { u.h.SHA256 = digestHex([]byte(newRelease)) }},
		{"wrong tag", "not the v0.3.0 you named", nil},
		{"downgrade", "never downgrades", func(u *upgradeHost) {
			writeRoot(u.t, u.h.Executable, []byte("macserve binary release v0.0.9"), 0o755)
			u.h.SHA256 = digestHex([]byte("macserve binary release v0.0.9"))
		}},
		{"same version", "already installed", func(u *upgradeHost) {
			writeRoot(u.t, u.h.Executable, []byte("macserve binary release v0.1.0"), 0o755)
			u.h.SHA256 = digestHex([]byte("macserve binary release v0.1.0"))
		}},
		{"dev build", "not a release build", func(u *upgradeHost) {
			writeRoot(u.t, u.h.Executable, []byte("macserve dev"), 0o755)
			u.h.SHA256 = digestHex([]byte("macserve dev"))
		}},
		{"anchor of another ledger", "not the one this setup ledger recorded", func(u *upgradeHost) {
			writeRoot(u.t, u.h.configPath("activation-anchor.json"), []byte(`{"other":1}`), 0o644)
		}},
		{"approval without ledger record", "did not record", func(u *upgradeHost) {
			l := u.ledger()
			l.Approval.Approved = nil
			l.Records[slices.Index(Steps, StepApproveAndStart)] = Record{Step: StepApproveAndStart, Status: StatusPending}
			l.Records[slices.Index(Steps, StepFirstBuild)] = Record{Step: StepFirstBuild, Status: StatusPending}
			l.Approval = nil
			if err := u.h.Store.Save(l, LedgerInstalled); err != nil {
				u.t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := newUpgradeHost(t)
			before := u.installed()
			req := Request{}
			if tc.name == "wrong tag" {
				req.Tag = "v0.3.0"
			}
			if tc.name == "request digest" {
				req.SHA256 = strings.Repeat("b", 64)
			}
			if tc.prepare != nil {
				tc.prepare(u)
			}
			r := u.upgrade(req)
			if !strings.Contains(r.Error, tc.want) {
				t.Fatalf("got %+v, want %q", r, tc.want)
			}
			if u.installed() != before || len(u.ledger().Releases) != 0 {
				t.Fatal("refused upgrade changed the binary or the ledger")
			}
		})
	}
}

// TestUpgradeVerbOnlyOnUpgradeHelper: each helper serves only its verbs,
// and the upgrade helper never runs from the installed binary.
func TestUpgradeVerbOnlyOnUpgradeHelper(t *testing.T) {
	u := newUpgradeHost(t)
	if r := u.h.Handle(Request{Verb: VerbSummary}); !strings.Contains(r.Error, "not served by this helper") {
		t.Fatalf("upgrade helper served summary: %+v", r)
	}
	u.h.Upgrade = false
	if r := u.upgrade(Request{}); !strings.Contains(r.Error, "not served by this helper") {
		t.Fatalf("setup helper served upgrade: %+v", r)
	}
	u.h.Upgrade, u.h.Executable = true, u.h.installedPath()
	u.h.SHA256 = u.installed()
	if err := u.h.CheckStart(); err == nil || !strings.Contains(err.Error(), "downloaded new release") {
		t.Fatalf("CheckStart from the installed binary: %v", err)
	}
}

// TestUpgradeReplaceIsAtomicAndRechecked: the replace is one rename of a
// fully written root file, re-hashed afterwards, behind the stopped gate
// again; an interrupted replace's temporary file is removed first.
func TestUpgradeReplaceIsAtomicAndRechecked(t *testing.T) {
	u := newUpgradeHost(t)
	ctx := context.Background()
	if err := u.h.replaceBinary(ctx, 6201, u.h.installedPath(), []byte("other"), u.h.SHA256); err == nil {
		t.Fatal("replaced with unverified bytes")
	}
	stale := filepath.Join(filepath.Dir(u.h.installedPath()), ".macserve.0123456789abcdef")
	writeRoot(t, stale, []byte("partial"), 0o600)
	u.loaded["org.macserve.worker"] = true
	if err := u.h.replaceBinary(ctx, 6201, u.h.installedPath(), []byte(newRelease), u.h.SHA256); err == nil || u.installed() == u.h.SHA256 {
		t.Fatalf("replace passed a loaded service: %v", err)
	}
	u.loaded = map[string]bool{}
	if err := u.h.replaceBinary(ctx, 6201, u.h.installedPath(), []byte(newRelease), u.h.SHA256); err != nil {
		t.Fatal(err)
	}
	if got := u.installed(); got != u.h.SHA256 {
		t.Fatalf("installed %s", got)
	}
	writeRoot(t, filepath.Join(filepath.Dir(u.h.installedPath()), ".macserve-controller.0123456789abcdef"), []byte("partial"), 0o600)
	if err := u.h.replaceBinaries(ctx, 6201, releaseBytes{macserve: []byte(newRelease), controller: []byte(newController)}); err != nil {
		t.Fatal(err)
	}
	if got, err := u.h.installedController(); err != nil || got != u.h.ControllerSHA256 {
		t.Fatalf("installed controller %s %v", got, err)
	}
	entries, _ := os.ReadDir(filepath.Dir(u.h.installedPath()))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Fatalf("temporary file %s left behind", e.Name())
		}
	}
	info, _ := os.Stat(u.h.installedPath())
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("mode %v", info.Mode())
	}
}

// TestUpgradeOrder: owner.pause and the invalidation precede the replace
// on the full path, and owner.pause precedes it on the carry path.
func TestUpgradeOrder(t *testing.T) {
	for _, carry := range []bool{false, true} {
		u := newUpgradeHost(t)
		os.Remove(u.h.configPath("owner.pause"))
		if carry {
			u.procs = u.gui()
		}
		u.failProcsAt = 3 // the stopped gate repeated by the replace
		r := u.upgrade(u.carryRequest(carry))
		if want := []bool{true, carry}; !slices.Equal(u.atReplace, want) {
			t.Fatalf("carry=%v: at the replace owner.pause, anchor = %v, want %v", carry, u.atReplace, want)
		}
		if carry {
			// The carry falls back; the build account's logout is required.
			if r.Error != "" || !strings.Contains(u.ledger().Releases[0].CarryAbandoned, "replace") || !u.ledger().JobLogoutPending() {
				t.Fatalf("carry fallback %+v", r)
			}
		} else if r.Error == "" || u.installed() == u.h.SHA256 {
			t.Fatalf("full path replaced past a failed gate: %+v", r)
		}
	}
}

// TestUpgradeResumesInterrupted: an upgrade interrupted after it was
// recorded blocks setup and other releases; the same release resumes it
// to full requalification, with the job-session guard again (or, for an
// interrupted carry, the job logout required).
func TestUpgradeResumesInterrupted(t *testing.T) {
	for _, tc := range []struct {
		name           string
		carry, swapped bool
		live           bool
		want           string
		logoutRequired bool
	}{
		{"before swap", false, false, false, "", false},
		{"after swap", false, true, false, "", false},
		{"after swap guard", false, true, true, "GUI session is live", false},
		{"carry", true, true, true, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := newUpgradeHost(t)
			l := u.ledger()
			boot, _ := u.h.Boot()
			rel := Release{Status: StatusRunning, Started: u.h.Now(), Boot: boot, From: "v0.1.0", To: "v0.2.0", FromSHA256: u.installed(), SHA256: u.h.SHA256, FromControllerSHA256: u.installedController(), ControllerSHA256: u.h.ControllerSHA256}
			if tc.carry {
				rel.Carry, rel.CarryProofSHA256 = true, digestHex([]byte(u.proof()))
			}
			if err := l.BeginRelease(rel); err != nil {
				t.Fatal(err)
			}
			if err := u.h.Store.Save(l, LedgerInstalled); err != nil {
				t.Fatal(err)
			}
			if _, _, err := u.ledger().Next(); err == nil || !strings.Contains(err.Error(), "interrupted") {
				t.Fatalf("setup not blocked: %v", err)
			}
			if tc.swapped {
				// The controller is replaced first: interrupted between
				// the two replaces.
				writeRoot(t, u.h.installedControllerPath(), []byte(newController), 0o755)
				if tc.name != "after swap" {
					writeRoot(t, u.h.installedPath(), []byte(newRelease), 0o755)
				}
			}
			if tc.live {
				u.procs = u.gui()
			}
			// Another release cannot pass the interrupted one.
			other := []byte("macserve binary release v0.3.0")
			exe := u.h.Executable
			writeRoot(t, exe, other, 0o755)
			u.h.SHA256 = digestHex(other)
			if r := u.upgrade(Request{}); !strings.Contains(r.Error, "was interrupted") {
				t.Fatalf("other release %+v", r)
			}
			writeRoot(t, exe, []byte(newRelease), 0o755)
			u.h.SHA256 = digestHex([]byte(newRelease))
			r := u.upgrade(Request{})
			if tc.want != "" {
				if !strings.Contains(r.Error, tc.want) {
					t.Fatalf("resume %+v, want %q", r, tc.want)
				}
				return
			}
			if r.Error != "" || !r.Done {
				t.Fatalf("resume %+v", r)
			}
			abandoned := ""
			if tc.carry {
				abandoned = "interrupted"
			}
			u.wantRequalified(abandoned)
			if u.ledger().JobLogoutPending() != tc.logoutRequired {
				t.Fatalf("job logout pending %v", u.ledger().JobLogoutPending())
			}
		})
	}
	// A binary changed during the interruption is refused.
	u := newUpgradeHost(t)
	l := u.ledger()
	boot, _ := u.h.Boot()
	if err := l.BeginRelease(Release{Status: StatusRunning, Started: u.h.Now(), Boot: boot, From: "v0.1.0", To: "v0.2.0", FromSHA256: u.installed(), SHA256: u.h.SHA256, FromControllerSHA256: u.installedController(), ControllerSHA256: u.h.ControllerSHA256}); err != nil {
		t.Fatal(err)
	}
	if err := u.h.Store.Save(l, LedgerInstalled); err != nil {
		t.Fatal(err)
	}
	installed := u.installed()
	writeRoot(t, u.h.installedPath(), []byte("macserve binary release v0.1.5"), 0o755)
	if r := u.upgrade(Request{}); !strings.Contains(r.Error, "changed during the interrupted upgrade") {
		t.Fatalf("%+v", r)
	}
	// So is a controller changed during the interruption.
	writeRoot(t, u.h.installedPath(), []byte("macserve binary"), 0o755)
	if u.installed() != installed {
		t.Fatal("fixture")
	}
	writeRoot(t, u.h.installedControllerPath(), []byte("another controller"), 0o755)
	if r := u.upgrade(Request{}); !strings.Contains(r.Error, "macserve-controller changed during the interrupted upgrade") {
		t.Fatalf("%+v", r)
	}
}

func (u *upgradeHost) installedController() string {
	u.t.Helper()
	d, err := u.h.installedController()
	if err != nil {
		u.t.Fatal(err)
	}
	return d
}

func TestUpgradeCarry(t *testing.T) {
	u := newUpgradeHost(t)
	u.procs = u.gui()
	approval := u.ledger().Approval
	r := u.upgrade(u.carryRequest(true))
	if r.Error != "" || !r.Done || !slices.Equal(r.Items, []string{EffectCarried}) {
		t.Fatalf("carry %+v", r)
	}
	if want := []string{"self-test", "begin", "job-probe", "_qualify-tool-evidence", "carry"}; !slices.Equal(u.carried, want) {
		t.Fatalf("carry verbs %q, want %q", u.carried, want)
	}
	begin := u.execs[len(u.execs)-4]
	if !slices.Contains(begin, "--carry") || slices.Contains(begin, "--requalify") {
		t.Fatalf("begin %q", begin)
	}
	l := u.ledger()
	if l.Releases[0].Effect != EffectCarried || !l.Releases[0].Carry || l.Approval == nil || l.Approval.SummarySHA256 != approval.SummarySHA256 || l.AnchorSHA256() != digestHex([]byte(`{"anchor":2}`)) {
		t.Fatalf("ledger %+v", l.Releases)
	}
	if next, _, err := l.Next(); err != nil || next.Step != StepFirstBuild {
		t.Fatalf("carried ledger next %v %v", next, err)
	}
	if u.installed() != u.h.SHA256 || l.InstalledBinary() != u.h.SHA256 || l.JobLogoutPending() {
		t.Fatal("carried binary not installed")
	}
	if !slices.ContainsFunc(u.outputs, func(a []string) bool { return len(a) > 1 && a[1] == "worker-quiescent" }) || !slices.Contains(u.q.calls, "CarryPreflight") {
		t.Fatal("worker-quiescent or the qualify carry pre-check not run")
	}
	if _, err := os.Lstat(u.h.configPath("owner.pause")); err != nil {
		t.Fatalf("owner.pause: %v", err)
	}
}

// TestUpgradeCarryFallsBack: a failure of any carry verb after the swap
// falls back to full requalification and requires the build account's
// logout before setup counts a job login.
func TestUpgradeCarryFallsBack(t *testing.T) {
	for _, step := range []string{"self-test", "begin", "job-probe", "_qualify-tool-evidence", "carry"} {
		t.Run(step, func(t *testing.T) {
			u := newUpgradeHost(t)
			u.procs = u.gui()
			u.execErr[step] = errors.New("exit status 1")
			r := u.upgrade(u.carryRequest(true))
			if r.Error != "" || !r.Done || !slices.Equal(r.Items, []string{EffectRequalify}) {
				t.Fatalf("fallback %+v", r)
			}
			if u.carried[len(u.carried)-1] != step {
				t.Fatalf("ran %q after the failed %s", u.carried, step)
			}
			u.wantRequalified("carry abandoned at")
			if !u.ledger().JobLogoutPending() {
				t.Fatal("job logout not required after a carry fallback")
			}
			if len(u.loaded) != 0 {
				t.Fatalf("services started: %v", u.loaded)
			}
			u.wantLogoutGate()
		})
	}
}

// TestUpgradeCarryRefused: with a live build-account session (the only
// guard a carry skips) every carry pre-check that fails keeps the guard:
// the upgrade is refused and nothing changes. Each case breaks exactly one
// pre-check; the base request carries.
func TestUpgradeCarryRefused(t *testing.T) {
	for _, tc := range []struct {
		name    string
		prepare func(u *upgradeHost, r *Request)
		want    string
	}{
		{"proof for another release", func(u *upgradeHost, r *Request) {
			u.reproof(r, func(s string) string { return strings.Replace(s, `"v0.2.0"`, `"v0.3.0"`, 1) })
		}, "carry proof is for"},
		{"boundary class", func(u *upgradeHost, r *Request) {
			u.reproof(r, func(s string) string { return strings.ReplaceAll(s, `"T"`, `"B"`) })
		}, "changes B path"},
		{"empty commits", func(u *upgradeHost, r *Request) {
			u.reproof(r, func(s string) string { return strings.ReplaceAll(s, `"commit":"c1"`, `"commit":""`) })
		}, "identities incomplete"},
		{"classes_present", func(u *upgradeHost, r *Request) {
			u.reproof(r, func(s string) string {
				return strings.Replace(s, `"classes_present":["T"]`, `"classes_present":["C"]`, 1)
			})
		}, "classes_present"},
		{"duplicate path", func(u *upgradeHost, r *Request) {
			u.reproof(r, func(s string) string {
				return strings.Replace(s, `"changed":[`, `"changed":[{"path":"docs/install.md","class":"T","new":["100644","c"]},`, 1)
			})
		}, "change list invalid"},
		{"unknown field", func(u *upgradeHost, r *Request) {
			u.reproof(r, func(s string) string { return strings.Replace(s, `{`, `{"extra":1,`, 1) })
		}, "carry proof"},
		{"proof not in SHA256SUMS", func(u *upgradeHost, r *Request) {
			r.Sums = strings.Join(strings.Split(r.Sums, "\n")[:2], "\n") + "\n"
		}, "publishes no carry-proof.json"},
		{"proof not the asset", func(u *upgradeHost, r *Request) { r.Proof += " " }, "not the release's carry-proof.json"},
		{"qualify carry pre-check", func(u *upgradeHost, r *Request) { u.q.errs["CarryPreflight"] = errors.New("anchor schema 1") }, "qualify carry would refuse"},
		{"not quiescent", func(u *upgradeHost, r *Request) { u.quiescent = 1 }, "worker-quiescent"},
		{"no approval", func(u *upgradeHost, r *Request) { u.dropApproval() }, "no completed approval"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := newUpgradeHost(t)
			u.procs = u.gui()
			r := u.carryRequest(true)
			tc.prepare(u, &r)
			before := u.installed()
			resp := u.upgrade(r)
			if !strings.Contains(resp.Error, "carry not possible") || !strings.Contains(resp.Error, tc.want) || !strings.Contains(resp.Error, "GUI session is live") {
				t.Fatalf("got %+v, want %q", resp, tc.want)
			}
			if u.installed() != before || len(u.ledger().Releases) != 0 || len(u.carried) != 0 {
				t.Fatal("a refused carry changed something")
			}
		})
	}
	// Without a live session a carry is not possible either, and the
	// upgrade requalifies with the guard satisfied (no logout needed).
	u := newUpgradeHost(t)
	r := u.upgrade(u.carryRequest(true))
	if r.Error != "" || !slices.Equal(r.Items, []string{EffectRequalify}) || len(u.carried) != 0 {
		t.Fatalf("got %+v", r)
	}
	u.wantRequalified("not live")
	if u.ledger().JobLogoutPending() {
		t.Fatal("logout required although the guard held")
	}
}

// TestUpgradeGateUnknownExecutable: a live process without an executable
// path fails the stopped gate closed; zombies and kernel_task do not.
func TestUpgradeGateUnknownExecutable(t *testing.T) {
	u := newUpgradeHost(t)
	u.procs = []Process{{PID: 0, UID: 0}, {PID: 5, UID: 6201, Zombie: true}, {PID: 7, UID: 0, Executable: "/sbin/launchd"}}
	if err := u.h.stoppedGate(context.Background(), 6201); err != nil {
		t.Fatal(err)
	}
	u.procs = append(u.procs, Process{PID: 8, UID: 0})
	if err := u.h.stoppedGate(context.Background(), 6201); err == nil || !strings.Contains(err.Error(), "no readable executable") {
		t.Fatalf("gate %v", err)
	}
	u.procs = []Process{{PID: 8, UID: 0, Executable: u.h.installedPath() + "/."}}
	if err := u.h.stoppedGate(context.Background(), 6201); err == nil {
		t.Fatal("non-canonical installed path passed")
	}
}

// TestUpgradeLedgerRefusals: an install not done, a failed step and an
// installed binary other than the recorded one are refused.
func TestUpgradeLedgerRefusals(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		prepare    func(u *upgradeHost)
	}{
		{"installed digest", "the one setup recorded", func(u *upgradeHost) {
			writeRoot(u.t, u.h.installedPath(), []byte("macserve binary release v0.1.1"), 0o755)
		}},
		{"failed step", "failed", func(u *upgradeHost) {
			l := u.ledger()
			i := slices.Index(Steps, StepFirstBuild)
			now := u.h.Now()
			boot, _ := u.h.Boot()
			l.Records[i] = Record{Step: StepFirstBuild, Status: StatusFailed, Started: &now, Finished: &now, Boot: &boot, Error: "x"}
			if err := u.h.Store.Save(l, LedgerInstalled); err != nil {
				u.t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := newUpgradeHost(t)
			tc.prepare(u)
			if r := u.upgrade(Request{}); !strings.Contains(r.Error, tc.want) || len(u.ledger().Releases) != 0 {
				t.Fatalf("got %+v, want %q", r, tc.want)
			}
		})
	}
	// Install not done: a staged ledger is not upgraded.
	f := newFakeHost(t)
	f.through(StepInstall)
	f.h.Upgrade, f.h.Version = true, fakeVersion
	f.h.Processes = func() ([]Process, error) { return nil, nil }
	if r := f.h.Handle(Request{Verb: VerbUpgrade, SHA256: f.h.SHA256}); !strings.Contains(r.Error, "no installed setup ledger") {
		t.Fatalf("%+v", r)
	}
}

// TestReleaseChain: the ledger refuses a release that does not continue
// from the previous one, or the first from another binary than install's.
func TestReleaseChain(t *testing.T) {
	u := newUpgradeHost(t)
	if r := u.upgrade(Request{}); r.Error != "" {
		t.Fatal(r.Error)
	}
	l := u.ledger()
	boot, _ := u.h.Boot()
	next := Release{Status: StatusRunning, Started: u.h.Now(), Boot: boot, From: "v0.2.0", To: "v0.3.0", FromSHA256: strings.Repeat("e", 64), SHA256: strings.Repeat("f", 64), FromControllerSHA256: u.h.ControllerSHA256, ControllerSHA256: strings.Repeat("c", 64)}
	if err := l.BeginRelease(next); err == nil || !strings.Contains(err.Error(), "does not continue") {
		t.Fatalf("chain %v", err)
	}
	next.FromSHA256, next.From = u.h.SHA256, "v0.1.9"
	if err := l.BeginRelease(next); err == nil {
		t.Fatal("chain from another tag accepted")
	}
	l = u.ledger()
	l.Releases[0].FromSHA256 = strings.Repeat("d", 64)
	if err := l.validate(); err == nil || !strings.Contains(err.Error(), "installed binaries") {
		t.Fatalf("first release %v", err)
	}
	l = u.ledger()
	l.Releases[0].FromControllerSHA256 = strings.Repeat("d", 64)
	if err := l.validate(); err == nil || !strings.Contains(err.Error(), "installed binaries") {
		t.Fatalf("first release controller %v", err)
	}
	// The release recorded both binaries; a later release must continue
	// from the controller it installed.
	l = u.ledger()
	if r := l.Releases[0]; r.ControllerSHA256 != u.h.ControllerSHA256 || r.FromControllerSHA256 != digestHex([]byte(controllerBinary)) || l.InstalledController() != u.h.ControllerSHA256 {
		t.Fatalf("release record %+v", r)
	}
	next.FromSHA256, next.From, next.FromControllerSHA256 = u.h.SHA256, "v0.2.0", strings.Repeat("e", 64)
	if err := l.BeginRelease(next); err == nil || !strings.Contains(err.Error(), "does not continue") {
		t.Fatalf("chain from another controller %v", err)
	}
}

func TestReleaseChecks(t *testing.T) {
	sums := []byte(strings.Repeat("a", 64) + "  " + ReleaseAsset + "\n" + strings.Repeat("b", 64) + "  macserve.rb\n")
	if d, err := ReleaseDigest(sums, ReleaseAsset); err != nil || d != strings.Repeat("a", 64) {
		t.Fatalf("%q %v", d, err)
	}
	for _, bad := range []string{"", "x\n", strings.Repeat("a", 64) + "  other\n", string(sums) + strings.Repeat("c", 64) + "  " + ReleaseAsset + "\n"} {
		if _, err := ReleaseDigest([]byte(bad), ReleaseAsset); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	for _, tc := range []struct {
		from, to string
		ok       bool
	}{{"v0.1.9", "v0.1.10", true}, {"v0.1.9", "v1.0.0", true}, {"v0.2.0", "v0.1.99", false}, {"v0.2.0", "v0.2.0", false}, {"v0.2.0", "0.3.0", false}} {
		if err := CompareReleases(tc.from, tc.to); (err == nil) != tc.ok {
			t.Errorf("%s to %s: %v", tc.from, tc.to, err)
		}
	}
	if _, err := ReleaseVersion([]byte("not a go binary")); err == nil {
		t.Error("version of a non-Go file")
	}
	// A carried release in the ledger history requires its own approval.
	l := NewLedger("jdoe", 501, time.Now())
	if err := l.BeginRelease(Release{Status: StatusRunning}); err == nil {
		t.Error("release before install")
	}
}

// TestOwnerActionsWaitsForCarryLogout: after a carry fallback the
// owner-actions step (the verb that records it) is not completed while the
// build account is still logged in from the carry; once it is logged out
// the gate clears and the step completes.
func TestOwnerActionsWaitsForCarryLogout(t *testing.T) {
	u := newUpgradeHost(t)
	u.procs = u.gui()
	u.execErr["begin"] = errors.New("exit status 1")
	if r := u.upgrade(u.carryRequest(true)); r.Error != "" || !u.ledger().JobLogoutPending() {
		t.Fatalf("fallback %+v", r)
	}
	u.h.Upgrade, u.h.Executable = false, u.h.installedPath()
	r := u.h.Handle(Request{Verb: VerbOwnerActions})
	if r.Done || !strings.Contains(r.Detail, "still logged in from the upgrade") || u.status(StepOwnerActions) == StatusDone {
		t.Fatalf("owner-actions counted the carry's session: %+v", r)
	}
	u.procs = u.gui()[:1]
	if r := u.h.Handle(Request{Verb: VerbOwnerActions}); r.Error != "" || !r.Done || u.ledger().JobLogoutPending() || u.status(StepOwnerActions) != StatusDone {
		t.Fatalf("owner-actions after logout %+v", r)
	}
}

// TestUpgradeRefusesSumsWithoutOwnDigest: a SHA256SUMS that does not list
// the helper's own digest is refused before anything changes, also with a
// proof it lists.
func TestUpgradeRefusesSumsWithoutOwnDigest(t *testing.T) {
	u := newUpgradeHost(t)
	u.procs = u.gui()
	r := u.carryRequest(true)
	r.Sums = strings.Repeat("e", 64) + "  " + ReleaseAsset + "\n" + digestHex([]byte(r.Proof)) + "  " + CarryProofAsset + "\n"
	before := u.installed()
	if resp := u.upgrade(r); !strings.Contains(resp.Error, "does not list this helper's digest") {
		t.Fatalf("got %+v", resp)
	}
	if u.installed() != before || len(u.ledger().Releases) != 0 || len(u.carried) != 0 {
		t.Fatal("refused upgrade changed something")
	}
}

// preSplit turns the fixture into an installation from before the
// controller binary: no bin/macserve-controller and no recorded digest.
func (u *upgradeHost) preSplit() {
	u.t.Helper()
	if err := os.Remove(u.h.installedControllerPath()); err != nil {
		u.t.Fatal(err)
	}
	l := u.ledger()
	delete(l.record(StepInstall).Inputs, ControllerInput)
	if err := u.h.Store.Save(l, LedgerInstalled); err != nil {
		u.t.Fatal(err)
	}
	writeRoot(u.t, u.h.daemonPlist("org.macserve.controller"), []byte(legacyControllerPlist), 0o644)
}

// legacyControllerPlist is the org.macserve.controller plist deploy-install
// rendered before the controller binary existed.
const legacyControllerPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>org.macserve.controller</string>
<key>ProgramArguments</key><array><string>/Library/macserve/bin/macserve</string><string>controller</string><string>--config</string><string>/Library/macserve/config/controller.json</string></array>
<key>UserName</key><string>_macserve</string>
<key>Disabled</key><true/>
<key>RunAtLoad</key><false/>
</dict></plist>
`

// migratedControllerPlist is legacyControllerPlist after the upgrade.
var migratedControllerPlist = strings.Replace(legacyControllerPlist, "<string>/Library/macserve/bin/macserve</string><string>controller</string>", "<string>/Library/macserve/bin/macserve-controller</string>", 1)

func (u *upgradeHost) controllerPlist() string {
	u.t.Helper()
	data, err := os.ReadFile(u.h.daemonPlist("org.macserve.controller"))
	if err != nil {
		u.t.Fatal(err)
	}
	return string(data)
}

// TestUpgradeFromBeforeTheControllerBinary: an installation without
// bin/macserve-controller upgrades by full requalification, installing the
// controller; a carry proof is refused with a clear reason and nothing
// changes while the build account is logged in.
func TestUpgradeFromBeforeTheControllerBinary(t *testing.T) {
	u := newUpgradeHost(t)
	u.preSplit()
	u.procs = u.gui()
	before := u.installed()
	r := u.upgrade(u.carryRequest(true))
	if !strings.Contains(r.Error, "predates the controller binary") || !strings.Contains(r.Error, "GUI session is live") {
		t.Fatalf("carry from a pre-split install %+v", r)
	}
	if u.installed() != before || len(u.ledger().Releases) != 0 || len(u.carried) != 0 {
		t.Fatal("a refused carry changed something")
	}
	if _, err := os.Lstat(u.h.installedControllerPath()); err == nil {
		t.Fatal("a refused carry installed the controller")
	}
	u.procs = nil
	if r := u.upgrade(Request{}); r.Error != "" || !r.Done {
		t.Fatalf("requalify %+v", r)
	}
	u.wantRequalified("")
	if rel := u.ledger().Releases[0]; rel.FromControllerSHA256 != "" || rel.ControllerSHA256 != u.h.ControllerSHA256 {
		t.Fatalf("release %+v", rel)
	}
	if got := u.controllerPlist(); got != migratedControllerPlist {
		t.Fatalf("controller plist not migrated to macserve-controller:\n%s", got)
	}
}

// TestUpgradeFromBeforeTheControllerBinaryMigratesPlistOnResume: a
// pre-split upgrade interrupted after both binaries were replaced (and
// with a temporary plist left behind) migrates the controller plist when it
// resumes, and a second migration is a no-op; a plist other than the one
// deploy-install wrote is refused and the release stays pending.
func TestUpgradeFromBeforeTheControllerBinaryMigratesPlistOnResume(t *testing.T) {
	u := newUpgradeHost(t)
	u.preSplit()
	l := u.ledger()
	boot, _ := u.h.Boot()
	rel := Release{Status: StatusRunning, Started: u.h.Now(), Boot: boot, From: "v0.1.0", To: "v0.2.0", FromSHA256: u.installed(), SHA256: u.h.SHA256, ControllerSHA256: u.h.ControllerSHA256}
	if err := l.BeginRelease(rel); err != nil {
		t.Fatal(err)
	}
	if err := u.h.Store.Save(l, LedgerInstalled); err != nil {
		t.Fatal(err)
	}
	writeRoot(t, u.h.installedControllerPath(), []byte(newController), 0o755)
	writeRoot(t, u.h.installedPath(), []byte(newRelease), 0o755)
	temp := filepath.Join(filepath.Dir(u.h.daemonPlist("org.macserve.controller")), ".org.macserve.controller.plist.0123456789abcdef")
	writeRoot(t, temp, []byte("partial"), 0o600)

	plist := u.h.daemonPlist("org.macserve.controller")
	writeRoot(t, plist, []byte(strings.Replace(legacyControllerPlist, "--config", "--cfg", 1)), 0o644)
	if r := u.upgrade(Request{}); !strings.Contains(r.Error, "reconcile it by hand") || u.ledger().PendingRelease() == nil {
		t.Fatalf("hand-edited plist %+v", r)
	}
	writeRoot(t, plist, []byte(legacyControllerPlist), 0o644)
	if r := u.upgrade(Request{}); r.Error != "" || !r.Done {
		t.Fatalf("resume %+v", r)
	}
	u.wantRequalified("")
	if got := u.controllerPlist(); got != migratedControllerPlist {
		t.Fatalf("controller plist not migrated on resume:\n%s", got)
	}
	if _, err := os.Lstat(temp); err == nil {
		t.Fatal("stale temporary plist kept")
	}
	if err := u.h.migrateControllerPlist(); err != nil || u.controllerPlist() != migratedControllerPlist {
		t.Fatalf("second migration: %v", err)
	}
}

// TestUpgradeRefusesUnrecordedController: bin/macserve-controller must be
// the one setup recorded (or absent when setup recorded none).
func TestUpgradeRefusesUnrecordedController(t *testing.T) {
	u := newUpgradeHost(t)
	writeRoot(t, u.h.installedControllerPath(), []byte("another controller"), 0o755)
	if r := u.upgrade(Request{}); !strings.Contains(r.Error, "not "+digestHex([]byte(controllerBinary))) {
		t.Fatalf("%+v", r)
	}
	u = newUpgradeHost(t)
	if err := os.Remove(u.h.installedControllerPath()); err != nil {
		t.Fatal(err)
	}
	if r := u.upgrade(Request{}); !strings.Contains(r.Error, "is missing") {
		t.Fatalf("%+v", r)
	}
	if len(u.ledger().Releases) != 0 {
		t.Fatal("a refused upgrade recorded a release")
	}
}

// TestUpgradeMapsSignedBinaries: with installed-binaries.json the signed
// installed bytes map to the release digests the ledger recorded, and the
// upgrade, installing unsigned release bytes, removes the stale map.
func TestUpgradeMapsSignedBinaries(t *testing.T) {
	u := newUpgradeHost(t)
	writeRoot(t, u.h.installedPath(), []byte("signed macserve"), 0o755)
	writeRoot(t, u.h.installedControllerPath(), []byte("signed controller"), 0o755)
	if r := u.upgrade(Request{}); !strings.Contains(r.Error, "not "+digestHex([]byte("macserve binary"))) {
		t.Fatalf("signed bytes without the map %+v", r)
	}
	inv := deploy.InstalledBinaries{Schema: "macserve-installed-binaries/1", Binaries: map[string]deploy.InstalledBinary{
		"macserve":            {ReleaseSHA256: digestHex([]byte("macserve binary")), InstalledSHA256: digestHex([]byte("signed macserve")), Identifier: "app.themartian.macserve"},
		"macserve-controller": {ReleaseSHA256: digestHex([]byte(controllerBinary)), InstalledSHA256: digestHex([]byte("signed controller")), Identifier: "app.themartian.macserve-controller"},
	}}
	data, err := json.Marshal(inv)
	if err != nil {
		t.Fatal(err)
	}
	writeRoot(t, u.h.configPath(installedBinariesName), data, 0o644)
	// fakeVersion names the signed bytes' release by the release digest.
	u.h.Version = func(b []byte) (string, error) {
		if string(b) == "signed macserve" {
			return "v0.1.0", nil
		}
		return fakeVersion(b)
	}
	if r := u.upgrade(Request{}); r.Error != "" || !r.Done {
		t.Fatalf("upgrade %+v", r)
	}
	if rel := u.ledger().Releases[0]; rel.FromSHA256 != digestHex([]byte("macserve binary")) || rel.FromControllerSHA256 != digestHex([]byte(controllerBinary)) {
		t.Fatalf("release from %+v", rel)
	}
	if _, err := os.Lstat(u.h.configPath(installedBinariesName)); err == nil {
		t.Fatal("stale installed-binaries.json kept after installing unsigned release bytes")
	}
}

// TestControllerRebindKeepsLedgerConsistent: a controller rebind
// (qualify rebind-controller) recorded in the setup ledger makes the
// ledger vouch for the new controller and anchor, so the upgrade's
// installed-binary and anchor checks accept them; a re-run is a no-op, a
// same-release re-sign records only the new anchor, and no rebind is
// recorded while an upgrade runs.
func TestControllerRebindKeepsLedgerConsistent(t *testing.T) {
	u := newUpgradeHost(t)
	if u.ledger().AnchorSHA256() == "" {
		t.Fatal("fixture has no approved anchor")
	}
	rebound := []byte("macserve-controller release v0.1.1")
	writeRoot(t, u.h.installedControllerPath(), rebound, 0o755)
	anchor := u.h.configPath("activation-anchor.json")
	writeRoot(t, anchor, []byte(`{"rebound":1}`), 0o644)
	if r := u.upgrade(Request{}); r.Error == "" {
		t.Fatal("an unrecorded rebind was accepted")
	}
	at := u.h.Now().Add(time.Minute)
	if err := RecordControllerRebind(u.h.Store, digestHex(rebound), digestHex([]byte(`{"rebound":1}`)), at); err != nil {
		t.Fatal(err)
	}
	if err := RecordControllerRebind(u.h.Store, digestHex(rebound), digestHex([]byte(`{"rebound":1}`)), at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	l := u.ledger()
	if len(l.Rebinds) != 1 || l.InstalledController() != digestHex(rebound) || l.AnchorSHA256() != digestHex([]byte(`{"rebound":1}`)) {
		t.Fatalf("rebind not recorded once: %+v", l.Rebinds)
	}
	// A same-release re-sign changes only the anchor.
	writeRoot(t, anchor, []byte(`{"rebound":2}`), 0o644)
	if err := RecordControllerRebind(u.h.Store, digestHex(rebound), digestHex([]byte(`{"rebound":2}`)), at.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if l := u.ledger(); len(l.Rebinds) != 2 || l.AnchorSHA256() != digestHex([]byte(`{"rebound":2}`)) {
		t.Fatalf("re-sign not recorded: %+v", l.Rebinds)
	}
	if r := u.upgrade(Request{}); r.Error != "" || !r.Done {
		t.Fatalf("upgrade after a recorded rebind %+v", r)
	}
	if rel := u.ledger().Releases[0]; rel.FromControllerSHA256 != digestHex(rebound) {
		t.Fatalf("release does not continue from the rebound controller: %+v", rel)
	}

	u = newUpgradeHost(t)
	l = u.ledger()
	boot, _ := u.h.Boot()
	if err := l.BeginRelease(Release{Status: StatusRunning, Started: u.h.Now(), Boot: boot, From: "v0.1.0", To: "v0.2.0", FromSHA256: u.installed(), SHA256: u.h.SHA256, FromControllerSHA256: u.installedController(), ControllerSHA256: u.h.ControllerSHA256}); err != nil {
		t.Fatal(err)
	}
	if err := u.h.Store.Save(l, LedgerInstalled); err != nil {
		t.Fatal(err)
	}
	if err := CheckControllerRebind(u.h.Store); err == nil || !strings.Contains(err.Error(), "upgrade is running") {
		t.Fatalf("rebind during an upgrade: %v", err)
	}
	l.Rebinds = []ControllerRebind{{At: u.h.Now().Add(time.Minute), After: 1, FromControllerSHA256: u.installedController(), ControllerSHA256: digestHex(rebound), AnchorSHA256: digestHex([]byte("a"))}}
	if err := l.validateRebinds(); err == nil {
		t.Fatal("rebind during an upgrade validated")
	}
	l.Releases = nil
	l.Rebinds[0].After, l.Rebinds[0].FromControllerSHA256 = 0, digestHex([]byte("other"))
	if err := l.validateRebinds(); err == nil {
		t.Fatal("rebind from another controller validated")
	}
}

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
}

const newRelease = "macserve binary release v0.2.0"

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
	exe := filepath.Join(f.top, "macserve-v0.2.0")
	writeRoot(t, exe, []byte(newRelease), 0o755)
	f.h.Executable, f.h.SHA256, f.h.Upgrade = exe, digestHex([]byte(newRelease)), true
	f.h.Version = fakeVersion
	f.h.Processes = func() ([]Process, error) { return slices.Clone(u.procs), nil }
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
		Schema: 1, Kind: "release-carry-proof", ReleaseEffect: "QualificationCarried",
		From:                 qualification.CarryRelease{Tag: "v0.1.0", Commit: "c1", BinarySHA256: digestHex([]byte("macserve binary"))},
		To:                   qualification.CarryRelease{Tag: "v0.2.0", Commit: "c2", BinarySHA256: u.h.SHA256},
		BoundaryManifestBlob: "b", ClassesPresent: []string{"T"},
		Changed: []qualification.CarryChange{{Path: "docs/install.md", Class: "T", Old: []string{"100644", "a"}, New: []string{"100644", "b"}}},
	}
	data, err := json.Marshal(p)
	if err != nil {
		u.t.Fatal(err)
	}
	return string(data)
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
	if l.Approval != nil || l.InstalledBinary() != u.h.SHA256 {
		u.t.Fatalf("approval %+v installed %s", l.Approval, l.InstalledBinary())
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
// fully written root file, re-hashed afterwards; a resumed upgrade whose
// binary is already in place finishes without writing it again.
func TestUpgradeReplaceIsAtomicAndRechecked(t *testing.T) {
	u := newUpgradeHost(t)
	// The bytes to install must be the verified ones.
	if err := u.h.replaceBinary([]byte("other")); err == nil {
		t.Fatal("replaced with unverified bytes")
	}
	if err := u.h.replaceBinary([]byte(newRelease)); err != nil {
		t.Fatal(err)
	}
	if got := u.installed(); got != u.h.SHA256 {
		t.Fatalf("installed %s", got)
	}
	entries, _ := os.ReadDir(filepath.Dir(u.h.installedPath()))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Fatalf("temporary file %s left behind", e.Name())
		}
	}
	// A swap that does not read back as the verified digest is reported.
	u.h.SHA256 = digestHex([]byte("x"))
	if err := u.h.replaceBinary([]byte("x")); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(u.h.installedPath())
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("mode %v", info.Mode())
	}
}

// TestUpgradeResumesInterrupted: an upgrade interrupted after it was
// recorded blocks setup and other releases, and the same release resumes
// it to full requalification.
func TestUpgradeResumesInterrupted(t *testing.T) {
	u := newUpgradeHost(t)
	l := u.ledger()
	boot, _ := u.h.Boot()
	rel := Release{Status: StatusRunning, Started: u.h.Now(), Boot: boot, From: "v0.1.0", To: "v0.2.0", FromSHA256: u.installed(), SHA256: u.h.SHA256}
	if err := l.BeginRelease(rel); err != nil {
		t.Fatal(err)
	}
	if err := u.h.Store.Save(l, LedgerInstalled); err != nil {
		t.Fatal(err)
	}
	if _, _, err := u.ledger().Next(); err == nil || !strings.Contains(err.Error(), "interrupted") {
		t.Fatalf("setup not blocked: %v", err)
	}
	if err := u.h.replaceBinary([]byte(newRelease)); err != nil {
		t.Fatal(err)
	}
	r := u.upgrade(Request{})
	if r.Error != "" || !r.Done {
		t.Fatalf("resume %+v", r)
	}
	u.wantRequalified("")
}

func TestUpgradeCarry(t *testing.T) {
	u := newUpgradeHost(t)
	u.procs = []Process{{PID: 9, UID: 6202, Executable: "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow"}}
	approval := u.ledger().Approval
	r := u.upgrade(Request{Proof: u.proof()})
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
	if l.Releases[0].Effect != EffectCarried || l.Approval == nil || l.Approval.SummarySHA256 != approval.SummarySHA256 || l.AnchorSHA256() != digestHex([]byte(`{"anchor":2}`)) {
		t.Fatalf("ledger %+v", l.Releases)
	}
	if next, _, err := l.Next(); err != nil || next.Step != StepFirstBuild {
		t.Fatalf("carried ledger next %v %v", next, err)
	}
	if u.installed() != u.h.SHA256 || l.InstalledBinary() != u.h.SHA256 {
		t.Fatal("carried binary not installed")
	}
	if !slices.ContainsFunc(u.outputs, func(a []string) bool { return len(a) > 1 && a[1] == "worker-quiescent" }) {
		t.Fatal("worker-quiescent not run")
	}
}

func TestUpgradeCarryFallsBack(t *testing.T) {
	gui := []Process{{PID: 9, UID: 6202, Executable: "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow"}}
	for _, step := range []string{"self-test", "begin", "job-probe", "_qualify-tool-evidence", "carry"} {
		t.Run(step, func(t *testing.T) {
			u := newUpgradeHost(t)
			u.procs = gui
			u.execErr[step] = errors.New("exit status 1")
			r := u.upgrade(Request{Proof: u.proof()})
			if r.Error != "" || !r.Done || !slices.Equal(r.Items, []string{EffectRequalify}) {
				t.Fatalf("fallback %+v", r)
			}
			if u.carried[len(u.carried)-1] != step {
				t.Fatalf("ran %q after the failed %s", u.carried, step)
			}
			u.wantRequalified("carry abandoned at")
		})
	}
	// Before anything changes: a bad proof, no live session or residual
	// job processes fall back too (the guard then applies).
	for _, tc := range []struct {
		name    string
		prepare func(u *upgradeHost) string
		err     string
	}{
		{"proof for another release", func(u *upgradeHost) string { return strings.Replace(u.proof(), "v0.2.0", "v0.3.0", 1) }, ""},
		{"boundary class", func(u *upgradeHost) string { return strings.Replace(u.proof(), `"class":"T"`, `"class":"B"`, 1) }, ""},
		{"not quiescent", func(u *upgradeHost) string { u.quiescent = 1; return u.proof() }, "GUI session is live"},
		{"no job session", func(u *upgradeHost) string { u.procs = nil; return u.proof() }, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := newUpgradeHost(t)
			u.procs = gui
			proof := tc.prepare(u)
			if tc.err == "" {
				u.procs = nil
			}
			r := u.upgrade(Request{Proof: proof})
			if tc.err != "" {
				if !strings.Contains(r.Error, tc.err) || !strings.Contains(r.Error, "carry not possible") || len(u.ledger().Releases) != 0 {
					t.Fatalf("got %+v", r)
				}
				return
			}
			if r.Error != "" || !slices.Equal(r.Items, []string{EffectRequalify}) || len(u.carried) != 0 {
				t.Fatalf("got %+v ran %q", r, u.carried)
			}
			u.wantRequalified("carry not possible")
		})
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

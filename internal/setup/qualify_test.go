package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/qualification"
	"github.com/jerryfane/macserve/internal/worker"
)

// fakeQualifier stands in for every qualification and worker API the
// rounds and approve-and-start call. Each call is recorded by name; errs
// makes a method fail.
type fakeQualifier struct {
	f           *fakeHost
	calls       []string
	errs        map[string]error
	procs       []JobProcess
	persistence worker.PersistenceManifest
	accepted    string
	resets      [][]int
	begins      []qualification.BeginOptions
	sources     []string
	evidence    []string
	// categories overrides the collected category statuses.
	categories map[string]string
	health     []string
	// afterApprove runs after a successful Approve (a change during it).
	afterApprove func()
}

func newFakeQualifier(f *fakeHost) *fakeQualifier {
	return &fakeQualifier{
		f: f, errs: map[string]error{},
		procs: []JobProcess{
			{PID: 410, Start: "1700000000:2", Executable: "/usr/libexec/cfprefsd"},
			{PID: 400, Start: "1700000000:1", Executable: "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow"},
			{PID: 420, Start: "1700000000:3", Executable: "/usr/libexec/cfprefsd"},
		},
		persistence: worker.PersistenceManifest{Version: 1, JobUID: 6202, OSBuild: "25A1", Code: map[string]worker.RegisteredCode{}},
		health:      []string{"owner_pause"},
	}
}

func (q *fakeQualifier) call(name string) error {
	q.calls = append(q.calls, name)
	return q.errs[name]
}

// writeRoot writes a file as root would: RootUID-owned with mode perm.
func writeRoot(t *testing.T, path string, data []byte, perm fs.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, perm); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, perm); err != nil {
		t.Fatal(err)
	}
}

func (q *fakeQualifier) ReviewPersistence(_ context.Context, candidate string) (string, error) {
	if err := q.call("ReviewPersistence"); err != nil {
		return "", err
	}
	data, err := json.MarshalIndent(q.persistence, "", "  ")
	if err != nil {
		return "", err
	}
	writeRoot(q.f.t, candidate, data, 0o600)
	return digestHex(data), nil
}

func (q *fakeQualifier) AcceptPersistence(_ context.Context, candidate, reviewed string) error {
	if err := q.call("AcceptPersistence"); err != nil {
		return err
	}
	data, err := os.ReadFile(candidate)
	if err != nil || digestHex(data) != reviewed {
		return errors.New("candidate is not the reviewed one")
	}
	q.accepted = reviewed
	return nil
}

func (q *fakeQualifier) PersistenceDigest() (string, error) {
	if q.accepted == "" {
		return "", fs.ErrNotExist
	}
	return q.accepted, nil
}

func (q *fakeQualifier) ResetBaseline(_ context.Context, pids []int) error {
	if err := q.call("ResetBaseline"); err != nil {
		return err
	}
	q.resets = append(q.resets, pids)
	return nil
}

func (q *fakeQualifier) CheckBaseline(context.Context) error { return q.call("CheckBaseline") }

func (q *fakeQualifier) JobProcesses(uid uint32) ([]JobProcess, error) {
	if uid != 6202 {
		return nil, errors.New("not the job UID")
	}
	return slices.Clone(q.procs), nil
}

func (q *fakeQualifier) Source(_ context.Context, repo, dir string) (worker.Source, error) {
	if err := q.call("Source"); err != nil {
		return worker.Source{}, err
	}
	if dir != filepath.Join(q.f.h.Root, "qualification-sources") {
		return worker.Source{}, errors.New("unexpected archive directory " + dir)
	}
	q.sources = append(q.sources, repo)
	return worker.Source{Commit: strings.Repeat("a", 40), Tree: strings.Repeat("b", 40), SHA256: strings.Repeat("c", 64), SizeBytes: 1234}, nil
}

func (q *fakeQualifier) Begin(_ context.Context, o qualification.BeginOptions) error {
	if err := q.call("Begin"); err != nil {
		return err
	}
	q.begins = append(q.begins, o)
	return os.MkdirAll(o.Session, 0o700)
}

func (q *fakeQualifier) ToolEvidence(_ context.Context, session string) error {
	if err := q.call("ToolEvidence"); err != nil {
		return err
	}
	q.evidence = append(q.evidence, session)
	return nil
}

func (q *fakeQualifier) Collect(_ context.Context, dir, owner, receipts string) error {
	if err := q.call("Collect"); err != nil {
		return err
	}
	_, wantOwner, wantReceipts := OwnerFiles(q.f.h.Owner.Home, filepath.Base(dir))
	if owner != wantOwner || receipts != wantReceipts {
		return errors.New("collect got other owner files")
	}
	statuses := map[string]string{"boundary": "pass", "reboot": "pass", "network": "not enforced in phase 1", "persistence": "pass"}
	if strings.Contains(filepath.Base(dir), string(StepRound1)) {
		statuses["reboot"] = "pending"
	}
	maps.Copy(statuses, q.categories)
	c := qualification.Candidate{Schema: 1, Categories: map[string]qualification.Category{}}
	for name, status := range statuses {
		c.Categories[name] = qualification.Category{Status: status, Reason: "fake " + name}
	}
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	writeRoot(q.f.t, filepath.Join(dir, "candidate.json"), data, 0o600)
	return nil
}

func (q *fakeQualifier) Approve(_ context.Context, dir string) error {
	if err := q.call("Approve"); err != nil {
		return err
	}
	writeRoot(q.f.t, filepath.Join(dir, "approved-boundary-evidence.json"), []byte("{}"), 0o600)
	writeRoot(q.f.t, q.f.h.configPath("qualification.json"), []byte("{}"), 0o644)
	writeRoot(q.f.t, q.f.h.configPath("activation-anchor.json"), []byte("{\"anchor\":1}"), 0o644)
	if q.afterApprove != nil {
		q.afterApprove()
	}
	return nil
}

func (q *fakeQualifier) ActivationCheck(context.Context) error { return q.call("ActivationCheck") }

// CarryPreflight stands in for qualification.CarryPreflight: the proof
// must pass qualification.ValidateCarryProof to target from the binary
// the fake anchor binds (the installed one at approval).
func (q *fakeQualifier) CarryPreflight(_ context.Context, proof []byte, target string) error {
	if err := q.call("CarryPreflight"); err != nil {
		return err
	}
	_, err := qualification.ValidateCarryProof(proof, digestHex([]byte("macserve binary")), target)
	return err
}

func (q *fakeQualifier) Health(context.Context) ([]string, error) {
	if err := q.call("Health"); err != nil {
		return nil, err
	}
	return slices.Clone(q.health), nil
}

// output is a fake Output: launchctl's disabled list, print, enable and
// bootstrap of macserve's services, and fdesetup.
func (f *fakeHost) output(_ context.Context, c Cmd) ([]byte, int, error) {
	f.outputs = append(f.outputs, c.Argv)
	if !slices.Equal(c.Env, []string{FixedPath}) {
		f.t.Errorf("output %q env %q", c.Argv, c.Env)
	}
	a := c.Argv
	switch {
	case slices.Equal(a, []string{"/bin/launchctl", "print-disabled", "system"}):
		var b strings.Builder
		b.WriteString("disabled services = {\n")
		for _, label := range serviceLabels {
			b.WriteString("\t\"" + label + "\" => disabled\n")
		}
		b.WriteString("}\n")
		return []byte(b.String()), 0, nil
	case len(a) == 3 && a[0] == "/bin/launchctl" && a[1] == "print" && strings.HasPrefix(a[2], "system/"):
		if f.loaded[strings.TrimPrefix(a[2], "system/")] {
			return []byte("state = running\n"), 0, nil
		}
		return nil, 113, nil
	case len(a) == 3 && a[0] == "/bin/launchctl" && a[1] == "enable":
		return nil, 0, nil
	case len(a) == 4 && a[0] == "/bin/launchctl" && a[1] == "bootstrap" && a[2] == "system":
		f.loaded[strings.TrimSuffix(filepath.Base(a[3]), ".plist")] = true
		return nil, 0, nil
	case slices.Equal(a, []string{"/usr/bin/fdesetup", "status"}):
		return []byte(f.fileVault + "\n"), 0, nil
	case slices.Equal(a, []string{"/usr/bin/fdesetup", "supportsauthrestart"}):
		return []byte("true\n"), 0, nil
	}
	f.t.Errorf("unexpected output command %q", a)
	return nil, 1, nil
}

// newQualifyHost is a fake Mac ready for round 1: the owner has a home
// under the fake top, deploy-install's disabled launchd plists and
// owner.pause exist. The owner canary must be the owner's file, so a test
// that does not run as root qualifies as its own user.
func newQualifyHost(t *testing.T) *fakeHost {
	t.Helper()
	f := newFakeHost(t)
	if uid := uint32(os.Getuid()); uid != 0 {
		f.h.Owner.UID, f.console = uid, uid
	}
	f.h.Owner.Home = filepath.Join(f.top, "Users/jdoe")
	if err := os.MkdirAll(f.h.Owner.Home, 0o755); err != nil {
		t.Fatal(err)
	}
	daemons := filepath.Join(f.top, "Library/LaunchDaemons")
	if err := os.MkdirAll(daemons, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, label := range serviceLabels {
		plist := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + label + `</string>
	<key>ProgramArguments</key>
	<array><string>/Library/macserve/bin/macserve</string></array>
	<key>Disabled</key>
	<true/>
	<key>RunAtLoad</key>
	<false/>
</dict>
</plist>
`
		writeRoot(t, filepath.Join(daemons, label+".plist"), []byte(plist), 0o644)
	}
	f.through(StepRound1)
	writeRoot(t, f.h.configPath("owner.pause"), []byte("paused by deploy-install\n"), 0o644)
	f.canary()
	return f
}

// canary creates the owner canary as the wizard does.
func (f *fakeHost) canary() {
	f.t.Helper()
	path := OwnerCanary(f.h.Owner.Home)
	if err := os.WriteFile(path, []byte(OwnerCanaryContent), 0o644); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Lchown(path, int(f.h.Owner.UID), int(f.h.Owner.GID)); err != nil && os.Getuid() == 0 {
		f.t.Fatal(err)
	}
}

func (f *fakeHost) req(r Request) Response {
	f.t.Helper()
	return f.h.Handle(r)
}

func (f *fakeHost) mustReq(r Request) Response {
	f.t.Helper()
	resp := f.req(r)
	if resp.Error != "" {
		f.t.Fatalf("%s: %+v", r.Verb, resp)
	}
	return resp
}

// prepare runs round-prepare and returns the review.
func (f *fakeHost) prepare() *RoundReview {
	f.t.Helper()
	r := f.mustReq(Request{Verb: VerbRoundPrepare})
	if r.Review == nil {
		f.t.Fatalf("no review: %+v", r)
	}
	return r.Review
}

// round runs one round to its recorded completion.
func (f *fakeHost) round(step Step) {
	f.t.Helper()
	review := f.prepare()
	if r := f.mustReq(Request{Verb: VerbRoundBegin, SHA256: review.Digest}); !strings.HasPrefix(r.Session, "setup-"+string(step)+"-") {
		f.t.Fatalf("session %+v", r)
	}
	f.mustDo(VerbRoundJobProbe, "")
	f.mustDo(VerbRoundCollect, "")
}

// restart begins the reboot step, restarts the fake Mac and completes it.
func (f *fakeHost) restart() {
	f.t.Helper()
	if r := f.mustReq(Request{Verb: VerbReboot}); r.Done || !slices.Equal(r.Items, []string{RestartAuth}) || r.Detail != AfterBoot {
		f.t.Fatalf("reboot guidance %+v", r)
	}
	f.newBoot()
	f.mustDo(VerbReboot, "")
}

func (f *fakeHost) newBoot() {
	n, _ := strconv.Atoi(strings.TrimPrefix(f.boot.Time, "boot-time-"))
	f.boot = Boot{Time: "boot-time-" + strconv.Itoa(n+1), SessionUUID: "2222222" + strconv.Itoa(n%10) + "-2222-2222-2222-222222222222"}
}

// approveAndStart reads the summary and approves exactly it.
func (f *fakeHost) approveAndStart() Response {
	f.t.Helper()
	s := f.mustReq(Request{Verb: VerbSummary})
	r := f.mustReq(Request{Verb: VerbApprove, SHA256: digestHex([]byte(s.Detail))})
	if !r.Done {
		f.t.Fatalf("approve: %+v", r)
	}
	return r
}

func (f *fakeHost) status(s Step) Status {
	f.t.Helper()
	return f.ledger().record(s).Status
}

func (f *fakeHost) wantNext(s Step) {
	f.t.Helper()
	next, done, err := f.ledger().Next()
	if err != nil || done || next.Step != s {
		f.t.Fatalf("next %s done %v err %v, want %s", next.Step, done, err, s)
	}
}

// TestQualificationLedgerTransitions runs round 1, the restart, round 2,
// approve-and-start and the owner.pause release against fakes of every
// helper verb's commands and every qualification API, checking the
// ledger after each step.
func TestQualificationLedgerTransitions(t *testing.T) {
	f := newQualifyHost(t)
	q := f.q

	// Round 1: review, begin, probes, collect.
	review := f.prepare()
	if f.status(StepRound1) != StatusRunning || len(q.resets) != 0 {
		t.Fatalf("prepare: %s, resets %v", f.status(StepRound1), q.resets)
	}
	if !review.Accept || len(review.Persistence) != 0 || review.Processes != 3 ||
		!slices.Equal(review.Executables, []string{"cfprefsd (2)", "loginwindow"}) || !sha256Hex.MatchString(review.Digest) {
		t.Errorf("review %+v", review)
	}
	r := f.mustReq(Request{Verb: VerbRoundBegin, SHA256: review.Digest})
	session1 := r.Session
	if !slices.Equal(q.calls, []string{"ReviewPersistence", "AcceptPersistence", "ResetBaseline", "CheckBaseline", "Begin"}) {
		t.Errorf("round-begin calls %v", q.calls)
	}
	if len(q.resets) != 1 || !slices.Equal(q.resets[0], []int{400, 410, 420}) {
		t.Errorf("reset pids %v", q.resets)
	}
	want := qualification.BeginOptions{Environment: f.h.configPath("deploy.env"), Session: f.h.sessionDir(session1), OwnerCanary: OwnerCanary(f.h.Owner.Home)}
	if len(q.begins) != 1 || q.begins[0] != want {
		t.Errorf("begin %+v, want %+v", q.begins, want)
	}
	f.execs = nil
	f.mustDo(VerbRoundJobProbe, "")
	probe := []string{"/bin/launchctl", "asuser", "6202", filepath.Join(f.h.Root, "bin/macserve"), "_qualify-job-probe", session1}
	if len(f.execs) != 1 || !slices.Equal(f.execs[0], probe) {
		t.Errorf("job probe %q", f.execs)
	}
	r = f.mustDo(VerbRoundCollect, "")
	if r.Categories["reboot"] != "pending" || r.Categories["boundary"] != "pass" {
		t.Errorf("round 1 categories %v", r.Categories)
	}
	if slices.Contains(q.calls, "ToolEvidence") || slices.Contains(q.calls, "Source") {
		t.Errorf("tool evidence without recipes: %v", q.calls)
	}
	l := f.ledger()
	if rec := l.record(StepRound1); rec.Status != StatusDone || rec.Inputs["candidate.json"] == "" || rec.Inputs["round-state"] == "" {
		t.Errorf("round 1 record %+v", rec)
	}
	f.wantNext(StepReboot)

	// Reboot: guidance until the boot identity changes.
	for _, tc := range []struct{ vault, kind string }{{"FileVault is Off.", RestartPlain}, {"FileVault is On.", RestartAuth}} {
		f.fileVault = tc.vault
		if r := f.mustReq(Request{Verb: VerbReboot}); r.Done || !slices.Equal(r.Items, []string{tc.kind}) || r.Detail != AfterBoot {
			t.Errorf("%s: %+v", tc.vault, r)
		}
		if f.status(StepReboot) != StatusRunning {
			t.Errorf("reboot %s", f.status(StepReboot))
		}
	}
	f.newBoot()
	f.mustDo(VerbReboot, "")
	f.wantNext(StepRound2)

	// Round 2: on the new boot, with round 1 as the previous session; the
	// accepted persistence is not accepted again.
	q.calls = nil
	review = f.prepare()
	if review.Accept {
		t.Errorf("round 2 asks again to accept the accepted list: %+v", review)
	}
	r = f.mustReq(Request{Verb: VerbRoundBegin, SHA256: review.Digest})
	session2 := r.Session
	if q.begins[1].Previous != f.h.sessionDir(session1) || session2 == session1 {
		t.Errorf("round 2 begin %+v", q.begins[1])
	}
	if slices.Contains(q.calls, "AcceptPersistence") {
		t.Errorf("round 2 calls %v", q.calls)
	}
	f.mustDo(VerbRoundJobProbe, "")
	if r := f.mustDo(VerbRoundCollect, ""); r.Categories["reboot"] != "pass" {
		t.Errorf("round 2 categories %v", r.Categories)
	}
	f.wantNext(StepApproveAndStart)

	// Approve-and-start: summary, typed approval, start.
	q.calls, f.outputs = nil, nil
	s := f.mustReq(Request{Verb: VerbSummary})
	for _, line := range []string{"Owner: jdoe", "Build account: macservejob (uid 6202)", "GitHub App 77, installation 555", "jdoe/myapp (id 4242)",
		"round 1 " + session1 + ", round 2 " + session2, "reboot: pass"} {
		if !strings.Contains(s.Detail, line) {
			t.Errorf("summary lacks %q:\n%s", line, s.Detail)
		}
	}
	if f.status(StepApproveAndStart) != StatusRunning || f.ledger().Approval != nil {
		t.Fatal("summary approved or did not begin the step")
	}
	r = f.mustReq(Request{Verb: VerbApprove, SHA256: digestHex([]byte(s.Detail))})
	if !r.Done || !slices.Equal(r.Items, serviceLabels) {
		t.Fatalf("approve %+v", r)
	}
	if !slices.Equal(q.calls, []string{"Approve", "ActivationCheck"}) {
		t.Errorf("approve calls %v", q.calls)
	}
	var starts [][]string
	for _, a := range f.outputs {
		if a[1] == "enable" || a[1] == "bootstrap" {
			starts = append(starts, a[1:])
		}
	}
	var wantStarts [][]string
	for _, label := range serviceLabels {
		wantStarts = append(wantStarts, []string{"enable", "system/" + label}, []string{"bootstrap", "system", f.h.daemonPlist(label)})
	}
	if !slices.EqualFunc(starts, wantStarts, slices.Equal) {
		t.Errorf("start commands %q", starts)
	}
	l = f.ledger()
	if l.Approval == nil || l.Approval.SummarySHA256 != digestHex([]byte(s.Detail)) || l.Approval.Boot != f.boot {
		t.Errorf("approval %+v", l.Approval)
	}
	if rec := l.record(StepApproveAndStart); rec.Status != StatusDone || rec.Inputs["activation-anchor.json"] != digestHex([]byte("{\"anchor\":1}")) {
		t.Errorf("approve-and-start record %+v", rec)
	}
	f.wantNext(StepFirstBuild)

	// owner.pause stays until health is valid, then is removed once.
	q.health = []string{"owner_pause", "health_stale"}
	if r := f.mustReq(Request{Verb: VerbReleasePause}); r.Done || !slices.Equal(r.Items, []string{"health_stale"}) {
		t.Errorf("unhealthy release %+v", r)
	}
	if _, err := os.Lstat(f.h.configPath("owner.pause")); err != nil {
		t.Fatal("owner.pause removed while health is invalid")
	}
	q.health = []string{"owner_pause"}
	if r := f.mustDo(VerbReleasePause, ""); r.Detail != "owner.pause removed" {
		t.Errorf("release %+v", r)
	}
	if _, err := os.Lstat(f.h.configPath("owner.pause")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("owner.pause: %v", err)
	}
	if r := f.call(VerbReleasePause, ""); !strings.Contains(r.Error, "only right after it started the services") {
		t.Errorf("second release %+v", r)
	}
	// The approved Mac serves nothing that changes a bound file.
	for _, v := range []Verb{VerbInstall, VerbGitHub, VerbTools, VerbRoundPrepare, VerbReboot} {
		if r := f.call(v, ""); !strings.Contains(r.Error, "approved") {
			t.Errorf("%s after approval: %+v", v, r)
		}
	}
	f.h.Executable = filepath.Join(f.h.Root, "bin/macserve")
	if err := f.h.CheckStart(); err != nil {
		t.Errorf("CheckStart after own approval: %v", err)
	}
}

// writeProfile installs a one-profile registry, as connect-github leaves.
func (f *fakeHost) writeProfile() {
	f.t.Helper()
	p := model.Profile{
		ID: "myapp-build-v1", Version: 1, Repo: "jdoe/myapp", Kind: model.Build, Xcode: model.Xcode{Version: "26.1", Build: "17B55"},
		DeveloperDir: "/Applications/Xcode.app/Contents/Developer", WorkDir: ".",
		Run:                   model.Command{Executable: "/usr/bin/xcrun", Args: []string{"xcodebuild", "-scheme", "App", "build"}},
		DefaultTimeoutSeconds: 1800, MaxTimeoutSeconds: 3600, MemoryLimitMiB: 32768,
	}
	data, err := json.Marshal(struct {
		Profiles []model.Profile `json:"profiles"`
	}{[]model.Profile{p}})
	if err != nil {
		f.t.Fatal(err)
	}
	writeRoot(f.t, f.h.configPath("profiles.json"), data, 0o644)
}

// TestRoundPinsSourceAndRunsToolEvidence: with a recipe, round-begin pins
// one internal/source archive per repository (kept for round 2) and
// collect runs tool evidence first.
func TestRoundPinsSourceAndRunsToolEvidence(t *testing.T) {
	f := newQualifyHost(t)
	f.writeProfile()
	f.round(StepRound1)
	if !slices.Equal(f.q.sources, []string{"jdoe/myapp"}) || len(f.q.evidence) != 1 {
		t.Fatalf("sources %v evidence %v", f.q.sources, f.q.evidence)
	}
	pins, err := f.h.readConfig("qualification-sources.json", 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	var sp qualification.SourcePins
	if err := json.Unmarshal(pins, &sp); err != nil || len(sp.Sources) != 1 || sp.Sources[0].Profile != "myapp-build-v1" || sp.Sources[0].Commit != strings.Repeat("a", 40) || sp.Sources[0].Repo != "" {
		t.Fatalf("pins %s %v", pins, err)
	}
	if f.ledger().record(StepRound1).Inputs["qualification-sources.json"] != digestHex(pins) {
		t.Error("round 1 does not bind the source pins")
	}
	f.restart()
	f.round(StepRound2)
	if len(f.q.sources) != 1 || len(f.q.evidence) != 2 {
		t.Errorf("round 2 sources %v evidence %v", f.q.sources, f.q.evidence)
	}
	if s := f.mustReq(Request{Verb: VerbSummary}); !strings.Contains(s.Detail, "Qualified with a real build of myapp-build-v1 at "+strings.Repeat("a", 40)) {
		t.Errorf("summary:\n%s", s.Detail)
	}
}

func TestRoundRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		// before changes the fake Mac between prepare and begin.
		before func(f *fakeHost)
		want   string
	}{
		{"other digest", nil, "not the review you confirmed"},
		{"processes changed", func(f *fakeHost) { f.q.procs = f.q.procs[:2] }, "processes changed since you confirmed"},
		{"shell in the session", func(f *fakeHost) {
			f.q.procs = append(f.q.procs, JobProcess{PID: 500, Start: "1:5", Executable: "/bin/zsh"})
		}, "shells, interpreters and Terminal"},
		{"not SIP-restricted", func(f *fakeHost) { f.q.procs[0].Restricted = errors.New("not SIP-restricted") }, "not SIP-restricted"},
		{"zombie", func(f *fakeHost) { f.q.procs[0].Zombie = true }, "zombie"},
		{"no canary", func(f *fakeHost) { os.Remove(OwnerCanary(f.h.Owner.Home)) }, "owner canary"},
		{"canary writable", func(f *fakeHost) { os.Chmod(OwnerCanary(f.h.Owner.Home), 0o666) }, "mode 0644"},
		{"owner not on console", func(f *fakeHost) { f.console = 503 }, "Switch User"},
		{"job logged out", func(f *fakeHost) { f.guiSession = false }, "GUI session"},
		{"service loaded", func(f *fakeHost) { f.loaded["org.macserve.worker"] = true }, "org.macserve.worker"},
		{"wrong boot", func(f *fakeHost) { f.newBoot() }, "not running in this boot"},
		{"failed reset", func(f *fakeHost) { f.q.errs["ResetBaseline"] = errors.New("reset refused") }, "worker-reset: reset refused"},
		{"baseline policy", func(f *fakeHost) { f.q.errs["CheckBaseline"] = errors.New("policy") }, "the reset baseline: policy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newQualifyHost(t)
			review := f.prepare()
			digest := review.Digest
			if tc.before == nil {
				digest = strings.Repeat("0", 64)
			} else {
				tc.before(f)
			}
			r := f.req(Request{Verb: VerbRoundBegin, SHA256: digest})
			if !strings.Contains(r.Error, tc.want) || r.Session != "" {
				t.Fatalf("begin: %+v, want %q", r, tc.want)
			}
			if slices.Contains(f.q.calls, "Begin") {
				t.Errorf("a session began: %v", f.q.calls)
			}
			if tc.want != "worker-reset: reset refused" && tc.want != "the reset baseline: policy" && len(f.q.resets) != 0 {
				t.Errorf("baseline reset despite the refusal")
			}
			// The probes never run without a begun session.
			for _, v := range []Verb{VerbRoundJobProbe, VerbRoundCollect} {
				if r := f.call(v, ""); r.Error == "" {
					t.Errorf("%s: %+v", v, r)
				}
			}
			if f.status(StepRound1) == StatusDone {
				t.Error("round recorded")
			}
		})
	}
}

func TestRoundPrepareRefusals(t *testing.T) {
	f := newQualifyHost(t)
	// Not ready: the owner is not at the console, or the job is logged out.
	f.console = 503
	if r := f.req(Request{Verb: VerbRoundPrepare}); r.Error != "" || r.Review != nil || r.Detail == "" || r.Done {
		t.Errorf("owner not on console: %+v", r)
	}
	f.console, f.guiSession = f.h.Owner.UID, false
	if r := f.req(Request{Verb: VerbRoundPrepare}); r.Error != "" || r.Review != nil || !strings.Contains(r.Detail, "GUI session") {
		t.Errorf("job logged out: %+v", r)
	}
	if f.status(StepRound1) != StatusPending || len(f.q.calls) != 0 {
		t.Errorf("round began: %s %v", f.status(StepRound1), f.q.calls)
	}
	f.guiSession = true
	// Unresolved persistence problems are refused before any review.
	f.q.persistence.Problems = []string{"unregistered agent"}
	if r := f.req(Request{Verb: VerbRoundPrepare}); !strings.Contains(r.Error, "unresolved login items") || r.Review != nil {
		t.Errorf("problems: %+v", r)
	}
	f.q.persistence.Problems = nil
	// A started service means the baseline is no longer setup's to propose.
	f.loaded["org.macserve.controller"] = true
	if r := f.req(Request{Verb: VerbRoundPrepare}); !strings.Contains(r.Error, "already loaded") {
		t.Errorf("loaded: %+v", r)
	}
	delete(f.loaded, "org.macserve.controller")
	// Third-party persistence is listed for the owner to accept.
	f.q.persistence.Code = map[string]worker.RegisteredCode{"com.example.agent": {Identifier: "com.example.agent", Team: "ABCDE12345", Requirement: "anchor apple generic", Path: "/Applications/Example.app"}}
	if review := f.prepare(); len(review.Persistence) != 1 || !strings.Contains(review.Persistence[0], "com.example.agent") || !review.Accept {
		t.Errorf("persistence review %+v", review)
	}
}

func TestRoundCollectFailureSpendsSession(t *testing.T) {
	f := newQualifyHost(t)
	review := f.prepare()
	first := f.mustReq(Request{Verb: VerbRoundBegin, SHA256: review.Digest}).Session
	f.mustDo(VerbRoundJobProbe, "")
	f.q.categories = map[string]string{"boundary": "fail"}
	r := f.req(Request{Verb: VerbRoundCollect})
	if r.Error != "" || r.Done || !slices.Equal(r.Items, []string{"boundary: fail (fake boundary)"}) || r.Categories["boundary"] != "fail" {
		t.Fatalf("failed collect %+v", r)
	}
	if f.status(StepRound1) != StatusRunning {
		t.Errorf("round 1 %s", f.status(StepRound1))
	}
	if r := f.call(VerbRoundCollect, ""); r.Error == "" {
		t.Errorf("collected a spent session again: %+v", r)
	}
	// The next attempt reviews again and begins a new session.
	f.q.categories = nil
	review = f.prepare()
	second := f.mustReq(Request{Verb: VerbRoundBegin, SHA256: review.Digest}).Session
	if second == first {
		t.Error("the spent session was reused")
	}
	f.mustDo(VerbRoundJobProbe, "")
	f.mustDo(VerbRoundCollect, "")
	f.wantNext(StepReboot)
	// A round 2 that skips the restart is refused by the ledger.
	if r := f.call(VerbRoundPrepare, ""); !strings.Contains(r.Error, "not served") {
		t.Errorf("round 2 before the restart: %+v", r)
	}
}

// TestRoundResumesAfterEachPart: an interruption after each part of a
// round resumes where it may and begins a new session where it must.
func TestRoundResumesAfterEachPart(t *testing.T) {
	f := newQualifyHost(t)
	// After prepare: prepare again reviews again.
	first := f.prepare()
	if again := f.prepare(); again.Digest != first.Digest {
		t.Errorf("same Mac, other review: %+v %+v", first, again)
	}
	// After begin: a fresh session continues without a new begin.
	session := f.mustReq(Request{Verb: VerbRoundBegin, SHA256: first.Digest}).Session
	f.q.calls = nil
	if r := f.mustReq(Request{Verb: VerbRoundPrepare}); r.Session != session || r.Review != nil {
		t.Errorf("fresh session not continued: %+v", r)
	}
	if len(f.q.calls) != 0 {
		t.Errorf("continuing called %v", f.q.calls)
	}
	// A stale begun session is not continued.
	now := f.h.Now
	f.h.Now = func() time.Time { return now().Add(sessionFresh + time.Minute) }
	if r := f.mustReq(Request{Verb: VerbRoundPrepare}); r.Review == nil || r.Session != "" {
		t.Errorf("stale session continued: %+v", r)
	}
	f.h.Now = now
	review := f.prepare()
	session = f.mustReq(Request{Verb: VerbRoundBegin, SHA256: review.Digest}).Session
	// After the job probe: the session is spent; the probe cannot rerun.
	f.mustDo(VerbRoundJobProbe, "")
	if r := f.call(VerbRoundJobProbe, ""); r.Error == "" {
		t.Errorf("job probe ran twice in one session: %+v", r)
	}
	if r := f.mustReq(Request{Verb: VerbRoundPrepare}); r.Review == nil || r.Session == session {
		t.Errorf("probed session continued: %+v", r)
	}
	// A helper started afresh (same files) completes the round.
	h := *f.h
	f.h = &h
	f.round(StepRound1)
	f.wantNext(StepReboot)
	// Reboot: rerunning before the restart repeats the guidance.
	for range 2 {
		if r := f.mustReq(Request{Verb: VerbReboot}); r.Done {
			t.Fatal("reboot done without a restart")
		}
	}
	f.newBoot()
	f.mustDo(VerbReboot, "")
	// Round 2, interrupted by another restart, begins again in the new boot.
	review = f.prepare()
	f.mustReq(Request{Verb: VerbRoundBegin, SHA256: review.Digest})
	f.newBoot()
	if r := f.call(VerbRoundJobProbe, ""); !strings.Contains(r.Error, "not running in this boot") {
		t.Errorf("probe of another boot's session: %+v", r)
	}
	f.round(StepRound2)
	f.wantNext(StepApproveAndStart)
	// Summary twice in one boot: the same summary, the step still running.
	a := f.mustReq(Request{Verb: VerbSummary}).Detail
	if b := f.mustReq(Request{Verb: VerbSummary}).Detail; a != b {
		t.Error("summary changed between reads")
	}
}

func TestApproveRefusals(t *testing.T) {
	ready := func(t *testing.T) *fakeHost {
		f := newQualifyHost(t)
		f.through(StepApproveAndStart)
		f.q.calls, f.outputs = nil, nil
		return f
	}
	nothingStarted := func(t *testing.T, f *fakeHost) {
		t.Helper()
		if slices.Contains(f.q.calls, "Approve") || slices.Contains(f.q.calls, "ActivationCheck") || len(f.loaded) != 0 {
			t.Errorf("started: calls %v loaded %v", f.q.calls, f.loaded)
		}
		if approved, _ := f.h.Approved(); approved {
			t.Error("qualification approved")
		}
	}
	t.Run("start before approve", func(t *testing.T) {
		f := ready(t)
		if r := f.req(Request{Verb: VerbApprove, SHA256: strings.Repeat("a", 64)}); !strings.Contains(r.Error, "read the summary first") {
			t.Errorf("approve before summary: %+v", r)
		}
		if r := f.call(VerbReleasePause, ""); !strings.Contains(r.Error, "not served") {
			t.Errorf("release-pause before approval: %+v", r)
		}
		l := f.ledger()
		if err := l.AuthorizeStart(f.boot); err == nil {
			t.Error("start authorized without approval")
		}
		nothingStarted(t, f)
	})
	t.Run("summary digest changed", func(t *testing.T) {
		f := ready(t)
		s := f.mustReq(Request{Verb: VerbSummary})
		f.connectGitHubApp(78)
		if r := f.req(Request{Verb: VerbApprove, SHA256: digestHex([]byte(s.Detail))}); !strings.Contains(r.Error, "summary changed") {
			t.Errorf("changed summary approved: %+v", r)
		}
		if f.ledger().Approval != nil {
			t.Error("approval recorded")
		}
		nothingStarted(t, f)
		// Reading the new summary and approving it works.
		f.approveAndStart()
	})
	t.Run("owner not on console", func(t *testing.T) {
		f := ready(t)
		s := f.mustReq(Request{Verb: VerbSummary})
		f.console = 0
		if r := f.req(Request{Verb: VerbApprove, SHA256: digestHex([]byte(s.Detail))}); !strings.Contains(r.Error, "approve at this Mac's screen") {
			t.Errorf("approved away from the console: %+v", r)
		}
		nothingStarted(t, f)
	})
	t.Run("approval in another boot", func(t *testing.T) {
		f := ready(t)
		s := f.mustReq(Request{Verb: VerbSummary})
		f.newBoot()
		for _, r := range []Request{{Verb: VerbApprove, SHA256: digestHex([]byte(s.Detail))}, {Verb: VerbSummary}} {
			if resp := f.req(r); !strings.Contains(resp.Error, "approval is bound to one boot") {
				t.Errorf("%s in another boot: %+v", r.Verb, resp)
			}
		}
		nothingStarted(t, f)
		// A ledger approval of another boot never authorizes a start.
		l := f.ledger()
		old := *l.record(StepApproveAndStart).Boot
		if err := l.Approve(digestHex([]byte(s.Detail)), "owner.pause absent, profiles.json x", old, time.Now()); err != nil {
			t.Fatal(err)
		}
		if err := l.AuthorizeStart(f.boot); err == nil || !strings.Contains(err.Error(), "another boot") {
			t.Errorf("AuthorizeStart: %v", err)
		}
	})
	t.Run("release-pause in another boot", func(t *testing.T) {
		f := ready(t)
		f.approveAndStart()
		f.newBoot()
		if r := f.call(VerbReleasePause, ""); !strings.Contains(r.Error, "approval is bound to one boot") {
			t.Errorf("release in another boot: %+v", r)
		}
		if _, err := os.Lstat(f.h.configPath("owner.pause")); err != nil {
			t.Error("owner.pause removed")
		}
	})
	t.Run("service loaded before start", func(t *testing.T) {
		f := ready(t)
		s := f.mustReq(Request{Verb: VerbSummary})
		f.loaded["org.macserve.maintenance"] = true
		if r := f.req(Request{Verb: VerbApprove, SHA256: digestHex([]byte(s.Detail))}); !strings.Contains(r.Error, "already loaded") {
			t.Errorf("approve with a loaded service: %+v", r)
		}
		if slices.Contains(f.q.calls, "Approve") {
			t.Error("qualify approve ran")
		}
	})
	t.Run("partial start fails the ledger", func(t *testing.T) {
		f := ready(t)
		s := f.mustReq(Request{Verb: VerbSummary})
		out := f.h.Output
		f.h.Output = func(ctx context.Context, c Cmd) ([]byte, int, error) {
			if len(c.Argv) == 4 && c.Argv[1] == "bootstrap" && strings.Contains(c.Argv[3], "maintenance") {
				return nil, 5, nil
			}
			return out(ctx, c)
		}
		r := f.req(Request{Verb: VerbApprove, SHA256: digestHex([]byte(s.Detail))})
		if !strings.Contains(r.Error, "PARTIAL START (bootstrapped by setup: org.macserve.worker)") || len(r.Items) != 2*len(serviceLabels) {
			t.Fatalf("partial start %+v", r)
		}
		if f.status(StepApproveAndStart) != StatusFailed {
			t.Errorf("approve-and-start %s", f.status(StepApproveAndStart))
		}
		if _, err := os.Lstat(f.h.configPath("owner.pause")); err != nil {
			t.Error("owner.pause removed")
		}
		if r := f.call(VerbApprove, ""); r.Error == "" {
			t.Errorf("served after a partial start: %+v", r)
		}
	})
}

// connectGitHubApp rewrites controller.json with another App ID.
func (f *fakeHost) connectGitHubApp(appID int64) {
	f.t.Helper()
	var c map[string]any
	data, err := os.ReadFile(f.h.configPath("controller.json"))
	if err != nil || json.Unmarshal(data, &c) != nil {
		f.t.Fatal("controller.json", err)
	}
	c["github"].(map[string]any)["app_id"] = appID
	data, _ = json.MarshalIndent(c, "", "  ")
	writeRoot(f.t, f.h.configPath("controller.json"), data, 0o644)
}

// TestApproveResumesAfterInterruption: an approval this ledger recorded
// finishes after an interruption (the helper may start again on the
// approved Mac), without running qualify approve twice.
func TestApproveResumesAfterInterruption(t *testing.T) {
	f := newQualifyHost(t)
	f.through(StepApproveAndStart)
	f.q.errs["ActivationCheck"] = errors.New("anchor mismatch")
	s := f.mustReq(Request{Verb: VerbSummary})
	digest := digestHex([]byte(s.Detail))
	if r := f.req(Request{Verb: VerbApprove, SHA256: digest}); !strings.Contains(r.Error, "activation-check: anchor mismatch") {
		t.Fatalf("approve %+v", r)
	}
	if approved, _ := f.h.Approved(); !approved || f.status(StepApproveAndStart) != StatusRunning || len(f.loaded) != 0 {
		t.Fatalf("after the interruption: approved %v, %s, loaded %v", approved, f.status(StepApproveAndStart), f.loaded)
	}
	f.h.Executable = filepath.Join(f.h.Root, "bin/macserve")
	if err := f.h.CheckStart(); err != nil {
		t.Fatalf("CheckStart: %v", err)
	}
	delete(f.q.errs, "ActivationCheck")
	f.q.calls = nil
	h := *f.h
	f.h = &h
	f.approveAndStart()
	if !slices.Equal(f.q.calls, []string{"ActivationCheck"}) {
		t.Errorf("resume calls %v", f.q.calls)
	}
	f.wantNext(StepFirstBuild)
	// An approval from outside this ledger is still refused.
	g := newQualifyHost(t)
	writeRoot(t, g.h.configPath("qualification.json"), []byte("{}"), 0o644)
	g.h.Executable = filepath.Join(g.h.Root, "bin/macserve")
	if err := g.h.CheckStart(); err == nil || !strings.Contains(err.Error(), "approved") {
		t.Errorf("foreign approval: CheckStart %v", err)
	}
	if r := g.call(VerbSummary, ""); !strings.Contains(r.Error, "approved") {
		t.Errorf("foreign approval: summary %+v", r)
	}
}

// TestQualifierVerbsNeedTheirSeams: a helper built without Qualify or
// Output refuses the verbs that need them instead of panicking.
func TestQualifierVerbsNeedTheirSeams(t *testing.T) {
	f := newQualifyHost(t)
	for _, strip := range []func(*Helper){func(h *Helper) { h.Qualify = nil }, func(h *Helper) { h.Output = nil }} {
		h := *f.h
		strip(&h)
		for _, r := range []Request{{Verb: VerbRoundPrepare}, {Verb: VerbRoundBegin, SHA256: strings.Repeat("a", 64)}, {Verb: VerbRoundJobProbe}, {Verb: VerbRoundCollect}} {
			if resp := h.Handle(r); !strings.Contains(resp.Error, "not given") {
				t.Errorf("%s: %+v", r.Verb, resp)
			}
		}
	}
	if f.status(StepRound1) != StatusPending {
		t.Errorf("round 1 %s", f.status(StepRound1))
	}
}

// TestTokenFilter: deploy-install's token line never reaches the
// terminal, however the output is split; everything else passes through
// as it comes (the password prompt has no newline).
func TestTokenFilter(t *testing.T) {
	const tok = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	input := "Creating accounts\nPassword for macservejob: \nAPI_BEARER_TOKEN=" + tok + "\nAPI_ not the token\nAPI_BEARER_TOKEN\nDone.\n"
	want := "Creating accounts\nPassword for macservejob: \nAPI_ not the token\nAPI_BEARER_TOKEN\nDone.\n"
	for size := 1; size <= len(input); size++ {
		var out bytes.Buffer
		f := &tokenFilter{out: &out}
		for i := 0; i < len(input); i += size {
			if _, err := f.Write([]byte(input[i:min(i+size, len(input))])); err != nil {
				t.Fatal(err)
			}
		}
		if out.String() != want || f.token() != tok {
			t.Fatalf("chunk %d: out %q token %q", size, out.String(), f.token())
		}
	}
	// The prompt is passed on before its line ends.
	var out bytes.Buffer
	f := &tokenFilter{out: &out}
	f.Write([]byte("Password: "))
	if out.String() != "Password: " {
		t.Errorf("prompt held back: %q", out.String())
	}
	// An unterminated token line is no token.
	f = &tokenFilter{out: &out}
	f.Write([]byte("API_BEARER_TOKEN=" + tok))
	if f.token() != "" || strings.Contains(out.String(), tok) {
		t.Errorf("unterminated token %q, out %q", f.token(), out.String())
	}
}

// TestTokenNeverStored: through a whole setup the one-time token is only
// in the install response: never on the terminal, in the ledger, the
// audit log or any file setup wrote.
func TestTokenNeverStored(t *testing.T) {
	f := newQualifyHost(t)
	f.through(StepFirstBuild)
	f.mustDo(VerbReleasePause, "")
	secret := strings.TrimPrefix(testToken, tokenPrefix)
	if strings.Contains(f.terminal.String(), secret) {
		t.Error("token on the terminal")
	}
	err := filepath.WalkDir(f.top, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(data, []byte(secret)) {
			t.Errorf("token in %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

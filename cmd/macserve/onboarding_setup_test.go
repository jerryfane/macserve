package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/setup"
	"github.com/jerryfane/macserve/internal/setup/plan"
)

var (
	wizardBoot = setup.Boot{Time: "t1", SessionUUID: "11111111-1111-1111-1111-111111111111"}
	wizardNow  = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	// rebootedBoot is the boot after the setup restart.
	rebootedBoot = setup.Boot{Time: "t2", SessionUUID: "22222222-2222-2222-2222-222222222222"}
)

// fakeHelper is the root helper as the wizard sees it: a real ledger,
// steps completed by script, every request recorded.
type fakeHelper struct {
	t        *testing.T
	root     string
	ledger   *setup.Ledger
	requests []setup.Verb
	// detections before github, fda-check and job-login-check succeed.
	githubAfter, fdaAfter, loginAfter int
	failInstall                       bool
	closed                            bool
	env                               string
	// boot is the Mac's boot; restarted reports a boot after the reboot
	// step began. session is the round's begun session.
	boot      setup.Boot
	restarted bool
	session   string
	approved  string
}

// fakeToken is deploy-install's one-time API token in the fake.
var fakeToken = strings.Repeat("5e", 32)

var fakeReview = setup.RoundReview{Persistence: []string{}, Accept: true, Processes: 3, Executables: []string{"cfprefsd (2)", "loginwindow"}, Digest: strings.Repeat("d", 64)}

const fakeSummary = "Summary: what you approve\n  Owner: jdoe (uid 501).\n"

// currentBoot is the boot the Mac runs: the new one once the reboot step
// is recorded.
func (f *fakeHelper) currentBoot() setup.Boot {
	for _, r := range f.ledger.Records {
		if r.Step == setup.StepReboot && r.Status == setup.StatusDone {
			return rebootedBoot
		}
	}
	return wizardBoot
}

func (f *fakeHelper) begin(s setup.Step) {
	f.t.Helper()
	if f.ledger.Records[slices.IndexFunc(f.ledger.Records, func(r setup.Record) bool { return r.Step == s })].Status == setup.StatusRunning {
		return
	}
	if err := f.ledger.Begin(s, f.currentBoot(), wizardNow); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakeHelper) complete(s setup.Step) {
	f.t.Helper()
	boot := f.currentBoot()
	if s == setup.StepReboot {
		boot = rebootedBoot
	}
	if err := f.ledger.Complete(s, boot, nil, wizardNow); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakeHelper) Close() error { f.closed = true; return nil }

func (f *fakeHelper) step(s setup.Step) {
	f.t.Helper()
	if err := f.ledger.Begin(s, wizardBoot, wizardNow); err != nil {
		f.t.Fatal(err)
	}
	if err := f.ledger.Complete(s, wizardBoot, nil, wizardNow); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakeHelper) Call(r setup.Request) (setup.Response, error) {
	f.requests = append(f.requests, r.Verb)
	resp, err := f.handle(r)
	if f.ledger != nil {
		resp.Ledger, _ = f.ledger.Encode()
	}
	if err != nil {
		resp.Error = err.Error()
	}
	return resp, err
}

func (f *fakeHelper) handle(r setup.Request) (setup.Response, error) {
	switch r.Verb {
	case setup.VerbStatus:
		return setup.Response{}, nil
	case setup.VerbPreflight:
		f.env = r.Env
		f.ledger = setup.NewLedger("jdoe", 501, wizardNow)
		f.step(setup.StepPreflight)
	case setup.VerbInstall:
		if f.failInstall {
			_ = f.ledger.Begin(setup.StepInstall, wizardBoot, wizardNow)
			_ = f.ledger.Fail(setup.StepInstall, "PARTIAL FAILURE", wizardNow)
			return setup.Response{}, errors.New("PARTIAL FAILURE: do not rerun")
		}
		config := filepath.Join(f.root, "config")
		if err := os.MkdirAll(config, 0o755); err != nil {
			f.t.Fatal(err)
		}
		for name, data := range map[string]string{"deploy.env": f.env, "profiles.json": "{\"profiles\":[]}\n"} {
			if err := os.WriteFile(filepath.Join(config, name), []byte(data), 0o644); err != nil {
				f.t.Fatal(err)
			}
		}
		f.step(setup.StepInstall)
		return setup.Response{Done: true, Token: fakeToken}, nil
	case setup.VerbGitHub:
		if f.githubAfter > 0 {
			f.githubAfter--
			return setup.Response{Detail: "controller.json has no github section yet"}, nil
		}
		f.step(setup.StepGitHub)
	case setup.VerbTools:
		f.step(setup.StepTools)
	case setup.VerbFDACheck:
		if f.fdaAfter > 0 {
			f.fdaAfter--
			return setup.Response{Detail: "not granted"}, nil
		}
	case setup.VerbJobLogin:
		if f.loginAfter > 0 {
			f.loginAfter--
			return setup.Response{Detail: "the build account has no GUI session yet"}, nil
		}
	case setup.VerbOwnerActions:
		f.step(setup.StepOwnerActions)
	case setup.VerbRoundPrepare:
		next, _, _ := f.ledger.Next()
		f.begin(next.Step)
		if f.session != "" {
			return setup.Response{Session: f.session}, nil
		}
		review := fakeReview
		return setup.Response{Review: &review}, nil
	case setup.VerbRoundBegin:
		if r.SHA256 != fakeReview.Digest {
			return setup.Response{}, errors.New("not the review you confirmed")
		}
		next, _, _ := f.ledger.Next()
		f.session = "setup-" + string(next.Step) + "-0123456789abcdef"
		return setup.Response{Session: f.session}, nil
	case setup.VerbRoundJobProbe:
		if f.session == "" {
			return setup.Response{}, errors.New("no session")
		}
	case setup.VerbRoundCollect:
		next, _, _ := f.ledger.Next()
		f.complete(next.Step)
		f.session = ""
		categories := map[string]string{"boundary": "pass", "reboot": "pass", "network": "not enforced in phase 1"}
		if next.Step == setup.StepRound1 {
			categories["reboot"] = "pending"
		}
		return setup.Response{Done: true, Categories: categories}, nil
	case setup.VerbReboot:
		f.begin(setup.StepReboot)
		if !f.restarted {
			return setup.Response{Detail: setup.AfterBoot, Items: []string{setup.RestartAuth}}, nil
		}
		f.complete(setup.StepReboot)
	case setup.VerbSummary:
		f.begin(setup.StepApproveAndStart)
		return setup.Response{Detail: fakeSummary}, nil
	case setup.VerbApprove:
		sum := sha256.Sum256([]byte(fakeSummary))
		if r.SHA256 != hex.EncodeToString(sum[:]) {
			return setup.Response{}, errors.New("the summary changed since you read it")
		}
		if err := f.ledger.Approve(r.SHA256, f.currentBoot(), wizardNow); err != nil {
			return setup.Response{}, err
		}
		f.approved = r.SHA256
		f.complete(setup.StepApproveAndStart)
		return setup.Response{Done: true, Items: []string{"org.macserve.worker", "org.macserve.maintenance", "org.macserve.controller"}}, nil
	case setup.VerbReleasePause:
		return setup.Response{Done: true, Detail: "owner.pause removed"}, nil
	default:
		return setup.Response{}, errors.New("unknown verb")
	}
	return setup.Response{Done: true}, nil
}

type wizardRun struct {
	helper  *fakeHelper
	w       *setupWizard
	out     bytes.Buffer
	stderr  bytes.Buffer
	opens   [][]string
	started [][2]string
	ran     int
	sha     string
	// tokens went to the keychain; restarts are the restart kinds; owner
	// lists the owner-side runs (control, probe) by session.
	tokens   []string
	restarts []string
	mu       sync.Mutex
	owner    []string
}

func (r *wizardRun) ownerRun(what string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.owner = append(r.owner, what)
}

func newWizardRun(t *testing.T, input string) *wizardRun {
	r := &wizardRun{}
	root := filepath.Join(t.TempDir(), "Library/macserve")
	r.helper = &fakeHelper{t: t, root: root}
	self := filepath.Join(t.TempDir(), "macserve-darwin-arm64")
	if err := os.WriteFile(self, []byte("release binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("release binary"))
	r.sha = hex.EncodeToString(sum[:])
	r.w = &setupWizard{
		probe: fakeSetupHost(t, &r.ran), in: bufio.NewReader(strings.NewReader(input)), out: &r.out, root: root, self: self,
		start: func(path, digest string) (setupSession, error) {
			r.started = append(r.started, [2]string{path, digest})
			return r.helper, nil
		},
		open:  func(args ...string) error { r.opens = append(r.opens, args); return nil },
		sleep: func(time.Duration) {}, loginPoll: time.Millisecond, loginWait: time.Hour,
		home:     t.TempDir(),
		keychain: func(token string) error { r.tokens = append(r.tokens, token); return nil },
		homeControl: func(ctx context.Context, sessionDir, out string) error {
			r.ownerRun("control " + filepath.Base(sessionDir))
			<-ctx.Done()
			return nil
		},
		ownerReport: func(_ context.Context, sessionDir, out string) error {
			r.ownerRun("probe " + filepath.Base(sessionDir))
			return nil
		},
		restart:    func(kind string) error { r.restarts = append(r.restarts, kind); return nil },
		healthWait: time.Hour,
	}
	return r
}

func (r *wizardRun) run(choices plan.Choices) int {
	return r.w.run(choices, r.sha, &r.stderr)
}

func repoChoices() plan.Choices {
	c := plan.DefaultChoices()
	c.Repository = "jdoe/myapp:4242"
	return c
}

func TestSetupApplyRefusesSudo(t *testing.T) {
	r := newWizardRun(t, "yes\n")
	r.w.probe.Environ = append(r.w.probe.Environ, "SUDO_UID=501")
	if got := r.run(repoChoices()); got != 2 || len(r.started) != 0 || !strings.Contains(r.stderr.String(), "not with sudo") {
		t.Fatalf("exit %d started %v stderr %q", got, r.started, r.stderr.String())
	}
}

func TestSetupApplyNeedsRepositoryBeforeInstall(t *testing.T) {
	r := newWizardRun(t, "yes\n")
	if got := r.run(plan.DefaultChoices()); got != 2 || len(r.started) != 0 || !strings.Contains(r.stderr.String(), "--repository") {
		t.Fatalf("exit %d started %v stderr %q", got, r.started, r.stderr.String())
	}
}

func TestSetupApplyDeclineChangesNothing(t *testing.T) {
	r := newWizardRun(t, "no\n")
	if got := r.run(repoChoices()); got != 0 || len(r.started) != 0 || !strings.Contains(r.out.String(), "Nothing was changed") {
		t.Fatalf("exit %d started %v out %s", got, r.started, r.out.String())
	}
}

// TestSetupApplyRunsToRound1: preflight, one helper start, install (the
// token goes to the keychain, never to the terminal), github with the
// exact commands, tools, guided owner actions, then round 1 with the
// owner's review and both owner-side runs; it stops at the restart when
// the owner declines it, and a second run resumes there.
func TestSetupApplyRunsToRound1(t *testing.T) {
	r := newWizardRun(t, "yes\n\n\ny\nn\n")
	r.helper.githubAfter, r.helper.fdaAfter, r.helper.loginAfter = 1, 1, 3
	got := r.run(repoChoices())
	out := r.out.String()
	if got != 0 {
		t.Fatalf("exit %d stderr %s\n%s", got, r.stderr.String(), out)
	}
	if len(r.started) != 1 || !r.helper.closed || r.started[0] != [2]string{r.w.self, r.sha} {
		t.Errorf("helper started %v, closed %v", r.started, r.helper.closed)
	}
	for _, want := range []string{
		"temporary until O5/O7",
		"sudo /usr/bin/tee " + r.w.root + "/config/profiles.json >/dev/null <<'JSON'",
		`"id": "myapp-build-v1"`,
		`"version": "26.1"`,
		"sudo " + r.w.root + "/bin/macserve connect-github --profile myapp-build-v1 --repository jdoe/myapp\n",
		`Your API token is saved in your login keychain as "macserve API token".`,
		"Full Disk Access: granted in launchd context.",
		"Switch User",
		"Qualification round 1.",
		"Build account has 0 third-party login items or agents ✓",
		"Build-session processes: 3",
		"cfprefsd (2), loginwindow",
		"Round 1: 1/3 categories passed.",
		"FileVault is on: fdesetup asks for your password now",
		setup.AfterBoot,
		"Restart when you are ready",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q", want)
		}
	}
	if strings.Contains(out, fakeToken) || strings.Contains(r.stderr.String(), fakeToken) {
		t.Error("the API token reached the terminal")
	}
	if !slices.Equal(r.tokens, []string{fakeToken}) {
		t.Errorf("keychain got %q", r.tokens)
	}
	wantOpens := [][]string{{"x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"}, {"-R", r.w.root + "/bin/macserve"}}
	if !slices.EqualFunc(r.opens, wantOpens, slices.Equal) {
		t.Errorf("opened %q", r.opens)
	}
	session := "setup-round-1-0123456789abcdef"
	if slices.Sort(r.owner); !slices.Equal(r.owner, []string{"control " + session, "probe " + session}) {
		t.Errorf("owner side %q", r.owner)
	}
	canary, err := os.ReadFile(setup.OwnerCanary(r.w.home))
	if err != nil || string(canary) != setup.OwnerCanaryContent {
		t.Errorf("owner canary %q %v", canary, err)
	}
	if info, err := os.Stat(setup.OwnerCanary(r.w.home)); err != nil || info.Mode().Perm() != 0o644 {
		t.Errorf("owner canary mode %v", info)
	}
	roundVerbs := []setup.Verb{setup.VerbJobLogin, setup.VerbRoundPrepare, setup.VerbRoundBegin, setup.VerbRoundJobProbe, setup.VerbRoundCollect}
	if i := slices.Index(r.helper.requests, setup.VerbRoundPrepare) - 1; i < 0 || !slices.Equal(r.helper.requests[i:i+len(roundVerbs)], roundVerbs) {
		t.Errorf("round requests %v", r.helper.requests)
	}
	if l := r.helper.ledger; l == nil {
		t.Fatal("no ledger")
	} else if next, _, _ := l.Next(); next.Step != setup.StepReboot {
		t.Errorf("stopped at %s", next.Step)
	}
	if len(r.restarts) != 0 {
		t.Errorf("restarted %v without a y", r.restarts)
	}
	// Running again resumes from the ledger: no preflight, no install, the
	// restart guidance again.
	r.helper.requests = nil
	r.out.Reset()
	r.w.in = bufio.NewReader(strings.NewReader(""))
	if got := r.run(plan.DefaultChoices()); got != 0 || !slices.Equal(r.helper.requests, []setup.Verb{setup.VerbStatus, setup.VerbReboot}) || !strings.Contains(r.out.String(), setup.AfterBoot) {
		t.Errorf("resume: exit %d requests %v\n%s", got, r.helper.requests, r.out.String())
	}
}

// TestSetupApplyQualifiesAndStarts: the restart on a typed y, then after
// it round 2, the summary, the typed approval of exactly that summary,
// and owner.pause released once health is valid.
func TestSetupApplyQualifiesAndStarts(t *testing.T) {
	r := newWizardRun(t, "yes\ny\ny\n")
	got := r.run(repoChoices())
	if got != 0 || !slices.Equal(r.restarts, []string{setup.RestartAuth}) || !strings.Contains(r.out.String(), "Restarting.") {
		t.Fatalf("exit %d restarts %v stderr %s\n%s", got, r.restarts, r.stderr.String(), r.out.String())
	}
	// After the restart.
	r.helper.restarted, r.helper.requests, r.owner = true, nil, nil
	r.out.Reset()
	r.w.in = bufio.NewReader(strings.NewReader("y\nnot yet\n"))
	if got := r.run(plan.DefaultChoices()); got != 0 || !strings.Contains(r.out.String(), "Stopped. Run macserve setup again") {
		t.Fatalf("declined approval: exit %d\n%s", got, r.out.String())
	}
	out := r.out.String()
	for _, want := range []string{"The Mac restarted; continuing.", "Qualification round 2.", "Round 2: 2/3 categories passed.", fakeSummary, `Type "approve"`} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q", want)
		}
	}
	if strings.Contains(out, `"reboot" passes in round 2`) {
		t.Error("round 2 promises the reboot category again")
	}
	if r.helper.approved != "" || slices.Contains(r.helper.requests, setup.VerbApprove) {
		t.Fatal("approved without the typed word")
	}
	session := "setup-round-2-0123456789abcdef"
	if slices.Sort(r.owner); !slices.Equal(r.owner, []string{"control " + session, "probe " + session}) {
		t.Errorf("owner side %q", r.owner)
	}
	r.helper.requests = nil
	r.out.Reset()
	r.w.in = bufio.NewReader(strings.NewReader("approve\n"))
	if got := r.run(plan.DefaultChoices()); got != 0 {
		t.Fatalf("approve: exit %d stderr %s\n%s", got, r.stderr.String(), r.out.String())
	}
	sum := sha256.Sum256([]byte(fakeSummary))
	if r.helper.approved != hex.EncodeToString(sum[:]) {
		t.Errorf("approved %q", r.helper.approved)
	}
	want := []setup.Verb{setup.VerbStatus, setup.VerbSummary, setup.VerbApprove, setup.VerbStatus, setup.VerbReleasePause}
	if !slices.Equal(r.helper.requests, want) {
		t.Errorf("requests %v, want %v", r.helper.requests, want)
	}
	for _, line := range []string{"services started: org.macserve.worker, org.macserve.maintenance, org.macserve.controller", "owner.pause removed; macserve accepts builds"} {
		if !strings.Contains(r.out.String(), line) {
			t.Errorf("output lacks %q:\n%s", line, r.out.String())
		}
	}
	if len(r.tokens) != 1 {
		t.Errorf("keychain writes %d", len(r.tokens))
	}
}

// TestSetupApplyTokenNotStored: a keychain that refuses the token leaves
// it shown only on the owner's typed request, and discarded otherwise.
func TestSetupApplyTokenNotStored(t *testing.T) {
	for _, tc := range []struct {
		answer string
		shown  bool
	}{{"show", true}, {"no", false}} {
		r := newWizardRun(t, "yes\n"+tc.answer+"\n")
		r.w.keychain = func(string) error { return errors.New("keychain locked") }
		got := r.run(repoChoices())
		if strings.Contains(r.out.String(), fakeToken) != tc.shown {
			t.Errorf("%s: token shown %v\n%s", tc.answer, !tc.shown, r.out.String())
		}
		if !tc.shown && (got != 1 || !strings.Contains(r.stderr.String(), "API token was discarded")) {
			t.Errorf("%s: exit %d stderr %s", tc.answer, got, r.stderr.String())
		}
		if strings.Contains(r.stderr.String(), fakeToken) {
			t.Errorf("%s: token on stderr", tc.answer)
		}
	}
}

func TestSetupApplyStopsAndResumes(t *testing.T) {
	r := newWizardRun(t, "yes\nq\n")
	r.helper.githubAfter = 5
	if got := r.run(repoChoices()); got != 0 || !strings.Contains(r.out.String(), "Stopped. Run macserve setup again") {
		t.Fatalf("exit %d\n%s", got, r.out.String())
	}
	if next, _, _ := r.helper.ledger.Next(); next.Step != setup.StepGitHub {
		t.Errorf("stopped at %s", next.Step)
	}
}

func TestSetupApplyFailedStepBlocks(t *testing.T) {
	r := newWizardRun(t, "yes\n")
	r.helper.failInstall = true
	if got := r.run(repoChoices()); got != 1 || !strings.Contains(r.stderr.String(), "PARTIAL FAILURE") {
		t.Fatalf("exit %d stderr %q", got, r.stderr.String())
	}
	// Before /Library/macserve exists the wizard cannot read the root-only
	// staged ledger, so it runs the preflight again; the helper's ledger
	// then blocks.
	r.helper.requests = nil
	r.stderr.Reset()
	r.w.in = bufio.NewReader(strings.NewReader("yes\n"))
	if got := r.run(repoChoices()); got != 1 || !strings.Contains(r.stderr.String(), "later steps are blocked") || !slices.Equal(r.helper.requests, []setup.Verb{setup.VerbStatus}) {
		t.Errorf("after failure: exit %d requests %v stderr %q", got, r.helper.requests, r.stderr.String())
	}
}

func TestSetupModeSelectsApplyOnlyWithoutPlanFlag(t *testing.T) {
	for _, args := range [][]string{{"--plan"}, {"-plan"}, {"--plan=false"}, {"-plan=true"}, {"--repository", "a/b:1", "--plan"}} {
		if plan.Mode(args) != "plan" {
			t.Errorf("%q selects %s", args, plan.Mode(args))
		}
	}
	for _, args := range [][]string{nil, {"--repository", "a/b:1"}, {"--sha256", strings.Repeat("a", 64)}, {"plan"}, {"---plan"}} {
		if plan.Mode(args) != plan.ModeApply {
			t.Errorf("%q selects %s", args, plan.Mode(args))
		}
	}
	// --plan=false goes to the plan, which refuses it without --plan.
	var stdout, stderr bytes.Buffer
	if got := run([]string{"setup", "--plan=false"}, &stdout, &stderr); got != 2 || stdout.Len() != 0 {
		t.Errorf("--plan=false: exit %d stdout %q", got, stdout.String())
	}
}

func TestSetupApplyRefusesBadFlags(t *testing.T) {
	for _, args := range [][]string{{"extra"}, {"--sha256", "ABC"}, {"--apply"}} {
		var stdout, stderr bytes.Buffer
		if got := runSetupApply(args, &stdout, &stderr); got != 2 || stdout.Len() != 0 {
			t.Errorf("%q: exit %d stdout %q", args, got, stdout.String())
		}
	}
}

func TestInternalCommandsHiddenAndStrict(t *testing.T) {
	var stdout, stderr bytes.Buffer
	run([]string{"no-such-command"}, &stdout, &stderr)
	if strings.Contains(stderr.String(), "_setup-root") || strings.Contains(stderr.String(), "_fda-check") {
		t.Errorf("usage lists internal commands:\n%s", stderr.String())
	}
	stderr.Reset()
	if got := run([]string{"_fda-check", "extra"}, &stdout, &stderr); got != 2 {
		t.Errorf("_fda-check extra: exit %d", got)
	}
	stdout.Reset()
	if got := run([]string{"_fda-check"}, &stdout, &stderr); got != 2 || !strings.HasPrefix(stdout.String(), "not-launchd") {
		t.Errorf("_fda-check outside launchd: exit %d %q", got, stdout.String())
	}
	stderr.Reset()
	if got := run([]string{"_setup-root", "--sha256", strings.Repeat("a", 64)}, &stdout, &stderr); got == 0 {
		t.Errorf("_setup-root ran as a test user: %q", stderr.String())
	}
}

// TestSetupApplyDigestComesFromTheRelease: before install the digest is the
// owner's (--sha256 or SHA256SUMS), never this binary's own, and a binary
// that does not match is refused before sudo.
func TestSetupApplyDigestComesFromTheRelease(t *testing.T) {
	r := newWizardRun(t, "yes\n")
	r.sha = ""
	if got := r.run(repoChoices()); got != 2 || len(r.started) != 0 || r.ran != 0 || !strings.Contains(r.stderr.String(), "--sha256sums") {
		t.Fatalf("no digest: exit %d started %v ran %d stderr %q", got, r.started, r.ran, r.stderr.String())
	}
	r.stderr.Reset()
	r.sha = strings.Repeat("0", 64)
	if got := r.run(repoChoices()); got != 2 || len(r.started) != 0 || r.ran != 0 || !strings.Contains(r.stderr.String(), "not the release digest") {
		t.Fatalf("mismatch: exit %d started %v stderr %q", got, r.started, r.stderr.String())
	}
}

func TestReleaseDigestFromSHA256SUMS(t *testing.T) {
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	if got, err := releaseDigest([]byte(a+"  macserve-darwin-arm64\n"+b+" *macserve.rb\n"), releaseAsset); err != nil || got != a {
		t.Errorf("valid: %q %v", got, err)
	}
	for name, data := range map[string]string{
		"missing":    b + "  macserve.rb\n",
		"twice":      a + "  macserve-darwin-arm64\n" + b + "  macserve-darwin-arm64\n",
		"uppercase":  strings.ToUpper(a) + "  macserve-darwin-arm64\n",
		"path":       a + "  bin/macserve-darwin-arm64\n",
		"extra text": a + "  macserve-darwin-arm64 extra\n",
		"empty":      "",
	} {
		if _, err := releaseDigest([]byte(data), releaseAsset); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// TestHelperIdentityAfterInstall: once installed, the helper is the
// installed binary, refused if it is writable by others; a given digest
// must match it.
func TestHelperIdentityAfterInstall(t *testing.T) {
	root := filepath.Join(t.TempDir(), "Library/macserve")
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	installed := filepath.Join(root, "bin", "macserve")
	if err := os.WriteFile(installed, []byte("installed"), 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("installed"))
	digest := hex.EncodeToString(sum[:])
	if os.Getuid() == 0 {
		if path, got, err := helperIdentity(root, "/elsewhere/macserve", ""); err != nil || path != installed || got != digest {
			t.Errorf("installed: %q %q %v", path, got, err)
		}
		if _, _, err := helperIdentity(root, "/elsewhere/macserve", strings.Repeat("0", 64)); err == nil {
			t.Error("accepted a --sha256 that does not match the installed binary")
		}
	} else if _, _, err := helperIdentity(root, "/elsewhere/macserve", ""); err == nil || !strings.Contains(err.Error(), "not a root-owned binary") {
		t.Errorf("non-root-owned installed binary: %v", err)
	}
	if err := os.Chmod(installed, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, _, err := helperIdentity(root, "/elsewhere/macserve", digest); err == nil || !strings.Contains(err.Error(), "not a root-owned binary") {
		t.Errorf("writable installed binary: %v", err)
	}
}

package main

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/setup"
	"github.com/jerryfane/macserve/internal/setup/plan"
)

var (
	wizardBoot = setup.Boot{Time: "t1", SessionUUID: "11111111-1111-1111-1111-111111111111"}
	wizardNow  = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
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
	started []string
	ran     int
}

func newWizardRun(t *testing.T, input string) *wizardRun {
	r := &wizardRun{}
	root := filepath.Join(t.TempDir(), "Library/macserve")
	r.helper = &fakeHelper{t: t, root: root}
	r.w = &setupWizard{
		probe: fakeSetupHost(t, &r.ran), in: bufio.NewReader(strings.NewReader(input)), out: &r.out, root: root,
		start: func(sha string) (setupSession, error) {
			r.started = append(r.started, sha)
			return r.helper, nil
		},
		open:  func(args ...string) error { r.opens = append(r.opens, args); return nil },
		sleep: func(time.Duration) {}, loginPoll: time.Millisecond, loginWait: time.Hour,
	}
	return r
}

func (r *wizardRun) run(choices plan.Choices) int {
	return r.w.run(choices, "", &r.stderr)
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

// TestSetupApplyRunsToRound1: preflight, one helper start, install,
// github with the exact commands, tools, guided owner actions; it stops
// before round 1 and never asks the helper for anything else.
func TestSetupApplyRunsToRound1(t *testing.T) {
	r := newWizardRun(t, "yes\n\n\n")
	r.helper.githubAfter, r.helper.fdaAfter, r.helper.loginAfter = 1, 1, 3
	got := r.run(repoChoices())
	out := r.out.String()
	if got != 0 {
		t.Fatalf("exit %d stderr %s\n%s", got, r.stderr.String(), out)
	}
	if len(r.started) != 1 || !r.helper.closed {
		t.Errorf("helper started %d times, closed %v", len(r.started), r.helper.closed)
	}
	for _, want := range []string{
		"temporary until O5/O7",
		"sudo /usr/bin/tee " + r.w.root + "/config/profiles.json >/dev/null <<'JSON'",
		`"id": "myapp-build-v1"`,
		`"version": "26.1"`,
		"sudo " + r.w.root + "/bin/macserve connect-github --profile myapp-build-v1 --repository jdoe/myapp\n",
		"API_BEARER_TOKEN once",
		"does not read, log or store it",
		"Full Disk Access: granted in launchd context.",
		"Switch User",
		"round 1, which this release of macserve setup does not run",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q", want)
		}
	}
	wantOpens := [][]string{{"x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"}, {"-R", r.w.root + "/bin/macserve"}}
	if !slices.EqualFunc(r.opens, wantOpens, slices.Equal) {
		t.Errorf("opened %q", r.opens)
	}
	for _, v := range r.helper.requests {
		if v == "" {
			t.Errorf("empty verb")
		}
	}
	if l := r.helper.ledger; l == nil {
		t.Fatal("no ledger")
	} else if next, _, _ := l.Next(); next.Step != setup.StepRound1 {
		t.Errorf("stopped at %s", next.Step)
	}
	// Running again resumes from the ledger: no preflight, no prompt.
	r.helper.requests = nil
	r.w.in = bufio.NewReader(strings.NewReader(""))
	if got := r.run(plan.DefaultChoices()); got != 0 || !slices.Equal(r.helper.requests, []setup.Verb{setup.VerbStatus}) {
		t.Errorf("resume: exit %d requests %v", got, r.helper.requests)
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

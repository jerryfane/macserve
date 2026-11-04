package setup

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/deploy"
)

// readyToApprove is a fake Mac at approve-and-start after both rounds.
func readyToApprove(t *testing.T) *fakeHost {
	t.Helper()
	f := newQualifyHost(t)
	f.through(StepApproveAndStart)
	f.q.calls, f.outputs = nil, nil
	return f
}

func (f *fakeHost) summaryDigest() string {
	f.t.Helper()
	return digestHex([]byte(f.mustReq(Request{Verb: VerbSummary}).Detail))
}

func (f *fakeHost) wantNothingStarted() {
	f.t.Helper()
	if len(f.loaded) != 0 || slices.Contains(f.q.calls, "ActivationCheck") {
		f.t.Errorf("started: loaded %v calls %v", f.loaded, f.q.calls)
	}
	if f.status(StepApproveAndStart) == StatusDone {
		f.t.Error("approve-and-start recorded")
	}
}

// TestStartNeverTrustsAnUnrecordedApproval (review P2-1): after a failed
// qualify approve, a qualification and activation anchor that appear on
// the Mac are not this setup's approval; the retry starts nothing.
func TestStartNeverTrustsAnUnrecordedApproval(t *testing.T) {
	f := readyToApprove(t)
	digest := f.summaryDigest()
	f.q.errs["Approve"] = errors.New("approve refused")
	if r := f.req(Request{Verb: VerbApprove, SHA256: digest}); !strings.Contains(r.Error, "qualify approve: approve refused") {
		t.Fatalf("approve %+v", r)
	}
	delete(f.q.errs, "Approve")
	writeRoot(t, f.h.configPath("qualification.json"), []byte(`{"foreign":1}`), 0o644)
	writeRoot(t, f.h.configPath("activation-anchor.json"), []byte(`{"foreign":1}`), 0o644)
	f.q.calls = nil
	if r := f.req(Request{Verb: VerbApprove, SHA256: digest}); r.Error == "" || r.Done {
		t.Fatalf("started on a foreign approval: %+v", r)
	}
	f.wantNothingStarted()
}

// TestStartComparesTheRecordedApprovedFiles: once qualify approve ran, a
// retry starts only if its files are exactly the ones recorded; a change
// fails the step.
func TestStartComparesTheRecordedApprovedFiles(t *testing.T) {
	f := readyToApprove(t)
	digest := f.summaryDigest()
	f.q.errs["ActivationCheck"] = errors.New("not yet")
	if r := f.req(Request{Verb: VerbApprove, SHA256: digest}); !strings.Contains(r.Error, "activation-check: not yet") {
		t.Fatalf("approve %+v", r)
	}
	if a := f.ledger().Approval; a == nil || len(a.Approved) != len(ApprovedFiles) || a.Approved["qualification.json"] != digestHex([]byte("{}")) {
		t.Fatalf("approved files not recorded: %+v", a)
	}
	delete(f.q.errs, "ActivationCheck")
	writeRoot(t, f.h.configPath("qualification.json"), []byte(`{"replaced":1}`), 0o644)
	f.q.calls = nil
	r := f.req(Request{Verb: VerbApprove, SHA256: digest})
	if !strings.Contains(r.Error, "the files qualify approve wrote changed") {
		t.Fatalf("retry %+v", r)
	}
	if f.status(StepApproveAndStart) != StatusFailed || slices.Contains(f.q.calls, "Approve") {
		t.Errorf("approve-and-start %s, calls %v", f.status(StepApproveAndStart), f.q.calls)
	}
	f.wantNothingStarted()
}

// TestPauseChangeDuringApprovalSurvivesNoRerun (review P2-2): owner.pause
// changed while qualify approve ran fails the step; running setup again
// cannot start the services.
func TestPauseChangeDuringApprovalSurvivesNoRerun(t *testing.T) {
	f := readyToApprove(t)
	digest := f.summaryDigest()
	f.q.afterApprove = func() { writeRoot(t, f.h.configPath("owner.pause"), []byte("set again by the owner\n"), 0o644) }
	if r := f.req(Request{Verb: VerbApprove, SHA256: digest}); !strings.Contains(r.Error, "changed during approval") {
		t.Fatalf("approve %+v", r)
	}
	f.q.afterApprove = nil
	// The wizard's next run: read the summary again and approve it.
	for _, d := range []string{digest, ""} {
		if d == "" {
			s := f.req(Request{Verb: VerbSummary})
			if s.Error != "" {
				continue
			}
			d = digestHex([]byte(s.Detail))
		}
		if r := f.req(Request{Verb: VerbApprove, SHA256: d}); r.Error == "" || r.Done {
			t.Fatalf("rerun started: %+v", r)
		}
	}
	f.wantNothingStarted()
}

// TestPauseChangeBeforeQualifyApproveNeedsANewApproval: owner.pause
// changed after the summary was read refuses the approval; reading the new
// summary and approving it works.
func TestPauseChangeBeforeQualifyApproveNeedsANewApproval(t *testing.T) {
	f := readyToApprove(t)
	digest := f.summaryDigest()
	writeRoot(t, f.h.configPath("owner.pause"), []byte("paused again\n"), 0o644)
	if r := f.req(Request{Verb: VerbApprove, SHA256: digest}); !strings.Contains(r.Error, "summary changed since you read it") {
		t.Fatalf("approve %+v", r)
	}
	f.wantNothingStarted()
	// An approval recorded before the change is not used either.
	digest = f.summaryDigest()
	f.q.errs["Approve"] = errors.New("interrupted")
	f.req(Request{Verb: VerbApprove, SHA256: digest})
	delete(f.q.errs, "Approve")
	writeRoot(t, f.h.configPath("owner.pause"), []byte("paused a third time\n"), 0o644)
	if r := f.req(Request{Verb: VerbApprove, SHA256: digest}); !strings.Contains(r.Error, "summary changed since you read it") {
		t.Fatalf("stale approval %+v", r)
	}
	f.approveAndStart()
	if a := f.ledger().Approval; a == nil || !strings.Contains(a.Bindings, digestHex([]byte("paused a third time\n"))) {
		t.Errorf("approval bindings %+v", a)
	}
}

// TestPauseChangeDuringStartFailsTheStep: a binding change between two
// service starts is a partial start.
func TestPauseChangeDuringStartFailsTheStep(t *testing.T) {
	f := readyToApprove(t)
	digest := f.summaryDigest()
	out := f.h.Output
	f.h.Output = func(ctx context.Context, c Cmd) ([]byte, int, error) {
		if len(c.Argv) == 4 && c.Argv[1] == "bootstrap" && strings.Contains(c.Argv[3], "worker") {
			writeRoot(t, f.h.configPath("profiles.json"), []byte(`{"profiles":[]}`+"\n\n"), 0o644)
		}
		return out(ctx, c)
	}
	r := f.req(Request{Verb: VerbApprove, SHA256: digest})
	if !strings.Contains(r.Error, "PARTIAL START (bootstrapped by setup: org.macserve.worker)") || f.status(StepApproveAndStart) != StatusFailed {
		t.Fatalf("approve %+v, step %s", r, f.status(StepApproveAndStart))
	}
}

// TestReleasePauseRemovesOnlyTheApprovedPauseOnce (review P2-3): the run
// that started the services removes deploy-install's owner.pause once; an
// owner.pause set again is never removed.
func TestReleasePauseRemovesOnlyTheApprovedPauseOnce(t *testing.T) {
	f := readyToApprove(t)
	f.approveAndStart()
	f.mustDo(VerbReleasePause, "")
	writeRoot(t, f.h.configPath("owner.pause"), []byte("kill switch\n"), 0o644)
	if r := f.call(VerbReleasePause, ""); r.Error == "" || r.Done {
		t.Fatalf("second release %+v", r)
	}
	if _, err := os.Lstat(f.h.configPath("owner.pause")); err != nil {
		t.Fatalf("owner.pause set again was removed: %v", err)
	}
}

// TestReleasePauseRefusesAChangedPause: an owner.pause changed after the
// approval is not the one approved and stays.
func TestReleasePauseRefusesAChangedPause(t *testing.T) {
	f := readyToApprove(t)
	f.approveAndStart()
	writeRoot(t, f.h.configPath("owner.pause"), []byte("paused by the owner after approval\n"), 0o644)
	if r := f.call(VerbReleasePause, ""); !strings.Contains(r.Error, "changed since your approval") {
		t.Fatalf("release %+v", r)
	}
	if _, err := os.Lstat(f.h.configPath("owner.pause")); err != nil {
		t.Fatalf("owner.pause removed: %v", err)
	}
	// Not later in the same run either.
	f.q.calls = nil
	if r := f.call(VerbReleasePause, ""); r.Error == "" || slices.Contains(f.q.calls, "Health") {
		t.Errorf("release again %+v", r)
	}
}

// TestReleasePauseNeverInALaterRun: a helper that did not start the
// services (any later macserve setup) refuses release-pause.
func TestReleasePauseNeverInALaterRun(t *testing.T) {
	f := readyToApprove(t)
	f.approveAndStart()
	later := *f.h
	later.started = false
	if r := later.Handle(Request{Verb: VerbReleasePause}); !strings.Contains(r.Error, "only right after it started the services") {
		t.Fatalf("later run %+v", r)
	}
	if _, err := os.Lstat(f.h.configPath("owner.pause")); err != nil {
		t.Fatalf("owner.pause removed: %v", err)
	}
}

// TestApproveAfterAClockStep (review P3): a wall-clock step moves
// kern.boottime but not kern.bootsessionuuid; the summary, the approval,
// the start and the release still belong to this boot.
func TestApproveAfterAClockStep(t *testing.T) {
	f := readyToApprove(t)
	digest := f.summaryDigest()
	f.boot.Time += "-stepped"
	if r := f.req(Request{Verb: VerbSummary}); r.Error != "" {
		t.Fatalf("summary after a clock step: %+v", r)
	}
	if r := f.req(Request{Verb: VerbApprove, SHA256: digest}); r.Error != "" || !r.Done {
		t.Fatalf("approve after a clock step: %+v", r)
	}
	f.mustDo(VerbReleasePause, "")
}

// TestRoundContinuesAfterAClockStep: a begun round session survives a
// clock step (same boot session).
func TestRoundContinuesAfterAClockStep(t *testing.T) {
	f := newQualifyHost(t)
	review := f.prepare()
	f.mustReq(Request{Verb: VerbRoundBegin, SHA256: review.Digest})
	f.boot.Time += "-stepped"
	f.mustDo(VerbRoundJobProbe, "")
	f.mustDo(VerbRoundCollect, "")
	f.wantNext(StepReboot)
	// And a clock step is not the restart.
	f.mustReq(Request{Verb: VerbReboot})
	f.boot.Time += "-again"
	if r := f.mustReq(Request{Verb: VerbReboot}); r.Done {
		t.Fatal("a clock step completed the reboot step")
	}
}

func TestOwnApprovalNeedsRecordedApprovedFiles(t *testing.T) {
	f := readyToApprove(t)
	if ownApproval(f.ledger()) {
		t.Error("own approval without an approval")
	}
	digest := f.summaryDigest()
	f.q.errs["Approve"] = errors.New("interrupted")
	f.req(Request{Verb: VerbApprove, SHA256: digest})
	if l := f.ledger(); l.Approval == nil || ownApproval(l) {
		t.Errorf("own approval before qualify approve: %+v", l.Approval)
	}
}

// TestRoundRefusesAChangedBaselineOfTheSameSize: the proposal binds the
// exact processes, not their count.
func TestRoundRefusesAChangedBaselineOfTheSameSize(t *testing.T) {
	f := newQualifyHost(t)
	review := f.prepare()
	f.q.procs[1].PID, f.q.procs[1].Start = 401, "1700000000:9"
	if r := f.req(Request{Verb: VerbRoundBegin, SHA256: review.Digest}); !strings.Contains(r.Error, "processes changed since you confirmed") {
		t.Fatalf("begin %+v", r)
	}
}

// TestRound2NeedsTheRebootCategory: reboot pending passes only in round 1.
func TestRound2NeedsTheRebootCategory(t *testing.T) {
	f := newQualifyHost(t)
	f.through(StepRound2)
	f.q.categories = map[string]string{"reboot": "pending"}
	review := f.prepare()
	f.mustReq(Request{Verb: VerbRoundBegin, SHA256: review.Digest})
	f.mustDo(VerbRoundJobProbe, "")
	if r := f.req(Request{Verb: VerbRoundCollect}); r.Done || !slices.Equal(r.Items, []string{"reboot: pending (fake reboot)"}) {
		t.Fatalf("round 2 with reboot pending: %+v", r)
	}
	f.wantNext(StepRound2)
}

// TestInstallWithoutTokenFails: deploy-install output without the token
// line fails install, which needs reconciliation.
func TestInstallWithoutTokenFails(t *testing.T) {
	f := newFakeHost(t)
	f.through(StepInstall)
	install := f.h.Install
	f.h.Install = func(o deploy.Options, _, stderr io.Writer) error { return install(o, io.Discard, stderr) }
	if r := f.call(VerbInstall, ""); !strings.Contains(r.Error, "without the one-time API token") || r.Token != "" {
		t.Fatalf("install %+v", r)
	}
	if f.status(StepInstall) != StatusFailed {
		t.Errorf("install %s", f.status(StepInstall))
	}
}

// TestBaselineRuleMatchesTheWorker pins setup's copy of the baseline
// executable rule to internal/worker's (the rule begin, collect and
// approve enforce), read from its source.
func TestBaselineRuleMatchesTheWorker(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "../worker/baseline_policy.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	lists := map[string][]string{}
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok || len(spec.Names) != 1 || len(spec.Values) != 1 {
			return true
		}
		lit, ok := spec.Values[0].(*ast.CompositeLit)
		if !ok {
			return true
		}
		for _, e := range lit.Elts {
			if b, ok := e.(*ast.BasicLit); ok && b.Kind == token.STRING {
				v, err := strconv.Unquote(b.Value)
				if err != nil {
					t.Fatal(err)
				}
				lists[spec.Names[0].Name] = append(lists[spec.Names[0].Name], v)
			}
		}
		return true
	})
	if !slices.Equal(lists["codeRunners"], codeRunners) || !slices.Equal(lists["codeRunnerDirs"], codeRunnerDirs) {
		t.Fatalf("worker rule %v, setup rule %v %v", lists, codeRunners, codeRunnerDirs)
	}
	for _, path := range []string{"/usr/bin/python3", "/bin/zsh", "/sbin/launchd", codeRunners[0]} {
		if !codeRunner(path) {
			t.Errorf("%s admitted", path)
		}
	}
	for _, path := range []string{"/usr/libexec/cfprefsd", "/usr/sbin/cfprefsd", "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"} {
		if codeRunner(path) {
			t.Errorf("%s refused", path)
		}
	}
}

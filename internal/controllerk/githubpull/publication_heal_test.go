package githubpull

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/controllerk/store"
	"github.com/jerryfane/macserve/internal/githubapi"
	"github.com/jerryfane/macserve/internal/model"
)

func (f *ownerFixture) advance(d time.Duration) {
	f.remote.mu.Lock()
	f.remote.now = f.remote.now.Add(d)
	f.remote.mu.Unlock()
}

// cancelActive ends every unfinished job of the matrix repository.
func (f *ownerFixture) cancelActive(t *testing.T) {
	t.Helper()
	for _, run := range f.active(t, matrixRepoID) {
		if _, err := f.s.Cancel(context.Background(), run.JobID, "test", model.CancelReason{Source: model.CancelGitHub}, f.options.Now()); err != nil {
			t.Fatal(err)
		}
	}
}

// busyMatrix is herdrup on #159's day: forty runs of eight heads, thirty
// with ended jobs and ten with queued jobs that fill the principal, and the
// head of a ninth pull request (not yet listed) whose build run sorts after
// every other run, as the stuck herdrup runs did.
func busyMatrix(t *testing.T) (*ownerFixture, string) {
	t.Helper()
	ctx := context.Background()
	f := newMatrixFixture(t, matrixPolicy())
	for _, heads := range []string{"12", "34", "56", "89"} {
		for _, c := range []byte(heads) {
			f.pull(matrixRepo, matrixPull(int(c-'0'), headSHA(c)), matrixConfig)
		}
		f.poll(t)
		if heads != "89" {
			f.cancelActive(t)
		}
	}
	all, err := f.s.GitHubRuns(ctx, matrixRepoID)
	if err != nil || len(all) != 40 {
		t.Fatalf("runs %d: %v", len(all), err)
	}
	last := ""
	for _, run := range all {
		last = max(last, run.Key)
	}
	for i := range 100000 {
		sha := fmt.Sprintf("7%039x", i)
		input, err := f.p.admission(f.p.policies[matrixRepo], matrixPull(7, sha), nativeBuild, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		if input.Run.Key > last {
			return f, sha
		}
	}
	t.Fatal("no head whose build run sorts last")
	return nil, ""
}

// finishRerun runs the rerun job (claimed first: the oldest queued) to
// success and returns the build check of sha after at most four polls at
// the default interval, the first after a full list's repairs.
func (f *ownerFixture) finishRerun(t *testing.T, sha string, run store.GitHubRun) githubapi.Check {
	t.Helper()
	ctx := context.Background()
	job, err := f.s.Claim(ctx, "worker-epoch", f.options.Now(), 1, false)
	if err != nil || job.ID != run.JobID {
		t.Fatalf("claimed %s, want the rerun %s: %v", job.ID, run.JobID, err)
	}
	// The job runs for a while: it ends after the latest repair.
	f.advance(time.Minute)
	if err = f.s.Transition(ctx, job.ID, job.LeaseToken, model.Preparing, model.Finalizing, "test execution finished", f.options.Now()); err != nil {
		t.Fatal(err)
	}
	if err = f.s.Finish(ctx, job.ID, job.LeaseToken, model.Succeeded, json.RawMessage(`{}`), true, "test terminal", f.options.Now()); err != nil {
		t.Fatal(err)
	}
	f.advance(16 * time.Minute)
	var check githubapi.Check
	for range 4 {
		f.poll(t)
		if check = f.checksOf(sha)[matrixChecks[0]]; check.Status == "completed" {
			break
		}
		f.advance(45 * time.Second)
	}
	return check
}

// #159: periodic repairs of a busy repository's current runs (every full
// pull list) exceeded the publisher's ten checks a cycle, and their
// run_key order let the same repairs win every cycle. A head that first
// waited for queue space then never got a check: not while waiting, not
// for the attempt an owner rerun started, not when that attempt ended.
// Fresh work goes first, so each check is created and then updated to the
// attempt's terminal result.
func TestWaitingRunPublishesThroughRerunUnderRepairVolume(t *testing.T) {
	ctx := context.Background()
	f, sha := busyMatrix(t)
	f.pull(matrixRepo, matrixPull(7, sha), matrixConfig)
	for range 3 {
		// Each poll lists in full and repairs all forty-five current runs.
		f.advance(16 * time.Minute)
		if err := f.p.Poll(ctx); !errors.Is(err, store.ErrFull) {
			t.Fatalf("poll: %v", err)
		}
	}
	waiting, checks := f.runsByCheck(t, sha), f.checksOf(sha)
	for _, name := range matrixChecks {
		run, check := waiting[name], checks[name]
		if run.JobID != "" || run.CheckID == 0 || check.ID != run.CheckID || check.Output.Title != "Waiting for queue space" {
			t.Fatalf("%s: waiting run has no waiting check: run %+v check %+v", name, run, check)
		}
	}
	// Space frees and the owner reruns the build (POST /v1/admin/github/rerun).
	f.cancelActive(t)
	run, started, err := f.p.Rerun(ctx, matrixRepoID, matrixRepo, sha, nativeBuild, "", f.options.Now())
	if err != nil || !started || run.JobID == "" {
		t.Fatalf("rerun: %+v %v %v", run, started, err)
	}
	// Fifteen fresh publications (the ten cancelled jobs, the rerun and the
	// four runs admitted now) take two cycles of ten, ahead of the repairs.
	for range 2 {
		f.advance(16 * time.Minute)
		f.poll(t)
	}
	build := matrixChecks[0]
	check := f.checksOf(sha)[build]
	if check.ID != waiting[build].CheckID || check.ExternalID != run.JobID || check.Status != "queued" || check.Output.Title != "Mac evidence queued" {
		t.Fatalf("rerun attempt not published on its check: %+v", check)
	}
	check = f.finishRerun(t, sha, run)
	if check.ID != waiting[build].CheckID || check.ExternalID != run.JobID || check.Status != "completed" || check.Output.Title != "Mac evidence succeeded" {
		t.Fatalf("terminal attempt not published on its check: %+v", check)
	}
}

// herdrup #672's build run (#159): a run that never got a check (it waited
// for queue space, its publication never served) gets a job from an owner
// rerun. Under the same repair volume, the next polls create its check for
// that job and update it to the job's terminal result.
func TestRerunOfRunWithoutCheckCreatesCheck(t *testing.T) {
	ctx := context.Background()
	f, sha := busyMatrix(t)
	f.pull(matrixRepo, matrixPull(7, sha), matrixConfig)
	// Admitted without a publication pass: waiting, no check.
	input, err := f.p.admission(f.p.policies[matrixRepo], matrixPull(7, sha), nativeBuild, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.AdmitGitHub(ctx, input, f.options.Now()); !errors.Is(err, store.ErrFull) {
		t.Fatalf("admission: %v", err)
	}
	f.cancelActive(t)
	run, started, err := f.p.Rerun(ctx, matrixRepoID, matrixRepo, sha, nativeBuild, "", f.options.Now())
	if err != nil || !started || run.JobID == "" || run.CheckID != 0 {
		t.Fatalf("rerun: %+v %v %v", run, started, err)
	}
	for range 3 {
		// Each poll lists in full and repairs every current run.
		f.advance(16 * time.Minute)
		f.poll(t)
	}
	build := matrixChecks[0]
	check := f.checksOf(sha)[build]
	if check.ID == 0 || check.ExternalID != run.JobID || check.Status != "queued" || check.Output.Title != "Mac evidence queued" {
		t.Fatalf("rerun of a run without a check published none: %+v", check)
	}
	if stored := f.runsByCheck(t, sha)[build]; stored.CheckID != check.ID {
		t.Fatalf("check %d not recorded: %+v", check.ID, stored)
	}
	if final := f.finishRerun(t, sha, run); final.ID != check.ID || final.Status != "completed" || final.Output.Title != "Mac evidence succeeded" {
		t.Fatalf("terminal attempt not published on its check: %+v", final)
	}
}

// #168 review F1: a repository whose policy was removed is no longer polled,
// so its last current-run snapshot stays eligible. Healing its runs gave the
// publisher work it refuses (no configured policy) without recording a
// check, so the next poll healed them again: more than ten such runs took the
// heal budget and every publication slot each poll, and a configured run
// without a check never got one. The heal skips refused runs, so the
// configured run's check is created within two polls and no refused run is
// published.
func TestHealSkipsRunsOfRemovedPolicies(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	input, err := f.p.admission(f.p.policies[testRepo], f.remote.pull, testProfile, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.AdmitGitHub(ctx, input, f.options.Now()); err != nil {
		t.Fatal(err)
	}
	// Twelve runs of a removed repository, sorting before the configured run:
	// ten with jobs, two waiting for queue space.
	removed := make(map[string]bool)
	for i := 1; i <= 12; i++ {
		gone := input
		gone.Run.Key, gone.Run.RepositoryID, gone.Run.Repository = fmt.Sprintf("%064x", i), 777, "acme/removed"
		gone.Admission.Request.Repo, gone.Admission.Profile.Repo = gone.Run.Repository, gone.Run.Repository
		if gone.Admission.ProfileDigest, err = gone.Admission.Profile.SnapshotDigest(); err != nil {
			t.Fatal(err)
		}
		if _, err := f.s.AdmitGitHub(ctx, gone, f.options.Now()); err != nil && !errors.Is(err, store.ErrFull) {
			t.Fatal(err)
		}
		removed[gone.Run.Key] = true
	}
	if err = f.s.MaintainGitHub(ctx, 777, removed, f.options.Now()); err != nil {
		t.Fatal(err)
	}
	// Every run's publication was lost: no check, nothing pending.
	for {
		publication, err := f.s.NextGitHubPublication(ctx, f.options.Now())
		if errors.Is(err, store.ErrNotFound) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if err = f.s.FinishGitHubPublication(ctx, publication, 0, time.Time{}); err != nil {
			t.Fatal(err)
		}
	}
	// The pull list is not due in full, so no periodic repair runs.
	if err = f.s.SaveGitHubCursor(ctx, 123, store.GitHubCursor{FullAt: f.options.Now(), Pulls: []byte("[]")}); err != nil {
		t.Fatal(err)
	}
	var logged strings.Builder
	previous := log.Writer()
	log.SetOutput(&logged)
	defer log.SetOutput(previous)
	for range 2 {
		f.advance(time.Minute)
		f.poll(t)
	}
	if run := f.run(t); run.CheckID == 0 {
		t.Fatalf("configured run starved by removed-policy runs: %+v, log %q", run, logged.String())
	}
	if strings.Contains(logged.String(), "acme/removed") {
		t.Fatalf("removed-policy runs healed: %q", logged.String())
	}
}

// A run left with a terminal job, no check and no pending publication (as
// a lost or starved publication left herdrup's runs) is healed by the next
// poll without a full list or a rerun: its check reports the stored result.
func TestPollHealsRunWithoutCheck(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	input, err := f.p.admission(f.p.policies[testRepo], f.remote.pull, testProfile, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.AdmitGitHub(ctx, input, f.options.Now()); err != nil {
		t.Fatal(err)
	}
	f.finish(t, model.Succeeded, json.RawMessage(`{}`))
	for {
		publication, err := f.s.NextGitHubPublication(ctx, f.options.Now())
		if errors.Is(err, store.ErrNotFound) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if err = f.s.FinishGitHubPublication(ctx, publication, 0, time.Time{}); err != nil {
			t.Fatal(err)
		}
	}
	// The pull list is not due in full, so no periodic repair runs.
	if err = f.s.SaveGitHubCursor(ctx, 123, store.GitHubCursor{FullAt: f.options.Now(), Pulls: []byte("[]")}); err != nil {
		t.Fatal(err)
	}
	f.advance(time.Minute)
	var logged strings.Builder
	previous := log.Writer()
	log.SetOutput(&logged)
	defer log.SetOutput(previous)
	f.poll(t)
	run := f.run(t)
	if run.CheckID == 0 {
		t.Fatalf("run without a check not healed: %+v, log %q", run, logged.String())
	}
	check, packet := f.current(t)
	if check.Status != "completed" || check.ExternalID != run.JobID || packet.JobID != run.JobID || check.Output.Title != "Mac evidence succeeded" {
		t.Fatalf("healed check lacks the stored result: %+v %+v", check, packet)
	}
	if !strings.Contains(logged.String(), "GitHub publication healed: run="+run.Key) {
		t.Fatalf("heal not logged: %q", logged.String())
	}
	if _, err = f.s.NextGitHubPublication(ctx, f.options.Now().Add(time.Hour)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("healed run left publication work: %v", err)
	}
}

// publishOne never skips a check silently: each skip logs its run and why.
func TestPublicationSkipIsLogged(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	input, err := f.p.admission(f.p.policies[testRepo], githubapi.PullRequest{Number: 7, HeadSHA: testSHA}, testProfile, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	retired := input.Run
	retired.PolicyRevision = 99
	if err = f.s.BlockGitHub(ctx, retired, "retired policy", f.options.Now()); err != nil {
		t.Fatal(err)
	}
	var logged strings.Builder
	previous := log.Writer()
	log.SetOutput(&logged)
	defer log.SetOutput(previous)
	if err = f.p.publish(ctx); err != nil {
		t.Fatal(err)
	}
	want := "GitHub publication skipped: repository=" + testRepo + " head=" + testSHA + " check=mac-evidence/" + testProfile + " run=" + retired.Key + " job= check_id=0: policy revision 1 is not the run's 99\n"
	if !strings.HasSuffix(logged.String(), want) {
		t.Fatalf("skip not logged: %q", logged.String())
	}
}

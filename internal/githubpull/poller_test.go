package githubpull

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/githubapi"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/receipt"
	"github.com/jerryfane/macserve/internal/store"
	"github.com/jerryfane/macserve/internal/worker"
)

const testRepo = "example-org/example-app"
const testProfile = "example-build-v1"

var testSHA = strings.Repeat("a", 40)

type fakeGitHub struct {
	mu                         sync.Mutex
	server                     *httptest.Server
	now                        time.Time
	pull                       githubapi.PullRequest
	comments                   []githubapi.Comment
	checks                     map[int64]githubapi.Check
	created                    int
	lostCreate                 bool
	conditional, unconditional int
	commentSince               string
	force304                   bool
}

func (f *fakeGitHub) checkJSON(check githubapi.Check) any {
	return map[string]any{"id": check.ID, "name": check.Name, "head_sha": check.HeadSHA, "external_id": check.ExternalID, "status": check.Status, "conclusion": check.Conclusion, "html_url": fmt.Sprintf("https://github.com/%s/runs/%d", testRepo, check.ID), "app": map[string]any{"id": check.AppID}, "output": check.Output}
}
func (f *fakeGitHub) pullJSON() any {
	p := f.pull
	return map[string]any{"number": p.Number, "state": p.State, "draft": p.Draft, "head": map[string]any{"sha": p.HeadSHA, "repo": map[string]any{"id": p.HeadRepositoryID}}, "user": map[string]any{"id": p.AuthorID}, "base": map[string]any{"ref": p.BaseRef}, "updated_at": f.now.Format(time.RFC3339)}
}
func (f *fakeGitHub) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	encode := func(value any) {
		if err := json.NewEncoder(w).Encode(value); err != nil {
			panic(err)
		}
	}
	repoPath := "/repos/" + testRepo
	switch {
	case r.URL.Path == "/app/installations/22/access_tokens":
		encode(map[string]any{"token": "fake-installation-token", "expires_at": f.now.Add(time.Hour).Format(time.RFC3339), "repositories": []any{map[string]any{"id": int64(123), "full_name": testRepo}}})
	case r.URL.Path == repoPath:
		encode(map[string]any{"id": int64(123), "full_name": testRepo})
	case r.URL.Path == repoPath+"/pulls":
		if r.Header.Get("If-None-Match") != "" {
			f.conditional++
			if f.force304 || r.Header.Get("If-None-Match") == `"stable"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		} else {
			f.unconditional++
		}
		w.Header().Set("ETag", `"stable"`)
		if f.pull.State == "open" {
			encode([]any{f.pullJSON()})
		} else {
			encode([]any{})
		}
	case r.URL.Path == repoPath+"/pulls/7":
		encode(f.pullJSON())
	case r.URL.Path == repoPath+"/issues/comments":
		f.commentSince = r.URL.Query().Get("since")
		comments := make([]any, 0, len(f.comments))
		for _, c := range f.comments {
			row := map[string]any{"id": c.ID, "body": c.Body, "user": map[string]any{"id": c.AuthorID}, "issue_url": f.server.URL + repoPath + "/issues/" + strconv.Itoa(c.PullRequest), "created_at": c.CreatedAt.Format(time.RFC3339), "updated_at": c.UpdatedAt.Format(time.RFC3339)}
			if c.AppID != 0 {
				row["performed_via_github_app"] = map[string]any{"id": c.AppID}
			}
			comments = append(comments, row)
		}
		encode(comments)
	case strings.HasPrefix(r.URL.Path, repoPath+"/commits/") && strings.HasSuffix(r.URL.Path, "/check-runs"):
		sha := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, repoPath+"/commits/"), "/check-runs")
		checks := make([]any, 0)
		for _, c := range f.checks {
			if c.HeadSHA == sha {
				checks = append(checks, f.checkJSON(c))
			}
		}
		encode(map[string]any{"total_count": len(checks), "check_runs": checks})
	case r.URL.Path == repoPath+"/check-runs" && r.Method == http.MethodPost:
		var input githubapi.CheckInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			w.WriteHeader(400)
			return
		}
		f.created++
		id := int64(f.created + 100)
		check := githubapi.Check{ID: id, Name: input.Name, HeadSHA: input.HeadSHA, ExternalID: input.ExternalID, Status: input.Status, Conclusion: input.Conclusion, AppID: 11, Output: input.Output}
		f.checks[id] = check
		if f.lostCreate {
			f.lostCreate = false
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(201)
		encode(f.checkJSON(check))
	case strings.HasPrefix(r.URL.Path, repoPath+"/check-runs/"):
		id, err := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, repoPath+"/check-runs/"), 10, 64)
		check, ok := f.checks[id]
		if err != nil || !ok {
			w.WriteHeader(404)
			return
		}
		if r.Method == http.MethodPatch {
			var input githubapi.CheckInput
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				w.WriteHeader(400)
				return
			}
			check.Name = input.Name
			check.ExternalID = input.ExternalID
			check.Status = input.Status
			check.Conclusion = input.Conclusion
			check.Output = input.Output
			f.checks[id] = check
		}
		encode(f.checkJSON(check))
	default:
		w.WriteHeader(404)
	}
}

type fixture struct {
	p       *Poller
	s       *store.Store
	path    string
	remote  *fakeGitHub
	options Options
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	remote := &fakeGitHub{now: time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC), pull: githubapi.PullRequest{Number: 7, State: "open", HeadSHA: testSHA, HeadRepositoryID: 123, AuthorID: 42, BaseRef: "main"}, checks: make(map[int64]githubapi.Check)}
	remote.server = httptest.NewServer(http.HandlerFunc(remote.serve))
	t.Cleanup(remote.server.Close)
	now := func() time.Time { remote.mu.Lock(); defer remote.mu.Unlock(); return remote.now }
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	client, err := githubapi.NewApp(githubapi.AppOptions{AppID: 11, InstallationID: 22, PrivateKey: key, Repositories: map[string]int64{testRepo: 123}, HTTP: githubapi.HTTPOptions{BaseURL: remote.server.URL, Client: remote.server.Client(), Now: now}})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := profiles.New([]model.Profile{{ID: testProfile, Version: 1, Repo: testRepo, Kind: model.Build, Xcode: model.Xcode{Version: "26.0", Build: "17A100"}, DeveloperDir: "/Applications/ExampleToolchain.app/Contents/Developer", WorkDir: ".", Run: model.Command{Executable: "/usr/bin/true"}, DefaultTimeoutSeconds: 60, MaxTimeoutSeconds: 600, MemoryLimitMiB: 512}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "private", "queue.sqlite")
	s, err := store.Open(path, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	options := Options{Store: s, Profiles: registry, Client: client, Policies: []Policy{{RepositoryID: 123, Repository: testRepo, AuthorIDs: []int64{42}, BaseBranches: []string{"main"}, Profiles: []string{testProfile}, PolicyRevision: 1, ActionsBotID: 55, ActionsAppID: 66}}, VerifyReceipt: func(model.Job, json.RawMessage) error {
		return errors.New("no test receipt is cryptographically trusted")
	}, Now: now}
	p, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{p: p, s: s, path: path, remote: remote, options: options}
}
func (f *fixture) advance(d time.Duration) {
	f.remote.mu.Lock()
	f.remote.now = f.remote.now.Add(d)
	f.remote.mu.Unlock()
}
func (f *fixture) poll(t *testing.T) {
	t.Helper()
	if err := f.p.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
}
func (f *fixture) run(t *testing.T) store.GitHubRun {
	t.Helper()
	runs, err := f.s.GitHubRuns(context.Background(), 123)
	if err != nil || len(runs) != 1 {
		t.Fatalf("logical runs %+v err=%v", runs, err)
	}
	return runs[0]
}
func (f *fixture) current(t *testing.T) (githubapi.Check, Packet) {
	t.Helper()
	run := f.run(t)
	f.remote.mu.Lock()
	check, ok := f.remote.checks[run.CheckID]
	f.remote.mu.Unlock()
	if !ok {
		t.Fatalf("published check %d absent", run.CheckID)
	}
	var packet Packet
	if err := json.Unmarshal([]byte(check.Output.Text), &packet); err != nil {
		t.Fatal(err)
	}
	return check, packet
}
func (f *fixture) comment(id int64, mode string) githubapi.Comment {
	return githubapi.Comment{ID: id, Body: fmt.Sprintf("/mac-evidence sha=%s profile=%s request=actions:99:%d mode=%s", testSHA, testProfile, id, mode), AuthorID: 55, AppID: 66, PullRequest: 7, CreatedAt: f.options.Now(), UpdatedAt: f.options.Now()}
}
func (f *fixture) add(comments ...githubapi.Comment) {
	f.remote.mu.Lock()
	f.remote.comments = append(f.remote.comments, comments...)
	f.remote.mu.Unlock()
}
func (f *fixture) finish(t *testing.T, state model.State, result json.RawMessage) {
	t.Helper()
	ctx := context.Background()
	job, err := f.s.Claim(ctx, "worker-epoch", f.options.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err = f.s.Transition(ctx, job.ID, job.LeaseToken, model.Preparing, model.Finalizing, "test execution finished", f.options.Now()); err != nil {
		t.Fatal(err)
	}
	if err = f.s.Finish(ctx, job.ID, job.LeaseToken, state, result, true, "test terminal", f.options.Now()); err != nil {
		t.Fatal(err)
	}
}
func (f *fixture) reopen(t *testing.T) {
	t.Helper()
	if err := f.s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(f.path, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	f.s = s
	f.options.Store = s
	f.p, err = New(f.options)
	if err != nil {
		t.Fatal(err)
	}
}

func TestHTTPAutomaticEnrollmentStrictCommentsAndReopen(t *testing.T) {
	f := newFixture(t)
	f.poll(t)
	run := f.run(t)
	check, packet := f.current(t)
	if check.Name != "mac-evidence/"+testProfile || check.HeadSHA != testSHA || check.Status != "queued" || check.AppID != 11 || packet.JobID != run.JobID || packet.AttemptID != run.AttemptID {
		t.Fatalf("automatic enrollment not exact/App-bound: %+v %+v", check, packet)
	}
	valid := f.comment(1, "ensure")
	spoof := f.comment(2, "ensure")
	spoof.AuthorID = 77
	wrongApp := f.comment(3, "ensure")
	wrongApp.AppID = 88
	edited := f.comment(4, "ensure")
	edited.UpdatedAt = edited.UpdatedAt.Add(time.Second)
	multiline := f.comment(5, "ensure")
	multiline.Body += "\n"
	stale := f.comment(6, "ensure")
	stale.Body = strings.Replace(stale.Body, testSHA, strings.Repeat("b", 40), 1)
	f.add(valid, spoof, wrongApp, edited, multiline, stale)
	f.poll(t)
	_, packet = f.current(t)
	digest := sha256.Sum256([]byte(valid.Body))
	if len(packet.Requests) != 1 || packet.Requests[0].CommentID != 1 || packet.Requests[0].BodySHA256 != hex.EncodeToString(digest[:]) || packet.JobID != run.JobID {
		t.Fatalf("machine admission widened authority or lost correlation: %+v", packet)
	}
	f.reopen(t)
	f.advance(time.Minute)
	f.poll(t)
	_, packet = f.current(t)
	if packet.JobID != run.JobID || len(packet.Requests) != 1 {
		t.Fatalf("restart duplicated ensure: %+v", packet)
	}
	f.remote.mu.Lock()
	since := f.remote.commentSince
	f.remote.mu.Unlock()
	if want := valid.CreatedAt.Add(-2 * time.Minute).Format(time.RFC3339); since != want {
		t.Fatalf("restart lost durable overlap cursor: since=%s want=%s", since, want)
	}
	job, err := f.s.Get(context.Background(), run.JobID)
	if err != nil {
		t.Fatal(err)
	}
	approval, err := f.p.Approval(context.Background(), job)
	if err != nil || approval.Intake != "github_pull" || approval.AttemptID != run.AttemptID {
		t.Fatalf("wrong durable receipt approval: %+v %v", approval, err)
	}
}

func TestHTTPUnknownCreateResponseReconcilesWithoutExecutionRetry(t *testing.T) {
	f := newFixture(t)
	f.remote.lostCreate = true
	if err := f.p.Poll(context.Background()); err == nil {
		t.Fatal("lost create response unexpectedly succeeded")
	}
	run := f.run(t)
	if run.CheckID != 0 {
		t.Fatal("unknown response recorded a speculative check ID")
	}
	f.reopen(t)
	f.advance(20 * time.Second)
	f.poll(t)
	check, packet := f.current(t)
	if f.remote.created != 1 || check.ID != 101 || packet.JobID != run.JobID {
		t.Fatalf("external_id reconciliation duplicated check/execution: creates=%d check=%+v packet=%+v", f.remote.created, check, packet)
	}
}

func TestHTTPFailureEnsureAndExplicitBoundedReruns(t *testing.T) {
	f := newFixture(t)
	f.poll(t)
	first := f.run(t)
	f.finish(t, model.Failed, json.RawMessage(`{}`))
	f.poll(t)
	f.add(f.comment(1, "ensure"))
	f.poll(t)
	check, packet := f.current(t)
	if check.Conclusion != "failure" || packet.JobID != first.JobID || len(packet.Requests) != 1 {
		t.Fatalf("ensure retried failure: %+v %+v", check, packet)
	}
	for i := int64(2); i <= 3; i++ {
		f.add(f.comment(i, "rerun"))
		f.poll(t)
		check, packet = f.current(t)
		if check.ID != first.CheckID || check.Status != "queued" || check.Conclusion != "" || packet.JobID == first.JobID || len(packet.Requests) != 1 || packet.Requests[0].CommentID != i {
			t.Fatalf("rerun did not replace current check/correlation: %+v %+v", check, packet)
		}
		f.finish(t, model.Failed, json.RawMessage(`{}`))
		f.poll(t)
	}
	last := f.run(t)
	f.add(f.comment(4, "rerun"))
	f.poll(t)
	if run := f.run(t); run.JobID != last.JobID {
		t.Fatal("third hourly rerun executed")
	}
}

func TestHTTPCurrentHeadRevalidationAndPeriodicUnconditionalEnrollment(t *testing.T) {
	f := newFixture(t)
	f.poll(t)
	old := f.run(t)
	job, err := f.s.Get(context.Background(), old.JobID)
	if err != nil {
		t.Fatal(err)
	}
	f.remote.mu.Lock()
	f.remote.pull.HeadSHA = strings.Repeat("b", 40)
	f.remote.force304 = true
	f.remote.mu.Unlock()
	if err = f.p.BeforeDispatch(context.Background(), job); !errors.Is(err, ErrIneligible) {
		t.Fatalf("superseded head dispatched: %v", err)
	}
	f.poll(t)
	cancelled, err := f.s.Get(context.Background(), old.JobID)
	if err != nil || cancelled.State != model.Cancelled {
		t.Fatalf("superseded queued job survived: %+v %v", cancelled, err)
	}
	f.advance(16 * time.Minute)
	f.poll(t)
	runs, err := f.s.GitHubRuns(context.Background(), 123)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, run := range runs {
		if run.SHA == strings.Repeat("b", 40) && run.JobID != "" {
			found = true
		}
	}
	if !found {
		t.Fatalf("unchanged ETag prevented periodic current-head enrollment: %+v", runs)
	}
	if f.remote.unconditional < 2 {
		t.Fatal("periodic reconciliation remained conditional")
	}
}

func TestHTTPForkAndUnlistedAuthorNeverEnqueue(t *testing.T) {
	for _, scenario := range []string{"fork", "author", "base"} {
		t.Run(scenario, func(t *testing.T) {
			f := newFixture(t)
			switch scenario {
			case "fork":
				f.remote.pull.HeadRepositoryID = 999
			case "author":
				f.remote.pull.AuthorID = 999
			case "base":
				f.remote.pull.BaseRef = "unapproved"
			}
			f.add(f.comment(1, "ensure"))
			f.poll(t)
			run := f.run(t)
			check, packet := f.current(t)
			if run.JobID != "" || check.Conclusion != "action_required" || packet.JobID != "" || len(packet.Requests) != 0 {
				t.Fatalf("ineligible head admitted or cleared gate: %+v %+v %+v", run, check, packet)
			}
			if _, err := f.s.Claim(context.Background(), "epoch", f.options.Now()); !errors.Is(err, store.ErrNoJob) {
				t.Fatalf("ineligible code became claimable: %v", err)
			}
		})
	}
}

func TestHTTPSuccessWithoutVerifiedSignedEvidenceCannotClearGate(t *testing.T) {
	f := newFixture(t)
	f.poll(t)
	f.finish(t, model.Succeeded, json.RawMessage(`{"receipt":{"payload":{"job_id":"forged","attempt_id":"forged"},"signature":{"algorithm":"Ed25519","encoding":"base64","key_id":"forged","value":"forged"}}}`))
	f.poll(t)
	check, _ := f.current(t)
	if check.Conclusion != "action_required" {
		t.Fatalf("unverified evidence cleared gate: %+v", check)
	}
}

func TestHTTPPeriodicPublicationRepairDoesNotRerunExecution(t *testing.T) {
	f := newFixture(t)
	f.poll(t)
	run := f.run(t)
	f.finish(t, model.Failed, json.RawMessage(`{}`))
	f.poll(t)
	f.remote.mu.Lock()
	delete(f.remote.checks, run.CheckID)
	f.remote.mu.Unlock()
	f.advance(16 * time.Minute)
	f.poll(t)
	check, packet := f.current(t)
	if check.ID == run.CheckID || check.Conclusion != "failure" || packet.JobID != run.JobID {
		t.Fatalf("remote repair reran execution or lost terminal result: %+v %+v", check, packet)
	}
}

func TestParseRequestRejectsAmbiguousAndUnboundedCommands(t *testing.T) {
	body := fmt.Sprintf("/mac-evidence sha=%s profile=%s request=actions:123:1 mode=ensure", testSHA, testProfile)
	for _, bad := range []string{body + "\n", " " + body, strings.Replace(body, "actions:123:1", "actions:0123:1", 1), strings.Replace(body, "actions:123:1", "actions:9223372036854775808:1", 1), strings.Replace(body, "mode=ensure", "mode=ensure extra=yes", 1), strings.Replace(body, testSHA, strings.ToUpper(testSHA), 1)} {
		if _, err := ParseRequest(bad); err == nil {
			t.Fatalf("accepted ambiguous request %q", bad)
		}
	}
}

func TestHTTPSignedSuccessPreservesCanonicalReceiptAndAttempt(t *testing.T) {
	f := newFixture(t)
	f.poll(t)
	ctx := context.Background()
	job, err := f.s.Claim(ctx, "worker-epoch", f.options.Now())
	if err != nil {
		t.Fatal(err)
	}
	started := *job.StartedAt
	finished := started.Add(10 * time.Second)
	zero := 0
	result := worker.Result{State: model.Succeeded, ExitCode: &zero, CleanupOK: true, StartedAt: started, FinishedAt: finished, Source: worker.Source{Commit: job.Request.SHA, Tree: strings.Repeat("b", 40), SHA256: strings.Repeat("c", 64), SizeBytes: 1024}, Observation: worker.Observation{Xcode: job.Request.Xcode, SDKVersion: "26.0", SDKBuild: "23A100", SwiftVersion: "Swift 6.2", OSVersion: "26.0", OSBuild: "25A100", Architecture: "arm64", GeneratedDigests: map[string]string{}, LockfileDigests: map[string]string{}}, Commands: []worker.ExecutedCommand{{Executable: job.Profile.Run.Executable, StartedAt: started, FinishedAt: finished.Add(-time.Second), ExitCode: 0}}}
	for _, name := range []string{"stdout", "stderr"} {
		result.Artifacts = append(result.Artifacts, evidence.Artifact{ID: name, Name: "evidence/" + name + ".log", MediaType: "text/plain", SizeBytes: 10, SHA256: strings.Repeat("d", 64), ExpiresAt: finished.Add(time.Hour)})
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	signer, err := receipt.NewSigner(receipt.Options{Root: filepath.Join(t.TempDir(), "receipts"), KeyID: "test-key", PrivateKey: key, Service: receipt.ServiceIdentity{ID: "service<>&", HostID: "host", Version: "1", BinarySHA256: strings.Repeat("e", 64)}, Repository: func(context.Context, model.Job) (receipt.Repository, error) {
		return receipt.Repository{ID: 123, Name: testRepo}, nil
	}, Approval: f.p.Approval, Now: func() time.Time { return finished.Add(time.Second) }})
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()
	raw, err := signer.Seal(ctx, job, result)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]ed25519.PublicKey{"test-key": key.Public().(ed25519.PublicKey)}
	f.p.options.VerifyReceipt = func(j model.Job, raw json.RawMessage) error {
		payload, err := receipt.Verify(raw, keys)
		if err != nil {
			return err
		}
		if payload.JobID != j.ID {
			return errors.New("wrong receipt job")
		}
		return receipt.ValidateSuccess(payload, receipt.Expected{RepositoryID: 123, Repo: j.Request.Repo, SHA: j.Request.SHA, Profile: j.Request.Profile, ProfileDigest: j.ProfileDigest, Kind: j.Request.Kind, Xcode: j.Request.Xcode, Simulator: j.Request.Simulator, RequiredTests: j.Profile.RequiredTests})
	}
	if err = f.s.Transition(ctx, job.ID, job.LeaseToken, model.Preparing, model.Finalizing, "collecting", finished); err != nil {
		t.Fatal(err)
	}
	completion := append([]byte(`{"receipt":`), raw...)
	completion = append(completion, '}')
	if err = f.s.Finish(ctx, job.ID, job.LeaseToken, model.Succeeded, completion, true, "finished", finished); err != nil {
		t.Fatal(err)
	}
	f.advance(11 * time.Second)
	f.add(f.comment(1, "ensure"))
	f.poll(t)
	check, packet := f.current(t)
	if check.Conclusion != "success" || packet.JobID != job.ID || !bytes.Equal(packet.Receipt, raw) {
		t.Fatalf("genuine canonical receipt did not survive publication: conclusion=%s job=%s receiptEqual=%v", check.Conclusion, packet.JobID, bytes.Equal(packet.Receipt, raw))
	}
	payload, err := receipt.Verify(packet.Receipt, keys)
	if err != nil || payload.AttemptID != packet.AttemptID || payload.JobID != packet.JobID {
		t.Fatalf("published success has wrong signed attempt: %+v %v", payload, err)
	}
	digest, err := receipt.Digest(raw)
	if err != nil || packet.ReceiptDigest != digest {
		t.Fatalf("publication receipt digest mismatch: %s %v", packet.ReceiptDigest, err)
	}
}

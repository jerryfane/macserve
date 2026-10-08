package api

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/controller"
	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/store"
	"github.com/jerryfane/macserve/internal/worker"
)

const testToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

var testTime = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func principal(token, id, repo string, scopes ...string) store.Principal {
	sum := sha256.Sum256([]byte(token))
	return store.Principal{ID: id, TokenSHA256: hex.EncodeToString(sum[:]), Repositories: []string{repo}, Scopes: scopes}
}

type fixture struct {
	db           *store.Store
	path         string
	options      Options
	handler      http.Handler
	request      model.Request
	owner        store.Principal
	artifactPath string
}

func setup(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{path: filepath.Join(t.TempDir(), "db", "queue.sqlite")}
	var err error
	f.db, err = store.Open(f.path, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.db.Close() })
	profile := model.Profile{ID: "build-v1", Version: 1, Repo: "example-org/example-app", Kind: model.Build, Xcode: model.Xcode{Version: "27.0", Build: "27A100"}, DeveloperDir: "/Applications/Example.app/Contents/Developer", WorkDir: ".", Run: model.Command{Executable: "/usr/bin/true"}, GeneratedFiles: []model.GeneratedFile{{Path: "config", Content: "recipe-private-value"}}, DefaultTimeoutSeconds: 60, MaxTimeoutSeconds: 600}
	registry, err := profiles.New([]model.Profile{profile})
	if err != nil {
		t.Fatal(err)
	}
	f.request = model.Request{Repo: profile.Repo, SHA: strings.Repeat("a", 40), Kind: profile.Kind, Profile: profile.ID, Xcode: profile.Xcode}
	f.owner = principal(testToken, "coordinator", profile.Repo, "jobs:submit", "jobs:read", "jobs:cancel", "service:admin")
	if err := f.db.ReplacePrincipals(context.Background(), []store.Principal{f.owner}); err != nil {
		t.Fatal(err)
	}
	f.artifactPath = filepath.Join(t.TempDir(), "sealed.bin")
	if err := os.WriteFile(f.artifactPath, []byte("0123456789"), 0600); err != nil {
		t.Fatal(err)
	}
	f.options = Options{Store: f.db, Profiles: registry, Now: func() time.Time { return testTime }, Status: func(ctx context.Context) (controller.Status, error) {
		s, err := f.db.ServiceState(ctx)
		return controller.Status{Service: s, WorkerReady: true, Quiescent: true, Gate: controller.GateState{Ready: true, Blockers: []string{}}}, err
	}, Artifact: func(ctx context.Context, job, id string) (*os.File, evidence.Artifact, error) {
		if id != "a_one" {
			return nil, evidence.Artifact{}, store.ErrNotFound
		}
		file, err := os.Open(f.artifactPath)
		return file, evidence.Artifact{ID: id, Name: "output.bin", MediaType: "application/octet-stream", SizeBytes: 10, SHA256: strings.Repeat("b", 64), ExpiresAt: testTime.Add(time.Hour)}, err
	}, Receipt: func(context.Context, string) (json.RawMessage, error) { return nil, controller.ErrNotReady }}
	f.handler, err = New(f.options)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func perform(h http.Handler, method, path, token, key, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if key != "" {
		r.Header.Set("Idempotency-Key", key)
	}
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func (f *fixture) submit(t *testing.T, key string) model.Job {
	t.Helper()
	data, _ := json.Marshal(f.request)
	w := perform(f.handler, "POST", "/v1/jobs", testToken, key, string(data))
	if w.Code != 202 {
		t.Fatalf("submit %d: %s", w.Code, w.Body.String())
	}
	job, err := f.db.Lookup(context.Background(), f.owner.ID, key)
	if err != nil {
		t.Fatal(err)
	}
	return job
}
func TestCredentialReplacementAtomicAndDurable(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	for _, bad := range [][]store.Principal{{f.owner, f.owner}, {f.owner, principal(testToken, "other", "example-org/example-app", "jobs:read")}, {principal(strings.Repeat("z", 64), "bad", "example-org/example-app", "unknown")}} {
		if err := f.db.ReplacePrincipals(ctx, bad); !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("invalid replacement: %v", err)
		}
		if _, err := f.db.Authenticate(ctx, testToken); err != nil {
			t.Fatalf("replacement changed existing auth: %v", err)
		}
	}
	revoked := f.owner
	revoked.Revoked = true
	if err := f.db.ReplacePrincipals(ctx, []store.Principal{revoked}); err != nil {
		t.Fatal(err)
	}
	if err := f.db.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	f.db, err = store.Open(f.path, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Authenticate(ctx, testToken); !errors.Is(err, store.ErrUnauthenticated) {
		t.Fatalf("revocation lost: %v", err)
	}
}
func TestStrictRequestsAndSnapshotReplay(t *testing.T) {
	f := setup(t)
	body, _ := json.Marshal(f.request)
	for _, bad := range []string{`null`, `{} {}`, `{"repo":"a/b","repo":"c/d"}`, strings.TrimSuffix(string(body), "}") + `,"command":"/bin/sh"}`, `{"context":{"gate_ref":"` + strings.Repeat("x", 64<<10) + `"}}`} {
		w := perform(f.handler, "POST", "/v1/jobs", testToken, "bad", bad)
		if w.Code != 400 {
			t.Fatalf("invalid JSON status %d", w.Code)
		}
	}
	job := f.submit(t, "stable")
	registry, err := profiles.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	f.options.Profiles = registry
	h, err := New(f.options)
	if err != nil {
		t.Fatal(err)
	}
	w := perform(h, "POST", "/v1/jobs", testToken, "stable", string(body))
	if w.Code != 200 || !strings.Contains(w.Body.String(), job.ID) {
		t.Fatalf("snapshot replay: %d %s", w.Code, w.Body.String())
	}
	changed := f.request
	changed.SHA = strings.Repeat("b", 40)
	data, _ := json.Marshal(changed)
	w = perform(h, "POST", "/v1/jobs", testToken, "stable", string(data))
	if w.Code != 409 {
		t.Fatalf("conflicting replay: %d", w.Code)
	}
	for _, path := range []string{"/v1/capabilities", "/v1/jobs", "/v1/jobs/" + job.ID} {
		w = perform(h, "GET", path, testToken, "", "")
		for _, secret := range []string{"recipe-private-value", "Developer", "generated_files", "lease_token", "token_sha256"} {
			if strings.Contains(w.Body.String(), secret) {
				t.Fatalf("%s leaked %s", path, secret)
			}
		}
	}
}
func TestAuthorizationEveryJobSurface(t *testing.T) {
	f := setup(t)
	job := f.submit(t, "first")
	otherToken := strings.Repeat("z", 64)
	other := principal(otherToken, "other", "example-org/other-app", "jobs:read", "jobs:cancel")
	if err := f.db.ReplacePrincipals(context.Background(), []store.Principal{f.owner, other}); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", "/logs", "/logs/stream", "/results", "/results/junit", "/artifacts", "/artifacts/a_one", "/receipt", "/cancel"} {
		method, body := "GET", ""
		if suffix == "/cancel" {
			method, body = "POST", `{"reason":"stop"}`
		}
		w := perform(f.handler, method, "/v1/jobs/"+job.ID+suffix, otherToken, "", body)
		if w.Code != 404 {
			t.Fatalf("%s: %d", suffix, w.Code)
		}
	}
	w := perform(f.handler, "GET", "/v1/jobs", otherToken, "", "")
	if w.Code != 200 || strings.Contains(w.Body.String(), job.ID) {
		t.Fatalf("list authorization: %s", w.Body.String())
	}
	w = perform(f.handler, "GET", "/v1/admin/state", otherToken, "", "")
	if w.Code != 403 {
		t.Fatalf("admin scope %d", w.Code)
	}
	w = perform(f.handler, "GET", "/v1/jobs?access_token="+testToken, "", "", "")
	if w.Code != 401 || w.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("URL credential accepted: %d", w.Code)
	}
}
func TestLogsPagingTerminalAndStreamResume(t *testing.T) {
	f := setup(t)
	job := f.submit(t, "logs")
	ctx := context.Background()
	for _, text := range []string{"first\n", "\x1b[31msecond\x1b[0m\n"} {
		if _, err := f.db.AppendLog(ctx, job.ID, "stdout", text, testTime); err != nil {
			t.Fatal(err)
		}
	}
	w := perform(f.handler, "GET", "/v1/jobs/"+job.ID+"/logs?limit_bytes=6", testToken, "", "")
	var page struct {
		Records []model.LogRecord `json:"records"`
		Next    string            `json:"next_cursor"`
		EOF     bool              `json:"eof"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || len(page.Records) != 1 || page.Records[0].Seq != 1 || page.EOF {
		t.Fatalf("page: %s", w.Body.String())
	}
	if _, err := f.db.Cancel(ctx, job.ID, "stop", testTime); err != nil {
		t.Fatal(err)
	}
	w = perform(f.handler, "GET", "/v1/jobs/"+job.ID+"/logs?cursor="+page.Next, testToken, "", "")
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if !page.EOF || len(page.Records) != 1 || page.Records[0].Text != "second\n" {
		t.Fatalf("terminal page: %s", w.Body.String())
	}
	server := httptest.NewServer(f.handler)
	defer server.Close()
	req, _ := http.NewRequest("GET", server.URL+"/v1/jobs/"+job.ID+"/logs/stream", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Last-Event-ID", "1")
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if response.StatusCode != 200 || strings.Contains(text, "id: 1\n") || !strings.Contains(text, "id: 2\n") || !strings.Contains(text, "event: terminal") {
		t.Fatalf("SSE: %d %s", response.StatusCode, text)
	}
}
func TestStreamRevocationClosesConnection(t *testing.T) {
	f := setup(t)
	job := f.submit(t, "stream")
	server := httptest.NewServer(f.handler)
	defer server.Close()
	req, _ := http.NewRequest("GET", server.URL+"/v1/jobs/"+job.ID+"/logs/stream", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	reader := bufio.NewReader(response.Body)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	f.owner.Revoked = true
	if err := f.db.ReplacePrincipals(context.Background(), []store.Principal{f.owner}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(reader); err != nil {
		t.Fatalf("stream did not end after revocation: %v", err)
	}
}
func TestResultsRangesReceiptAndControl(t *testing.T) {
	f := setup(t)
	job := f.submit(t, "result")
	ctx := context.Background()
	for _, suffix := range []string{"results", "receipt"} {
		w := perform(f.handler, "GET", "/v1/jobs/"+job.ID+"/"+suffix, testToken, "", "")
		if w.Code != 409 {
			t.Fatalf("early %s: %d", suffix, w.Code)
		}
	}
	claimed, err := f.db.Claim(ctx, "epoch", testTime)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.db.Transition(ctx, job.ID, claimed.LeaseToken, model.Preparing, model.Finalizing, "done", testTime); err != nil {
		t.Fatal(err)
	}
	summary := &evidence.Summary{SchemaVersion: 1, ParserVersion: "test", ParseStatus: "complete", Tests: 2, Failed: 1, Skipped: 1, Cases: []evidence.TestCase{{ID: "suite/fail", Suite: "suite", Name: "fail", Outcome: "failed", Failures: []string{"expected <value>"}, Attempt: 1}, {ID: "suite/skip", Suite: "suite", Name: "skip", Outcome: "skipped", Attempt: 1}}}
	result, _ := json.Marshal(controller.Completion{Result: worker.Result{State: model.Failed, CleanupOK: true, Summary: summary, Artifacts: []evidence.Artifact{{ID: "a_one", Name: "output.bin", SizeBytes: 10}}}})
	if err := f.db.Finish(ctx, job.ID, claimed.LeaseToken, model.Failed, result, true, "failed", testTime); err != nil {
		t.Fatal(err)
	}
	w := perform(f.handler, "GET", "/v1/jobs/"+job.ID+"/results/junit", testToken, "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "&lt;value&gt;") || !strings.Contains(w.Body.String(), "<skipped") {
		t.Fatalf("JUnit: %d %s", w.Code, w.Body.String())
	}
	req := httptest.NewRequest("GET", "/v1/jobs/"+job.ID+"/artifacts/a_one", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Range", "bytes=2-5")
	w = httptest.NewRecorder()
	f.handler.ServeHTTP(w, req)
	if w.Code != 206 || w.Body.String() != "2345" || w.Header().Get("ETag") == "" {
		t.Fatalf("range %d %s", w.Code, w.Body.String())
	}
	req.Header.Set("Range", "bytes=100-200")
	w = httptest.NewRecorder()
	f.handler.ServeHTTP(w, req)
	if w.Code != 416 || !strings.Contains(w.Body.String(), `"code":"invalid_range"`) || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("range error %d %s", w.Code, w.Body.String())
	}
	w = perform(f.handler, "GET", "/v1/jobs/"+job.ID+"/results", testToken, "", "")
	var normalized evidence.Summary
	if err := json.Unmarshal(w.Body.Bytes(), &normalized); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || normalized.Failed != 1 || normalized.Skipped != 1 || normalized.Cases[0].Failures[0] != "expected <value>" {
		t.Fatalf("normalized result: %s", w.Body.String())
	}
	expiredOptions := f.options
	expiredOptions.Now = func() time.Time { return testTime.Add(2 * time.Hour) }
	expiredHandler, err := New(expiredOptions)
	if err != nil {
		t.Fatal(err)
	}
	w = perform(expiredHandler, "GET", "/v1/jobs/"+job.ID+"/artifacts/a_one", testToken, "", "")
	if w.Code != 410 {
		t.Fatalf("expired bytes %d", w.Code)
	}
	w = perform(expiredHandler, "GET", "/v1/jobs/"+job.ID+"/artifacts", testToken, "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"id":"a_one"`) {
		t.Fatalf("expired metadata %d %s", w.Code, w.Body.String())
	}
	w = perform(f.handler, "PUT", "/v1/admin/pause", testToken, "", `{"reason":"benchmark","mode":"drain"}`)
	if w.Code != 200 {
		t.Fatalf("pause %d", w.Code)
	}
	state, err := f.db.ServiceState(ctx)
	if err != nil || !state.Paused {
		t.Fatalf("pause state: %+v %v", state, err)
	}
	w = perform(f.handler, "DELETE", "/v1/admin/pause", testToken, "", "")
	if w.Code != 200 {
		t.Fatalf("resume %d", w.Code)
	}
	state, err = f.db.ServiceState(ctx)
	if err != nil || state.Paused {
		t.Fatalf("resume state: %+v %v", state, err)
	}
	w = perform(f.handler, "POST", "/v1/jobs/"+job.ID+"/cancel", testToken, "", `{"reason":"late"}`)
	if w.Code != 200 {
		t.Fatalf("terminal cancel %d", w.Code)
	}
	after, err := f.db.Get(ctx, job.ID)
	if err != nil || string(after.Result) != string(result) || after.State != model.Failed {
		t.Fatalf("terminal evidence changed: %+v %v", after, err)
	}
}

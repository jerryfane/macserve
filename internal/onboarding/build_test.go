package onboarding

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
)

const (
	testToken = "msv_SECRET_TOKEN_value"
	testSHA   = "0123456789abcdef0123456789abcdef01234567"
)

// fakeAPI is the controller API as `macserve build` uses it.
type fakeAPI struct {
	t        *testing.T
	mu       sync.Mutex
	caps     string
	states   []model.State // successive GET /v1/jobs/ID states
	polls    int
	submits  []*http.Request
	bodies   []model.Request
	receipt  []byte
	logs     []string
	logPolls int
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+testToken {
		w.WriteHeader(401)
		return
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/v1/capabilities":
		io.WriteString(w, f.caps)
	case r.Method == "POST" && r.URL.Path == "/v1/jobs":
		var req model.Request
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			f.t.Errorf("submit body: %v", err)
		}
		f.submits = append(f.submits, r)
		f.bodies = append(f.bodies, req)
		w.WriteHeader(202)
		io.WriteString(w, `{"id":"job1","state":"queued"}`)
	case r.Method == "GET" && r.URL.Path == "/v1/jobs/job1":
		i := min(f.polls, len(f.states)-1)
		f.polls++
		exit := ""
		if f.states[i] == model.Failed {
			exit = `,"exit_code":65`
		}
		io.WriteString(w, `{"id":"job1","state":"`+string(f.states[i])+`","repo":"jdoe/app","sha":"`+testSHA+`"`+exit+`}`)
	case r.Method == "GET" && r.URL.Path == "/v1/jobs/job1/logs":
		f.logPolls++
		terminal := f.polls > 0 && f.states[min(f.polls-1, len(f.states)-1)].Terminal()
		var recs []model.LogRecord
		if c := r.URL.Query().Get("cursor"); c == "" && len(f.logs) > 0 {
			for i, l := range f.logs {
				recs = append(recs, model.LogRecord{Seq: int64(i + 1), Stream: "stdout", Text: l})
			}
			json.NewEncoder(w).Encode(map[string]any{"records": recs, "next_cursor": "c1", "eof": false})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"records": []model.LogRecord{}, "next_cursor": "c1", "eof": terminal})
	case r.Method == "GET" && r.URL.Path == "/v1/jobs/job1/receipt":
		w.Write(f.receipt)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"error":{"code":"not_found","message":"x"}}`)
	}
}

const templateCaps = `{"profiles":[],"templates":[{"id":"org-ios-sim-build-v1","owners":["jdoe"],"kind":"build","xcode":{"version":"16.2","build":"16C5032a"}}],"blocked_by":[]}`

func newTestBuild(t *testing.T, f *fakeAPI) (*Build, *bytes.Buffer) {
	t.Helper()
	f.t = t
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	var out bytes.Buffer
	return &Build{
		Endpoint: srv.URL, HTTP: srv.Client(), Out: &out,
		Token:  func(context.Context) (string, error) { return testToken, nil },
		Sleep:  func(ctx context.Context, _ time.Duration) error { return ctx.Err() },
		NewKey: func() (string, error) { return "key-1", nil },
	}, &out
}

func TestSubmitRequestShape(t *testing.T) {
	f := &fakeAPI{caps: templateCaps}
	b, out := newTestBuild(t, f)
	id, err := b.Submit(context.Background(), BuildRequest{Repo: "jdoe/app", SHA: testSHA, RepoConfig: []byte(`{"version":1,"work_dir":".","project":"App.xcodeproj","scheme":"App"}`)})
	if err != nil || id != "job1" {
		t.Fatalf("submit %q %v", id, err)
	}
	want := model.Request{Repo: "jdoe/app", SHA: testSHA, Kind: "build", Profile: "org-ios-sim-build-v1", Xcode: model.Xcode{Version: "16.2", Build: "16C5032a"}}
	if len(f.bodies) != 1 || f.bodies[0] != want {
		t.Errorf("bodies %+v", f.bodies)
	}
	if keys := f.submits[0].Header.Values("Idempotency-Key"); len(keys) != 1 || keys[0] != "key-1" {
		t.Errorf("Idempotency-Key %q", keys)
	}
	if f.submits[0].Header.Get("Content-Type") != "application/json" {
		t.Errorf("content type %q", f.submits[0].Header.Get("Content-Type"))
	}
	if strings.Contains(out.String(), testToken) {
		t.Error("token printed")
	}
}

func TestSubmitChoosesProfile(t *testing.T) {
	caps := `{"profiles":[{"id":"app-build","repo":"jdoe/app","kind":"build","xcode":{"version":"16.2","build":"16C5032a"}}],"templates":[{"id":"org","owners":["jdoe"],"kind":"build","xcode":{"version":"16.2","build":"16C5032a"}}]}`
	f := &fakeAPI{caps: caps}
	b, _ := newTestBuild(t, f)
	if _, err := b.Submit(context.Background(), BuildRequest{Repo: "jdoe/app", SHA: testSHA}); err == nil || !strings.Contains(err.Error(), "--profile") {
		t.Errorf("ambiguous: %v", err)
	}
	if _, err := b.Submit(context.Background(), BuildRequest{Repo: "jdoe/app", SHA: testSHA, Profile: "app-build"}); err != nil {
		t.Fatal(err)
	}
	if f.bodies[0].Profile != "app-build" {
		t.Errorf("profile %q", f.bodies[0].Profile)
	}
	if _, err := b.Submit(context.Background(), BuildRequest{Repo: "other/app", SHA: testSHA}); err == nil {
		t.Error("unadmitted repo submitted")
	}
}

func TestSubmitRejectsBadInput(t *testing.T) {
	f := &fakeAPI{caps: templateCaps}
	b, _ := newTestBuild(t, f)
	for _, r := range []BuildRequest{
		{Repo: "jdoe", SHA: testSHA},
		{Repo: "jdoe/app", SHA: "HEAD"},
		{Repo: "jdoe/app", SHA: testSHA, RepoConfig: []byte(`{"version":1,"scheme":"App","run":"rm -rf /"}`)},
	} {
		if _, err := b.Submit(context.Background(), r); err == nil {
			t.Errorf("accepted %+v", r)
		}
	}
	if len(f.submits) != 0 {
		t.Error("invalid input reached the API")
	}
}

// TestTokenNeverPrinted: API errors and keychain errors carry no token.
func TestTokenNeverPrinted(t *testing.T) {
	f := &fakeAPI{caps: templateCaps}
	b, out := newTestBuild(t, f)
	b.Token = func(context.Context) (string, error) { return "wrong " + testToken, nil }
	_, err := b.Submit(context.Background(), BuildRequest{Repo: "jdoe/app", SHA: testSHA})
	if err == nil || strings.Contains(err.Error(), testToken) || strings.Contains(out.String(), testToken) {
		t.Errorf("err %v out %q", err, out.String())
	}
	b, out = newTestBuild(t, &fakeAPI{caps: templateCaps})
	b.Token = func(context.Context) (string, error) { return "", errors.New("security: " + testToken) }
	_, err = b.Submit(context.Background(), BuildRequest{Repo: "jdoe/app", SHA: testSHA})
	if err == nil || strings.Contains(err.Error(), testToken) || strings.Contains(out.String(), testToken) {
		t.Errorf("keychain err %v", err)
	}
}

func TestAPIErrorHasOnlyCode(t *testing.T) {
	b, _ := newTestBuild(t, &fakeAPI{caps: templateCaps})
	err := b.do(context.Background(), "GET", "/v1/nope", nil, nil, nil)
	var api *APIError
	if !errors.As(err, &api) || api.Status != 404 || api.Code != "not_found" {
		t.Errorf("%v", err)
	}
}

func signedReceipt(t *testing.T, jobID string) ([]byte, Pins) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	raw := receiptFixture(t, priv, jobID)
	return raw, Pins{ReceiptKeyID: "k1", ReceiptPublicKey: base64.StdEncoding.EncodeToString(pub)}
}

func TestFollowTerminalStates(t *testing.T) {
	for _, tc := range []struct {
		states  []model.State
		want    model.State
		receipt bool
	}{
		{[]model.State{model.Queued, model.Running, model.Succeeded}, model.Succeeded, true},
		{[]model.State{model.Running, model.Failed}, model.Failed, false},
		{[]model.State{model.Cancelled}, model.Cancelled, false},
		{[]model.State{model.TimedOut}, model.TimedOut, false},
		{[]model.State{model.Expired}, model.Expired, false},
		{[]model.State{model.Interrupted}, model.Interrupted, false},
	} {
		f := &fakeAPI{caps: templateCaps, states: tc.states, logs: []string{"Compiling App\n", "** BUILD SUCCEEDED **\n"}}
		b, out := newTestBuild(t, f)
		b.Sleep = func(context.Context, time.Duration) error { return nil }
		if tc.receipt {
			f.receipt, b.Pins = signedReceipt(t, "job1")
		}
		res, err := b.Follow(context.Background(), "job1")
		if err != nil || res.State != tc.want || res.Receipt != tc.receipt {
			t.Errorf("%v: %+v %v", tc.states, res, err)
		}
		if !strings.Contains(out.String(), "** BUILD SUCCEEDED **") || strings.Count(out.String(), "Compiling App") != 1 {
			t.Errorf("logs:\n%s", out.String())
		}
		if tc.want == model.Failed && (res.ExitCode == nil || *res.ExitCode != 65) {
			t.Errorf("exit code %v", res.ExitCode)
		}
	}
}

func TestFollowRejectsForeignReceipt(t *testing.T) {
	f := &fakeAPI{caps: templateCaps, states: []model.State{model.Succeeded}}
	b, _ := newTestBuild(t, f)
	f.receipt, b.Pins = signedReceipt(t, "job2")
	if _, err := b.Follow(context.Background(), "job1"); err == nil {
		t.Error("receipt of another job accepted")
	}
	_, other := signedReceipt(t, "job1")
	f.receipt, _ = signedReceipt(t, "job1")
	b.Pins = other
	if _, err := b.Follow(context.Background(), "job1"); err == nil {
		t.Error("receipt under another key accepted")
	}
}

// TestFollowCancellation: a cancelled context stops following, without
// cancelling the job.
func TestFollowCancellation(t *testing.T) {
	f := &fakeAPI{caps: templateCaps, states: []model.State{model.Running}}
	b, _ := newTestBuild(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	n := 0
	b.Sleep = func(ctx context.Context, _ time.Duration) error {
		if n++; n == 3 {
			cancel()
		}
		return ctx.Err()
	}
	if _, err := b.Follow(ctx, "job1"); !errors.Is(err, ErrInterrupted) {
		t.Fatalf("err %v", err)
	}
	if f.polls != 3 {
		t.Errorf("polls %d", f.polls)
	}
}

func TestLocalRepo(t *testing.T) {
	dir := t.TempDir()
	git := filepath.Join(dir, ".git")
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(git, "refs/heads"), 0o755))
	must(os.WriteFile(filepath.Join(git, "HEAD"), []byte("ref: refs/heads/main\n"), 0o644))
	must(os.WriteFile(filepath.Join(git, "config"), []byte("[core]\n\tbare = false\n[remote \"upstream\"]\n\turl = git@github.com:other/x.git\n[remote \"origin\"]\n\turl = git@github.com:jdoe/app.git\n"), 0o644))
	must(os.WriteFile(filepath.Join(git, "packed-refs"), []byte("# pack-refs\n"+testSHA+" refs/heads/main\n"), 0o644))
	must(os.WriteFile(filepath.Join(dir, ".macserve.json"), []byte(`{}`), 0o644))
	repo, sha, cfg, err := LocalRepo(dir)
	if err != nil || repo != "jdoe/app" || sha != testSHA || string(cfg) != "{}" {
		t.Errorf("%q %q %q %v", repo, sha, cfg, err)
	}
	must(os.WriteFile(filepath.Join(git, "refs/heads/main"), []byte(strings.Repeat("f", 40)+"\n"), 0o644))
	if _, sha, _, _ = LocalRepo(dir); sha != strings.Repeat("f", 40) {
		t.Errorf("loose ref %q", sha)
	}
	must(os.WriteFile(filepath.Join(git, "HEAD"), []byte("ref: refs/../../etc\n"), 0o644))
	if _, _, _, err := LocalRepo(dir); err == nil {
		t.Error("escaping ref accepted")
	}
	if _, _, _, err := LocalRepo(t.TempDir()); err == nil {
		t.Error("non-repository accepted")
	}
	for url, want := range map[string]string{"https://github.com/jdoe/app": "jdoe/app", "ssh://git@github.com/jdoe/app.git": "jdoe/app", "https://gitlab.com/jdoe/app": ""} {
		if got := originRepo("[remote \"origin\"]\n\turl = " + url + "\n"); got != want {
			t.Errorf("%s: %q", url, got)
		}
	}
}

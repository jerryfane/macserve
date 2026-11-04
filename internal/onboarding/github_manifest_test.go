package onboarding

import (
	"context"
	"encoding/json"
	"errors"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/githubapi"
)

// TestManifestPermissionsEqualInstallationTokenRequest pins the manifest's
// default_permissions to the permissions internal/githubapi actually sends
// when it mints an installation token, and pins the absence of a webhook.
func TestManifestPermissionsEqualInstallationTokenRequest(t *testing.T) {
	f := newFakeGitHub(t)
	key, _ := appKey(t)
	client, err := githubapi.NewApp(githubapi.AppOptions{AppID: f.appID, InstallationID: 555, PrivateKey: key, Repositories: map[string]int64{"jdoe/myapp": 4242}, HTTP: f.options()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Repository(context.Background(), "jdoe/myapp"); err != nil {
		t.Fatal(err)
	}
	if len(f.tokenPerms) != 1 {
		t.Fatalf("token requests %v", f.tokenPerms)
	}
	raw, err := json.Marshal(NewManifest("macserve-studio", 49152))
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	perms := map[string]string{}
	for k, v := range manifest["default_permissions"].(map[string]any) {
		perms[k] = v.(string)
	}
	if !EqualPermissions(perms) || !EqualPermissions(f.tokenPerms[0]) {
		t.Fatalf("manifest permissions %v, controller token request %v", perms, f.tokenPerms[0])
	}
	if _, ok := manifest["hook_attributes"]; ok {
		t.Fatal("manifest has hook_attributes")
	}
	if events, ok := manifest["default_events"].([]any); !ok || len(events) != 0 {
		t.Fatalf("default_events %v", manifest["default_events"])
	}
	if manifest["public"] != false || manifest["redirect_url"] != "http://127.0.0.1:49152/created" || manifest["setup_url"] != "http://127.0.0.1:49152/installed" || manifest["url"] != HomepageURL {
		t.Fatalf("manifest %s", raw)
	}
}

func TestAppName(t *testing.T) {
	for host, want := range map[string]string{
		"Jane's Mac Studio.local":           "macserve-jane-s-mac-studio",
		"a-very-long-host-name-for-testing": "macserve-a-very-long-host-name-for",
		"---":                               "macserve",
	} {
		if got := AppName(host); got != want || len(got) > maxAppName {
			t.Errorf("AppName(%q) = %q, want %q", host, got, want)
		}
	}
}

// loopback serves a flow on a real 127.0.0.1 listener.
func loopback(t *testing.T, account Account) (*Flow, *httptest.Server) {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	port := srv.Listener.Addr().(interface{ String() string }).String()
	_, p, _ := strings.Cut(port, ":")
	n, _ := strconv.Atoi(p)
	flow, err := NewFlow(account, "macserve-test", n)
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = flow.Handler()
	srv.Start()
	t.Cleanup(srv.Close)
	return flow, srv
}

func get(t *testing.T, u string) (int, string) {
	t.Helper()
	resp, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

var actionPattern = regexp.MustCompile(`action="([^"]+)"`)

func TestStartPagePostsManifestWithState(t *testing.T) {
	flow, srv := loopback(t, Account{Login: "jdoe"})
	status, body := get(t, srv.URL+"/")
	m := actionPattern.FindStringSubmatch(body)
	if status != http.StatusOK || m == nil {
		t.Fatalf("status %d body %s", status, body)
	}
	action, err := url.Parse(html.UnescapeString(m[1]))
	if err != nil || action.Scheme+"://"+action.Host+action.Path != "https://github.com/settings/apps/new" || action.Query().Get("state") != flow.state || len(flow.state) != 64 {
		t.Fatalf("form action %q", m[1])
	}
	if !strings.Contains(body, `name="manifest"`) || !strings.Contains(body, "default_permissions") || !strings.Contains(body, `method="post"`) {
		t.Fatalf("start page %s", body)
	}
	org, _ := NewFlow(Account{Login: "acme", Org: true}, "x", 1)
	if !strings.HasPrefix(org.FormAction(), "https://github.com/organizations/acme/settings/apps/new?state=") {
		t.Fatal(org.FormAction())
	}
}

func TestManifestCallbackRejectsStateMismatch(t *testing.T) {
	flow, srv := loopback(t, Account{Login: "jdoe"})
	for _, query := range []string{"code=abc&state=" + strings.Repeat("0", 64), "code=abc", "code=abc&state=" + flow.state[:63]} {
		if status, _ := get(t, srv.URL+"/created?"+query); status != http.StatusBadRequest {
			t.Errorf("%s: status %d", query, status)
		}
	}
	if err := flow.AcceptCode("abc", "wrong"); !errors.Is(err, ErrStateMismatch) {
		t.Fatal(err)
	}
	select {
	case code := <-flow.Codes():
		t.Fatalf("accepted %q", code)
	default:
	}
	// A rejected state does not consume the flow.
	if status, _ := get(t, srv.URL+"/created?code=abc&state="+flow.state); status != http.StatusOK || <-flow.Codes() != "abc" {
		t.Fatalf("status %d", status)
	}
}

func TestManifestCallbackSingleUse(t *testing.T) {
	flow, srv := loopback(t, Account{Login: "jdoe"})
	if status, _ := get(t, srv.URL+"/created?code=first&state="+flow.state); status != http.StatusOK {
		t.Fatal(status)
	}
	if status, _ := get(t, srv.URL+"/created?code=second&state="+flow.state); status != http.StatusGone {
		t.Fatalf("replay status %d", status)
	}
	if status, _ := get(t, srv.URL+"/"); status != http.StatusGone {
		t.Fatalf("start page after use: %d", status)
	}
	if err := flow.AcceptCode("third", flow.state); !errors.Is(err, ErrCodeUsed) {
		t.Fatal(err)
	}
	if code := <-flow.Codes(); code != "first" {
		t.Fatal(code)
	}
}

func TestHandlerRefusesOtherHost(t *testing.T) {
	flow, srv := loopback(t, Account{Login: "jdoe"})
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	req.Host = "attacker.example:80"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusMisdirectedRequest || strings.Contains(string(body), flow.state) {
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
}

func TestInstalledRedirectOffersUntrustedCandidate(t *testing.T) {
	flow, srv := loopback(t, Account{Login: "jdoe"})
	if status, _ := get(t, srv.URL+"/installed?installation_id=555&setup_action=install"); status != http.StatusOK {
		t.Fatal(status)
	}
	if id := <-flow.Installations(); id != 555 {
		t.Fatal(id)
	}
	if status, _ := get(t, srv.URL+"/installed?installation_id=-1"); status != http.StatusBadRequest {
		t.Fatal(status)
	}
}

func TestPastedRedirectParsesCodeAndState(t *testing.T) {
	flow, _ := NewFlow(Account{Login: "jdoe"}, "x", 50000)
	pasted := "  http://127.0.0.1:50000/created?code=a180b1a3d263c81bc6441d7b990bae27d4c10679&state=" + flow.state + "\n"
	if installation, err := flow.AcceptPasted(pasted); err != nil || installation {
		t.Fatal(installation, err)
	}
	if code := <-flow.Codes(); code != "a180b1a3d263c81bc6441d7b990bae27d4c10679" {
		t.Fatal(code)
	}
	if installation, err := flow.AcceptPasted("http://127.0.0.1:50000/installed?installation_id=555&setup_action=install"); err != nil || !installation || <-flow.Installations() != 555 {
		t.Fatal(installation, err)
	}
}

func TestPastedRedirectRefusesMalformed(t *testing.T) {
	flow, _ := NewFlow(Account{Login: "jdoe"}, "x", 50000)
	state := flow.state
	for _, text := range []string{
		"",
		"code=abc&state=" + state,
		"https://127.0.0.1:50000/created?code=abc&state=" + state,
		"http://127.0.0.1:50001/created?code=abc&state=" + state,
		"http://localhost:50000/created?code=abc&state=" + state,
		"http://user@127.0.0.1:50000/created?code=abc&state=" + state,
		"http://127.0.0.1:50000/other?code=abc&state=" + state,
		"http://127.0.0.1:50000/created?code=abc&code=def&state=" + state,
		"http://127.0.0.1:50000/created?code=abc&state=" + state + "&extra=1",
		"http://127.0.0.1:50000/created?code=a%2Fb&state=" + state,
		"http://127.0.0.1:50000/created?code=abc&state=" + state + "#frag",
		"http://127.0.0.1:50000/created?code=abc def&state=" + state,
		"http://127.0.0.1:50000/created?code=abc;state=" + state,
		"http://127.0.0.1:50000/installed?installation_id=0",
		"http://127.0.0.1:50000/installed?installation_id=1e3",
		"http://127.0.0.1:50000/installed?installation_id=5&installation_id=6",
		"http://127.0.0.1:50000/installed?installation_id=5&setup_action=delete",
		"http://127.0.0.1:50000/installed?installation_id=5&code=abc",
		"http://127.0.0.1:50000/created?code=" + strings.Repeat("a", 2100) + "&state=" + state,
	} {
		if _, err := flow.AcceptPasted(text); !errors.Is(err, ErrRedirect) {
			t.Errorf("%q: %v", text, err)
		}
	}
	if _, err := flow.AcceptPasted("http://127.0.0.1:50000/created?code=abc&state=" + strings.Repeat("f", 64)); !errors.Is(err, ErrStateMismatch) {
		t.Error(err)
	}
	select {
	case code := <-flow.Codes():
		t.Fatalf("accepted %q", code)
	case id := <-flow.Installations():
		t.Fatalf("accepted installation %d", id)
	default:
	}
}

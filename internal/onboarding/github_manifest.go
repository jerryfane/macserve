// Package onboarding implements the first-time setup steps that talk to
// GitHub for credentials: the GitHub App manifest flow behind
// macserve connect-github, the App key install, the controller
// configuration writer for the github section and the read-only
// .macserve.json detection.
//
// The manifest flow follows GitHub Docs, "Registering a GitHub App from a
// manifest":
// https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest
//
//  1. The browser POSTs manifest=<JSON> to
//     https://github.com/settings/apps/new?state=<state> (or
//     /organizations/<org>/settings/apps/new for an organization).
//  2. GitHub redirects to redirect_url?code=<code>&state=<state>.
//  3. POST /app-manifests/{code}/conversions returns the App ID and PEM;
//     all three steps must finish within one hour.
//
// Installing the App redirects to setup_url with installation_id
// (GitHub Docs, "About the setup URL":
// https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/about-the-setup-url).
// That parameter is only a candidate: it is confirmed by authenticating as
// the App (Confirm).
package onboarding

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"maps"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/jerryfane/macserve/internal/githubapi"
)

const (
	// WebOrigin is where the manifest form posts and the App is installed.
	WebOrigin = "https://github.com"
	// HomepageURL is the App's required homepage.
	HomepageURL = "https://github.com/jerryfane/macserve"
	// maxAppName is GitHub's App name length limit.
	maxAppName = 34
)

// RequiredPermissions is the App's permission set. It is exactly the map
// internal/githubapi requests for every installation token
// (githubapi.Client.repositoryToken): an App with less cannot mint the
// controller's tokens, and the App never needs more.
// TestManifestPermissionsEqualInstallationTokenRequest pins the equality.
func RequiredPermissions() map[string]string {
	return map[string]string{"metadata": "read", "contents": "read", "pull_requests": "read", "checks": "write"}
}

// Manifest is the GitHub App manifest. It has no hook_attributes: macserve
// polls pull requests and needs no webhook, so no events are subscribed.
// Public is false: only the creating account can install the App.
// SetupOnUpdate sends the user back to setup_url after they correct an
// installation (for example to "Only select repositories").
type Manifest struct {
	Name               string            `json:"name"`
	URL                string            `json:"url"`
	RedirectURL        string            `json:"redirect_url"`
	SetupURL           string            `json:"setup_url"`
	SetupOnUpdate      bool              `json:"setup_on_update"`
	Public             bool              `json:"public"`
	DefaultPermissions map[string]string `json:"default_permissions"`
	DefaultEvents      []string          `json:"default_events"`
}

// Account is where the App is registered: the user's own account, or an
// organization only on explicit request.
type Account struct {
	Login string
	Org   bool
}

// AppName derives "macserve-<hostname slug>" within GitHub's name limit.
// The user may still edit the name on GitHub's page.
func AppName(hostname string) string {
	host, _, _ := strings.Cut(hostname, ".")
	var b strings.Builder
	dash := true
	for _, r := range strings.ToLower(host) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			dash = false
		} else if !dash {
			b.WriteByte('-')
			dash = true
		}
	}
	name := "macserve-" + strings.Trim(b.String(), "-")
	if len(name) > maxAppName {
		name = name[:maxAppName]
	}
	return strings.TrimRight(name, "-")
}

// NewManifest returns the manifest for a loopback listener on port.
func NewManifest(name string, port int) Manifest {
	base := "http://127.0.0.1:" + strconv.Itoa(port)
	return Manifest{
		Name: name, URL: HomepageURL,
		RedirectURL: base + "/created", SetupURL: base + "/installed", SetupOnUpdate: true,
		Public: false, DefaultPermissions: RequiredPermissions(), DefaultEvents: []string{},
	}
}

// EqualPermissions reports whether got is exactly RequiredPermissions.
func EqualPermissions(got map[string]string) bool {
	return maps.Equal(got, RequiredPermissions())
}

// ErrStateMismatch, ErrCodeUsed and ErrRedirect are the callback refusals.
var (
	ErrStateMismatch = errors.New("GitHub redirect state does not match this setup; start again")
	ErrCodeUsed      = errors.New("the GitHub App creation redirect was already used")
	ErrRedirect      = errors.New("not a GitHub redirect to this setup")
)

var (
	codePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	idPattern   = regexp.MustCompile(`^[1-9][0-9]{0,15}$`)
)

// Flow is one manifest flow: a 256-bit state, a single-use creation
// redirect and untrusted installation candidates. Its handler serves only
// the loopback address it was created for.
type Flow struct {
	state    string
	host     string
	account  Account
	manifest []byte

	mu       sync.Mutex
	codeUsed bool
	codes    chan string
	installs chan int64
}

// NewFlow starts a flow for a listener on 127.0.0.1:port.
func NewFlow(account Account, appName string, port int) (*Flow, error) {
	if !githubapi.ValidOwner(account.Login) {
		return nil, errors.New("GitHub account must be a lowercase login")
	}
	if port <= 0 || port > 65535 {
		return nil, errors.New("invalid loopback port")
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	manifest, err := json.Marshal(NewManifest(appName, port))
	if err != nil {
		return nil, err
	}
	return &Flow{
		state: hex.EncodeToString(nonce[:]), host: "127.0.0.1:" + strconv.Itoa(port),
		account: account, manifest: manifest,
		codes: make(chan string, 1), installs: make(chan int64, 8),
	}, nil
}

// StartURL is the local page that posts the manifest to GitHub.
func (f *Flow) StartURL() string { return "http://" + f.host + "/" }

// FormAction is GitHub's App registration endpoint with this flow's state.
func (f *Flow) FormAction() string {
	path := "/settings/apps/new"
	if f.account.Org {
		path = "/organizations/" + f.account.Login + "/settings/apps/new"
	}
	return WebOrigin + path + "?state=" + f.state
}

// Codes delivers the one accepted creation code.
func (f *Flow) Codes() <-chan string { return f.codes }

// Installations delivers installation_id candidates. None is trusted.
func (f *Flow) Installations() <-chan int64 { return f.installs }

// AcceptCode accepts the creation redirect once, and only with this flow's
// state. A rejected state does not consume the flow.
func (f *Flow) AcceptCode(code, state string) error {
	if subtle.ConstantTimeCompare([]byte(state), []byte(f.state)) != 1 {
		return ErrStateMismatch
	}
	if !codePattern.MatchString(code) {
		return ErrRedirect
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.codeUsed {
		return ErrCodeUsed
	}
	f.codeUsed = true
	f.codes <- code
	return nil
}

// OfferInstallation queues an installation_id candidate; extra candidates
// beyond the queue are dropped.
func (f *Flow) OfferInstallation(id int64) {
	select {
	case f.installs <- id:
	default:
	}
}

// AcceptPasted accepts a redirect address copied from a browser on another
// device: the creation redirect (code and state) or the setup redirect
// (installation_id). It applies the same checks as the loopback handler.
func (f *Flow) AcceptPasted(text string) (installation bool, err error) {
	code, state, id, err := ParseRedirect(text, f.host)
	if err != nil {
		return false, err
	}
	if id > 0 {
		f.OfferInstallation(id)
		return true, nil
	}
	return false, f.AcceptCode(code, state)
}

// ParseRedirect parses a pasted http://<host>/created?code=…&state=… or
// http://<host>/installed?installation_id=… address. Every parameter must
// appear exactly once; nothing else in the address is accepted.
func ParseRedirect(text, host string) (code, state string, installation int64, err error) {
	text = strings.TrimSpace(text)
	if text == "" || len(text) > 2048 || strings.ContainsAny(text, " \t\r\n") {
		return "", "", 0, ErrRedirect
	}
	u, err := url.Parse(text)
	if err != nil || u.Scheme != "http" || u.Host != host || u.User != nil || u.Fragment != "" {
		return "", "", 0, ErrRedirect
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", "", 0, ErrRedirect
	}
	one := func(key string) (string, bool) {
		v := q[key]
		return strings.Join(v, ""), len(v) == 1 && v[0] != ""
	}
	switch u.Path {
	case "/created":
		code, okCode := one("code")
		state, okState := one("state")
		if !okCode || !okState || len(q) != 2 || !codePattern.MatchString(code) {
			return "", "", 0, ErrRedirect
		}
		return code, state, 0, nil
	case "/installed":
		raw, ok := one("installation_id")
		for key := range q {
			if key != "installation_id" && key != "setup_action" {
				return "", "", 0, ErrRedirect
			}
		}
		if action := q["setup_action"]; len(action) > 1 || len(action) == 1 && action[0] != "install" && action[0] != "update" {
			return "", "", 0, ErrRedirect
		}
		if !ok || !idPattern.MatchString(raw) {
			return "", "", 0, ErrRedirect
		}
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return "", "", 0, ErrRedirect
		}
		return "", "", id, nil
	}
	return "", "", 0, ErrRedirect
}

var startPage = template.Must(template.New("start").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>macserve: create GitHub App</title></head>
<body>
<p>Sending the macserve GitHub App manifest to GitHub…</p>
<form id="manifest-form" action="{{.Action}}" method="post">
<input type="hidden" name="manifest" value="{{.Manifest}}">
<button type="submit">Continue to GitHub</button>
</form>
<script>document.getElementById("manifest-form").submit()</script>
</body></html>
`))

const donePage = `<!doctype html><html><head><meta charset="utf-8"><title>macserve</title></head><body><p>%s</p></body></html>`

// Handler serves the start page, the creation redirect and the setup
// redirect. Requests for any other Host are refused, so a page that
// rebinds its own name to 127.0.0.1 cannot read the state.
func (f *Flow) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		used := f.codeUsed
		f.mu.Unlock()
		if used {
			http.Error(w, "already used", http.StatusGone)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = startPage.Execute(w, struct{ Action, Manifest string }{f.FormAction(), string(f.manifest)})
	})
	mux.HandleFunc("GET /created", func(w http.ResponseWriter, r *http.Request) {
		code, state, _, err := ParseRedirect("http://"+r.Host+r.URL.RequestURI(), f.host)
		if err == nil {
			err = f.AcceptCode(code, state)
		}
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, ErrCodeUsed) {
				status = http.StatusGone
			}
			w.WriteHeader(status)
			fmt.Fprintf(w, donePage, template.HTMLEscapeString(err.Error()))
			return
		}
		fmt.Fprintf(w, donePage, "GitHub App created. Return to the terminal to install it.")
	})
	mux.HandleFunc("GET /installed", func(w http.ResponseWriter, r *http.Request) {
		_, _, id, err := ParseRedirect("http://"+r.Host+r.URL.RequestURI(), f.host)
		if err != nil || id == 0 {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, donePage, template.HTMLEscapeString(ErrRedirect.Error()))
			return
		}
		f.OfferInstallation(id)
		fmt.Fprintf(w, donePage, "Installation received. Return to the terminal; macserve confirms it with GitHub.")
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.Host != f.host {
			http.Error(w, "wrong host", http.StatusMisdirectedRequest)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// Listen opens the loopback listener on a random port.
func Listen() (net.Listener, error) {
	return net.Listen("tcp", "127.0.0.1:0")
}

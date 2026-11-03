package onboarding

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jerryfane/macserve/internal/githubapi"
)

const (
	apiOrigin      = "https://api.github.com"
	maxAPIResponse = 8 << 20
	apiTimeout     = 30 * time.Second
	maxPEMBytes    = 16 << 10
)

// StatusError is a GitHub HTTP refusal. It carries no response body.
type StatusError struct {
	Status int
	Path   string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("GitHub refused %s with HTTP status %d", e.Path, e.Status)
}

// ErrCodeRejected is GitHub refusing a manifest code: already converted,
// older than one hour, or never issued.
var ErrCodeRejected = errors.New("GitHub refused the App creation code: it was already used or is more than one hour old; run macserve connect-github again")

// API is the bounded REST client of the onboarding flow. It shares the
// githubapi transport policy: no proxy from the environment, no redirects,
// no cookies, bounded responses.
type API struct {
	http   *http.Client
	origin string
	now    func() time.Time
	opts   githubapi.HTTPOptions
}

// NewAPI returns a client; o.BaseURL is a test seam only.
func NewAPI(o githubapi.HTTPOptions) (*API, error) {
	origin := o.BaseURL
	if origin == "" {
		origin = apiOrigin
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || u.Scheme != "https" && u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
		return nil, errors.New("invalid GitHub API origin")
	}
	var h http.Client
	if o.Client != nil {
		h = *o.Client
	} else {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		transport.ResponseHeaderTimeout = apiTimeout
		transport.MaxResponseHeaderBytes = 64 << 10
		h.Transport = transport
	}
	h.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	h.Jar = nil
	if h.Timeout <= 0 || h.Timeout > apiTimeout {
		h.Timeout = apiTimeout
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	return &API{http: &h, origin: u.Scheme + "://" + u.Host, now: now, opts: o}, nil
}

func (a *API) do(ctx context.Context, method, path, token string, input, output any) error {
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return errors.New("cannot encode GitHub request")
		}
		body = bytes.NewReader(data)
	}
	ctx, cancel := context.WithTimeout(ctx, apiTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, a.origin+path, body)
	if err != nil {
		return errors.New("cannot construct GitHub request")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "macserve-onboarding")
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("GitHub request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		route, _, _ := strings.Cut(path, "?")
		return &StatusError{Status: resp.StatusCode, Path: route}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponse+1))
	if err != nil || len(data) > maxAPIResponse {
		return errors.New("cannot read GitHub response")
	}
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) || json.Unmarshal(data, output) != nil {
		return errors.New("invalid GitHub JSON response")
	}
	return nil
}

func status(err error) int {
	var s *StatusError
	if errors.As(err, &s) {
		return s.Status
	}
	return 0
}

// Owner is a GitHub account.
type Owner struct {
	Login string `json:"login"`
	ID    int64  `json:"id"`
	Type  string `json:"type"`
}

func (o Owner) matches(account Account) bool {
	kind := "User"
	if account.Org {
		kind = "Organization"
	}
	return o.ID > 0 && strings.EqualFold(o.Login, account.Login) && o.Type == kind
}

// App is a converted manifest. The webhook and OAuth client secrets in the
// conversion reply are never decoded.
type App struct {
	ID    int64
	Slug  string
	Owner Owner
	PEM   []byte
	Key   *rsa.PrivateKey
}

// SettingsURL is where the user deletes a refused App.
func (a App) SettingsURL(account Account) string {
	if account.Org {
		return WebOrigin + "/organizations/" + account.Login + "/settings/apps/" + a.Slug + "/advanced"
	}
	return WebOrigin + "/settings/apps/" + a.Slug + "/advanced"
}

// InstallURL is where the user installs the App on one repository.
func (a App) InstallURL() string { return WebOrigin + "/apps/" + a.Slug + "/installations/new" }

func validSlug(slug string) bool {
	if slug == "" || len(slug) > 100 {
		return false
	}
	for _, r := range slug {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

// RefusedAppError reports an App GitHub created but macserve refuses to
// use; the App's key is not kept and the user must delete the App.
type RefusedAppError struct {
	Reason   string
	Settings string
}

func (e *RefusedAppError) Error() string {
	if e.Settings == "" {
		return "refusing the created GitHub App: " + e.Reason
	}
	return "refusing the created GitHub App: " + e.Reason + "; its key was not kept; delete the App at " + e.Settings
}

// Convert exchanges the manifest code at once (POST
// /app-manifests/{code}/conversions; GitHub Docs, "Registering a GitHub
// App from a manifest", step 3). The App must belong to account and have
// exactly RequiredPermissions and no events.
func (a *API) Convert(ctx context.Context, code string, account Account) (App, error) {
	if !codePattern.MatchString(code) {
		return App{}, ErrRedirect
	}
	var reply struct {
		ID          int64             `json:"id"`
		Slug        string            `json:"slug"`
		Owner       Owner             `json:"owner"`
		Permissions map[string]string `json:"permissions"`
		Events      []string          `json:"events"`
		PEM         string            `json:"pem"`
	}
	err := a.do(ctx, http.MethodPost, "/app-manifests/"+code+"/conversions", "", nil, &reply)
	if s := status(err); s == http.StatusNotFound || s == http.StatusUnprocessableEntity || s == http.StatusGone {
		return App{}, ErrCodeRejected
	}
	if err != nil {
		return App{}, err
	}
	if reply.ID <= 0 || !validSlug(reply.Slug) {
		return App{}, errors.New("invalid GitHub App conversion reply")
	}
	app := App{ID: reply.ID, Slug: reply.Slug, Owner: reply.Owner}
	refuse := func(reason string) (App, error) {
		return App{}, &RefusedAppError{Reason: reason, Settings: app.SettingsURL(account)}
	}
	if !reply.Owner.matches(account) {
		return refuse(fmt.Sprintf("it belongs to %q, not %q", reply.Owner.Login, account.Login))
	}
	if !EqualPermissions(reply.Permissions) {
		return refuse("its permissions differ from metadata, contents and pull requests read, checks write")
	}
	if len(reply.Events) != 0 {
		return refuse("it subscribes to webhook events")
	}
	key, err := ParseAppKey([]byte(reply.PEM))
	if err != nil {
		return refuse(err.Error())
	}
	app.PEM, app.Key = []byte(reply.PEM), key
	return app, nil
}

// ParseAppKey accepts exactly one RSA private key PEM block of at least
// 2048 bits, the forms the controller loads (cmd/macserve/integrations.go).
func ParseAppKey(data []byte) (*rsa.PrivateKey, error) {
	if len(data) == 0 || len(data) > maxPEMBytes {
		return nil, errors.New("GitHub App key is missing or too large")
	}
	block, rest := pem.Decode(data)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("GitHub App key is not a single PEM block")
	}
	var key *rsa.PrivateKey
	var err error
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		var parsed any
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		key, _ = parsed.(*rsa.PrivateKey)
	}
	if err != nil || key == nil || key.N.BitLen() < 2048 || key.Validate() != nil {
		return nil, errors.New("GitHub App key is not an RSA private key of at least 2048 bits")
	}
	return key, nil
}

// jwt signs the App JWT as githubapi does (RS256, iat one minute back,
// eight-minute lifetime).
func (a *API) jwt(app App) (string, error) {
	now := a.now()
	payload, err := json.Marshal(struct {
		Issued  int64 `json:"iat"`
		Expires int64 `json:"exp"`
		Issuer  int64 `json:"iss"`
	}{now.Add(-time.Minute).Unix(), now.Add(8 * time.Minute).Unix(), app.ID})
	if err != nil {
		return "", errors.New("cannot encode GitHub App JWT")
	}
	unsigned := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, app.Key, crypto.SHA256, digest[:])
	if err != nil {
		return "", errors.New("cannot sign GitHub App JWT")
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// Installation is an installation confirmed with the App's own JWT.
// Selection is GitHub's repository_selection: "selected" or "all".
type Installation struct {
	ID        int64
	Account   Owner
	Selection string
}

// ErrNotInstallation is a setup_url installation_id this App does not own.
var ErrNotInstallation = errors.New("the installation in the GitHub redirect is not an installation of this App; install it from the address macserve printed")

// Confirm authenticates as the App and reads GET /app/installations/{id}.
// The installation_id from the setup redirect is never trusted: it must be
// this App's, on account, with exactly RequiredPermissions, no events and
// not suspended. Which repositories it must grant is the policy's Scope.
func (a *API) Confirm(ctx context.Context, app App, account Account, candidate int64) (Installation, error) {
	if candidate <= 0 {
		return Installation{}, ErrNotInstallation
	}
	jwt, err := a.jwt(app)
	if err != nil {
		return Installation{}, err
	}
	var reply struct {
		ID          int64             `json:"id"`
		AppID       int64             `json:"app_id"`
		Account     Owner             `json:"account"`
		Selection   string            `json:"repository_selection"`
		Permissions map[string]string `json:"permissions"`
		Events      []string          `json:"events"`
		SuspendedAt *string           `json:"suspended_at"`
	}
	err = a.do(ctx, http.MethodGet, "/app/installations/"+strconv.FormatInt(candidate, 10), jwt, nil, &reply)
	if s := status(err); s == http.StatusNotFound || s == http.StatusForbidden {
		return Installation{}, ErrNotInstallation
	}
	if err != nil {
		return Installation{}, err
	}
	switch {
	case reply.ID != candidate || reply.AppID != app.ID:
		return Installation{}, ErrNotInstallation
	case !reply.Account.matches(account):
		return Installation{}, fmt.Errorf("the App was installed on %q, not %q; uninstall it there and install it on your repository", reply.Account.Login, account.Login)
	case reply.Selection != "selected" && reply.Selection != "all":
		return Installation{}, errors.New("invalid installation repository selection")
	case !EqualPermissions(reply.Permissions) || len(reply.Events) != 0:
		return Installation{}, errors.New("the installation's permissions differ from the App manifest")
	case reply.SuspendedAt != nil:
		return Installation{}, errors.New("the App installation is suspended")
	}
	return Installation{ID: reply.ID, Account: reply.Account, Selection: reply.Selection}, nil
}

// readToken mints a short-lived installation token limited to metadata and
// contents read, enough to list the selected repositories and read
// .macserve.json. It is never stored or printed.
func (a *API) readToken(ctx context.Context, app App, installation Installation) (string, error) {
	jwt, err := a.jwt(app)
	if err != nil {
		return "", err
	}
	var reply struct {
		Token   string    `json:"token"`
		Expires time.Time `json:"expires_at"`
	}
	input := map[string]any{"permissions": map[string]string{"metadata": "read", "contents": "read"}}
	if err := a.do(ctx, http.MethodPost, "/app/installations/"+strconv.FormatInt(installation.ID, 10)+"/access_tokens", jwt, input, &reply); err != nil {
		return "", err
	}
	if reply.Token == "" || len(reply.Token) > 16384 || strings.ContainsAny(reply.Token, " \t\r\n") || !a.now().Before(reply.Expires) {
		return "", errors.New("invalid GitHub installation token reply")
	}
	return reply.Token, nil
}

// Repository is one repository the installation was granted.
type Repository struct {
	ID            int64  `json:"id"`
	FullName      string `json:"full_name"`
	Owner         Owner  `json:"owner"`
	DefaultBranch string `json:"default_branch"`
}

// Repositories lists GET /installation/repositories (at most 100: a
// selected installation for macserve has one).
func (a *API) repositories(ctx context.Context, token string) ([]Repository, error) {
	var reply struct {
		Total        int          `json:"total_count"`
		Repositories []Repository `json:"repositories"`
	}
	if err := a.do(ctx, http.MethodGet, "/installation/repositories?per_page=100", token, nil, &reply); err != nil {
		return nil, err
	}
	if reply.Total != len(reply.Repositories) {
		return nil, errors.New("the App installation has more than 100 repositories; select only your repository")
	}
	for _, r := range reply.Repositories {
		if r.ID <= 0 || r.DefaultBranch == "" || strings.ContainsAny(r.DefaultBranch, "\x00\r\n") {
			return nil, errors.New("invalid GitHub repository in the installation")
		}
	}
	return reply.Repositories, nil
}

// repository reads one repository the installation token can see
// (GET /repos/{owner}/{name}).
func (a *API) repository(ctx context.Context, token, fullName string) (Repository, error) {
	var reply Repository
	if err := a.do(ctx, http.MethodGet, repoPath(fullName), token, nil, &reply); err != nil {
		return Repository{}, err
	}
	if reply.ID <= 0 || reply.DefaultBranch == "" || strings.ContainsAny(reply.DefaultBranch, "\x00\r\n") {
		return Repository{}, errors.New("invalid GitHub repository reply")
	}
	return reply, nil
}

// user resolves the numeric ID of a user login (GET /users/{login}).
func (a *API) user(ctx context.Context, token, login string) (Owner, error) {
	if !githubapi.ValidOwner(login) {
		return Owner{}, errors.New("invalid GitHub login")
	}
	var reply Owner
	if err := a.do(ctx, http.MethodGet, "/users/"+login, token, nil, &reply); err != nil {
		return Owner{}, err
	}
	if reply.ID <= 0 || reply.Type != "User" || !strings.EqualFold(reply.Login, login) {
		return Owner{}, fmt.Errorf("GitHub login %q is not a user account", login)
	}
	return reply, nil
}

func repoPath(fullName string) string {
	owner, name, _ := strings.Cut(fullName, "/")
	return "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name)
}

func refPath(ref string) string {
	parts := strings.Split(ref, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}

// head returns the default branch's commit and tree SHAs.
func (a *API) head(ctx context.Context, token string, repo Repository) (commit, tree string, err error) {
	var reply struct {
		Commit struct {
			SHA    string `json:"sha"`
			Commit struct {
				Tree struct {
					SHA string `json:"sha"`
				} `json:"tree"`
			} `json:"commit"`
		} `json:"commit"`
	}
	if err := a.do(ctx, http.MethodGet, repoPath(repo.FullName)+"/branches/"+refPath(repo.DefaultBranch), token, nil, &reply); err != nil {
		return "", "", err
	}
	if !objectID(reply.Commit.SHA) || !objectID(reply.Commit.Commit.Tree.SHA) {
		return "", "", errors.New("invalid GitHub branch reply")
	}
	return reply.Commit.SHA, reply.Commit.Commit.Tree.SHA, nil
}

func objectID(sha string) bool {
	if len(sha) != 40 && len(sha) != 64 {
		return false
	}
	for _, r := range sha {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

// file reads one file at commit through the contents API, or reports it
// missing. It is bytes only: nothing from the repository is executed.
func (a *API) file(ctx context.Context, token string, repo Repository, commit, name string, limit int) ([]byte, bool, error) {
	var reply struct {
		Type     string `json:"type"`
		Size     int    `json:"size"`
		Encoding string `json:"encoding"`
		Content  string `json:"content"`
	}
	err := a.do(ctx, http.MethodGet, repoPath(repo.FullName)+"/contents/"+url.PathEscape(name)+"?ref="+commit, token, nil, &reply)
	if status(err) == http.StatusNotFound {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if reply.Type != "file" || reply.Encoding != "base64" || reply.Size < 0 {
		return nil, true, fmt.Errorf("%s is not a regular file", name)
	}
	if reply.Size > limit {
		return nil, true, fmt.Errorf("%s exceeds %d bytes", name, limit)
	}
	data, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(reply.Content, "\n", ""))
	if err != nil || len(data) != reply.Size {
		return nil, true, fmt.Errorf("%s has an invalid encoding", name)
	}
	return data, true, nil
}

// TreeEntry is one path of a recursive tree listing.
type TreeEntry struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

func (a *API) tree(ctx context.Context, token string, repo Repository, tree string) ([]TreeEntry, bool, error) {
	var reply struct {
		Tree      []TreeEntry `json:"tree"`
		Truncated bool        `json:"truncated"`
	}
	if err := a.do(ctx, http.MethodGet, repoPath(repo.FullName)+"/git/trees/"+tree+"?recursive=1", token, nil, &reply); err != nil {
		return nil, false, err
	}
	return reply.Tree, reply.Truncated, nil
}

package onboarding

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"maps"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/githubapi"
)

var (
	testKeyOnce sync.Once
	testKey     *rsa.PrivateKey
	testKeyPEM  []byte
)

// appKey is one RSA key shared by the tests; generating it is slow.
func appKey(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	testKeyOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		testKey = key
		testKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	})
	return testKey, testKeyPEM
}

type fakeInstallation struct {
	AppID       int64
	Account     Owner
	Selection   string
	Permissions map[string]string
	Events      []string
}

// fakeGitHub is GitHub's API for one manifest flow. Codes are single use;
// JWTs must verify against the App key.
type fakeGitHub struct {
	t   *testing.T
	srv *httptest.Server

	mu            sync.Mutex
	appID         int64
	slug          string
	owner         Owner
	permissions   map[string]string
	events        []string
	codes         map[string]bool
	installations map[int64]fakeInstallation
	repos         []Repository
	repoConfig    []byte
	tree          []TreeEntry
	tokenPerms    []map[string]string
	calls         []string
}

const (
	fakeToken  = "ghs_fake_installation_token"
	fakeCommit = "1111111111111111111111111111111111111111"
	fakeTree   = "2222222222222222222222222222222222222222"
)

func newFakeGitHub(t *testing.T) *fakeGitHub {
	f := &fakeGitHub{
		t: t, appID: 77, slug: "macserve-studio",
		owner:       Owner{Login: "jdoe", ID: 1001, Type: "User"},
		permissions: RequiredPermissions(),
		codes:       map[string]bool{"goodcode": true},
		installations: map[int64]fakeInstallation{
			555: {AppID: 77, Account: Owner{Login: "jdoe", ID: 1001, Type: "User"}, Selection: "selected", Permissions: RequiredPermissions()},
		},
		repos: []Repository{{ID: 4242, FullName: "jdoe/myapp", Owner: Owner{Login: "jdoe", ID: 1001, Type: "User"}, DefaultBranch: "main"}},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGitHub) options() githubapi.HTTPOptions {
	return githubapi.HTTPOptions{BaseURL: f.srv.URL, Client: f.srv.Client()}
}

func (f *fakeGitHub) write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// verifyJWT checks an App JWT signed with the shared key for this App.
func (f *fakeGitHub) verifyJWT(r *http.Request) bool {
	key, _ := appKey(f.t)
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	parts := strings.Split(token, ".")
	if !ok || len(parts) != 3 {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig) != nil {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	var claims struct {
		Iss int64 `json:"iss"`
		Exp int64 `json:"exp"`
	}
	return err == nil && json.Unmarshal(payload, &claims) == nil && claims.Iss == f.appID && claims.Exp > time.Now().Unix()
}

func (f *fakeGitHub) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	path := r.URL.Path
	installationToken := r.Header.Get("Authorization") == "Bearer "+fakeToken
	switch {
	case r.Method == http.MethodPost && strings.HasPrefix(path, "/app-manifests/") && strings.HasSuffix(path, "/conversions"):
		code := strings.TrimSuffix(strings.TrimPrefix(path, "/app-manifests/"), "/conversions")
		if !f.codes[code] {
			f.write(w, http.StatusNotFound, map[string]string{"message": "Not Found"})
			return
		}
		delete(f.codes, code)
		_, pemBytes := appKey(f.t)
		f.write(w, http.StatusCreated, map[string]any{
			"id": f.appID, "slug": f.slug, "owner": f.owner, "permissions": f.permissions, "events": f.events,
			"pem": string(pemBytes), "webhook_secret": "discarded", "client_secret": "discarded",
		})
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/app/installations/"):
		if !f.verifyJWT(r) {
			f.write(w, http.StatusUnauthorized, nil)
			return
		}
		id, _ := strconv.ParseInt(strings.TrimPrefix(path, "/app/installations/"), 10, 64)
		inst, ok := f.installations[id]
		if !ok || inst.AppID != f.appID {
			f.write(w, http.StatusNotFound, map[string]string{"message": "Not Found"})
			return
		}
		f.write(w, http.StatusOK, map[string]any{"id": id, "app_id": inst.AppID, "account": inst.Account, "repository_selection": inst.Selection, "permissions": inst.Permissions, "events": inst.Events})
	case r.Method == http.MethodPost && strings.HasPrefix(path, "/app/installations/") && strings.HasSuffix(path, "/access_tokens"):
		if !f.verifyJWT(r) {
			f.write(w, http.StatusUnauthorized, nil)
			return
		}
		var body struct {
			RepositoryIDs []int64           `json:"repository_ids"`
			Permissions   map[string]string `json:"permissions"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.tokenPerms = append(f.tokenPerms, maps.Clone(body.Permissions))
		reply := map[string]any{"token": fakeToken, "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
		if len(body.RepositoryIDs) == 1 {
			for _, repo := range f.repos {
				if repo.ID == body.RepositoryIDs[0] {
					reply["repositories"] = []map[string]any{{"id": repo.ID, "full_name": repo.FullName, "owner": repo.Owner}}
				}
			}
		}
		f.write(w, http.StatusCreated, reply)
	case !installationToken:
		f.write(w, http.StatusUnauthorized, nil)
	case r.Method == http.MethodDelete && path == "/installation/token":
		w.WriteHeader(http.StatusNoContent)
	case path == "/installation/repositories":
		f.write(w, http.StatusOK, map[string]any{"total_count": len(f.repos), "repositories": f.repos})
	case strings.HasPrefix(path, "/users/"):
		login := strings.TrimPrefix(path, "/users/")
		if login != "jdoe" {
			f.write(w, http.StatusNotFound, nil)
			return
		}
		f.write(w, http.StatusOK, Owner{Login: "jdoe", ID: 1001, Type: "User"})
	case path == "/repos/jdoe/myapp":
		f.write(w, http.StatusOK, map[string]any{"id": 4242, "full_name": "jdoe/myapp", "default_branch": "main", "owner": map[string]any{"login": "jdoe", "id": 1001, "type": "User"}})
	case path == "/repos/jdoe/myapp/branches/main":
		f.write(w, http.StatusOK, map[string]any{"commit": map[string]any{"sha": fakeCommit, "commit": map[string]any{"tree": map[string]any{"sha": fakeTree}}}})
	case path == "/repos/jdoe/myapp/contents/.macserve.json":
		if r.URL.Query().Get("ref") != fakeCommit {
			f.write(w, http.StatusBadRequest, nil)
			return
		}
		if f.repoConfig == nil {
			f.write(w, http.StatusNotFound, nil)
			return
		}
		f.write(w, http.StatusOK, map[string]any{"type": "file", "size": len(f.repoConfig), "encoding": "base64", "content": base64.StdEncoding.EncodeToString(f.repoConfig)})
	case path == "/repos/jdoe/myapp/git/trees/"+fakeTree:
		f.write(w, http.StatusOK, map[string]any{"tree": f.tree, "truncated": false})
	default:
		f.write(w, http.StatusNotFound, nil)
	}
}

func (f *fakeGitHub) app(t *testing.T) App {
	key, pemBytes := appKey(t)
	return App{ID: f.appID, Slug: f.slug, Owner: f.owner, PEM: pemBytes, Key: key}
}

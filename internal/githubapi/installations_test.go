package githubapi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type mintRecord struct {
	path string
	body map[string]any
}

// orgServer answers token mints with reply and repository lookups with repo.
func orgServer(t *testing.T, reply func(installation string, body map[string]any) map[string]any, repo func(path string) Repository) (*httptest.Server, *[]mintRecord, *sync.Mutex) {
	t.Helper()
	var mu sync.Mutex
	var mints []mintRecord
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/app/installations/") {
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			mu.Lock()
			mints = append(mints, mintRecord{r.URL.Path, body})
			mu.Unlock()
			installation := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/app/installations/"), "/access_tokens")
			writeJSON(t, w, reply(installation, body))
			return
		}
		writeJSON(t, w, repo(r.URL.Path))
	}))
	t.Cleanup(s.Close)
	return s, &mints, &mu
}

func orgKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestInstallationSelectedByOwnerAndRepositoryIDLearned(t *testing.T) {
	ids := map[string]int64{"themartianapp/new-app": 901, "jerryfane/tool": 902, "themartianapp/keephair": 1318491892}
	s, mints, mu := orgServer(t, func(installation string, body map[string]any) map[string]any {
		var name string
		if names, ok := body["repositories"].([]any); ok && len(names) == 1 {
			name, _ = names[0].(string)
		}
		owner := map[string]string{"111": "themartianapp", "222": "jerryfane"}[installation]
		full := owner + "/" + name
		if name == "" {
			full = "themartianapp/keephair"
		}
		return map[string]any{"token": "tok-" + installation, "expires_at": testTime.Add(time.Hour), "repositories": []any{map[string]any{"id": ids[full], "full_name": full, "owner": map[string]any{"login": strings.Split(full, "/")[0]}}}}
	}, func(path string) Repository {
		full := strings.TrimPrefix(path, "/repos/")
		return Repository{ID: ids[full], FullName: full, Owner: RepositoryOwner{Login: strings.Split(full, "/")[0]}}
	})
	c, err := NewApp(AppOptions{AppID: 12, Installations: map[string]int64{"themartianapp": 111, "jerryfane": 222}, PrivateKey: orgKey(t), Repositories: map[string]int64{"themartianapp/keephair": 1318491892}, Owners: []string{"themartianapp", "jerryfane"}, HTTP: HTTPOptions{BaseURL: s.URL, Client: s.Client(), Now: func() time.Time { return testTime }}})
	if err != nil {
		t.Fatal(err)
	}
	if _, known := c.RepositoryID("themartianapp/new-app"); known {
		t.Fatal("owner-approved repository ID known before verification")
	}
	for repo, installation := range map[string]string{"themartianapp/new-app": "111", "jerryfane/tool": "222", "themartianapp/keephair": "111"} {
		token, err := c.SourceToken(context.Background(), repo)
		if err != nil || token != "tok-"+installation {
			t.Fatalf("%s: token %q %v", repo, token, err)
		}
		if id, known := c.RepositoryID(repo); !known || id != ids[repo] {
			t.Fatalf("%s: repository ID %d %v", repo, id, known)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for _, m := range *mints {
		perms, _ := m.body["permissions"].(map[string]any)
		if len(perms) != 4 || perms["contents"] != "read" || perms["metadata"] != "read" || perms["pull_requests"] != "read" || perms["checks"] != "write" {
			t.Fatalf("permissions changed: %v", m.body)
		}
		names, byName := m.body["repositories"].([]any)
		pinned, byID := m.body["repository_ids"].([]any)
		if byName == byID || byName && len(names) != 1 || byID && (len(pinned) != 1 || pinned[0] != float64(1318491892)) {
			t.Fatalf("token not scoped to exactly one repository: %v", m.body)
		}
	}
	if _, err := c.SourceToken(context.Background(), "someone-else/app"); err == nil || !strings.Contains(err.Error(), "not approved") {
		t.Fatalf("unapproved owner minted a token: %v", err)
	}
}

func TestLegacySingleInstallationStillUsed(t *testing.T) {
	s, mints, mu := orgServer(t, func(string, map[string]any) map[string]any {
		return map[string]any{"token": "legacy", "expires_at": testTime.Add(time.Hour)}
	}, func(string) Repository { return Repository{ID: 56, FullName: testRepo} })
	c, err := NewApp(AppOptions{AppID: 12, InstallationID: 34, PrivateKey: orgKey(t), Repositories: map[string]int64{testRepo: 56}, HTTP: HTTPOptions{BaseURL: s.URL, Client: s.Client(), Now: func() time.Time { return testTime }}})
	if err != nil {
		t.Fatal(err)
	}
	if token, err := c.SourceToken(context.Background(), testRepo); err != nil || token != "legacy" {
		t.Fatalf("legacy token %q %v", token, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*mints) != 1 || (*mints)[0].path != "/app/installations/34/access_tokens" {
		t.Fatalf("legacy installation not used: %+v", *mints)
	}
	if _, err := NewApp(AppOptions{AppID: 12, PrivateKey: orgKey(t), Repositories: map[string]int64{testRepo: 56}}); err == nil {
		t.Fatal("App without any installation accepted")
	}
	if _, err := NewApp(AppOptions{AppID: 12, Installations: map[string]int64{"Upper": 1}, PrivateKey: orgKey(t), Owners: []string{"upper"}}); err == nil {
		t.Fatal("non-canonical installation owner accepted")
	}
}

func TestOwnerApprovedTokenReplyMustMatchRepositoryAndOwner(t *testing.T) {
	cases := map[string]map[string]any{
		"no repositories":    {"token": "t", "expires_at": testTime.Add(time.Hour)},
		"other repository":   {"token": "t", "expires_at": testTime.Add(time.Hour), "repositories": []any{map[string]any{"id": 9, "full_name": "themartianapp/other", "owner": map[string]any{"login": "themartianapp"}}}},
		"other owner login":  {"token": "t", "expires_at": testTime.Add(time.Hour), "repositories": []any{map[string]any{"id": 9, "full_name": "themartianapp/new-app", "owner": map[string]any{"login": "evil"}}}},
		"two repositories":   {"token": "t", "expires_at": testTime.Add(time.Hour), "repositories": []any{map[string]any{"id": 9, "full_name": "themartianapp/new-app", "owner": map[string]any{"login": "themartianapp"}}, map[string]any{"id": 10, "full_name": "themartianapp/x", "owner": map[string]any{"login": "themartianapp"}}}},
		"invalid ID":         {"token": "t", "expires_at": testTime.Add(time.Hour), "repositories": []any{map[string]any{"id": 0, "full_name": "themartianapp/new-app", "owner": map[string]any{"login": "themartianapp"}}}},
		"lookup ID mismatch": {"token": "t", "expires_at": testTime.Add(time.Hour), "repositories": []any{map[string]any{"id": 9, "full_name": "themartianapp/new-app", "owner": map[string]any{"login": "themartianapp"}}}},
	}
	for name, reply := range cases {
		t.Run(name, func(t *testing.T) {
			s, _, _ := orgServer(t, func(string, map[string]any) map[string]any { return reply }, func(string) Repository {
				return Repository{ID: 10, FullName: "themartianapp/new-app", Owner: RepositoryOwner{Login: "themartianapp"}}
			})
			c, err := NewApp(AppOptions{AppID: 12, Installations: map[string]int64{"themartianapp": 111}, PrivateKey: orgKey(t), Owners: []string{"themartianapp"}, HTTP: HTTPOptions{BaseURL: s.URL, Client: s.Client(), Now: func() time.Time { return testTime }}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.SourceToken(context.Background(), "themartianapp/new-app"); err == nil {
				t.Fatal("inconsistent repository identity accepted")
			}
		})
	}
}

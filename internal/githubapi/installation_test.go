package githubapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// listingServer serves an installation listing of total repositories of
// themartianapp (owner ID 900) in pages of 100, plus one of another account,
// recording each listing token's permissions and each page request.
func listingServer(t *testing.T, total int, reportedTotal int) (*Client, *[]string, *[]map[string]any) {
	t.Helper()
	var mu sync.Mutex
	var pages []string
	var permissions []map[string]any
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.URL.Path == "/app/installations/111/access_tokens":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			permissions = append(permissions, body)
			writeJSON(t, w, map[string]any{"token": "tok-list", "expires_at": testTime.Add(time.Hour)})
		case r.URL.Path == "/installation/repositories":
			if r.Header.Get("Authorization") != "Bearer tok-list" {
				t.Errorf("listing with %q", r.Header.Get("Authorization"))
			}
			page, _ := strconv.Atoi(r.URL.Query().Get("page"))
			if page == 0 {
				page = 1
			}
			pages = append(pages, r.URL.RawQuery)
			var repos []any
			for i := (page-1)*100 + 1; i <= min(page*100, total); i++ {
				repos = append(repos, map[string]any{"id": 5000 + i, "full_name": fmt.Sprintf("themartianapp/app-%d", i), "default_branch": "main", "owner": map[string]any{"login": "themartianapp", "id": 900}})
			}
			if page*100 >= total {
				repos = append(repos, map[string]any{"id": 4000, "full_name": "someone-else/app", "owner": map[string]any{"login": "someone-else", "id": 901}})
			}
			if page*100 < total {
				w.Header().Set("Link", fmt.Sprintf("<%s/installation/repositories?per_page=100&page=%d>; rel=\"next\"", "http://"+r.Host, page+1))
			}
			writeJSON(t, w, map[string]any{"total_count": reportedTotal, "repositories": repos})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(s.Close)
	c, err := NewApp(AppOptions{AppID: 12, Installations: map[string]int64{"themartianapp": 111}, PrivateKey: orgKey(t), Owners: []string{"themartianapp"}, HTTP: HTTPOptions{BaseURL: s.URL, Client: s.Client(), Now: func() time.Time { return testTime }}})
	if err != nil {
		t.Fatal(err)
	}
	return c, &pages, &permissions
}

// The installation listing follows every page, keeps only the owner's
// repositories with their owner IDs and default branches, and mints a
// metadata-only token; an unapproved owner is refused without a request.
func TestInstallationRepositoriesPaginates(t *testing.T) {
	c, pages, permissions := listingServer(t, 250, 250)
	repos, err := c.InstallationRepositories(context.Background(), "themartianapp")
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 250 || len(*pages) != 3 || repos[249].FullName != "themartianapp/app-250" || repos[0].Owner.ID != 900 || repos[0].DefaultBranch != "main" {
		t.Fatalf("listing: %d repositories over pages %v", len(repos), *pages)
	}
	for _, r := range repos {
		if r.Owner.Login != "themartianapp" {
			t.Fatalf("another account's repository listed: %+v", r)
		}
	}
	if len(*permissions) != 1 || fmt.Sprint((*permissions)[0]) != "map[permissions:map[metadata:read]]" {
		t.Fatalf("listing token request: %v", *permissions)
	}
	if _, err := c.InstallationRepositories(context.Background(), "jerryfane"); err == nil {
		t.Fatal("unapproved owner listed")
	}
}

// A listing beyond MaxInstallationRepositories is refused whole, whether
// GitHub reports the total up front or the pages exceed it.
func TestInstallationRepositoriesBound(t *testing.T) {
	for name, tc := range map[string]struct{ total, reported int }{"reported total": {120, MaxInstallationRepositories + 1}, "pages": {MaxInstallationRepositories + 1, 10}} {
		c, pages, _ := listingServer(t, tc.total, tc.reported)
		if repos, err := c.InstallationRepositories(context.Background(), "themartianapp"); err == nil {
			t.Fatalf("%s: unbounded listing accepted: %d", name, len(repos))
		}
		if len(*pages) > MaxInstallationRepositories/100+1 {
			t.Fatalf("%s: listing read %d pages", name, len(*pages))
		}
	}
}

// RegularFile returns a root regular file at a commit and reports a missing
// path, a directory, a symlink and an oversized file as absent.
func TestRegularFile(t *testing.T) {
	sha := strings.Repeat("a", 40)
	content := []byte(`{"version":1}`)
	var mode string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/app/installations/"):
			writeJSON(t, w, map[string]any{"token": "tok", "expires_at": testTime.Add(time.Hour), "repositories": []any{map[string]any{"id": 77, "full_name": "themartianapp/app", "owner": map[string]any{"login": "themartianapp"}}}})
		case r.URL.Path == "/repos/themartianapp/app":
			writeJSON(t, w, Repository{ID: 77, FullName: "themartianapp/app", Owner: RepositoryOwner{Login: "themartianapp", ID: 900}})
		case r.URL.Path == "/repos/themartianapp/app/contents/.macserve.json" && r.URL.Query().Get("ref") == sha:
			switch mode {
			case "missing":
				w.WriteHeader(http.StatusNotFound)
			case "directory":
				writeJSON(t, w, []any{map[string]any{"type": "file"}})
			case "symlink":
				writeJSON(t, w, map[string]any{"type": "symlink", "size": 3, "encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte("../"))})
			case "large":
				writeJSON(t, w, map[string]any{"type": "file", "size": 1 << 20, "encoding": "base64", "content": ""})
			default:
				writeJSON(t, w, map[string]any{"type": "file", "size": len(content), "encoding": "base64", "content": base64.StdEncoding.EncodeToString(content)})
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(s.Close)
	c, err := NewApp(AppOptions{AppID: 12, Installations: map[string]int64{"themartianapp": 111}, PrivateKey: orgKey(t), Owners: []string{"themartianapp"}, HTTP: HTTPOptions{BaseURL: s.URL, Client: s.Client(), Now: func() time.Time { return testTime }}})
	if err != nil {
		t.Fatal(err)
	}
	data, found, err := c.RegularFile(context.Background(), "themartianapp/app", sha, ".macserve.json", 16384)
	if err != nil || !found || string(data) != string(content) {
		t.Fatalf("file: %q %v %v", data, found, err)
	}
	for _, mode = range []string{"missing", "directory", "symlink", "large"} {
		if data, found, err := c.RegularFile(context.Background(), "themartianapp/app", sha, ".macserve.json", 16384); err != nil || found {
			t.Fatalf("%s: %q %v %v", mode, data, found, err)
		}
	}
	if _, _, err := c.RegularFile(context.Background(), "themartianapp/app", sha, "../x", 16384); err == nil {
		t.Fatal("path traversal accepted")
	}
}

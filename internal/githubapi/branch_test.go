package githubapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// branchClient is an App client for testRepo (ID 56) whose repository read
// reports branch as its default and whose ref read answers ref.
func branchClient(t *testing.T, branch string, ref func(path string) (int, any)) (*Client, *[]string) {
	t.Helper()
	var paths []string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/app/installations/34/access_tokens":
			writeJSON(t, w, map[string]any{"token": "scoped-56", "expires_at": testTime.Add(time.Hour)})
			return
		case r.Header.Get("Authorization") != "Bearer scoped-56" || r.Method != http.MethodGet:
			t.Errorf("%s %s without the installation token", r.Method, r.URL.Path)
		}
		paths = append(paths, r.URL.Path)
		if r.URL.Path == "/repos/"+testRepo {
			writeJSON(t, w, Repository{ID: 56, FullName: testRepo, DefaultBranch: branch})
			return
		}
		status, body := ref(r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		writeJSON(t, w, body)
	}))
	t.Cleanup(s.Close)
	c, err := NewApp(AppOptions{AppID: 12, InstallationID: 34, PrivateKey: orgKey(t), Repositories: map[string]int64{testRepo: 56}, HTTP: HTTPOptions{BaseURL: s.URL, Client: s.Client(), Now: func() time.Time { return testTime }}})
	if err != nil {
		t.Fatal(err)
	}
	return c, &paths
}

func refJSON(ref, kind, sha string) map[string]any {
	return map[string]any{"ref": ref, "object": map[string]any{"type": kind, "sha": sha}}
}

func TestDefaultBranchHeadResolvesExactCommitRef(t *testing.T) {
	c, paths := branchClient(t, "release/2.x", func(path string) (int, any) {
		return 200, refJSON("refs/heads/release/2.x", "commit", testSHA)
	})
	head, err := c.DefaultBranchHead(context.Background(), testRepo)
	if err != nil || head != (BranchHead{RepositoryID: 56, Branch: "release/2.x", SHA: testSHA}) {
		t.Fatalf("head = %+v, %v", head, err)
	}
	if want := []string{"/repos/" + testRepo, "/repos/" + testRepo + "/git/ref/heads/release/2.x"}; strings.Join(*paths, " ") != strings.Join(want, " ") {
		t.Fatalf("paths = %v", *paths)
	}
}

func TestDefaultBranchHeadRefusesAnythingButTheBranchCommit(t *testing.T) {
	for name, c := range map[string]struct {
		branch string
		status int
		body   any
	}{
		"ref mismatch":      {"main", 200, refJSON("refs/heads/main-old", "commit", testSHA)},
		"tag namespace":     {"main", 200, refJSON("refs/tags/main", "commit", testSHA)},
		"prefix match list": {"main", 200, []any{refJSON("refs/heads/main-a", "commit", testSHA)}},
		"annotated tag":     {"main", 200, refJSON("refs/heads/main", "tag", testSHA)},
		"short sha":         {"main", 200, refJSON("refs/heads/main", "commit", testSHA[:39])},
		"uppercase sha":     {"main", 200, refJSON("refs/heads/main", "commit", strings.ToUpper(testSHA))},
		"missing ref":       {"main", 404, map[string]any{"message": "Not Found"}},
		"no default branch": {"", 200, refJSON("refs/heads/", "commit", testSHA)},
		"unsafe branch":     {"main/../x", 200, refJSON("refs/heads/main/../x", "commit", testSHA)},
		"lock branch":       {"main.lock", 200, refJSON("refs/heads/main.lock", "commit", testSHA)},
	} {
		client, paths := branchClient(t, c.branch, func(string) (int, any) { return c.status, c.body })
		if head, err := client.DefaultBranchHead(context.Background(), testRepo); err == nil {
			t.Errorf("%s: accepted %+v", name, head)
		}
		if c.branch == "" || strings.Contains(c.branch, "..") || strings.HasSuffix(c.branch, ".lock") {
			if len(*paths) != 1 {
				t.Errorf("%s: read a ref for an invalid branch: %v", name, *paths)
			}
		}
	}
}

func TestDefaultBranchHeadRequiresApp(t *testing.T) {
	c, _ := tokenClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("token client contacted GitHub: %s", r.URL.Path)
	})
	if _, err := c.DefaultBranchHead(context.Background(), testRepo); err == nil || !strings.Contains(err.Error(), "requires a GitHub App") {
		t.Fatalf("token client resolved a default branch: %v", err)
	}
}

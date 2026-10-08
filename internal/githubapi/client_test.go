package githubapi

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testRepo = "example-org/example-app"
const testSHA = "0123456789abcdef0123456789abcdef01234567"

var testTime = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func tokenClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	s := httptest.NewServer(handler)
	t.Cleanup(s.Close)
	c, err := NewToken("test-secret", HTTPOptions{BaseURL: s.URL, Client: s.Client(), Now: func() time.Time { return testTime }})
	if err != nil {
		t.Fatal(err)
	}
	return c, s
}

func writeJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Error(err)
	}
}

func pullJSON(number int) map[string]any {
	return map[string]any{"number": number, "state": "open", "draft": true, "head": map[string]any{"sha": testSHA, "repo": map[string]any{"id": int64(9007199254740993)}}, "user": map[string]any{"id": int64(9007199254740995)}, "base": map[string]any{"ref": "main"}, "updated_at": testTime}
}

func checkJSON(id int64) map[string]any {
	return map[string]any{"id": id, "name": "mac-evidence/unit", "head_sha": testSHA, "external_id": "job-1", "status": "completed", "conclusion": "success", "html_url": "https://github.com/" + testRepo + "/runs/12", "app": map[string]any{"id": 23}, "output": map[string]any{"title": "Evidence", "summary": "Passed", "text": "signed-packet"}}
}

func commentJSON(origin string, id int64, body string) map[string]any {
	return map[string]any{"id": id, "body": body, "user": map[string]any{"id": 45}, "performed_via_github_app": map[string]any{"id": 67}, "issue_url": origin + "/repos/" + testRepo + "/issues/7", "created_at": testTime, "updated_at": testTime}
}

func TestAppJWTScopedCacheAndFreshRepositoryIdentity(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := testTime
	var tokens, repoReads atomic.Int64
	var mismatch atomic.Bool
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app/installations/34/access_tokens" {
			if r.Method != http.MethodPost {
				t.Errorf("token method = %s", r.Method)
			}
			parts := strings.Split(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), ".")
			if len(parts) != 3 {
				t.Error("missing App JWT")
				w.WriteHeader(401)
				return
			}
			header, err := base64.RawURLEncoding.DecodeString(parts[0])
			if err != nil || string(header) != `{"alg":"RS256","typ":"JWT"}` {
				t.Error("wrong JWT header")
			}
			payload, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				t.Error(err)
				return
			}
			var claims struct {
				Issuer  int64 `json:"iss"`
				Issued  int64 `json:"iat"`
				Expires int64 `json:"exp"`
			}
			if err := json.Unmarshal(payload, &claims); err != nil {
				t.Error(err)
				return
			}
			if claims.Issuer != 12 || claims.Issued != now.Add(-time.Minute).Unix() || claims.Expires <= now.Unix() || claims.Expires-claims.Issued > 600 {
				t.Errorf("invalid JWT claims: %+v", claims)
			}
			sig, err := base64.RawURLEncoding.DecodeString(parts[2])
			if err != nil {
				t.Error(err)
				return
			}
			digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
			if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
				t.Error(err)
			}
			var body struct {
				IDs         []int64           `json:"repository_ids"`
				Permissions map[string]string `json:"permissions"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
				return
			}
			if len(body.IDs) != 1 || (body.IDs[0] != 56 && body.IDs[0] != 78) || len(body.Permissions) != 4 || body.Permissions["contents"] != "read" || body.Permissions["metadata"] != "read" || body.Permissions["pull_requests"] != "read" || body.Permissions["checks"] != "write" {
				t.Errorf("incorrect scope: %+v", body)
			}
			n := tokens.Add(1)
			writeJSON(t, w, map[string]any{"token": fmt.Sprintf("scoped-%d-%d", body.IDs[0], n), "expires_at": now.Add(time.Hour)})
			return
		}
		repoReads.Add(1)
		id := int64(56)
		repo := testRepo
		if r.URL.Path == "/repos/example-org/second" {
			id, repo = 78, "example-org/second"
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), fmt.Sprintf("Bearer scoped-%d-", id)) {
			t.Error("repository received another repository token")
		}
		if mismatch.Load() {
			id = 99
		}
		writeJSON(t, w, Repository{ID: id, FullName: repo})
	}))
	defer server.Close()
	c, err := NewApp(AppOptions{AppID: 12, InstallationID: 34, PrivateKey: key, Repositories: map[string]int64{testRepo: 56, "example-org/second": 78}, HTTP: HTTPOptions{BaseURL: server.URL, Client: server.Client(), Now: func() time.Time { return now }}})
	if err != nil {
		t.Fatal(err)
	}
	first, err := c.SourceToken(context.Background(), testRepo)
	if err != nil || first != "scoped-56-1" {
		t.Fatalf("first source token = %q, %v", first, err)
	}
	second, err := c.SourceToken(context.Background(), testRepo)
	if err != nil || second != first || tokens.Load() != 1 || repoReads.Load() != 2 {
		t.Fatalf("cache did not preserve fresh repository validation: %q %v", second, err)
	}
	other, err := c.SourceToken(context.Background(), "example-org/second")
	if err != nil || other != "scoped-78-2" {
		t.Fatalf("other scope = %q %v", other, err)
	}
	now = now.Add(59*time.Minute + time.Second)
	refreshed, err := c.SourceToken(context.Background(), testRepo)
	if err != nil || refreshed != "scoped-56-3" {
		t.Fatalf("near-expiry refresh = %q %v", refreshed, err)
	}
	mismatch.Store(true)
	if got, err := c.SourceToken(context.Background(), testRepo); err == nil || got != "" {
		t.Fatalf("returned token for changed repository: %q %v", got, err)
	}
	before := repoReads.Load()
	if _, err := c.SourceToken(context.Background(), "example-org/not-approved"); err == nil || repoReads.Load() != before {
		t.Fatal("unapproved repository reached network")
	}
}

func TestAppConcurrentTokenRequestsMintOnce(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var minted atomic.Int64
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/app/") {
			minted.Add(1)
			writeJSON(t, w, map[string]any{"token": "scoped", "expires_at": testTime.Add(time.Hour)})
		} else {
			writeJSON(t, w, Repository{ID: 56, FullName: testRepo})
		}
	}))
	defer s.Close()
	c, err := NewApp(AppOptions{AppID: 12, InstallationID: 34, PrivateKey: key, Repositories: map[string]int64{testRepo: 56}, HTTP: HTTPOptions{BaseURL: s.URL, Now: func() time.Time { return testTime }}})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			if token, err := c.SourceToken(context.Background(), testRepo); err != nil || token != "scoped" {
				t.Errorf("source token = %q %v", token, err)
			}
		})
	}
	wg.Wait()
	if minted.Load() != 1 {
		t.Fatalf("minted %d concurrent tokens", minted.Load())
	}
}

func TestPullPaginationConditionalAndWireIdentity(t *testing.T) {
	var requests atomic.Int64
	c, _ := tokenClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != "Bearer test-secret" {
			t.Error("missing token authentication")
		}
		if r.URL.Path == "/repos/"+testRepo+"/pulls/7" {
			writeJSON(t, w, pullJSON(7))
			return
		}
		if r.Header.Get("If-None-Match") == `"new"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if r.URL.Query().Get("page") == "2" {
			if r.Header.Get("If-None-Match") != "" {
				t.Error("ETag leaked onto later page")
			}
			writeJSON(t, w, []any{pullJSON(8)})
			return
		}
		if r.URL.Query().Get("state") != "open" || r.URL.Query().Get("per_page") != "100" {
			t.Error("incorrect pull listing query")
		}
		w.Header().Set("ETag", `"new"`)
		w.Header().Set("Link", `<?page=2>; rel="next", <?page=2>; rel="last"`)
		writeJSON(t, w, []any{pullJSON(7)})
	})
	items, etag, unchanged, err := c.ListPulls(context.Background(), testRepo, `"old"`)
	if err != nil || unchanged || etag != `"new"` || len(items) != 2 {
		t.Fatalf("list = %+v %q %v %v", items, etag, unchanged, err)
	}
	if items[0].HeadRepositoryID != 9007199254740993 || items[0].AuthorID != 9007199254740995 || items[0].HeadSHA != testSHA || items[0].BaseRef != "main" || !items[0].Draft || !items[0].UpdatedAt.Equal(testTime) || items[1].Number != 8 {
		t.Fatalf("wire decode = %+v", items)
	}
	items, etag, unchanged, err = c.ListPulls(context.Background(), testRepo, etag)
	if err != nil || !unchanged || etag != `"new"` || len(items) != 0 || requests.Load() != 3 {
		t.Fatalf("conditional list = %+v %q %v %v", items, etag, unchanged, err)
	}
	p, err := c.Pull(context.Background(), testRepo, 7)
	if err != nil || p.Number != 7 || p.HeadSHA != testSHA {
		t.Fatalf("pull = %+v %v", p, err)
	}
}

func TestCommentsAndChecksRealWireAndWrites(t *testing.T) {
	var origin string
	var created, updated, commented bool
	c, s := tokenClient(t, func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/issues/comments"):
			if r.URL.Query().Get("page") == "2" {
				writeJSON(t, w, []any{commentJSON(origin, 102, "second")})
				return
			}
			if r.URL.Query().Get("since") != testTime.Format(time.RFC3339) || r.URL.Query().Get("sort") != "updated" {
				t.Error("incorrect comment cursor")
			}
			w.Header().Set("Link", `<?page=2>; rel="next"`)
			writeJSON(t, w, []any{commentJSON(origin, 101, "first")})
		case strings.HasSuffix(path, "/issues/7/comments"):
			var body map[string]string
			if r.Method != http.MethodPost {
				t.Error("comment was not POST")
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if body["body"] != "machine \"request\"\n" {
				t.Errorf("comment body = %q", body["body"])
			}
			commented = true
			w.WriteHeader(http.StatusCreated)
			writeJSON(t, w, commentJSON(origin, 103, body["body"]))
		case strings.Contains(path, "/commits/"):
			id := int64(12)
			if r.URL.Query().Get("page") == "2" {
				id = 13
			} else {
				if r.URL.Query().Get("filter") != "all" {
					t.Error("check attempts filtered away")
				}
				w.Header().Set("Link", `<?page=2>; rel="next"`)
			}
			writeJSON(t, w, map[string]any{"total_count": 2, "check_runs": []any{checkJSON(id)}})
		case strings.HasSuffix(path, "/check-runs") || strings.HasSuffix(path, "/check-runs/12"):
			if r.Method != http.MethodGet {
				var body map[string]json.RawMessage
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				if r.Method == http.MethodPost {
					created = true
					if string(body["head_sha"]) != strconv.Quote(testSHA) || string(body["external_id"]) != `"job-1"` || body["conclusion"] != nil || body["completed_at"] != nil {
						t.Errorf("invalid create payload: %s", body)
					}
				} else if r.Method == http.MethodPatch {
					updated = true
					if body["head_sha"] != nil || string(body["conclusion"]) != `"success"` || string(body["completed_at"]) != strconv.Quote(testTime.Format(time.RFC3339)) {
						t.Errorf("invalid update payload: %s", body)
					}
				} else {
					t.Errorf("unexpected method %s", r.Method)
				}
			}
			writeJSON(t, w, checkJSON(12))
		default:
			t.Errorf("unexpected endpoint %s", path)
			w.WriteHeader(404)
		}
	})
	origin = s.URL
	comments, err := c.Comments(context.Background(), testRepo, testTime)
	if err != nil || len(comments) != 2 {
		t.Fatalf("comments = %+v %v", comments, err)
	}
	if got := comments[0]; got.ID != 101 || got.AuthorID != 45 || got.AppID != 67 || got.PullRequest != 7 || !got.CreatedAt.Equal(testTime) || !got.UpdatedAt.Equal(testTime) || got.Body != "first" {
		t.Fatalf("comment decode = %+v", got)
	}
	comment, err := c.CreateComment(context.Background(), testRepo, 7, "machine \"request\"\n")
	if err != nil || comment.ID != 103 || !commented {
		t.Fatalf("create comment = %+v %v", comment, err)
	}
	checks, err := c.Checks(context.Background(), testRepo, testSHA)
	if err != nil || len(checks) != 2 || checks[1].ID != 13 {
		t.Fatalf("checks = %+v %v", checks, err)
	}
	check, err := c.Check(context.Background(), testRepo, 12)
	if err != nil || check.AppID != 23 || check.ExternalID != "job-1" || check.Output.Text != "signed-packet" || check.Conclusion != "success" {
		t.Fatalf("check decode = %+v %v", check, err)
	}
	check, err = c.CreateCheck(context.Background(), testRepo, CheckInput{Name: "mac-evidence/unit", HeadSHA: testSHA, ExternalID: "job-1", Status: "queued"})
	if err != nil || !created || check.ID != 12 {
		t.Fatalf("create check = %+v %v", check, err)
	}
	check, err = c.UpdateCheck(context.Background(), testRepo, 12, CheckInput{HeadSHA: testSHA, Status: "completed", Conclusion: "success", CompletedAt: &testTime, Output: CheckOutput{Title: "Evidence", Summary: "Passed", Text: "signed-packet"}})
	if err != nil || !updated || check.ID != 12 {
		t.Fatalf("update check = %+v %v", check, err)
	}
}

func TestPaginationRefusesCredentialEscapeAndCycles(t *testing.T) {
	var escaped atomic.Int64
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { escaped.Add(1); w.WriteHeader(500) }))
	defer evil.Close()
	for _, link := range []string{evil.URL + "/repos/" + testRepo + "/pulls?page=2", "/repos/example-org/other/pulls?page=2", "/repos/" + testRepo + "/pulls?page=2#fragment", "http://user:pass@api.github.com/repos/" + testRepo + "/pulls?page=2", "?page=2"} {
		t.Run(link, func(t *testing.T) {
			var calls atomic.Int64
			c, _ := tokenClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Link", "<"+link+">; rel=\"next\"")
				writeJSON(t, w, []any{pullJSON(7)})
			})
			items, _, _, err := c.ListPulls(context.Background(), testRepo, "")
			if err == nil || items != nil || calls.Load() > 2 {
				t.Fatalf("unsafe/looping pagination returned %v, %v (%d requests)", items, err, calls.Load())
			}
		})
	}
	if escaped.Load() != 0 {
		t.Fatalf("credentials escaped origin %d times", escaped.Load())
	}
}

func TestRedirectsAndErrorsNeverLeakSecrets(t *testing.T) {
	var reached atomic.Int64
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1); w.WriteHeader(200) }))
	defer destination.Close()
	c, _ := tokenClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", destination.URL+"/?token=test-secret")
		w.WriteHeader(http.StatusTemporaryRedirect)
		fmt.Fprint(w, "test-secret remote-sensitive-response")
	})
	_, err := c.Repository(context.Background(), testRepo)
	var apiError *Error
	if !errors.As(err, &apiError) || apiError.Status != 307 || strings.Contains(err.Error(), "secret") || reached.Load() != 0 {
		t.Fatalf("redirect outcome = %v, reached %d", err, reached.Load())
	}
	c, _ = tokenClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		fmt.Fprint(w, "test-secret remote-sensitive-response")
	})
	_, err = c.Repository(context.Background(), testRepo)
	if !errors.As(err, &apiError) || apiError.Status != 500 || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("remote error leaked: %v", err)
	}
}

func TestRetryAfterAndSecondaryRateLimit(t *testing.T) {
	for _, test := range []struct {
		name, retry, remaining, reset string
		status                        int
		delay                         time.Duration
	}{
		{"seconds", "123", "", "", 429, 123 * time.Second},
		{"date", testTime.Add(2 * time.Minute).Format(http.TimeFormat), "", "", 503, 2 * time.Minute},
		{"primary", "", "0", strconv.FormatInt(testTime.Add(4*time.Minute).Unix(), 10), 403, 4 * time.Minute},
		{"secondary", "", "", "", 403, time.Minute},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int64
			c, _ := tokenClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Retry-After", test.retry)
				w.Header().Set("X-RateLimit-Remaining", test.remaining)
				w.Header().Set("X-RateLimit-Reset", test.reset)
				w.WriteHeader(test.status)
				fmt.Fprint(w, `{"message":"sensitive secondary rate limit"}`)
			})
			for range 2 {
				_, err := c.Repository(context.Background(), testRepo)
				var apiError *Error
				if !errors.As(err, &apiError) || apiError.Status != test.status || apiError.RetryAfter != test.delay {
					t.Fatalf("rate limit = %+v, %v", apiError, err)
				}
			}
			if calls.Load() != 1 {
				t.Fatalf("backoff sent %d requests", calls.Load())
			}
		})
	}
}

func TestBoundedResponseAndPagination(t *testing.T) {
	t.Run("oversized", func(t *testing.T) {
		c, _ := tokenClient(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, strings.Repeat(" ", maxResponseBytes+1)) })
		if _, err := c.Repository(context.Background(), testRepo); err == nil {
			t.Fatal("accepted oversized response")
		}
	})
	t.Run("pages", func(t *testing.T) {
		var calls atomic.Int64
		c, _ := tokenClient(t, func(w http.ResponseWriter, r *http.Request) {
			page := calls.Add(1)
			w.Header().Set("Link", fmt.Sprintf("<?page=%d>; rel=\"next\"", page+1))
			writeJSON(t, w, []any{pullJSON(int(page))})
		})
		items, _, _, err := c.ListPulls(context.Background(), testRepo, "")
		if err == nil || items != nil || calls.Load() != maxPages {
			t.Fatalf("pagination cap = %d calls, %v", calls.Load(), err)
		}
	})
	t.Run("missing checks page", func(t *testing.T) {
		c, _ := tokenClient(t, func(w http.ResponseWriter, r *http.Request) {
			writeJSON(t, w, map[string]any{"total_count": 2, "check_runs": []any{checkJSON(12)}})
		})
		if checks, err := c.Checks(context.Background(), testRepo, testSHA); err == nil || checks != nil {
			t.Fatalf("accepted truncated checks: %+v %v", checks, err)
		}
	})
	for _, body := range []string{"null", `{"id":1} {"id":2}`, `{"id":"test-secret"}`, `{"id":`} {
		t.Run(body, func(t *testing.T) {
			c, _ := tokenClient(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
			_, err := c.Repository(context.Background(), testRepo)
			if err == nil || strings.Contains(err.Error(), "test-secret") {
				t.Fatalf("malformed response = %v", err)
			}
		})
	}
}

func TestCommentsRejectForeignOrMalformedIssueURLs(t *testing.T) {
	for _, suffix := range []string{"/issues/0", "/issues/07", "/issues/7/extra", "/issues/7?private=1", "/issues/%37", "/issues/7#fragment", "/pulls/7"} {
		t.Run(suffix, func(t *testing.T) {
			var origin string
			c, s := tokenClient(t, func(w http.ResponseWriter, r *http.Request) {
				comment := commentJSON(origin, 1, "body")
				comment["issue_url"] = origin + "/repos/" + testRepo + suffix
				writeJSON(t, w, []any{comment})
			})
			origin = s.URL
			if comments, err := c.Comments(context.Background(), testRepo, time.Time{}); err == nil || comments != nil {
				t.Fatalf("accepted URL %s: %+v %v", suffix, comments, err)
			}
		})
	}
}

func TestUnknownMutationResponseIsNotRetried(t *testing.T) {
	var writes atomic.Int64
	c, _ := tokenClient(t, func(w http.ResponseWriter, r *http.Request) {
		writes.Add(1)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		conn.Close()
	})
	_, err := c.CreateCheck(context.Background(), testRepo, CheckInput{Name: "mac-evidence/unit", HeadSHA: testSHA})
	if err == nil || writes.Load() != 1 || strings.Contains(err.Error(), "test-secret") {
		t.Fatalf("unknown write response = %v, writes %d", err, writes.Load())
	}
}

func TestCancelledRequestAndTokenClientSourceIsolation(t *testing.T) {
	var calls atomic.Int64
	c, _ := tokenClient(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); io.WriteString(w, `{}`) })
	if token, err := c.SourceToken(context.Background(), testRepo); err == nil || token != "" || calls.Load() != 0 {
		t.Fatal("Actions token was exposed to source broker")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Repository(ctx, testRepo); !errors.Is(err, context.Canceled) || calls.Load() != 0 {
		t.Fatalf("cancelled request = %v, calls %d", err, calls.Load())
	}
	for _, repo := range []string{"../example-app", "example-org/../example-app", "example-org/example-app?token=secret", "https://api.github.com", "example-org/%2e%2e"} {
		if _, err := c.Repository(context.Background(), repo); err == nil {
			t.Errorf("accepted repository %q", repo)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid repository reached network")
	}
}

func TestAppRejectsWrongTokenScopeAndRepositoryBeforeMutation(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"scope", "expired", "repository"} {
		t.Run(mode, func(t *testing.T) {
			var writes atomic.Int64
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/app/") {
					expiry := testTime.Add(time.Hour)
					repoID := int64(56)
					if mode == "scope" {
						repoID = 99
					}
					if mode == "expired" {
						expiry = testTime
					}
					writeJSON(t, w, map[string]any{"token": "scoped-secret", "expires_at": expiry, "repositories": []Repository{{ID: repoID, FullName: testRepo}}})
					return
				}
				if r.Method != http.MethodGet {
					writes.Add(1)
				}
				writeJSON(t, w, Repository{ID: 99, FullName: testRepo})
			}))
			defer s.Close()
			c, err := NewApp(AppOptions{AppID: 12, InstallationID: 34, PrivateKey: key, Repositories: map[string]int64{testRepo: 56}, HTTP: HTTPOptions{BaseURL: s.URL, Now: func() time.Time { return testTime }}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.CreateCheck(context.Background(), testRepo, CheckInput{Name: "mac-evidence/unit", HeadSHA: testSHA})
			if err == nil || writes.Load() != 0 || strings.Contains(err.Error(), "secret") {
				t.Fatalf("unsafe App mutation: writes=%d err=%v", writes.Load(), err)
			}
		})
	}
}

func TestForeignCommentOriginAndIdentityAreRejected(t *testing.T) {
	for _, issueURL := range []string{"https://api.github.com/repos/" + testRepo + "/issues/7", "/repos/" + testRepo + "/issues/7", "https://api.github.com/repos/example-org/other/issues/7"} {
		t.Run(issueURL, func(t *testing.T) {
			c, _ := tokenClient(t, func(w http.ResponseWriter, r *http.Request) {
				comment := commentJSON("", 1, "body")
				comment["issue_url"] = issueURL
				writeJSON(t, w, []any{comment})
			})
			if comments, err := c.Comments(context.Background(), testRepo, time.Time{}); err == nil || comments != nil {
				t.Fatalf("accepted foreign comment: %+v %v", comments, err)
			}
		})
	}
}

func TestCheckListRejectsMissingEnvelopeAndExcessiveCount(t *testing.T) {
	for _, body := range []string{`{}`, `{"total_count":0,"check_runs":null}`, `{"check_runs":[]}`, `{"total_count":10001,"check_runs":[]}`} {
		t.Run(body, func(t *testing.T) {
			c, _ := tokenClient(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
			if checks, err := c.Checks(context.Background(), testRepo, testSHA); err == nil || checks != nil {
				t.Fatalf("accepted invalid check listing: %+v %v", checks, err)
			}
		})
	}
}

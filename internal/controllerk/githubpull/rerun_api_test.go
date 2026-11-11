package githubpull_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/controllerconfig"
	"github.com/jerryfane/macserve/internal/controllerk/api"
	"github.com/jerryfane/macserve/internal/controllerk/controller"
	"github.com/jerryfane/macserve/internal/controllerk/githubpull"
	"github.com/jerryfane/macserve/internal/evidence"
)

const (
	adminToken  = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	readerToken = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
)

func apiPrincipal(token, id string, scopes ...string) controllerconfig.Principal {
	sum := sha256.Sum256([]byte(token))
	return controllerconfig.Principal{ID: id, TokenSHA256: hex.EncodeToString(sum[:]), Repositories: []string{"themartianapp/app"}, Scopes: scopes}
}

// rerunHandler is the real API handler over the fixture's store, with the
// real poller's Rerun (or none, pull mode off).
func rerunHandler(t *testing.T, x *githubpull.RerunFixture, pullMode bool) http.Handler {
	t.Helper()
	principals := []controllerconfig.Principal{
		apiPrincipal(adminToken, "owner", "jobs:read", "service:admin"),
		apiPrincipal(readerToken, "reader", "jobs:submit", "jobs:read", "jobs:cancel"),
	}
	if err := x.Store.ReplacePrincipals(context.Background(), principals); err != nil {
		t.Fatal(err)
	}
	options := api.Options{Store: x.Store, Profiles: x.Profiles, Now: x.Now,
		Status: func(context.Context) (controller.Status, error) { return controller.Status{}, nil },
		Artifact: func(context.Context, string, string) (*os.File, evidence.Artifact, error) {
			return nil, evidence.Artifact{}, os.ErrNotExist
		},
		Receipt: func(context.Context, string) (json.RawMessage, error) { return nil, controller.ErrNotReady }}
	if pullMode {
		options.GitHubRerun = x.Poller.Rerun
	}
	h, err := api.New(options)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func postRerun(h http.Handler, token, body string) (int, map[string]any) {
	r := httptest.NewRequest(http.MethodPost, "/v1/admin/github/rerun", strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var value map[string]any
	json.Unmarshal(w.Body.Bytes(), &value)
	return w.Code, value
}

func errorCode(value map[string]any) string {
	e, _ := value["error"].(map[string]any)
	code, _ := e["code"].(string)
	return code
}

// POST /v1/admin/github/rerun through the real handler, store and poller:
// service:admin only; 200 while the attempt is queued, 202 with the new
// attempt on the same check after a terminal one, 429 over two per hour,
// 404 for an unknown run, 409 for a closed pull request, 400 for a malformed
// body.
func TestAdminGitHubRerunHandler(t *testing.T) {
	x := githubpull.NewRerunFixture(t)
	h := rerunHandler(t, x, true)
	first := x.Current(t)
	body := `{"repo":"` + x.Repo + `","sha":"` + x.SHA + `","profile":"` + githubpull.RerunProfile + `"}`

	if code, value := postRerun(h, "", body); code != 401 {
		t.Fatalf("unauthenticated: %d %v", code, value)
	}
	x.End(t)
	if code, value := postRerun(h, readerToken, body); code != 403 || errorCode(value) != "forbidden" {
		t.Fatalf("non-admin principal: %d %v", code, value)
	}
	if run := x.Current(t); run.JobID != first.JobID {
		t.Fatal("a refused request started an attempt")
	}

	code, value := postRerun(h, adminToken, body)
	second := x.Current(t)
	if code != 202 || value["rerun"] != true || value["job_id"] != second.JobID || second.JobID == first.JobID || value["attempt_id"] != second.AttemptID ||
		value["run_key"] != first.Key || value["check_name"] != "mac-evidence/"+githubpull.RerunProfile || second.CheckID != first.CheckID {
		t.Fatalf("rerun: %d %v (run %+v, first %+v)", code, value, second, first)
	}
	if code, value := postRerun(h, adminToken, body); code != 200 || value["rerun"] != false || value["job_id"] != second.JobID {
		t.Fatalf("rerun of a queued attempt: %d %v", code, value)
	}
	x.End(t)
	byID := `{"repository_id":501,"sha":"` + x.SHA + `","profile":"` + githubpull.RerunProfile + `"}`
	if code, value := postRerun(h, adminToken, byID); code != 202 || value["rerun"] != true {
		t.Fatalf("rerun by repository_id: %d %v", code, value)
	}
	x.End(t)
	if code, value := postRerun(h, adminToken, body); code != 429 || errorCode(value) != "rerun_limit" {
		t.Fatalf("third rerun within the hour: %d %v", code, value)
	}

	unknown := `{"repo":"` + x.Repo + `","sha":"` + strings.Repeat("9", 40) + `","profile":"` + githubpull.RerunProfile + `"}`
	if code, value := postRerun(h, adminToken, unknown); code != 404 || errorCode(value) != "not_found" {
		t.Fatalf("unknown run: %d %v", code, value)
	}
	for _, bad := range []string{`{"sha":"` + x.SHA + `","profile":"p"}`, `{"repo":"no-slash","sha":"` + x.SHA + `","profile":"p"}`, `{"repo":"` + x.Repo + `","sha":"` + x.SHA + `"}`, `{"repo":"` + x.Repo + `","sha":"` + x.SHA + `","profile":"p","extra":1}`} {
		if code, value := postRerun(h, adminToken, bad); code != 400 || errorCode(value) != "invalid_request" {
			t.Fatalf("malformed %s: %d %v", bad, code, value)
		}
	}
	x.Close()
	if code, value := postRerun(h, adminToken, body); code != 409 || errorCode(value) != "not_eligible" {
		t.Fatalf("closed pull request: %d %v", code, value)
	}
}

// Without GitHub pull mode the route refuses with 422 (an unknown route,
// as before #119, was 404), still for service:admin only.
func TestAdminGitHubRerunWithoutPullMode(t *testing.T) {
	x := githubpull.NewRerunFixture(t)
	h := rerunHandler(t, x, false)
	body := `{"repo":"` + x.Repo + `","sha":"` + x.SHA + `","profile":"` + githubpull.RerunProfile + `"}`
	if code, value := postRerun(h, adminToken, body); code != 422 || errorCode(value) != "unsupported_request" {
		t.Fatalf("without pull mode: %d %v", code, value)
	}
	if code, value := postRerun(h, readerToken, body); code != 403 {
		t.Fatalf("non-admin without pull mode: %d %v", code, value)
	}
}

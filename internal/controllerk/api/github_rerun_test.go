package api

import (
	"strings"
	"testing"
)

// POST /v1/admin/github/rerun is a route (#119): without GitHub pull mode it
// refuses as unsupported (422), not as an unknown route (404), and a
// malformed body is 400. The full mapping through the real poller is
// githubpull's TestAdminGitHubRerunHandler.
func TestGitHubRerunRouteWithoutPullMode(t *testing.T) {
	f := setup(t)
	body := `{"repo":"example-org/example-app","sha":"` + strings.Repeat("a", 40) + `","profile":"build-v1"}`
	if w := perform(f.handler, "POST", "/v1/admin/github/rerun", testToken, "", body); w.Code != 422 || !strings.Contains(w.Body.String(), `"unsupported_request"`) {
		t.Fatalf("without pull mode: %d %s", w.Code, w.Body.String())
	}
	if w := perform(f.handler, "POST", "/v1/admin/github/rerun", testToken, "", `{"sha":"x"}`); w.Code != 400 {
		t.Fatalf("malformed: %d %s", w.Code, w.Body.String())
	}
}

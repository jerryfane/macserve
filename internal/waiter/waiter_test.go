package waiter_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/githubapi"
	"github.com/jerryfane/macserve/internal/githubpull"
	"github.com/jerryfane/macserve/internal/receipt"
	"github.com/jerryfane/macserve/internal/waiter"
)

const fixtureRepo = "example-org/example-app"
const fixtureJob = "0123456789abcdef0123456789abcdef"
const fixtureAttempt = "attempt-1"
const fixtureCheckID = int64(81)
const fixtureCommentID = int64(91)
const fixtureAppID = int64(41)
const fixtureRepoID = int64(31)
const fixturePR = 7
const fixtureRequest = "actions:123456:1"

type wire struct {
	t                            *testing.T
	mu                           sync.Mutex
	server                       *httptest.Server
	options                      waiter.Options
	raw                          json.RawMessage
	postedBody                   string
	posts, pulls, lists, details int
	unexpected                   int
	head                         func(int) string
	list                         func(int, int) []map[string]any
	detail                       func(int, map[string]any) map[string]any
	comment                      func(map[string]any)
	intercept                    func(http.ResponseWriter, *http.Request) bool
}

func newWire(t *testing.T) *wire {
	t.Helper()
	raw, expected, keys := signedFixture(t, nil)
	f := &wire{t: t, raw: raw}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	client, err := githubapi.NewToken("fixture-short-lived-actions-token", githubapi.HTTPOptions{Client: f.server.Client(), BaseURL: f.server.URL})
	if err != nil {
		t.Fatal(err)
	}
	f.options = waiter.Options{Client: client, Repo: fixtureRepo, RepositoryID: fixtureRepoID, PullRequest: fixturePR, Profile: expected.Profile, RequestID: fixtureRequest, Mode: "ensure", AppID: fixtureAppID, Expected: expected, Keys: keys, Timeout: 3 * time.Second, PollInterval: time.Millisecond}
	return f
}

func (f *wire) packet() githubpull.Packet {
	digest, err := receipt.Digest(f.raw)
	if err != nil {
		f.t.Fatal(err)
	}
	bodyDigest := sha256.Sum256([]byte(f.postedBody))
	return githubpull.Packet{Schema: 1, JobID: fixtureJob, AttemptID: fixtureAttempt, Requests: []githubpull.Correlation{{CommentID: fixtureCommentID, RequestID: fixtureRequest, BodySHA256: hex.EncodeToString(bodyDigest[:])}}, Receipt: f.raw, ReceiptDigest: digest}
}

func packetText(t *testing.T, packet githubpull.Packet) string {
	t.Helper()
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(packet); err != nil {
		t.Fatal(err)
	}
	return strings.TrimSuffix(body.String(), "\n")
}

func (f *wire) check() map[string]any {
	return map[string]any{"id": fixtureCheckID, "name": "mac-evidence/" + f.options.Profile, "head_sha": f.options.Expected.SHA, "external_id": fixtureJob, "status": "completed", "conclusion": "success", "html_url": "https://github.com/" + fixtureRepo + "/runs/81", "app": map[string]any{"id": fixtureAppID}, "output": githubapi.CheckOutput{Title: "Mac evidence", Summary: "Verified tests", Text: packetText(f.t, f.packet())}}
}

func (f *wire) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if r.Header.Get("Authorization") != "Bearer fixture-short-lived-actions-token" {
		f.t.Error("workflow token missing from GitHub request")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if f.intercept != nil && f.intercept(w, r) {
		return
	}
	base := "/repos/" + fixtureRepo
	var response any
	switch {
	case r.Method == http.MethodGet && r.URL.Path == base:
		response = map[string]any{"id": fixtureRepoID, "full_name": fixtureRepo}
	case r.Method == http.MethodGet && r.URL.Path == base+"/pulls/7":
		f.pulls++
		sha := f.options.Expected.SHA
		if f.head != nil {
			sha = f.head(f.pulls)
		}
		response = map[string]any{"number": fixturePR, "state": "open", "draft": false, "head": map[string]any{"sha": sha, "repo": map[string]any{"id": fixtureRepoID}}, "user": map[string]any{"id": 71}, "base": map[string]any{"ref": "main"}}
	case r.Method == http.MethodPost && r.URL.Path == base+"/issues/7/comments":
		f.posts++
		var request struct {
			Body string `json:"body"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			f.t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.postedBody = request.Body
		stamp := "2026-10-08T12:00:00Z"
		comment := map[string]any{"id": fixtureCommentID, "body": request.Body, "issue_url": f.server.URL + base + "/issues/7", "user": map[string]any{"id": 51}, "created_at": stamp, "updated_at": stamp}
		if f.comment != nil {
			f.comment(comment)
		}
		response = comment
		w.WriteHeader(http.StatusCreated)
	case r.Method == http.MethodGet && r.URL.Path == base+"/commits/"+f.options.Expected.SHA+"/check-runs":
		page := 1
		if r.URL.Query().Get("page") == "2" {
			page = 2
		}
		if page == 1 {
			f.lists++
		}
		checks := []map[string]any{}
		if f.list != nil {
			checks = f.list(f.lists, page)
		} else if page == 1 {
			spoof := f.check()
			spoof["id"] = int64(999)
			spoof["app"] = map[string]any{"id": fixtureAppID + 1}
			wrongName := f.check()
			wrongName["id"] = int64(998)
			wrongName["name"] = "mac-evidence/another-profile"
			checks = []map[string]any{spoof, wrongName}
		} else {
			checks = []map[string]any{f.check()}
		}
		if page == 1 {
			w.Header().Set("Link", "<"+f.server.URL+r.URL.Path+"?per_page=100&page=2>; rel=\"next\"")
		}
		response = map[string]any{"total_count": 0, "check_runs": checks}
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, base+"/check-runs/"):
		f.details++
		id, err := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, base+"/check-runs/"), 10, 64)
		if err != nil {
			f.t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		check := f.check()
		check["id"] = id
		if f.detail != nil {
			check = f.detail(f.details, check)
		}
		response = check
	default:
		f.unexpected++
		f.t.Errorf("unexpected GitHub operation: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(response); err != nil {
		f.t.Error(err)
		return
	}
	// Deadline scenarios intentionally disconnect. Encoding is a fixture
	// invariant; successful network delivery after client cancellation is not.
	_, _ = w.Write(body.Bytes())
}

func TestWaiterPostsExactRequestAndVerifiesPaginatedCurrentEvidence(t *testing.T) {
	for _, mode := range []string{"ensure", "rerun"} {
		t.Run(mode, func(t *testing.T) {
			f := newWire(t)
			f.options.Mode = mode
			// Discover the head through GitHub instead of relying on a merge SHA.
			options := f.options
			options.Expected.SHA = ""
			result, err := waiter.Run(context.Background(), options)
			if err != nil {
				t.Fatal(err)
			}
			wantDigest, err := receipt.Digest(f.raw)
			if err != nil {
				t.Fatal(err)
			}
			if result.JobID != fixtureJob || result.ReceiptDigest != wantDigest || result.CheckURL != "https://github.com/"+fixtureRepo+"/runs/81" {
				t.Fatalf("wrong verified result: %+v", result)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			wantBody := fmt.Sprintf("/mac-evidence sha=%s profile=%s request=%s mode=%s", f.options.Expected.SHA, f.options.Profile, fixtureRequest, mode)
			if f.postedBody != wantBody || f.posts != 1 {
				t.Fatalf("machine request = %q (%d posts)", f.postedBody, f.posts)
			}
			if f.details != 1 || f.pulls != 3 || f.unexpected != 0 {
				t.Fatalf("verification did not retrieve exact check and final head: details=%d pulls=%d unexpected=%d", f.details, f.pulls, f.unexpected)
			}
		})
	}
}

func TestWaiterRejectsUntrustedOrMismatchedEvidence(t *testing.T) {
	tests := []struct {
		name   string
		change func(*wire, map[string]any, *githubpull.Packet)
	}{
		{"wrong-app-on-detail", func(f *wire, c map[string]any, p *githubpull.Packet) {
			c["app"] = map[string]any{"id": fixtureAppID + 1}
		}},
		{"wrong-name-on-detail", func(f *wire, c map[string]any, p *githubpull.Packet) { c["name"] = "mac-evidence/not-the-profile" }},
		{"wrong-check-id", func(f *wire, c map[string]any, p *githubpull.Packet) { c["id"] = fixtureCheckID + 1 }},
		{"wrong-check-head", func(f *wire, c map[string]any, p *githubpull.Packet) { c["head_sha"] = strings.Repeat("e", 40) }},
		{"wrong-external-id", func(f *wire, c map[string]any, p *githubpull.Packet) { c["external_id"] = "different-job" }},
		{"wrong-request-id", func(f *wire, c map[string]any, p *githubpull.Packet) { p.Requests[0].RequestID = "actions:123456:2" }},
		{"wrong-body-digest", func(f *wire, c map[string]any, p *githubpull.Packet) {
			p.Requests[0].BodySHA256 = strings.Repeat("0", 64)
		}},
		{"duplicate-correlation", func(f *wire, c map[string]any, p *githubpull.Packet) { p.Requests = append(p.Requests, p.Requests[0]) }},
		{"wrong-packet-job", func(f *wire, c map[string]any, p *githubpull.Packet) {
			p.JobID = "another-job"
			c["external_id"] = p.JobID
		}},
		{"wrong-packet-attempt", func(f *wire, c map[string]any, p *githubpull.Packet) { p.AttemptID = "attempt-2" }},
		{"missing-receipt", func(f *wire, c map[string]any, p *githubpull.Packet) { p.Receipt = nil }},
		{"null-receipt", func(f *wire, c map[string]any, p *githubpull.Packet) { p.Receipt = json.RawMessage("null") }},
		{"wrong-receipt-digest", func(f *wire, c map[string]any, p *githubpull.Packet) { p.ReceiptDigest = strings.Repeat("0", 64) }},
		{"tampered-signed-payload", func(f *wire, c map[string]any, p *githubpull.Packet) {
			p.Receipt = bytes.Replace(p.Receipt, []byte(fixtureAttempt), []byte("attempt-9"), 1)
		}},
		{"unknown-key", func(f *wire, c map[string]any, p *githubpull.Packet) {
			p.Receipt = bytes.Replace(p.Receipt, []byte(`"key_id":"fixture-key"`), []byte(`"key_id":"revoked-key"`), 1)
		}},
		{"trailing-publication", func(f *wire, c map[string]any, p *githubpull.Packet) {
			c["output"] = githubapi.CheckOutput{Text: packetText(t, *p) + "{}"}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newWire(t)
			f.detail = func(_ int, check map[string]any) map[string]any {
				packet := f.packet()
				delete(check, "output")
				test.change(f, check, &packet)
				if _, ok := check["output"]; !ok {
					check["output"] = githubapi.CheckOutput{Text: packetText(t, packet)}
				}
				return check
			}
			if result, err := waiter.Run(context.Background(), f.options); err == nil {
				t.Fatalf("accepted mismatched evidence: %+v", result)
			}
		})
	}
}

func TestWaiterRequiresExactPinnedReceiptPolicy(t *testing.T) {
	tests := []struct {
		name   string
		change func(*receipt.Expected)
	}{
		{"recipe", func(e *receipt.Expected) { e.ProfileDigest = strings.Repeat("a", 64) }},
		{"xcode-version", func(e *receipt.Expected) { e.Xcode.Version = "99.0" }},
		{"xcode-build", func(e *receipt.Expected) { e.Xcode.Build = "99A999" }},
		{"runtime-build", func(e *receipt.Expected) { e.Simulator.RuntimeBuild = "99A999" }},
		{"runtime-id", func(e *receipt.Expected) { e.Simulator.Runtime = "com.apple.CoreSimulator.SimRuntime.iOS-99-0" }},
		{"device-type", func(e *receipt.Expected) { e.Simulator.DeviceType = "com.apple.CoreSimulator.SimDeviceType.iPhone-99" }},
		{"required-tests", func(e *receipt.Expected) { e.RequiredTests = []string{"NeverExecuted"} }},
		{"job-kind", func(e *receipt.Expected) { e.Kind = "build" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newWire(t)
			test.change(&f.options.Expected)
			if _, err := waiter.Run(context.Background(), f.options); err == nil {
				t.Fatal("accepted evidence outside the pinned policy")
			}
		})
	}
}

func TestWaiterRejectsEveryNonSuccessConclusion(t *testing.T) {
	for _, conclusion := range []string{"failure", "cancelled", "timed_out", "neutral", "skipped", "action_required", "stale", ""} {
		t.Run(conclusion, func(t *testing.T) {
			f := newWire(t)
			f.detail = func(_ int, check map[string]any) map[string]any { check["conclusion"] = conclusion; return check }
			if _, err := waiter.Run(context.Background(), f.options); err == nil {
				t.Fatal("non-success conclusion cleared gate")
			}
		})
	}
}

func TestWaiterRejectsHeadChangeBeforeReturningSuccess(t *testing.T) {
	f := newWire(t)
	f.head = func(n int) string {
		if n >= 3 {
			return strings.Repeat("e", 40)
		}
		return f.options.Expected.SHA
	}
	if _, err := waiter.Run(context.Background(), f.options); err == nil || !strings.Contains(err.Error(), "superseded") {
		t.Fatalf("head race did not supersede success: %v", err)
	}
}

func TestWaiterRejectsContradictoryHeadWithoutPosting(t *testing.T) {
	f := newWire(t)
	options := f.options
	options.Expected.SHA = strings.Repeat("e", 40)
	if _, err := waiter.Run(context.Background(), options); err == nil {
		t.Fatal("accepted merge or stale SHA")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.posts != 0 {
		t.Fatal("posted request for contradictory SHA")
	}
}

func TestWaiterRejectsChangedCommentResponse(t *testing.T) {
	for _, edit := range []bool{false, true} {
		t.Run(strconv.FormatBool(edit), func(t *testing.T) {
			f := newWire(t)
			f.comment = func(comment map[string]any) {
				if edit {
					comment["updated_at"] = "2026-10-08T12:01:00Z"
				} else {
					comment["body"] = "changed request"
				}
			}
			if _, err := waiter.Run(context.Background(), f.options); err == nil {
				t.Fatal("accepted mutable request identity")
			}
		})
	}
}

func TestWaiterNeverAcceptsOlderCheckOrUnrelatedComment(t *testing.T) {
	for _, newer := range []bool{false, true} {
		t.Run(strconv.FormatBool(newer), func(t *testing.T) {
			f := newWire(t)
			f.options.Timeout = 250 * time.Millisecond
			if newer {
				f.list = func(_ int, page int) []map[string]any {
					if page == 1 {
						return []map[string]any{f.check()}
					}
					check := f.check()
					check["id"] = fixtureCheckID + 1
					return []map[string]any{check}
				}
			}
			f.detail = func(_ int, check map[string]any) map[string]any {
				packet := f.packet()
				packet.Requests[0].CommentID++
				check["output"] = githubapi.CheckOutput{Text: packetText(t, packet)}
				return check
			}
			if _, err := waiter.Run(context.Background(), f.options); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("unaccepted request should time out, got %v", err)
			}
		})
	}
}

func TestWaiterFailsWhenAcceptedAttemptIsReplaced(t *testing.T) {
	for _, newCheck := range []bool{false, true} {
		t.Run(strconv.FormatBool(newCheck), func(t *testing.T) {
			f := newWire(t)
			if newCheck {
				f.list = func(n, page int) []map[string]any {
					if page == 1 {
						return []map[string]any{}
					}
					check := f.check()
					if n > 1 {
						check["id"] = fixtureCheckID + 1
					}
					return []map[string]any{check}
				}
			}
			f.detail = func(n int, check map[string]any) map[string]any {
				if n == 1 {
					check["status"] = "queued"
					check["conclusion"] = ""
				} else {
					packet := f.packet()
					packet.AttemptID = "next-attempt"
					check["output"] = githubapi.CheckOutput{Text: packetText(t, packet)}
				}
				return check
			}
			if _, err := waiter.Run(context.Background(), f.options); err == nil || !strings.Contains(err.Error(), "superseded") {
				t.Fatalf("accepted superseded attempt: %v", err)
			}
		})
	}
}

func TestWaiterHonorsRetryAfterWithinOverallTimeout(t *testing.T) {
	f := newWire(t)
	f.options.Timeout = 250 * time.Millisecond
	attempts := 0
	f.intercept = func(w http.ResponseWriter, r *http.Request) bool {
		if !strings.Contains(r.URL.Path, "/commits/") {
			return false
		}
		attempts++
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		return true
	}
	if _, err := waiter.Run(context.Background(), f.options); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Retry-After wait escaped overall timeout: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if attempts != 1 || f.posts != 1 || f.unexpected != 0 {
		t.Fatalf("rate limit caused duplicate requests or job mutation: attempts=%d posts=%d unexpected=%d", attempts, f.posts, f.unexpected)
	}
}

func TestWaiterCancellationDoesNotCancelSharedMacJob(t *testing.T) {
	f := newWire(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.detail = func(_ int, check map[string]any) map[string]any {
		check["status"] = "in_progress"
		check["conclusion"] = ""
		cancel()
		return check
	}
	if _, err := waiter.Run(ctx, f.options); !errors.Is(err, context.Canceled) {
		t.Fatalf("wait cancellation = %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.posts != 1 || f.unexpected != 0 {
		t.Fatalf("cancellation mutated remote work: posts=%d unexpected=%d", f.posts, f.unexpected)
	}
}

func TestWaiterUnknownCommentOutcomeDoesNotPostAgain(t *testing.T) {
	f := newWire(t)
	attempts := 0
	f.intercept = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != http.MethodPost {
			return false
		}
		attempts++
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusServiceUnavailable)
		return true
	}
	if _, err := waiter.Run(context.Background(), f.options); err == nil {
		t.Fatal("accepted unknown comment outcome")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if attempts != 1 {
		t.Fatalf("retried potentially admitted request %d times", attempts)
	}
}

func TestWaiterRejectsInvalidMachineIdentityBeforeAPIMutation(t *testing.T) {
	for _, request := range []string{"actions:0:1", "actions:01:1", "actions:9223372036854775808:1", "actions:1:1\nmode=rerun", "human:1:1"} {
		t.Run(request, func(t *testing.T) {
			f := newWire(t)
			f.options.RequestID = request
			if _, err := waiter.Run(context.Background(), f.options); err == nil {
				t.Fatal("accepted non-machine request")
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.posts != 0 {
				t.Fatal("posted malformed machine request")
			}
		})
	}
}

func TestWaiterWaitsForAcceptanceThenCurrentCompletion(t *testing.T) {
	f := newWire(t)
	f.detail = func(n int, check map[string]any) map[string]any {
		packet := f.packet()
		if n == 1 {
			packet.Requests = nil
		}
		if n == 2 {
			check["status"] = "in_progress"
			check["conclusion"] = ""
		}
		check["output"] = githubapi.CheckOutput{Text: packetText(t, packet)}
		return check
	}
	if result, err := waiter.Run(context.Background(), f.options); err != nil || result.JobID != fixtureJob {
		t.Fatalf("current attempt did not complete: %+v %v", result, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.details != 3 {
		t.Fatalf("accepted unrelated or unfinished check after %d reads", f.details)
	}
}

func TestWaiterRetriesAfterGitHubRateLimit(t *testing.T) {
	f := newWire(t)
	f.options.Timeout = 5 * time.Second
	var limitedAt time.Time
	var elapsed time.Duration
	attempts := 0
	f.intercept = func(w http.ResponseWriter, r *http.Request) bool {
		if !strings.Contains(r.URL.Path, "/commits/") || r.URL.Query().Get("page") == "2" {
			return false
		}
		attempts++
		if attempts == 1 {
			limitedAt = time.Now()
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return true
		}
		elapsed = time.Since(limitedAt)
		return false
	}
	if _, err := waiter.Run(context.Background(), f.options); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if attempts != 2 || elapsed < time.Second {
		t.Fatalf("rate-limit backoff not honored: attempts=%d delay=%s", attempts, elapsed)
	}
}

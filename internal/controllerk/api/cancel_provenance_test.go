package api

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode"

	"github.com/jerryfane/macserve/internal/controllerk/store"
)

// captureLog collects the standard logger's output for the test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous, flags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(previous); log.SetFlags(flags) })
	return &buf
}

// cancelVia sends a client cancel from remote with the given headers.
func cancelVia(f *fixture, id, remote, reason string, header map[string]string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"reason": reason})
	r := httptest.NewRequest(http.MethodPost, "/v1/jobs/"+id+"/cancel", bytes.NewReader(body))
	r.RemoteAddr = remote
	r.Header.Set("Authorization", "Bearer "+testToken)
	r.Header.Set("Content-Type", "application/json")
	for name, value := range header {
		r.Header.Set(name, value)
	}
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	return w
}

// A client cancel through the keyring logs who sent it (peer, User-Agent,
// forwarding headers, the names but never the values of X-Keyring-* headers,
// principal, reason, request ID) and appends the peer and forwarded identity
// to the recorded cancel reason's detail.
func TestClientCancelRecordsProvenance(t *testing.T) {
	f := setup(t)
	logged := captureLog(t)
	job := f.submit(t, "provenance")
	w := cancelVia(f, job.ID, "100.111.92.43:51234", "superseded", map[string]string{
		"User-Agent":       "Python-urllib/3.12",
		"X-Forwarded-For":  "203.0.113.7, 10.0.0.2",
		"Forwarded":        "for=203.0.113.7;proto=https",
		"X-Keyring-Caller": "router-proof-secret",
	})
	if w.Code != 200 {
		t.Fatalf("cancel %d: %s", w.Code, w.Body.String())
	}
	wantDetail := `superseded [via remote=100.111.92.43:51234 ua="Python-urllib/3.12" xff="203.0.113.7, 10.0.0.2" forwarded="for=203.0.113.7;proto=https"]`
	cause, _ := decodeView(t, w.Body.Bytes())["cancel_reason"].(map[string]any)
	if cause["source"] != "client" || cause["principal"] != "coordinator" || cause["detail"] != wantDetail {
		t.Fatalf("cancel reason %v, want detail %s", cause, wantDetail)
	}
	requestID := w.Header().Get("X-Request-ID")
	wantLog := "controller client cancel: job=" + job.ID + ` principal="coordinator" remote=100.111.92.43:51234 ua="Python-urllib/3.12" xff="203.0.113.7, 10.0.0.2" forwarded="for=203.0.113.7;proto=https" keyring="X-Keyring-Caller" reason="superseded" request_id=` + requestID + ` result="state=cancelled"` + "\n"
	if requestID == "" || logged.String() != wantLog {
		t.Fatalf("log %q\nwant %q", logged.String(), wantLog)
	}
	if strings.Contains(logged.String()+w.Body.String(), "router-proof-secret") {
		t.Fatal("an X-Keyring-* header value was recorded")
	}
}

// Caller-supplied headers and reasons cannot inject log lines or control
// characters, and stay bounded: the detail keeps its provenance within
// store.MaxCancelDetailBytes by cutting the reason.
func TestClientCancelProvenanceSanitizedAndBounded(t *testing.T) {
	f := setup(t)
	logged := captureLog(t)
	job := f.submit(t, "hostile")
	forged := "evil\r\ncontroller client cancel: job=forged\x1b[31m\"\\\u2028\x00\xff"
	long := strings.Repeat("é", 400)
	w := cancelVia(f, job.ID, "192.0.2.9:4444", "stop\nnow "+strings.Repeat("r", 1000), map[string]string{
		"User-Agent":      forged + long,
		"X-Forwarded-For": forged + long,
		"Forwarded":       forged + long,
	})
	if w.Code != 200 {
		t.Fatalf("cancel %d: %s", w.Code, w.Body.String())
	}
	out := logged.String()
	if strings.Count(out, "\n") != 1 || !strings.HasPrefix(out, "controller client cancel: job="+job.ID+" ") || strings.Contains(out, "job=forged\n") {
		t.Fatalf("log is not one line: %q", out)
	}
	if strings.IndexFunc(strings.TrimSuffix(out, "\n"), func(r rune) bool { return !unicode.IsPrint(r) }) >= 0 {
		t.Fatalf("log carries a non-printable rune: %q", out)
	}
	sanitized := `evil??controller client cancel: job=forged?[31m'/???é`
	if !strings.Contains(out, `ua="`+sanitized) || !strings.Contains(out, `reason="stop\nnow rrr`) {
		t.Fatalf("log values not sanitized: %q", out)
	}
	// Each header value is held to 256 bytes and the reason to 512.
	if len(out) > 4*256+store.MaxCancelDetailBytes+512 {
		t.Fatalf("log line of %d bytes is not bounded", len(out))
	}

	cause, _ := decodeView(t, w.Body.Bytes())["cancel_reason"].(map[string]any)
	detail, _ := cause["detail"].(string)
	if len(detail) > store.MaxCancelDetailBytes || !strings.HasPrefix(detail, "stop\nnow rrr") || !strings.Contains(detail, " [via remote=192.0.2.9:4444 ua=\""+sanitized) || !strings.HasSuffix(detail, `"]`) {
		t.Fatalf("detail of %d bytes: %q", len(detail), detail)
	}
	via := detail[strings.Index(detail, " [via "):]
	if strings.IndexFunc(via, func(r rune) bool { return !unicode.IsPrint(r) }) >= 0 || strings.Count(via, `"`) != 6 {
		t.Fatalf("provenance not sanitized: %q", via)
	}
}

// A cancel the store refuses is still logged with its sender.
func TestRefusedClientCancelIsLogged(t *testing.T) {
	f := setup(t)
	logged := captureLog(t)
	job := f.submit(t, "refused")
	w := cancelVia(f, job.ID, "192.0.2.10:5555", strings.Repeat("x", store.MaxReasonBytes+1), map[string]string{"User-Agent": "curl/8.5.0"})
	if w.Code == 200 || w.Code == 202 {
		t.Fatalf("oversized reason accepted: %d", w.Code)
	}
	if out := logged.String(); !strings.Contains(out, "job="+job.ID+` principal="coordinator" remote=192.0.2.10:5555 ua="curl/8.5.0"`) || !strings.Contains(out, `result="error=`) {
		t.Fatalf("refused cancel log: %q", out)
	}
}

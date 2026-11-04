package onboarding

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/receipt"
)

// canonicalJSON re-encodes v with sorted keys, no spaces and no HTML
// escaping, the receipt package's canonical form.
func canonicalJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var generic any
	if err := d.Decode(&generic); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(generic); err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}

// sentRequest is what TestSubmitRequestShape's Submit sends.
var sentRequest = model.Request{Repo: "jdoe/app", SHA: testSHA, Kind: "build", Profile: "org-ios-sim-build-v1", Xcode: model.Xcode{Version: "16.2", Build: "16C5032a"}}

// receiptFixture is a signed, complete, successful receipt envelope for
// jobID and sentRequest, signed by priv under key ID "k1"; edit changes the
// payload before signing.
func receiptFixture(t *testing.T, priv ed25519.PrivateKey, jobID string, edit func(*receipt.Payload)) []byte {
	t.Helper()
	at := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	p := receipt.Payload{
		Schema: 1, JobID: jobID, AttemptID: "attempt-1", InputDigest: strings.Repeat("a", 64),
		Approval: receipt.Approval{AttemptID: "attempt-1"},
		Request:  sentRequest,
		State:    model.Succeeded, ExitCode: new(int), Complete: true,
		CreatedAt: at, StartedAt: at, FinishedAt: at, SealedAt: at,
		Details: &receipt.Details{},
	}
	if edit != nil {
		edit(&p)
	}
	payload := canonicalJSON(t, p)
	sig := ed25519.Sign(priv, payload)
	return canonicalJSON(t, receipt.Envelope{Payload: payload, Signature: receipt.Signature{Algorithm: "Ed25519", KeyID: "k1", Encoding: "base64", Value: base64.StdEncoding.EncodeToString(sig)}})
}

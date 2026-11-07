package keyholder

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/buildseal"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/receipt"
	"github.com/jerryfane/macserve/internal/worker"
)

// Signed receipt and manifest bytes cross the RPC unchanged, including
// valid text encoding/json would HTML-escape: the receipt still verifies and
// the manifest still matches the receipt's digest and size.
func TestRPCPreservesSignedReceiptAndManifestBytes(t *testing.T) {
	const reason = "compiler <diagnostic> & details"
	f := newFixture(t, scopedRelease)
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := receipt.NewSigner(receipt.Options{Root: filepath.Join(t.TempDir(), "receipts"), KeyID: "receipt", PrivateKey: key,
		Service: receipt.ServiceIdentity{ID: "service", HostID: "host", Version: "test", BinarySHA256: strings.Repeat("0", 64)},
		Repository: func(context.Context, model.Job) (receipt.Repository, error) {
			return receipt.Repository{ID: repoID, Name: repo}, nil
		},
		Approval: ApprovalFromContext})
	if err != nil {
		t.Fatal(err)
	}
	f.engine.options.Signer = signer
	f.result.State, f.result.Reason = model.Failed, reason
	req := f.request(t)
	direct, err := f.engine.Seal(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(direct), "<diagnostic> &") {
		t.Fatalf("fixture receipt lacks the HTML-sensitive reason: %s", direct)
	}
	dir, err := shortTempDir(t)
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "k.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go (&Server{Engine: f.engine, ControllerUID: 501, PeerUID: func(net.Conn) (uint32, error) { return 501, nil }}).Serve(ctx, listener)
	client := &Client{Socket: socket, KeyholderUID: 220, PeerUID: func(net.Conn) (uint32, error) { return 220, nil }}
	transported, err := client.Seal(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if string(transported) != string(direct) {
		t.Fatalf("receipt bytes changed in transit:\n%s\n%s", direct, transported)
	}
	payload, err := receipt.Verify(transported, map[string]ed25519.PublicKey{"receipt": public})
	if err != nil || payload.Reason != reason || payload.Manifest == nil {
		t.Fatalf("transported receipt: %+v %v", payload.Manifest, err)
	}
	manifest, err := client.Manifest(ctx, payload.JobID, payload.Manifest.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(manifest)
	if hex.EncodeToString(sum[:]) != payload.Manifest.SHA256 || int64(len(manifest)) != payload.Manifest.SizeBytes {
		t.Fatalf("manifest bytes changed in transit: %d bytes, receipt says %d", len(manifest), payload.Manifest.SizeBytes)
	}
}

// A worker seal over HTML-sensitive request text still verifies after the
// JSON hops worker → controller → keyholder.
func TestSealEnvelopeSurvivesJSONHops(t *testing.T) {
	f := newFixture(t, model.ReleaseRequest{BuildName: "1.4.0", BuildNumber: "42", DartDefines: map[string]string{"API_BASE_URL": "https://api.example.com/?a=<1>&b=2", "FLAVOR": "prod"}})
	env := f.request(t).Seal
	for range 3 {
		raw, err := json.Marshal(env)
		if err != nil {
			t.Fatal(err)
		}
		env = buildseal.Envelope{}
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := buildseal.Verify(env, f.engine.options.SealKeys); err != nil {
		t.Fatalf("seal no longer verifies after JSON hops: %v", err)
	}
}

type invalidSigner struct{ fakeSigner }

func (*invalidSigner) Seal(context.Context, model.Job, worker.Result) (json.RawMessage, error) {
	return nil, fmt.Errorf("%w: evidence does not prove success", receipt.ErrInvalid)
}

// Evidence the receipt signer refuses is a definitive refusal, so the
// controller completes the job unsuccessfully rather than retrying.
func TestSignerInvalidEvidenceIsRefusal(t *testing.T) {
	f := newFixture(t, scopedRelease)
	f.engine.options.Signer = &invalidSigner{}
	var refused *RefusalError
	if _, err := f.engine.Seal(context.Background(), f.request(t)); !errors.As(err, &refused) {
		t.Fatalf("invalid evidence not a refusal: %v", err)
	}
}

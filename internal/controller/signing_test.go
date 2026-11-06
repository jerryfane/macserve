package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/receipt"
	"github.com/jerryfane/macserve/internal/signer"
	"github.com/jerryfane/macserve/internal/store"
	"github.com/jerryfane/macserve/internal/worker"
)

func hexSum(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// fakeSignClient checks the handed-over inputs and answers with a fixed
// ipa and a signer receipt over them, signed by key.
type fakeSignClient struct {
	t        *testing.T
	key      ed25519.PrivateKey
	ipa      []byte
	tamper   bool
	archive  []byte
	manifest []byte
	got      signer.Request
}

func (f *fakeSignClient) Sign(_ context.Context, req signer.Request, ipa io.Writer) (signer.Result, error) {
	f.got = req
	for path, want := range map[string][]byte{req.ArchivePath: f.archive, req.ManifestPath: f.manifest} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o640 {
			return signer.Result{}, errors.New("input is not a 0640 hand-over")
		}
		data, err := os.ReadFile(path)
		if err != nil || string(data) != string(want) {
			return signer.Result{}, errors.New("input bytes differ")
		}
	}
	if _, err := ipa.Write(f.ipa); err != nil {
		return signer.Result{}, err
	}
	payload := signer.ReceiptPayload{
		Schema: signer.ReceiptSchema, JobID: req.JobID, JobReceiptSHA256: hexSum(req.Receipt),
		Archive:               signer.DigestRef{Name: profiles.ArchiveArtifact, SHA256: hexSum(f.archive), SizeBytes: int64(len(f.archive))},
		SigningManifestSHA256: hexSum(f.manifest), IdentitySHA1: strings.Repeat("A", 40), TeamID: "ABCDE12345",
		IPA:      signer.DigestRef{Name: signer.IPAArtifact, SHA256: hexSum(f.ipa), SizeBytes: int64(len(f.ipa))},
		Bundles:  []signer.SignedBundle{{Path: "Products/Applications/Example.app", BundleID: "com.example.app"}},
		Dylibs:   []string{},
		SignedAt: time.Unix(1, 0).UTC(), Signer: signer.SignerReference{KeyID: "signer-1"},
	}
	if f.tamper {
		payload.Archive.SHA256 = strings.Repeat("0", 64)
	}
	raw, _ := json.Marshal(payload)
	canonical, err := receipt.Canonical(raw)
	if err != nil {
		f.t.Fatal(err)
	}
	envelope, _ := json.Marshal(receipt.Envelope{Payload: canonical, Signature: receipt.Signature{Algorithm: "Ed25519", KeyID: "signer-1", Encoding: "base64", Value: base64.StdEncoding.EncodeToString(ed25519.Sign(f.key, canonical))}})
	out, err := receipt.Canonical(envelope)
	if err != nil {
		f.t.Fatal(err)
	}
	return signer.Result{Receipt: out, IPASHA256: hexSum(f.ipa), IPASize: int64(len(f.ipa))}, nil
}

// signableJob stores a succeeded ios_archive job with its archive and
// manifest artifacts on disk.
func signableJob(t *testing.T, f *runtimeFixture, client *fakeSignClient) model.Job {
	t.Helper()
	ctx := context.Background()
	template := model.Template{ID: "org-archive-v1", Version: 1, Kind: model.IOSArchive, Owners: []string{"example-org"}, Xcode: model.Xcode{Version: "27.0", Build: "27A100"}, DeveloperDir: "/Applications/ExampleToolchain.app/Contents/Developer", MemoryLimitMiB: 512}
	registry, err := profiles.New(nil, []model.Template{template})
	if err != nil {
		t.Fatal(err)
	}
	sha := strings.Repeat("a", 40)
	admission, err := registry.Resolve(model.Request{Repo: "example-org/example-app", SHA: sha, Kind: model.IOSArchive, Profile: template.ID, Xcode: template.Xcode, Release: &model.ReleaseRequest{BuildName: "1.0", BuildNumber: "1"}})
	if err != nil {
		t.Fatal(err)
	}
	admission.ReleaseProvenance = &model.ReleaseProvenance{RepositoryID: 1, DefaultBranch: "main", HeadSHA: sha, ResolvedAt: f.now.UTC(), Source: model.ProvenanceGitHubApp}
	job, _, err := f.db.Enqueue(ctx, "owner", "archive", admission, f.now)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := f.db.Claim(ctx, "epoch", f.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.db.Transition(ctx, job.ID, claimed.LeaseToken, model.Preparing, model.Finalizing, "done", f.now); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(f.controller.options.Root, "artifacts", job.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	var artifacts []evidence.Artifact
	for name, data := range map[string][]byte{profiles.ArchiveArtifact: client.archive, profiles.SigningManifestArtifact: client.manifest} {
		id := hexSum(data)
		if err := os.WriteFile(filepath.Join(dir, id), data, 0o600); err != nil {
			t.Fatal(err)
		}
		artifacts = append(artifacts, evidence.Artifact{ID: id, Name: name, MediaType: "application/octet-stream", SizeBytes: int64(len(data)), SHA256: id, ExpiresAt: f.now.Add(time.Hour)})
	}
	result, _ := json.Marshal(Completion{Result: worker.Result{State: model.Succeeded, CleanupOK: true, Artifacts: artifacts}, Receipt: json.RawMessage(`{"payload":{"job_id":"x"},"signature":{}}`)})
	if err := f.db.Finish(ctx, job.ID, claimed.LeaseToken, model.Succeeded, result, true, "done", f.now); err != nil {
		t.Fatal(err)
	}
	return job
}

func waitSigning(t *testing.T, f *runtimeFixture, id string) store.SigningRecord {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		record, err := f.db.GetSigning(context.Background(), id)
		if err == nil && record.Status != store.Signing {
			return record
		}
		if time.Now().After(deadline) {
			t.Fatalf("signing did not finish: %+v %v", record, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func signingFixture(t *testing.T) (*runtimeFixture, *fakeSignClient, string) {
	t.Helper()
	f := newRuntime(t)
	_, key, _ := ed25519.GenerateKey(nil)
	client := &fakeSignClient{t: t, key: key, ipa: []byte("signed ipa bytes"), archive: []byte("archive tar bytes"), manifest: []byte(`{"schema":1}`)}
	inbox := t.TempDir()
	f.controller.options.Signer = &SignerOptions{Client: client, Inbox: inbox, RPCGID: os.Getgid(), Keys: map[string]ed25519.PublicKey{"signer-1": key.Public().(ed25519.PublicKey)}}
	return f, client, inbox
}

// Sign hands over the job's receipt-bound inputs, verifies the signer
// receipt against them and stores App.ipa and signer-receipt.json.
func TestControllerSignStoresIPAAndSignerReceipt(t *testing.T) {
	f, client, inbox := signingFixture(t)
	job := signableJob(t, f, client)
	record, err := f.controller.Sign(context.Background(), job.ID)
	if err != nil || record.Status != store.Signing {
		t.Fatalf("sign: %+v %v", record, err)
	}
	record = waitSigning(t, f, job.ID)
	if record.Status != store.Signed || len(record.Artifacts) != 2 {
		t.Fatalf("record %+v", record)
	}
	archive, manifest := signer.RequestPaths(inbox, job.ID)
	if client.got.ArchivePath != archive || client.got.ManifestPath != manifest || client.got.JobID != job.ID {
		t.Fatalf("request %+v", client.got)
	}
	if _, err := os.Stat(filepath.Dir(archive)); !os.IsNotExist(err) {
		t.Fatalf("inbox inputs kept: %v", err)
	}
	for _, a := range record.Artifacts {
		file, got, err := f.controller.Artifact(context.Background(), job.ID, a.ID)
		if err != nil {
			t.Fatalf("%s: %v", a.Name, err)
		}
		data, _ := io.ReadAll(file)
		file.Close()
		if got.Name != a.Name || hexSum(data) != a.SHA256 {
			t.Fatalf("%s bytes", a.Name)
		}
		if a.Name == signer.IPAArtifact && string(data) != string(client.ipa) {
			t.Fatal("ipa bytes differ")
		}
	}
	// Idempotent once signed.
	again, err := f.controller.Sign(context.Background(), job.ID)
	if err != nil || again.Status != store.Signed {
		t.Fatalf("repeat: %+v %v", again, err)
	}
	if persisted, _ := f.db.Get(context.Background(), job.ID); persisted.State != model.Succeeded {
		t.Fatalf("job state %s", persisted.State)
	}
}

// A signer receipt that does not match the job's inputs fails the
// signing and stores nothing.
func TestControllerSignRejectsMismatchedSignerReceipt(t *testing.T) {
	f, client, _ := signingFixture(t)
	client.tamper = true
	job := signableJob(t, f, client)
	if _, err := f.controller.Sign(context.Background(), job.ID); err != nil {
		t.Fatal(err)
	}
	record := waitSigning(t, f, job.ID)
	if record.Status != store.SignFailed || !strings.Contains(record.Reason, "does not match") {
		t.Fatalf("record %+v", record)
	}
	if _, _, err := f.controller.Artifact(context.Background(), job.ID, hexSum(client.ipa)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("mismatched ipa stored: %v", err)
	}
}

func TestControllerSignWithoutSignerIsUnavailable(t *testing.T) {
	f := newRuntime(t)
	if _, err := f.controller.Sign(context.Background(), "job"); !errors.Is(err, ErrSigningUnavailable) {
		t.Fatalf("error = %v", err)
	}
}

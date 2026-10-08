package githubpull

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/receipt"
	"github.com/jerryfane/macserve/internal/worker"
)

func TestPublicationKeepsSmallPrivateManifestOutOfChecks(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		name := "compact"
		if legacy {
			name = "legacy-full"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.poll(t)
			ctx := context.Background()
			job, err := f.s.Claim(ctx, "worker-epoch", f.options.Now())
			if err != nil {
				t.Fatal(err)
			}
			const private = "recognizable-private-build-command"
			started := *job.StartedAt
			finished := started.Add(10 * time.Second)
			zero := 0
			result := worker.Result{State: model.Succeeded, ExitCode: &zero, CleanupOK: true, StartedAt: started, FinishedAt: finished, Source: worker.Source{Commit: job.Request.SHA, Tree: strings.Repeat("b", 40), SHA256: strings.Repeat("c", 64), SizeBytes: 1024}, Observation: worker.Observation{Xcode: job.Request.Xcode, SDKVersion: "26.0", SDKBuild: "23A100", SwiftVersion: "Swift 6.2", OSVersion: "26.0", OSBuild: "25A100", Architecture: "arm64", GeneratedDigests: map[string]string{}, LockfileDigests: map[string]string{}}, Commands: []worker.ExecutedCommand{{Executable: job.Profile.Run.Executable, Args: []string{private}, StartedAt: started, FinishedAt: finished.Add(-time.Second), ExitCode: 0}}}
			for _, log := range []string{"stdout", "stderr"} {
				result.Artifacts = append(result.Artifacts, evidence.Artifact{ID: log, Name: "evidence/" + log + ".log", MediaType: "text/plain", SizeBytes: 10, SHA256: strings.Repeat("d", 64), ExpiresAt: finished.Add(time.Hour)})
			}
			key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
			signer, err := receipt.NewSigner(receipt.Options{Root: filepath.Join(t.TempDir(), "receipts"), KeyID: "privacy-key", PrivateKey: key, Service: receipt.ServiceIdentity{ID: "service", HostID: "host", Version: "1", BinarySHA256: strings.Repeat("e", 64)}, Repository: func(context.Context, model.Job) (receipt.Repository, error) {
				return receipt.Repository{ID: 123, Name: testRepo}, nil
			}, Approval: f.p.Approval, Now: func() time.Time { return finished.Add(time.Second) }})
			if err != nil {
				t.Fatal(err)
			}
			defer signer.Close()
			raw, err := signer.Seal(ctx, job, result)
			if err != nil {
				t.Fatal(err)
			}
			keys := map[string]ed25519.PublicKey{"privacy-key": key.Public().(ed25519.PublicKey)}
			core, err := receipt.Verify(raw, keys)
			if err != nil || core.Manifest == nil || core.Details != nil {
				t.Fatalf("invalid compact receipt: %v", err)
			}
			manifest, err := signer.Manifest(ctx, job.ID, core.Manifest.SHA256)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(manifest)
			if len(manifest) >= receipt.MaxReceiptBytes || int64(len(manifest)) != core.Manifest.SizeBytes || hex.EncodeToString(digest[:]) != core.Manifest.SHA256 || !bytes.Contains(manifest, []byte(private)) {
				t.Fatal("private small manifest lost bytes or signed commitment")
			}
			if legacy {
				// Build a genuine canonical old-format envelope from the exact full payload.
				signature, err := json.Marshal(map[string]string{"algorithm": "Ed25519", "encoding": "base64", "key_id": "privacy-key", "value": base64.StdEncoding.EncodeToString(ed25519.Sign(key, manifest))})
				if err != nil {
					t.Fatal(err)
				}
				raw = append([]byte(`{"payload":`), manifest...)
				raw = append(raw, []byte(`,"signature":`)...)
				raw = append(raw, signature...)
				raw = append(raw, '}')
				if _, err := receipt.Verify(raw, keys); err != nil {
					t.Fatalf("legacy fixture is not genuine signed evidence: %v", err)
				}
			}
			f.p.options.VerifyReceipt = func(j model.Job, raw json.RawMessage) error {
				payload, err := receipt.Verify(raw, keys)
				if err != nil {
					return err
				}
				if payload.JobID != j.ID {
					return errors.New("wrong job")
				}
				return receipt.ValidateSuccess(payload, receipt.Expected{RepositoryID: 123, Repo: j.Request.Repo, SHA: j.Request.SHA, Profile: j.Request.Profile, ProfileDigest: j.ProfileDigest, Kind: j.Request.Kind, Xcode: j.Request.Xcode, RequiredTests: j.Profile.RequiredTests})
			}
			if err := f.p.options.VerifyReceipt(job, raw); err != nil {
				t.Fatal(err)
			}
			if err := f.s.Transition(ctx, job.ID, job.LeaseToken, model.Preparing, model.Finalizing, "collected", finished); err != nil {
				t.Fatal(err)
			}
			completion := append([]byte(`{"receipt":`), raw...)
			completion = append(completion, '}')
			if err := f.s.Finish(ctx, job.ID, job.LeaseToken, model.Succeeded, completion, true, "finished", finished); err != nil {
				t.Fatal(err)
			}
			f.advance(11 * time.Second)
			f.poll(t)
			check, packet := f.current(t)
			if strings.Contains(check.Output.Text, private) || strings.Contains(check.Output.Text, `"details"`) {
				t.Fatal("check output exposed private full execution evidence")
			}
			if legacy {
				if check.Conclusion != "action_required" || len(packet.Receipt) != 0 || packet.ReceiptDigest != "" || !strings.Contains(check.Output.Summary, "rerun") {
					t.Fatal("legacy receipt did not fail closed with rerun guidance")
				}
			} else if check.Conclusion != "success" || !bytes.Equal(packet.Receipt, raw) || packet.AttemptID != core.AttemptID || packet.JobID != core.JobID {
				t.Fatal("compact success lost signature bytes or signed identity bindings")
			}
			stored, err := f.s.Get(ctx, job.ID)
			if err != nil || !bytes.Equal(stored.Result, completion) {
				t.Fatal("publication rewrote committed private evidence")
			}
		})
	}
}

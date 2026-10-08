package waiter_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/receipt"
	"github.com/jerryfane/macserve/internal/waiter"
	"github.com/jerryfane/macserve/internal/worker"
)

// This fixture uses the actual controller signer, not a verifier stub. No Apple
// process, source checkout, credential, or external service is involved.
func signedFixture(t *testing.T, mutate func(*model.Job, *worker.Result)) (json.RawMessage, receipt.Expected, map[string]ed25519.PublicKey) {
	t.Helper()
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	xcode := model.Xcode{Version: "26.0", Build: "17A100"}
	sim := &model.Simulator{Runtime: "com.apple.CoreSimulator.SimRuntime.iOS-26-0", RuntimeBuild: "23A100", DeviceType: "com.apple.CoreSimulator.SimDeviceType.iPhone-17"}
	profile := model.Profile{ID: "unit-v1", Version: 1, Repo: fixtureRepo, Kind: model.UnitTest, Xcode: xcode, Simulator: sim, DeveloperDir: "/Applications/Xcode.app/Contents/Developer", WorkDir: ".", Run: model.Command{Executable: "/usr/bin/xcrun", Args: []string{"xcodebuild", "test"}}, RequiredTests: []string{"Suite/testWorks"}, DefaultTimeoutSeconds: 300, MaxTimeoutSeconds: 600, MemoryLimitMiB: 8192}
	encoded, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	started, finished, deadline := now.Add(time.Second), now.Add(10*time.Second), now.Add(5*time.Minute)
	job := model.Job{ID: fixtureJob, Principal: "github-machine-request", Request: model.Request{Repo: fixtureRepo, SHA: strings.Repeat("a", 40), Kind: profile.Kind, Profile: profile.ID, Xcode: xcode, Simulator: sim, TimeoutSeconds: 300}, Profile: profile, ProfileDigest: fixtureHash(encoded), CreatedAt: now, StartedAt: &started, Deadline: &deadline, WorkerEpoch: "epoch-1"}
	request, err := json.Marshal(job.Request)
	if err != nil {
		t.Fatal(err)
	}
	job.RequestDigest = fixtureHash(request)
	zero := 0
	result := worker.Result{State: model.Succeeded, ExitCode: &zero, CleanupOK: true, StartedAt: started, FinishedAt: finished, Source: worker.Source{Commit: job.Request.SHA, Tree: strings.Repeat("b", 40), SHA256: strings.Repeat("c", 64), SizeBytes: 1024}, Observation: worker.Observation{Xcode: xcode, SDKVersion: "26.0", SDKBuild: "23A100", SwiftVersion: "Swift 6.2", OSVersion: "26.0", OSBuild: "25A100", Architecture: "arm64", RuntimeVersion: "26.0", RuntimeBuild: sim.RuntimeBuild, DeviceUDID: "fixture-owned-device", GeneratedDigests: map[string]string{}, LockfileDigests: map[string]string{}}, Commands: []worker.ExecutedCommand{{Executable: profile.Run.Executable, Args: profile.Run.Args, StartedAt: started, FinishedAt: now.Add(9 * time.Second), ExitCode: 0}}}
	for _, log := range []string{"stdout", "stderr"} {
		result.Artifacts = append(result.Artifacts, evidence.Artifact{ID: log, Name: "evidence/" + log + ".log", MediaType: "text/plain", SizeBytes: 10, SHA256: fixtureHash([]byte(log)), ExpiresAt: now.Add(24 * time.Hour)})
	}
	archive := fixtureHash([]byte("xcresult fixture archive"))
	result.Artifacts = append(result.Artifacts, evidence.Artifact{ID: "tests", Name: "evidence/tests.json", MediaType: "application/json", SizeBytes: 100, SHA256: fixtureHash([]byte("tests fixture")), ExpiresAt: now.Add(24 * time.Hour)}, evidence.Artifact{ID: "archive", Name: "results.xcresult.tar.gz", MediaType: "application/gzip", SizeBytes: 100, SHA256: archive, ExpiresAt: now.Add(24 * time.Hour)})
	result.Summary = &evidence.Summary{SchemaVersion: 1, ParserVersion: "xcresult-tests-0.4.0", ParseStatus: "parsed", Tests: 1, Passed: 1, Cases: []evidence.TestCase{{ID: "Suite/testWorks", Suite: "Suite", Name: "testWorks", Outcome: "passed", Attempt: 1}}, RequiredTests: profile.RequiredTests, XCResultSHA256: archive}
	expected := receipt.Expected{RepositoryID: fixtureRepoID, Repo: fixtureRepo, SHA: job.Request.SHA, Profile: profile.ID, ProfileDigest: job.ProfileDigest, Kind: profile.Kind, Xcode: xcode, Simulator: sim, RequiredTests: append([]string(nil), profile.RequiredTests...)}
	if mutate != nil {
		mutate(&job, &result)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	signer, err := receipt.NewSigner(receipt.Options{Root: filepath.Join(t.TempDir(), "receipts"), KeyID: "fixture-key", PrivateKey: key, Service: receipt.ServiceIdentity{ID: "fixture-service", HostID: "fixture-host", Version: "1.0", BinarySHA256: strings.Repeat("d", 64)}, Repository: func(context.Context, model.Job) (receipt.Repository, error) {
		return receipt.Repository{ID: fixtureRepoID, Name: job.Request.Repo}, nil
	}, Approval: func(context.Context, model.Job) (receipt.Approval, error) {
		return receipt.Approval{Intake: "github", Identity: "actions-bot:51", AttemptID: fixtureAttempt}, nil
	}, Now: func() time.Time { return now.Add(11 * time.Second) }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := signer.Close(); err != nil {
			t.Error(err)
		}
	})
	raw, err := signer.Seal(context.Background(), job, result)
	if err != nil {
		t.Fatal(err)
	}
	return raw, expected, map[string]ed25519.PublicKey{"fixture-key": key.Public().(ed25519.PublicKey)}
}

func fixtureHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func TestWaiterRejectsSignedContainerFailureBehindSuccessfulCheck(t *testing.T) {
	f := newWire(t)
	f.raw, _, _ = signedFixture(t, func(_ *model.Job, r *worker.Result) {
		r.State = model.Failed
		r.Reason = "test container failed without executing required test"
		r.Summary.Passed = 0
		r.Summary.Failed = 1
		r.Summary.Cases[0].Outcome = "failed"
		r.Summary.Cases[0].Container = true
	})
	if _, err := waiter.Run(context.Background(), f.options); err == nil {
		t.Fatal("signed container diagnostic cleared executed-test gate")
	}
}

func TestWaiterVerifiesCompactReceiptWithoutFetchingManifest(t *testing.T) {
	f := newWire(t)
	f.raw, _, _ = signedFixture(t, func(_ *model.Job, r *worker.Result) {
		r.Commands[0].Args = append(r.Commands[0].Args, strings.Repeat("<>&", 14000))
	})
	if result, err := waiter.Run(context.Background(), f.options); err != nil || result.JobID != fixtureJob {
		t.Fatalf("compact signed evidence failed: %+v %v", result, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.unexpected != 0 {
		t.Fatal("waiter fetched an untrusted manifest or key")
	}
}

func TestWaiterPreservesCanonicalReceiptStringEscapes(t *testing.T) {
	f := newWire(t)
	f.raw, _, _ = signedFixture(t, func(_ *model.Job, r *worker.Result) {
		r.Commands[0].Args = append(r.Commands[0].Args, "setting=<>&")
	})
	if result, err := waiter.Run(context.Background(), f.options); err != nil || result.JobID != fixtureJob {
		t.Fatalf("canonical evidence string damaged in GitHub publication: %+v %v", result, err)
	}
}

func TestWaiterRejectsWrongPinnedPublicKey(t *testing.T) {
	f := newWire(t)
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	f.options.Keys = map[string]ed25519.PublicKey{"fixture-key": other.Public().(ed25519.PublicKey)}
	if _, err := waiter.Run(context.Background(), f.options); err == nil {
		t.Fatal("receipt verified with a different pinned public key")
	}
}

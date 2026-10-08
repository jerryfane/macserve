package receipt

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/worker"
)

func fixture(t *testing.T, kind model.Kind) (Options, model.Job, worker.Result, Expected) {
	t.Helper()
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	xcode := model.Xcode{Version: "26.0", Build: "17A100"}
	profile := model.Profile{ID: "unit", Version: 1, Repo: "example-org/example-app", Kind: kind, Xcode: xcode, DeveloperDir: "/Applications/Xcode.app/Contents/Developer", WorkDir: ".", Run: model.Command{Executable: "/usr/bin/xcrun", Args: []string{"xcodebuild", "test"}}, DefaultTimeoutSeconds: 300, MaxTimeoutSeconds: 600, MemoryLimitMiB: 8192}
	if kind != model.Build {
		profile.RequiredTests = []string{"Suite/testWorks"}
	}
	if kind == model.SimulatorUITest {
		profile.Simulator = &model.Simulator{Runtime: "com.apple.CoreSimulator.SimRuntime.iOS-26-0", RuntimeBuild: "23A100", DeviceType: "com.apple.CoreSimulator.SimDeviceType.iPhone-17"}
	}
	raw, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	deadline := now.Add(5 * time.Minute)
	started := now.Add(time.Second)
	job := model.Job{ID: "job-1", Principal: "test-principal", Request: model.Request{Repo: profile.Repo, SHA: strings.Repeat("a", 40), Kind: kind, Profile: profile.ID, Xcode: xcode, Simulator: profile.Simulator, TimeoutSeconds: 300}, Profile: profile, ProfileDigest: hashBytes(raw), CreatedAt: now, StartedAt: &started, Deadline: &deadline, WorkerEpoch: "epoch-1"}
	request, err := json.Marshal(job.Request)
	if err != nil {
		t.Fatal(err)
	}
	job.RequestDigest = hashBytes(request)
	zero := 0
	result := worker.Result{State: model.Succeeded, ExitCode: &zero, CleanupOK: true, StartedAt: started, FinishedAt: now.Add(10 * time.Second), Source: worker.Source{Commit: job.Request.SHA, Tree: strings.Repeat("b", 40), SHA256: strings.Repeat("c", 64), SizeBytes: 1024}, Observation: worker.Observation{Xcode: xcode, SDKVersion: "26.0", SDKBuild: "23A100", SwiftVersion: "Swift 6.2", OSVersion: "26.0", OSBuild: "25A100", Architecture: "arm64", GeneratedDigests: map[string]string{}, LockfileDigests: map[string]string{}}, Commands: []worker.ExecutedCommand{{Executable: profile.Run.Executable, Args: profile.Run.Args, StartedAt: started, FinishedAt: now.Add(9 * time.Second), ExitCode: 0}}}
	if profile.Simulator != nil {
		result.Observation.RuntimeVersion = "26.0"
		result.Observation.RuntimeBuild = profile.Simulator.RuntimeBuild
		result.Observation.DeviceUDID = "device-1"
	}
	for i, name := range []string{"evidence/stdout.log", "evidence/stderr.log"} {
		result.Artifacts = append(result.Artifacts, evidence.Artifact{ID: []string{"stdout", "stderr"}[i], Name: name, MediaType: "text/plain", SizeBytes: 10, SHA256: hashBytes([]byte(name)), ExpiresAt: now.Add(24 * time.Hour)})
	}
	if kind != model.Build {
		archive := hashBytes([]byte("archive"))
		result.Artifacts = append(result.Artifacts, evidence.Artifact{ID: "tests", Name: "evidence/tests.json", MediaType: "application/json", SizeBytes: 100, SHA256: hashBytes([]byte("tests")), ExpiresAt: now.Add(24 * time.Hour)}, evidence.Artifact{ID: "archive", Name: "results.xcresult.tar.gz", MediaType: "application/gzip", SizeBytes: 100, SHA256: archive, ExpiresAt: now.Add(24 * time.Hour)})
		result.Summary = &evidence.Summary{SchemaVersion: 1, ParserVersion: "xcresult-tests-0.4.0", ParseStatus: "parsed", Tests: 1, Passed: 1, Cases: []evidence.TestCase{{ID: "Suite/testWorks", Suite: "Suite", Name: "testWorks", Outcome: "passed", Attempt: 1}}, RequiredTests: profile.RequiredTests, XCResultSHA256: archive}
	}
	options := Options{Root: filepath.Join(t.TempDir(), "receipts"), KeyID: "key-1", PrivateKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)), Service: ServiceIdentity{ID: "service", HostID: "host", Version: "1.0", BinarySHA256: strings.Repeat("d", 64)}, Repository: func(context.Context, model.Job) (Repository, error) {
		return Repository{ID: 123, Name: profile.Repo}, nil
	}, Now: func() time.Time { return now.Add(11 * time.Second) }}
	expected := Expected{RepositoryID: 123, Repo: job.Request.Repo, SHA: job.Request.SHA, Profile: profile.ID, ProfileDigest: job.ProfileDigest, Kind: kind, Xcode: xcode, Simulator: profile.Simulator, RequiredTests: profile.RequiredTests}
	return options, job, result, expected
}
func sealFixture(t *testing.T, options Options, job model.Job, result worker.Result) (*Signer, json.RawMessage, Payload) {
	t.Helper()
	signer, err := NewSigner(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { signer.Close() })
	raw, err := signer.Seal(context.Background(), job, result)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Verify(raw, map[string]ed25519.PublicKey{options.KeyID: options.PrivateKey.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	return signer, raw, p
}

func TestSignedSuccessAndPinnedPolicy(t *testing.T) {
	for _, kind := range []model.Kind{model.Build, model.UnitTest, model.SimulatorUITest} {
		t.Run(string(kind), func(t *testing.T) {
			options, job, result, expected := fixture(t, kind)
			_, raw, p := sealFixture(t, options, job, result)
			if err := ValidateSuccess(p, expected); err != nil {
				t.Fatal(err)
			}
			for name, mutate := range map[string]func(*Expected){"repository ID": func(e *Expected) { e.RepositoryID++ }, "repository name": func(e *Expected) { e.Repo = "example-org/other" }, "source SHA": func(e *Expected) { e.SHA = strings.Repeat("b", 40) }, "profile": func(e *Expected) { e.Profile = "other" }, "recipe digest": func(e *Expected) { e.ProfileDigest = strings.Repeat("e", 64) }, "Xcode": func(e *Expected) { e.Xcode.Build = "other" }, "test scope": func(e *Expected) { e.RequiredTests = []string{"missing"} }, "kind": func(e *Expected) { e.Kind = "other" }} {
				t.Run(name, func(t *testing.T) {
					e := expected
					mutate(&e)
					if ValidateSuccess(p, e) == nil {
						t.Fatal("mismatched policy accepted")
					}
				})
			}
			if _, err := Verify(raw, nil); err == nil {
				t.Fatal("revoked key accepted")
			}
			if _, err := Verify(raw, map[string]ed25519.PublicKey{"key-1": ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32)).Public().(ed25519.PublicKey)}); err == nil {
				t.Fatal("wrong pinned key accepted")
			}
		})
	}
}

func TestSuccessRequiresCompleteEvidence(t *testing.T) {
	mutations := map[string]func(*worker.Result){
		"source": func(r *worker.Result) { r.Source.Tree = "" }, "commands": func(r *worker.Result) { r.Commands = nil }, "logs": func(r *worker.Result) { r.Artifacts = r.Artifacts[1:] }, "truncated": func(r *worker.Result) { r.LogsTruncated = true }, "cleanup": func(r *worker.Result) { r.CleanupOK = false }, "exit": func(r *worker.Result) { *r.ExitCode = 1 }, "toolchain": func(r *worker.Result) { r.Observation.SDKBuild = "" }, "no parsed evidence": func(r *worker.Result) { r.Summary = nil }, "zero tests": func(r *worker.Result) { r.Summary.Tests = 0 }, "invented counts": func(r *worker.Result) { r.Summary.Passed = 2; r.Summary.Tests = 2 }, "skipped required": func(r *worker.Result) {
			r.Summary.Cases[0].Outcome = "skipped"
			r.Summary.Passed = 0
			r.Summary.Skipped = 1
		}, "container cannot execute": func(r *worker.Result) { r.Summary.Cases[0].Container = true }, "aggregate failure": func(r *worker.Result) {
			r.Summary.Cases = append(r.Summary.Cases, evidence.TestCase{ID: "Suite", Name: "Suite", Outcome: "failed", Attempt: 1, Container: true})
			r.Summary.Tests++
			r.Summary.Failed++
		}, "generated": func(r *worker.Result) { r.Observation.GeneratedDigests["unexpected"] = "bad" }, "lockfile": func(r *worker.Result) { r.Observation.LockfileDigests["Package.resolved"] = "bad" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			options, job, result, _ := fixture(t, model.UnitTest)
			mutate(&result)
			signer, err := NewSigner(options)
			if err != nil {
				t.Fatal(err)
			}
			defer signer.Close()
			if _, err := signer.Seal(context.Background(), job, result); err == nil {
				t.Fatal("incomplete success signed")
			}
			files, err := os.ReadDir(options.Root)
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range files {
				if strings.HasSuffix(f.Name(), ".json") {
					t.Fatal("invalid success persisted")
				}
			}
		})
	}
}

func TestFailurePreservesIncompleteEvidence(t *testing.T) {
	options, job, _, expected := fixture(t, model.UnitTest)
	result := worker.Result{State: model.Failed, Reason: "source unavailable"}
	_, _, p := sealFixture(t, options, job, result)
	if p.Complete || len(p.Missing) == 0 || p.Details.Result.Source.Commit != "" || p.State != model.Failed || p.Reason != result.Reason {
		t.Fatal("failed evidence was fabricated")
	}
	if ValidateSuccess(p, expected) == nil {
		t.Fatal("failure treated as success")
	}
}

func TestCompactManifestRestartAndImmutability(t *testing.T) {
	options, job, result, expected := fixture(t, model.UnitTest)
	result.Commands[0].Args = append(result.Commands[0].Args, strings.Repeat("x", 40000))
	signer, raw, p := sealFixture(t, options, job, result)
	if p.Manifest == nil || p.Details != nil || len(raw) > MaxReceiptBytes {
		t.Fatal("receipt did not compact")
	}
	if err := ValidateSuccess(p, expected); err != nil {
		t.Fatal(err)
	}
	manifest, err := signer.Manifest(context.Background(), job.ID, p.Manifest.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if hashBytes(manifest) != p.Manifest.SHA256 || int64(len(manifest)) != p.Manifest.SizeBytes {
		t.Fatal("manifest commitment mismatch")
	}
	var full Payload
	if err := strictDecode(manifest, &full); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(full.Details.Result.Commands[0].Args[len(full.Details.Result.Commands[0].Args)-1], strings.Repeat("x", 40000)) {
		t.Fatal("full command evidence lost")
	}
	signer.Close()
	options.Now = func() time.Time { return time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC) }
	restarted, err := NewSigner(options)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	again, err := restarted.Seal(context.Background(), job, result)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, again) {
		t.Fatal("restart changed immutable receipt")
	}
	result.State = model.Cancelled
	result.Reason = "cancellation requested"
	job.CancelRequested = true
	cancelled, err := restarted.Seal(context.Background(), job, result)
	if err != nil {
		t.Fatal(err)
	}
	cancellation, err := Verify(cancelled, map[string]ed25519.PublicKey{options.KeyID: options.PrivateKey.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	if cancellation.State != model.Cancelled || cancellation.Manifest == nil || cancellation.Manifest.SHA256 == p.Manifest.SHA256 {
		t.Fatal("cancellation did not receive an independent manifest")
	}
	after, err := restarted.Manifest(context.Background(), job.ID, p.Manifest.SHA256)
	if err != nil || !bytes.Equal(manifest, after) {
		t.Fatal("prior signed manifest changed")
	}
	cancellationManifest, err := restarted.Manifest(context.Background(), job.ID, cancellation.Manifest.SHA256)
	if err != nil || hashBytes(cancellationManifest) != cancellation.Manifest.SHA256 {
		t.Fatal("cancellation manifest unavailable")
	}
	info, err := os.Stat(filepath.Join(options.Root, job.ID+"-manifest-"+p.Manifest.SHA256+".json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("manifest not private")
	}
}

func TestStrictJSONAndCanonicalization(t *testing.T) {
	for _, raw := range []string{`{"x":1,"x":2}`, `{"x":1,"\u0078":2}`, `{"x":9007199254740992}`, `{"x":9007199254740991.1}`, `{"x":1e400}`, `{"x":1e-400}`, `{"x":"\ud800"}`, `{"x":"\udc00"}`, `{"x":1} {}`, string([]byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'})} {
		if _, err := Digest([]byte(raw)); err == nil {
			t.Errorf("accepted invalid I-JSON %q", raw)
		}
	}
	raw := []byte(`{"\ue000":1,"\ud800\udc00":2,"number":1e-7,"text":"<>&"}`)
	canonicalJSON, err := canonical(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"number":1e-7,"text":"<>&","𐀀":2,"":1}`
	if string(canonicalJSON) != want {
		t.Fatalf("not RFC8785 UTF16/number/string canonicalization: %s", canonicalJSON)
	}
}

func TestTamperingAndNoncanonicalEnvelope(t *testing.T) {
	options, job, result, _ := fixture(t, model.UnitTest)
	_, raw, _ := sealFixture(t, options, job, result)
	keys := map[string]ed25519.PublicKey{options.KeyID: options.PrivateKey.Public().(ed25519.PublicKey)}
	for name, damaged := range map[string][]byte{"modified": bytes.Replace(raw, []byte(`"job-1"`), []byte(`"job-2"`), 1), "truncated": raw[:len(raw)-1], "whitespace": append([]byte(" "), raw...), "duplicate": append([]byte(`{"payload":null,`), raw[1:]...)} {
		t.Run(name, func(t *testing.T) {
			if _, err := Verify(damaged, keys); err == nil {
				t.Fatal("tampered receipt accepted")
			}
		})
	}
}

func TestPrivateKeyFormatsAndMalformedExpandedKey(t *testing.T) {
	seed := bytes.Repeat([]byte{3}, 32)
	key := ed25519.NewKeyFromSeed(seed)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{seed, key, []byte(base64.StdEncoding.EncodeToString(seed)), []byte(base64.StdEncoding.EncodeToString(key)), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})} {
		parsed, err := ParsePrivateKey(raw)
		if err != nil || !bytes.Equal(parsed, key) {
			t.Fatalf("private key roundtrip: %v", err)
		}
	}
	bad := append([]byte(nil), key...)
	bad[63] ^= 1
	if _, err := ParsePrivateKey(bad); err == nil {
		t.Fatal("inconsistent expanded key accepted")
	}
}

func TestManifestPathAndSymlinkProtection(t *testing.T) {
	options, job, _, _ := fixture(t, model.Build)
	signer, err := NewSigner(options)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("0", 64)
	if err := os.Symlink(outside, filepath.Join(options.Root, job.ID+"-manifest-"+digest+".json")); err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Manifest(context.Background(), job.ID, digest); err == nil {
		t.Fatal("symlink manifest served")
	}
	if _, err := signer.Manifest(context.Background(), "../outside", digest); err == nil {
		t.Fatal("path traversal accepted")
	}
	if _, err := signer.Manifest(context.Background(), job.ID, "../outside"); err == nil {
		t.Fatal("digest traversal accepted")
	}
}

func TestSignedUnknownFieldsAndCaseAliasesRejected(t *testing.T) {
	options, job, result, _ := fixture(t, model.UnitTest)
	_, _, p := sealFixture(t, options, job, result)
	raw, err := canonicalValue(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, modified := range [][]byte{
		bytes.Replace(raw, []byte(`"schema":1`), []byte(`"SCHEMA":1`), 1),
		bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":1,"unrecognized":true`), 1),
		bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":1,"SCHEMA":1`), 1),
	} {
		payload, err := canonical(modified)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := canonicalValue(Envelope{Payload: payload, Signature: Signature{Algorithm: "Ed25519", KeyID: options.KeyID, Encoding: "base64", Value: base64.StdEncoding.EncodeToString(ed25519.Sign(options.PrivateKey, payload))}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(envelope, map[string]ed25519.PublicKey{options.KeyID: options.PrivateKey.Public().(ed25519.PublicKey)}); err == nil {
			t.Fatal("signed ambiguous schema accepted")
		}
	}
}

func TestConcurrentSealsPreserveSingleManifest(t *testing.T) {
	options, job, result, _ := fixture(t, model.Build)
	first, err := NewSigner(options)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	later := options
	later.Now = func() time.Time { return options.Now().Add(time.Second) }
	second, err := NewSigner(later)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	type sealed struct {
		raw json.RawMessage
		err error
	}
	done := make(chan sealed, 2)
	start := make(chan struct{})
	for _, signer := range []*Signer{first, second} {
		go func() { <-start; raw, err := signer.Seal(context.Background(), job, result); done <- sealed{raw, err} }()
	}
	close(start)
	a, b := <-done, <-done
	if a.err != nil || b.err != nil {
		t.Fatalf("concurrent seals: %v / %v", a.err, b.err)
	}
	if !bytes.Equal(a.raw, b.raw) {
		t.Fatal("concurrent signers published conflicting receipts")
	}
}

func TestInvalidGoStringsAreNotRepaired(t *testing.T) {
	options, job, result, _ := fixture(t, model.Build)
	result.Commands[0].Args = []string{string([]byte{0xff})}
	signer, err := NewSigner(options)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()
	if _, err := signer.Seal(context.Background(), job, result); err == nil {
		t.Fatal("invalid command text silently replaced")
	}
}

func TestCompactFailureRetainsEvidenceAndMissingFlags(t *testing.T) {
	options, job, result, expected := fixture(t, model.UnitTest)
	result.State = model.Failed
	result.LogsTruncated = true
	result.Summary.Cases[0].Outcome = "failed"
	result.Summary.Cases[0].Failures = []string{strings.Repeat("failure detail ", 4000)}
	result.Summary.Failed = 1
	result.Summary.Passed = 0
	signer, raw, p := sealFixture(t, options, job, result)
	if len(raw) > MaxReceiptBytes || p.Manifest == nil || p.Complete || len(p.Missing) == 0 || !p.LogsTruncated {
		t.Fatal("compact failure concealed missing evidence")
	}
	if ValidateSuccess(p, expected) == nil {
		t.Fatal("compact failure proved success")
	}
	full, err := signer.Manifest(context.Background(), job.ID, p.Manifest.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	var payload Payload
	if err := strictDecode(full, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Details.Result.Summary.Cases[0].Failures[0] != result.Summary.Cases[0].Failures[0] {
		t.Fatal("failure details truncated")
	}
}

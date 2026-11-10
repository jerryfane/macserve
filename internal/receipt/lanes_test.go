package receipt

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/worker"
)

// laneFixture is a unit-test job that ran in lane 2 of 2 while job-0 ran.
func laneFixture(t *testing.T) (Options, model.Job, worker.Result, Expected) {
	t.Helper()
	options, job, result, expected := fixture(t, model.UnitTest)
	result.PeakMemoryMiB, result.HostPeakMemoryMiB = 2048, 6144
	result.Concurrency = &worker.Concurrency{Lane: 2, MaxLanes: 2, OverlappedJobs: []worker.Overlap{{JobID: "job-0", Seconds: 7}}, Attribution: worker.AttributionLineage, IdleVerdict: worker.IdleNotRequired}
	return options, job, result, expected
}

func signPayload(t *testing.T, options Options, p Payload) json.RawMessage {
	t.Helper()
	payload, err := canonicalValue(p)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := canonicalValue(Envelope{Payload: payload, Signature: Signature{Algorithm: "Ed25519", KeyID: options.KeyID, Encoding: "base64", Value: base64.StdEncoding.EncodeToString(ed25519.Sign(options.PrivateKey, payload))}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func publicKeys(options Options) map[string]ed25519.PublicKey {
	return map[string]ed25519.PublicKey{options.KeyID: options.PrivateKey.Public().(ed25519.PublicKey)}
}

// signedField is one top-level member of a receipt's signed payload, or nil.
func signedField(t *testing.T, raw json.RawMessage, name string) json.RawMessage {
	t.Helper()
	var envelope Envelope
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(envelope.Payload, &fields); err != nil {
		t.Fatal(err)
	}
	return fields[name]
}

func fullManifest(t *testing.T, signer *Signer, p Payload) Payload {
	t.Helper()
	raw, err := signer.Manifest(context.Background(), p.JobID, p.Manifest.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	var full Payload
	if err := strictDecode(raw, &full); err != nil {
		t.Fatal(err)
	}
	return full
}

func TestLaneReceiptValidates(t *testing.T) {
	options, job, result, expected := laneFixture(t)
	signer, raw, p := sealFixture(t, options, job, result)
	if err := ValidateSuccess(p, expected); err != nil {
		t.Fatal(err)
	}
	if p.Schema != 2 || p.Resources.HostPeakMemoryMiB != 6144 || p.Resources.PeakMemoryMiB != 2048 {
		t.Fatalf("lane receipt identity: schema %d resources %+v", p.Schema, p.Resources)
	}
	want := `{"attribution":"lineage+device/v1","idle_verdict":"not_required","lane":2,"max_lanes":2,"overlap_count":1,"overlapped_jobs":[{"job_id":"job-0","overlap_seconds":7}],"overlaps_sha256":"` + overlapsDigest([]Overlap{{JobID: "job-0", Seconds: 7}}) + `","unattributed_residue":0}`
	if got := string(signedField(t, raw, "concurrency")); got != want {
		t.Fatalf("signed lane record %s, want %s", got, want)
	}
	if !bytes.Contains(signedField(t, raw, "resources"), []byte(`"host_peak_memory_mib":6144`)) {
		t.Fatal("signed resources lack the host peak footprint")
	}
	if _, err := PublicDigest(raw); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSuccess(fullManifest(t, signer, p), expected); err != nil {
		t.Fatalf("full lane manifest: %v", err)
	}
	for name, mutate := range map[string]func(*worker.Concurrency, *worker.Result){
		"three lanes": func(c *worker.Concurrency, _ *worker.Result) { c.Lane, c.MaxLanes = 3, 3 },
		"residue removed before idle": func(c *worker.Concurrency, _ *worker.Result) {
			c.UnattributedResidue, c.IdleVerdict = 2, worker.IdleClean
		},
		"account rule running alone": func(c *worker.Concurrency, _ *worker.Result) {
			c.Attribution, c.OverlappedJobs = worker.AttributionAccount, nil
		},
		"single lane with host peak": func(c *worker.Concurrency, r *worker.Result) {
			c.Lane, c.MaxLanes, c.OverlappedJobs, c.IdleVerdict = 1, 1, nil, worker.IdleClean
			r.HostPeakMemoryMiB = r.PeakMemoryMiB
		},
		"single lane without host peak": func(c *worker.Concurrency, r *worker.Result) {
			c.Lane, c.MaxLanes, c.OverlappedJobs, c.IdleVerdict = 1, 1, nil, worker.IdleClean
			r.HostPeakMemoryMiB = 0
		},
	} {
		t.Run(name, func(t *testing.T) {
			options, job, result, expected := laneFixture(t)
			mutate(result.Concurrency, &result)
			_, _, p := sealFixture(t, options, job, result)
			if err := ValidateSuccess(p, expected); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPreLaneResultRecordsOneLane(t *testing.T) {
	for verdict, cleanup := range map[string]bool{worker.IdleClean: true, worker.IdleDeferred: false} {
		t.Run(verdict, func(t *testing.T) {
			options, job, result, _ := fixture(t, model.Build)
			result.CleanupOK = cleanup
			if !cleanup {
				result.State, result.Reason = model.Failed, "cleanup failed"
			}
			_, raw, p := sealFixture(t, options, job, result)
			want := `{"attribution":"account/v1","idle_verdict":"` + verdict + `","lane":1,"max_lanes":1,"overlap_count":0,"overlapped_jobs":[],"overlaps_sha256":"` + overlapsDigest(nil) + `","unattributed_residue":0}`
			if got := string(signedField(t, raw, "concurrency")); p.Schema != 2 || got != want {
				t.Fatalf("schema %d lane record %s, want %s", p.Schema, got, want)
			}
			if bytes.Contains(signedField(t, raw, "resources"), []byte("host_peak_memory_mib")) {
				t.Fatal("an unreported host peak was recorded")
			}
		})
	}
}

func TestLaneRecordRejections(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*worker.Concurrency, *worker.Result)
		want   string
	}{
		"idle verdict deferred": {func(c *worker.Concurrency, _ *worker.Result) { c.IdleVerdict = worker.IdleDeferred }, "idle cleanup verdict"},
		"unknown idle verdict":  {func(c *worker.Concurrency, _ *worker.Result) { c.IdleVerdict = "dirty" }, "lane record"},
		"lane above max_lanes":  {func(c *worker.Concurrency, _ *worker.Result) { c.Lane = 3 }, "lane record"},
		"lane zero":             {func(c *worker.Concurrency, _ *worker.Result) { c.Lane = 0 }, "lane record"},
		"max_lanes above limit": {func(c *worker.Concurrency, _ *worker.Result) { c.MaxLanes = model.MaxConcurrentJobs + 1 }, "lane record"},
		"self overlap":          {func(c *worker.Concurrency, _ *worker.Result) { c.OverlappedJobs[0].JobID = "job-1" }, "lane record"},
		"duplicate overlap": {func(c *worker.Concurrency, _ *worker.Result) {
			c.OverlappedJobs = append(c.OverlappedJobs, c.OverlappedJobs[0])
		}, "lane record"},
		"invalid overlapped job":    {func(c *worker.Concurrency, _ *worker.Result) { c.OverlappedJobs[0].JobID = "../job-0" }, "lane record"},
		"negative overlap":          {func(c *worker.Concurrency, _ *worker.Result) { c.OverlappedJobs[0].Seconds = -1 }, "lane record"},
		"unknown attribution":       {func(c *worker.Concurrency, _ *worker.Result) { c.Attribution = "uid/v1" }, "lane record"},
		"account rule with overlap": {func(c *worker.Concurrency, _ *worker.Result) { c.Attribution = worker.AttributionAccount }, "lane record"},
		"single lane with overlap":  {func(c *worker.Concurrency, _ *worker.Result) { c.Lane, c.MaxLanes = 1, 1 }, "lane record"},
		"negative residue":          {func(c *worker.Concurrency, _ *worker.Result) { c.UnattributedResidue = -1 }, "lane record"},
		"host peak below job peak":  {func(_ *worker.Concurrency, r *worker.Result) { r.HostPeakMemoryMiB = r.PeakMemoryMiB - 1 }, "lane record"},
	} {
		t.Run(name, func(t *testing.T) {
			options, job, valid, expected := laneFixture(t)
			_, _, p := sealFixture(t, options, job, valid)
			_, _, result, _ := laneFixture(t)
			tc.mutate(result.Concurrency, &result)
			signer, err := NewSigner(options)
			if err != nil {
				t.Fatal(err)
			}
			defer signer.Close()
			if _, err := signer.Seal(context.Background(), job, result); err == nil {
				t.Fatal("invalid lane record sealed as success")
			}
			p.Concurrency, p.Resources.HostPeakMemoryMiB = lanes(result), result.HostPeakMemoryMiB
			if err := ValidateSuccess(p, expected); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("compact receipt: %v, want %q", err, tc.want)
			}
		})
	}
	t.Run("deferred failure seals", func(t *testing.T) {
		options, job, result, _ := laneFixture(t)
		result.State, result.Reason, result.CleanupOK = model.Failed, "lane cleanup unverified", false
		result.Concurrency.IdleVerdict = worker.IdleDeferred
		_, _, p := sealFixture(t, options, job, result)
		if p.Complete || !strings.Contains(strings.Join(p.Missing, ";"), "idle cleanup verdict") {
			t.Fatalf("deferred cleanup not recorded as missing: %v", p.Missing)
		}
	})
}

func TestSchemaFixesLaneFields(t *testing.T) {
	options, job, result, _ := laneFixture(t)
	_, _, p := sealFixture(t, options, job, result)
	keys := publicKeys(options)
	for name, mutate := range map[string]func(*Payload){
		"schema 1 with lane record": func(p *Payload) { p.Schema, p.Resources.HostPeakMemoryMiB = 1, 0 },
		"schema 1 with host peak":   func(p *Payload) { p.Schema, p.Concurrency = 1, nil },
		"schema 2 without lanes":    func(p *Payload) { p.Concurrency = nil },
		"unknown schema":            func(p *Payload) { p.Schema = 3 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := p
			mutate(&changed)
			raw := signPayload(t, options, changed)
			if _, err := Verify(raw, keys); err == nil {
				t.Fatal("verified")
			}
			if _, err := PublicDigest(raw); err == nil {
				t.Fatal("publishable")
			}
			if !strings.Contains(strings.Join(incomplete(changed), ";"), "receipt identity") {
				t.Fatal("schema shape not required for success")
			}
		})
	}
}

func TestLaneRecordMatchesExecutionManifest(t *testing.T) {
	options, job, result, expected := laneFixture(t)
	signer, _, p := sealFixture(t, options, job, result)
	for name, mutate := range map[string]func(*Payload){
		"payload overlap":             func(p *Payload) { p.Concurrency.OverlappedJobs[0].Seconds++ },
		"payload lane":                func(p *Payload) { p.Concurrency.Lane = 1 },
		"payload host peak":           func(p *Payload) { p.Resources.HostPeakMemoryMiB++ },
		"manifest lane":               func(p *Payload) { p.Details.Result.Concurrency.Lane = 1 },
		"manifest residue":            func(p *Payload) { p.Details.Result.Concurrency.UnattributedResidue = 1 },
		"manifest host peak":          func(p *Payload) { p.Details.Result.HostPeakMemoryMiB++ },
		"manifest without lanes":      func(p *Payload) { p.Details.Result.Concurrency = nil },
		"schema 1 over lane manifest": func(p *Payload) { p.Schema, p.Concurrency, p.Resources.HostPeakMemoryMiB = 1, nil, 0 },
	} {
		t.Run(name, func(t *testing.T) {
			full := fullManifest(t, signer, p)
			if err := ValidateSuccess(full, expected); err != nil {
				t.Fatal(err)
			}
			mutate(&full)
			if err := ValidateSuccess(full, expected); err == nil || !strings.Contains(err.Error(), "execution manifest") {
				t.Fatalf("lane manifest mismatch: %v", err)
			}
		})
	}
}

// legacy is p as sealed before lanes: schema 1 without a lane record.
func legacy(p Payload) Payload {
	p.Schema, p.Concurrency, p.Resources.HostPeakMemoryMiB = 1, nil, 0
	return p
}

func TestSchemaOneReceiptsStillValidate(t *testing.T) {
	options, job, result, expected := fixture(t, model.UnitTest)
	signer, _, p := sealFixture(t, options, job, result)
	keys := publicKeys(options)
	compact := signPayload(t, options, legacy(p))
	verified, err := Verify(compact, keys)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateSuccess(verified, expected); err != nil {
		t.Fatalf("schema-1 compact receipt: %v", err)
	}
	if _, err := PublicDigest(compact); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSuccess(legacy(fullManifest(t, signer, p)), expected); err != nil {
		t.Fatalf("schema-1 full manifest: %v", err)
	}
}

// A schema-1 manifest sealed before the upgrade is republished as it was:
// schema 1, no lane record and no host peak.
func TestSchemaOneManifestReplaysUnchanged(t *testing.T) {
	options, job, result, expected := fixture(t, model.UnitTest)
	signer, _, p := sealFixture(t, options, job, result)
	old, err := canonicalValue(legacy(fullManifest(t, signer, p)))
	if err != nil {
		t.Fatal(err)
	}
	upgraded := options
	upgraded.Root = filepath.Join(t.TempDir(), "upgraded")
	restarted, err := NewSigner(upgraded)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if err := os.WriteFile(filepath.Join(upgraded.Root, job.ID+"-input-"+p.InputDigest+".json"), old, 0600); err != nil {
		t.Fatal(err)
	}
	raw, err := restarted.Seal(context.Background(), job, result)
	if err != nil {
		t.Fatal(err)
	}
	again, err := restarted.Seal(context.Background(), job, result)
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatalf("legacy republication changed: %v", err)
	}
	if signedField(t, raw, "concurrency") != nil || bytes.Contains(signedField(t, raw, "resources"), []byte("host_peak_memory_mib")) {
		t.Fatal("legacy receipt gained lane fields")
	}
	verified, err := Verify(raw, publicKeys(options))
	if err != nil || verified.Schema != 1 || verified.Manifest.SHA256 != hashBytes(old) {
		t.Fatalf("legacy receipt: schema %d %v", verified.Schema, err)
	}
	if err := ValidateSuccess(verified, expected); err != nil {
		t.Fatal(err)
	}
	manifest, err := restarted.Manifest(context.Background(), job.ID, verified.Manifest.SHA256)
	if err != nil || !bytes.Equal(manifest, old) {
		t.Fatalf("legacy manifest changed: %v", err)
	}
}

// A long job beside a replenished queue overlaps many jobs: its compact
// receipt publishes a bounded part (the longest overlaps, the count and a
// digest) and stays publishable, while the full manifest's complete list is
// bound by that digest.
func TestManyOverlapsStayPublishable(t *testing.T) {
	options, job, result, expected := laneFixture(t)
	const n = 400
	result.Concurrency.OverlappedJobs = nil
	for i := range n {
		result.Concurrency.OverlappedJobs = append(result.Concurrency.OverlappedJobs, worker.Overlap{JobID: fmt.Sprintf("j_%048d", i), Seconds: int64(i)})
	}
	signer, raw, p := sealFixture(t, options, job, result)
	if len(raw) > MaxReceiptBytes {
		t.Fatalf("compact receipt %d bytes", len(raw))
	}
	if _, err := PublicDigest(raw); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSuccess(p, expected); err != nil {
		t.Fatal(err)
	}
	c := p.Concurrency
	if c.OverlapCount != n || len(c.OverlappedJobs) != PublishedOverlaps || c.OverlappedJobs[0].Seconds != n-1 || c.OverlappedJobs[PublishedOverlaps-1].Seconds != n-PublishedOverlaps {
		t.Fatalf("published overlaps: count %d, %v", c.OverlapCount, c.OverlappedJobs)
	}
	full := fullManifest(t, signer, p)
	if err := ValidateSuccess(full, expected); err != nil {
		t.Fatalf("full manifest: %v", err)
	}
	// An unpublished entry of the complete list is still bound.
	full.Details.Result.Concurrency.OverlappedJobs[0].Seconds++
	if err := ValidateSuccess(full, expected); err == nil || !strings.Contains(err.Error(), "execution manifest") {
		t.Fatalf("unpublished overlap changed undetected: %v", err)
	}
}

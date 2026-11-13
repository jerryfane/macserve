package githubpull

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/receipt"
	"github.com/jerryfane/macserve/internal/worker"
)

const testTemplate = "org-ios-sim-build-v1"

func templateFor(owners ...string) model.Template {
	return model.Template{ID: testTemplate, Version: 1, Kind: model.Build, Owners: owners, Xcode: model.Xcode{Version: "26.0", Build: "17A100"}, DeveloperDir: "/Applications/ExampleToolchain.app/Contents/Developer", DefaultTimeoutSeconds: 60, MaxTimeoutSeconds: 600, MemoryLimitMiB: 512}
}

func explicitProfile(id, repo string) model.Profile {
	return model.Profile{ID: id, Version: 1, Repo: repo, Kind: model.Build, Xcode: model.Xcode{Version: "26.0", Build: "17A100"}, DeveloperDir: "/Applications/ExampleToolchain.app/Contents/Developer", WorkDir: ".", Run: model.Command{Executable: "/usr/bin/true"}, DefaultTimeoutSeconds: 60, MaxTimeoutSeconds: 600, MemoryLimitMiB: 512}
}

func registryOf(t *testing.T, profileList []model.Profile, templates ...model.Template) *profiles.Registry {
	t.Helper()
	registry, err := profiles.New(profileList, templates)
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func TestPolicyNamingTemplateAdmitsOnlyApprovedOwners(t *testing.T) {
	for name, tc := range map[string]struct {
		registry *profiles.Registry
		ids      []string
	}{
		"other owner":          {registryOf(t, nil, templateFor("someone-else")), []string{testTemplate}},
		"unknown id":           {registryOf(t, nil, templateFor("example-org")), []string{"org-unknown-v1"}},
		"shadowed by explicit": {registryOf(t, []model.Profile{explicitProfile(testProfile, testRepo)}, templateFor("example-org")), []string{testTemplate}},
		"other repo profile":   {registryOf(t, []model.Profile{explicitProfile("other-build-v1", "example-org/other-app")}), []string{"other-build-v1"}},
		"duplicate template":   {registryOf(t, nil, templateFor("example-org")), []string{testTemplate, testTemplate}},
	} {
		if _, err := newFixtureWith(t, tc.registry, tc.ids); err == nil || err.Error() != "invalid GitHub profile policy" {
			t.Errorf("%s: policy accepted or wrong error: %v", name, err)
		}
	}
	// Templates of another kind cannot be configured at all, so no policy can
	// name one: the registry is the single kind gate for API and PR intake.
	other := templateFor("example-org")
	other.Kind = model.UnitTest
	if _, err := profiles.New(nil, []model.Template{other}); err == nil {
		t.Fatal("registry accepted a non-build template")
	}
	// An explicit profile of another repository does not shadow the template.
	if _, err := newFixtureWith(t, registryOf(t, []model.Profile{explicitProfile("other-build-v1", "example-org/other-app")}, templateFor("example-org")), []string{testTemplate}); err != nil {
		t.Fatalf("template refused beside another repository's profile: %v", err)
	}
}

func TestPolicyNamingTemplateEnrollsAndReceiptBindsTemplateDigest(t *testing.T) {
	template := templateFor("other-org", "example-org")
	f, err := newFixtureWith(t, registryOf(t, nil, template), []string{testTemplate})
	if err != nil {
		t.Fatalf("policy naming a template for an approved owner refused: %v", err)
	}
	f.poll(t)
	run := f.run(t)
	check, packet := f.current(t)
	if run.Profile != testTemplate || check.Name != "mac-evidence/"+testTemplate || packet.JobID != run.JobID {
		t.Fatalf("template enrollment not exact: %+v %+v", run, check)
	}
	ctx := context.Background()
	job, err := f.s.Claim(ctx, "worker-epoch", f.options.Now(), 1)
	if err != nil {
		t.Fatal(err)
	}
	want, err := template.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if job.ProfileDigest != want || job.Profile.Template == nil || job.Profile.Repo != testRepo || job.Request.Profile != testTemplate || job.Request.Kind != model.Build || job.Request.Simulator != nil {
		t.Fatalf("template admission snapshot not bound: digest=%s profile=%+v request=%+v", job.ProfileDigest, job.Profile, job.Request)
	}
	if digest, err := job.Profile.Template.Digest(); err != nil || digest != want {
		t.Fatalf("snapshot template digest %s %v", digest, err)
	}
	started := *job.StartedAt
	finished := started.Add(10 * time.Second)
	// A failed attempt still seals a receipt that names the admitted recipe;
	// success additionally needs the worker's .macserve.json recipe evidence.
	one := 1
	result := worker.Result{State: model.Failed, Reason: "command_failed", ExitCode: &one, CleanupOK: true, StartedAt: started, FinishedAt: finished, Source: worker.Source{Commit: job.Request.SHA, Tree: strings.Repeat("b", 40), SHA256: strings.Repeat("c", 64), SizeBytes: 1024}, Observation: worker.Observation{Xcode: job.Request.Xcode, SDKVersion: "26.0", SDKBuild: "23A100", SwiftVersion: "Swift 6.2", OSVersion: "26.0", OSBuild: "25A100", Architecture: "arm64", GeneratedDigests: map[string]string{}, LockfileDigests: map[string]string{}}}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	signer, err := receipt.NewSigner(receipt.Options{Root: filepath.Join(t.TempDir(), "receipts"), KeyID: "test-key", PrivateKey: key, Service: receipt.ServiceIdentity{ID: "service", HostID: "host", Version: "1", BinarySHA256: strings.Repeat("e", 64)}, Repository: func(context.Context, model.Job) (receipt.Repository, error) {
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
	payload, err := receipt.Verify(raw, map[string]ed25519.PublicKey{"test-key": key.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	if payload.ProfileDigest != want || payload.Request.Profile != testTemplate || payload.Approval.Intake != "github_pull" || payload.Approval.AttemptID != run.AttemptID {
		t.Fatalf("receipt does not bind the template digest and PR approval: %+v", payload)
	}
}

// A template edit changes its digest, which must change the run key and stop
// a job admitted under the old template from dispatching.
func TestTemplateDigestPinsRunKeyAndDispatch(t *testing.T) {
	template := templateFor("example-org")
	f, err := newFixtureWith(t, registryOf(t, nil, template), []string{testTemplate})
	if err != nil {
		t.Fatal(err)
	}
	f.poll(t)
	run := f.run(t)
	ctx := context.Background()
	job, err := f.s.Get(ctx, run.JobID)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.p.BeforeDispatch(ctx, job); err != nil {
		t.Fatalf("current template job refused: %v", err)
	}
	edited := template
	edited.Version = 2
	options := f.options
	options.Profiles = registryOf(t, nil, edited)
	p, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	input, err := p.admission(options.Policies[0], f.remote.pull, testTemplate, "")
	if err != nil {
		t.Fatal(err)
	}
	want, err := edited.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if input.Admission.ProfileDigest != want || input.Run.Key == run.Key {
		t.Fatalf("run key does not bind the template digest: key=%s old=%s digest=%s", input.Run.Key, run.Key, input.Admission.ProfileDigest)
	}
	if err = p.BeforeDispatch(ctx, job); !errors.Is(err, ErrIneligible) {
		t.Fatalf("job admitted under the old template still dispatches: %v", err)
	}
}

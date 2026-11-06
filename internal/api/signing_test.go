package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/controller"
	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/githubapi"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/store"
	"github.com/jerryfane/macserve/internal/worker"
)

const (
	signToken  = "6666666666666666666666666666666666666666666666666666666666666666"
	otherToken = "7777777777777777777777777777777777777777777777777777777777777777"
)

// signSetup admits and completes an ios_archive job for the releaser,
// serves principals "signer-less" (no release:sign) and "other" (release:sign,
// not the job's), and records Sign calls.
func signSetup(t *testing.T) (*fixture, model.Job, *[]string) {
	t.Helper()
	heads := &fakeHeads{head: githubapi.BranchHead{RepositoryID: 77, Branch: "main", SHA: strings.Repeat("c", 40)}}
	f, request := archiveSetup(t, heads, "jobs:submit", "jobs:read", "release:archive", "release:sign")
	ctx := context.Background()
	if err := f.db.ReplacePrincipals(ctx, []store.Principal{
		f.owner,
		principal(archiveToken, "releaser", "themartianapp/*", "jobs:submit", "jobs:read", "release:archive", "release:sign"),
		principal(signToken, "reader", "themartianapp/*", "jobs:read"),
		principal(otherToken, "other", "themartianapp/*", "jobs:read", "release:sign"),
	}); err != nil {
		t.Fatal(err)
	}
	if code, body := submitArchive(t, f, "archive", request); code != 202 {
		t.Fatalf("submit %d %s", code, body)
	}
	job, err := f.db.Lookup(ctx, "releaser", "archive")
	if err != nil {
		t.Fatal(err)
	}
	calls := &[]string{}
	f.options.Sign = func(ctx context.Context, id string) (store.SigningRecord, error) {
		*calls = append(*calls, id)
		record, _, err := f.db.BeginSigning(ctx, id, testTime)
		return record, err
	}
	f.options.SignerKey = &SignerKey{KeyID: "signer-1", PublicKey: "cHVibGlj"}
	if f.handler, err = New(f.options); err != nil {
		t.Fatal(err)
	}
	return f, job, calls
}

func completeJob(t *testing.T, f *fixture, job model.Job, state model.State) {
	t.Helper()
	ctx := context.Background()
	claimed, err := f.db.Claim(ctx, "epoch", testTime)
	if err != nil || claimed.ID != job.ID {
		t.Fatalf("claim %v %v", claimed.ID, err)
	}
	if err := f.db.Transition(ctx, job.ID, claimed.LeaseToken, model.Preparing, model.Finalizing, "done", testTime); err != nil {
		t.Fatal(err)
	}
	result, _ := json.Marshal(controller.Completion{Result: worker.Result{State: state, CleanupOK: true, Artifacts: []evidence.Artifact{}}})
	if err := f.db.Finish(ctx, job.ID, claimed.LeaseToken, state, result, true, "done", testTime); err != nil {
		t.Fatal(err)
	}
}

// POST /v1/jobs/<id>/sign requires release:sign and the job's principal
// (or an admin); refused callers never reach the signer.
func TestSignRequiresReleaseSignScopeAndJobPrincipal(t *testing.T) {
	f, job, calls := signSetup(t)
	completeJob(t, f, job, model.Succeeded)
	path := "/v1/jobs/" + job.ID + "/sign"
	if w := perform(f.handler, "POST", path, signToken, "", ""); w.Code != 403 || !strings.Contains(w.Body.String(), `"forbidden"`) {
		t.Fatalf("without release:sign: %d %s", w.Code, w.Body.String())
	}
	if w := perform(f.handler, "POST", path, otherToken, "", ""); w.Code != 403 {
		t.Fatalf("other principal: %d %s", w.Code, w.Body.String())
	}
	if w := perform(f.handler, "POST", path, testToken, "", ""); w.Code != 403 {
		// The admin lacks release:sign, so it is refused by scope.
		t.Fatalf("admin without release:sign: %d %s", w.Code, w.Body.String())
	}
	if len(*calls) != 0 {
		t.Fatalf("refused requests reached the signer: %v", *calls)
	}
	w := perform(f.handler, "POST", path, archiveToken, "", "")
	if w.Code != 202 || !strings.Contains(w.Body.String(), `"status":"signing"`) || !strings.Contains(w.Body.String(), `"state":"succeeded"`) {
		t.Fatalf("sign: %d %s", w.Code, w.Body.String())
	}
	// Idempotent: a repeat returns the signing in progress.
	w = perform(f.handler, "POST", path, archiveToken, "", "")
	if w.Code != 202 || !strings.Contains(w.Body.String(), `"status":"signing"`) {
		t.Fatalf("repeat: %d %s", w.Code, w.Body.String())
	}
	artifact := evidence.Artifact{ID: strings.Repeat("a", 64), Name: "App.ipa", MediaType: "application/octet-stream", SizeBytes: 9, SHA256: strings.Repeat("a", 64), ExpiresAt: testTime.Add(1e12)}
	if err := f.db.FinishSigning(context.Background(), job.ID, store.Signed, "", []evidence.Artifact{artifact}, testTime); err != nil {
		t.Fatal(err)
	}
	w = perform(f.handler, "POST", path, archiveToken, "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"signed"`) || !strings.Contains(w.Body.String(), "/artifacts/"+artifact.ID) {
		t.Fatalf("signed: %d %s", w.Code, w.Body.String())
	}
	// The job view carries the sub-status beside its unchanged state.
	w = perform(f.handler, "GET", "/v1/jobs/"+job.ID, signToken, "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"state":"succeeded"`) || !strings.Contains(w.Body.String(), `"signing":{`) {
		t.Fatalf("job view: %d %s", w.Code, w.Body.String())
	}
	w = perform(f.handler, "GET", "/v1/jobs/"+job.ID+"/signing", signToken, "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"signed"`) {
		t.Fatalf("signing view: %d %s", w.Code, w.Body.String())
	}
}

// Only a succeeded ios_archive job signs; unfinished jobs are not ready.
func TestSignRefusesUnfinishedOrFailedJobs(t *testing.T) {
	f, job, _ := signSetup(t)
	path := "/v1/jobs/" + job.ID + "/sign"
	if w := perform(f.handler, "POST", path, archiveToken, "", ""); w.Code != 409 || !strings.Contains(w.Body.String(), "result_not_ready") {
		t.Fatalf("queued job: %d %s", w.Code, w.Body.String())
	}
	completeJob(t, f, job, model.Failed)
	if w := perform(f.handler, "POST", path, archiveToken, "", ""); w.Code != 409 {
		t.Fatalf("failed job: %d %s", w.Code, w.Body.String())
	}
}

// Capabilities publish the signer receipt key; without a signer, signing
// is refused as unsupported.
func TestSignerKeyInCapabilitiesAndSigningUnavailable(t *testing.T) {
	f, job, _ := signSetup(t)
	w := perform(f.handler, "GET", "/v1/capabilities", archiveToken, "", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"signer":{"key_id":"signer-1","public_key":"cHVibGlj"}`) {
		t.Fatalf("capabilities: %d %s", w.Code, w.Body.String())
	}
	completeJob(t, f, job, model.Succeeded)
	f.options.Sign, f.options.SignerKey = nil, nil
	var err error
	if f.handler, err = New(f.options); err != nil {
		t.Fatal(err)
	}
	if w := perform(f.handler, "POST", "/v1/jobs/"+job.ID+"/sign", archiveToken, "", ""); w.Code != 422 {
		t.Fatalf("no signer: %d %s", w.Code, w.Body.String())
	}
	if w := perform(f.handler, "GET", "/v1/capabilities", archiveToken, "", ""); strings.Contains(w.Body.String(), `"signer"`) {
		t.Fatalf("capabilities without signer: %s", w.Body.String())
	}
}

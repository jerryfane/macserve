package githubpull

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/controllerk/store"
	"github.com/jerryfane/macserve/internal/githubapi"
	"github.com/jerryfane/macserve/internal/githubwire"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
)

// buildOncePolicy is herdrup's UI shards consuming the org build's test
// products: the build profile is their producer.
func buildOncePolicy() githubwire.Policy {
	policy := matrixPolicy()
	policy.Profiles = []string{nativeBuild, uiTemplate}
	policy.Matrix = nil
	for _, entry := range matrixPolicy().Matrix[:3] {
		entry.Build = nativeBuild
		policy.Matrix = append(policy.Matrix, entry)
	}
	return policy
}

const buildCheck = "mac-evidence/" + nativeBuild

var shardChecks = []string{"mac-evidence/org-ios-sim-uitest-v1/iphone-terminal", "mac-evidence/org-ios-sim-uitest-v1/iphone-app", "mac-evidence/org-ios-sim-uitest-v1/ipad"}

const xctestrun = "Herdr_iphonesimulator27.1-arm64.xctestrun"

// finishJob claims the oldest queued job, which must be id, and ends it in
// state with result.
func (f *ownerFixture) finishJob(t *testing.T, id string, state model.State, result json.RawMessage) {
	t.Helper()
	ctx := context.Background()
	job, err := f.s.Claim(ctx, "worker-epoch", f.options.Now(), 4, false)
	if err != nil || job.ID != id {
		t.Fatalf("claimed %s, want %s: %v", job.ID, id, err)
	}
	if err = f.s.Transition(ctx, job.ID, job.LeaseToken, model.Preparing, model.Finalizing, "test execution finished", f.options.Now()); err != nil {
		t.Fatal(err)
	}
	if err = f.s.Finish(ctx, job.ID, job.LeaseToken, state, result, true, "test terminal", f.options.Now()); err != nil {
		t.Fatal(err)
	}
}

// succeedProducer ends producer job id succeeded with sealed test products
// of content, which the products pool records, and returns their digest.
func (f *ownerFixture) succeedProducer(t *testing.T, id, content string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(content))
	digest := hex.EncodeToString(sum[:])
	result := fmt.Sprintf(`{"input_digest":"x","result":{"state":"succeeded","artifacts":[{"id":"a1","name":"test-products.tar","media_type":"application/x-tar","size_bytes":%d,"sha256":%q}],"observation":{"xctestrun":%q}}}`, len(content), digest, xctestrun)
	f.finishJob(t, id, model.Succeeded, json.RawMessage(result))
	if err := f.s.RecordProduct(context.Background(), digest, int64(len(content)), id, f.options.Now()); err != nil {
		t.Fatal(err)
	}
	return digest
}

// One build-for-testing producer per head feeds every UI shard: the
// policy's build entry makes the build run a producer (its check name
// unchanged), and each shard run waits, with no job and a queued "Waiting
// for build" check naming the producer's job, until the producer succeeds.
// The next poll admits each shard with the producer's job, products digest
// and xctestrun, under the same run (key and check) it waited as.
func TestBuildOnceShardsWaitForTheirProducerThenRunFromItsProducts(t *testing.T) {
	f := newMatrixFixture(t, buildOncePolicy())
	sha := headSHA('1')
	f.pull(matrixRepo, matrixPull(1, sha), matrixConfig)
	f.poll(t)
	runs, checks := f.runsByCheck(t, sha), f.checksOf(sha)
	producer := runs[buildCheck]
	job := f.job(t, producer.JobID)
	if !job.Request.BuildForTesting || job.Request.Products != nil || checks[buildCheck].Status != "queued" {
		t.Fatalf("producer %+v check %+v", job.Request, checks[buildCheck])
	}
	for _, name := range shardChecks {
		run, check := runs[name], checks[name]
		if run.JobID != "" || run.Awaits != producer.Key || run.Blocked != "" {
			t.Fatalf("%s: run %+v", name, run)
		}
		if check.Status != "queued" || check.Output.Title != "Waiting for build "+producer.JobID || check.ExternalID != "waiting:"+run.Key {
			t.Fatalf("%s: check %+v", name, check)
		}
	}
	f.poll(t)
	if again := f.runsByCheck(t, sha); again[shardChecks[0]].JobID != "" {
		t.Fatalf("shard admitted before its producer succeeded: %+v", again[shardChecks[0]])
	}

	digest := f.succeedProducer(t, producer.JobID, "products of head 1")
	f.poll(t)
	admitted := f.runsByCheck(t, sha)
	want := model.ProductsRef{ProducerJobID: producer.JobID, SHA256: digest, Xctestrun: xctestrun}
	for _, name := range shardChecks {
		run := admitted[name]
		if run.Key != runs[name].Key || run.JobID == "" || run.Awaits != "" {
			t.Fatalf("%s: run %+v, waited as %s", name, run, runs[name].Key)
		}
		consumer := f.job(t, run.JobID)
		if consumer.Request.Products == nil || *consumer.Request.Products != want || consumer.Request.SHA != sha || consumer.Request.BuildForTesting {
			t.Fatalf("%s: consumer request %+v", name, consumer.Request)
		}
		if check := f.checksOf(sha)[name]; check.ExternalID != run.JobID || check.Status != "queued" {
			t.Fatalf("%s: check %+v", name, check)
		}
		// The dispatch check recomputes the run from the job's own request,
		// products included, and accepts it.
		if err := f.p.checkDispatch(context.Background(), consumer); err != nil {
			t.Fatalf("%s: dispatch check: %v", name, err)
		}
	}
}

// A policy without a build entry keeps the plain build and self-building
// shards: no producer flag, no waiting, no products.
func TestNoBuildEntryKeepsPlainBuildAndShards(t *testing.T) {
	policy := buildOncePolicy()
	for i := range policy.Matrix {
		policy.Matrix[i].Build = ""
	}
	f := newMatrixFixture(t, policy)
	f.pull(matrixRepo, matrixPull(1, headSHA('1')), matrixConfig)
	f.poll(t)
	for name, run := range f.runsByCheck(t, headSHA('1')) {
		job := f.job(t, run.JobID)
		if job.Request.BuildForTesting || job.Request.Products != nil || run.Awaits != "" {
			t.Fatalf("%s: %+v %+v", name, run, job.Request)
		}
	}
}

// A failed producer blocks every waiting shard (action_required naming the
// build job) without starting any job; the owner's rerun of the build makes
// them wait again, and its success admits them from the rerun's products.
func TestBuildOnceProducerFailureBlocksShardsUntilARerunSucceeds(t *testing.T) {
	f := newMatrixFixture(t, buildOncePolicy())
	sha := headSHA('1')
	f.pull(matrixRepo, matrixPull(1, sha), matrixConfig)
	f.poll(t)
	producer := f.runsByCheck(t, sha)[buildCheck]
	f.finishJob(t, producer.JobID, model.Failed, json.RawMessage(`{}`))
	f.poll(t)
	for _, name := range shardChecks {
		run, check := f.runsByCheck(t, sha)[name], f.checksOf(sha)[name]
		if run.JobID != "" || !strings.Contains(run.Blocked, "Build job "+producer.JobID+" failed") {
			t.Fatalf("%s: run %+v", name, run)
		}
		if check.Status != "completed" || check.Conclusion != "action_required" {
			t.Fatalf("%s: check %+v", name, check)
		}
	}
	// An owner rerun of a blocked shard has no products to run from.
	if _, _, err := f.p.Rerun(context.Background(), matrixRepoID, matrixRepo, sha, uiTemplate, "ipad", f.options.Now()); !errors.Is(err, ErrNoProducts) {
		t.Fatalf("shard rerun without products: %v", err)
	}

	rerun, started, err := f.p.Rerun(context.Background(), matrixRepoID, matrixRepo, sha, nativeBuild, "", f.options.Now())
	if err != nil || !started || rerun.JobID == producer.JobID {
		t.Fatalf("build rerun %+v %t %v", rerun, started, err)
	}
	f.poll(t)
	for _, name := range shardChecks {
		run, check := f.runsByCheck(t, sha)[name], f.checksOf(sha)[name]
		if run.JobID != "" || run.Blocked != "" || run.Awaits != producer.Key || check.Status != "queued" || check.Output.Title != "Waiting for build "+rerun.JobID {
			t.Fatalf("%s after the build rerun: run %+v check %+v", name, run, check)
		}
	}
	digest := f.succeedProducer(t, rerun.JobID, "rerun products")
	f.poll(t)
	for _, name := range shardChecks {
		run := f.runsByCheck(t, sha)[name]
		if run.JobID == "" || f.job(t, run.JobID).Request.Products.SHA256 != digest || f.job(t, run.JobID).Request.Products.ProducerJobID != rerun.JobID {
			t.Fatalf("%s not admitted from the rerun: %+v", name, run)
		}
	}
}

// Products evicted while a head waited (a draft held its full shards back
// past the pool's retention) start a producer rebuild, and the shards wait
// for it; rebuilds are bounded at two per run in any hour, at which the
// shards are blocked, until a later poll may rebuild again.
func TestBuildOnceEvictedProductsRebuildTheProducerWithinItsBound(t *testing.T) {
	ctx := context.Background()
	f := newMatrixFixture(t, buildOncePolicy())
	sha := headSHA('1')
	f.pull(matrixRepo, matrixPull(1, sha), matrixConfig)
	f.poll(t)
	producer := f.runsByCheck(t, sha)[buildCheck]
	jobID := producer.JobID
	for i := range 3 {
		digest := f.succeedProducer(t, jobID, fmt.Sprintf("products %d", i))
		if err := f.s.EvictProduct(ctx, digest, f.options.Now()); err != nil {
			t.Fatal(err)
		}
		f.poll(t)
		runs := f.runsByCheck(t, sha)
		rebuilt := runs[buildCheck]
		if i < 2 {
			job := f.job(t, rebuilt.JobID)
			if rebuilt.JobID == jobID || !job.Request.BuildForTesting || job.State != model.Queued {
				t.Fatalf("rebuild %d: run %+v job %s", i, rebuilt, job.State)
			}
			for _, name := range shardChecks {
				if run := runs[name]; run.JobID != "" || run.Awaits != producer.Key || run.Blocked != "" {
					t.Fatalf("rebuild %d: %s %+v", i, name, run)
				}
			}
			jobID = rebuilt.JobID
			continue
		}
		if rebuilt.JobID != jobID {
			t.Fatalf("third rebuild within the hour: %+v", rebuilt)
		}
		for _, name := range shardChecks {
			run, check := runs[name], f.checksOf(sha)[name]
			if run.JobID != "" || !strings.Contains(run.Blocked, "evicted") || check.Conclusion != "action_required" {
				t.Fatalf("at the rebuild bound: %s %+v %+v", name, run, check)
			}
		}
	}
	f.advance(time.Hour)
	f.poll(t)
	runs := f.runsByCheck(t, sha)
	if runs[buildCheck].JobID == jobID || runs[shardChecks[0]].Awaits != producer.Key || runs[shardChecks[0]].Blocked != "" {
		t.Fatalf("an hour later: build %+v shard %+v", runs[buildCheck], runs[shardChecks[0]])
	}
}

// A draft holds the shards back, but its producer still builds, and the
// products of a current eligible head's succeeded producer stay pinned
// against the pool's eviction while the head waits to be marked ready.
// Products an unfinished consumer names stay pinned after its producer is
// rerun; a new push unpins the old head's products once its consumers are
// cancelled.
func TestBuildOncePinsProductsOfCurrentHeadsAndUnfinishedConsumers(t *testing.T) {
	ctx := context.Background()
	policy := buildOncePolicy()
	policy.MatrixSkipDrafts = true
	f := newMatrixFixture(t, policy)
	sha := headSHA('1')
	pull := matrixPull(1, sha)
	pull.Draft = true
	f.pull(matrixRepo, pull, matrixConfig)
	f.poll(t)
	runs := f.runsByCheck(t, sha)
	if len(runs) != 1 || runs[buildCheck].JobID == "" {
		t.Fatalf("draft head runs %+v", runs)
	}
	digest := f.succeedProducer(t, runs[buildCheck].JobID, "head 1 products")
	f.poll(t)
	pinned, err := f.s.PinnedProducts(ctx)
	if err != nil || !pinned[digest] {
		t.Fatalf("current draft head's products not pinned: %v %v", pinned, err)
	}
	f.setPull(matrixRepo, func(p *githubapi.PullRequest) { p.Draft = false })
	f.poll(t)
	consumers := f.runsByCheck(t, sha)
	for _, name := range shardChecks {
		if consumers[name].JobID == "" || f.job(t, consumers[name].JobID).Request.Products.SHA256 != digest {
			t.Fatalf("%s not admitted from the draft-time products: %+v", name, consumers[name])
		}
	}

	// The rerun's products differ; the old ones stay pinned by the queued
	// consumers that name them.
	rerun, _, err := f.p.Rerun(ctx, matrixRepoID, matrixRepo, sha, nativeBuild, "", f.options.Now())
	if err != nil {
		t.Fatal(err)
	}
	if pinned, err = f.s.PinnedProducts(ctx); err != nil || !pinned[digest] {
		t.Fatalf("queued consumers' products not pinned during a build rerun: %v %v", pinned, err)
	}
	if rerun.JobID == consumers[buildCheck].JobID {
		t.Fatalf("no build rerun: %+v", rerun)
	}

	f.setPull(matrixRepo, func(p *githubapi.PullRequest) { p.HeadSHA = headSHA('2') })
	f.remote.mu.Lock()
	f.remote.files[matrixRepo+"@"+headSHA('2')] = matrixConfig
	f.remote.mu.Unlock()
	f.poll(t)
	for _, name := range shardChecks {
		if job := f.job(t, consumers[name].JobID); !job.State.Terminal() {
			t.Fatalf("%s: superseded consumer %s", name, job.State)
		}
	}
	if pinned, err = f.s.PinnedProducts(ctx); err != nil || pinned[digest] {
		t.Fatalf("superseded head's products still pinned: %v %v", pinned, err)
	}
	if runs := f.runsByCheck(t, headSHA('2')); runs[shardChecks[0]].Awaits != runs[buildCheck].Key {
		t.Fatalf("new head's shard does not wait for its own producer: %+v", runs)
	}
}

// The poller refuses a build entry that cannot produce or consume test
// products: a script entry, a build that is not a policy profile, a
// matrix profile or a Flutter build template.
func TestBuildOncePolicyValidation(t *testing.T) {
	if _, err := newOrgFixture(t, matrixTemplates(), buildOncePolicy()); err != nil {
		t.Fatalf("valid build-once policy refused: %v", err)
	}
	for name, mutate := range map[string]func(*githubwire.Policy){
		"script entry": func(p *githubwire.Policy) {
			p.Profiles = append(p.Profiles, scriptTmpl)
			p.Matrix = append(p.Matrix, githubwire.MatrixEntry{Profile: scriptTmpl, Shard: "ipad-script", Simulator: iPhone, Build: nativeBuild})
		},
		"build not a policy profile": func(p *githubwire.Policy) { p.Matrix[0].Build = flutterBuild },
		"build is a matrix profile":  func(p *githubwire.Policy) { p.Matrix[0].Build = uiTemplate },
		"flutter build": func(p *githubwire.Policy) {
			p.Profiles = append(p.Profiles, flutterBuild)
			p.Matrix[0].Build = flutterBuild
		},
	} {
		policy := buildOncePolicy()
		mutate(&policy)
		if _, err := newOrgFixture(t, matrixTemplates(), policy); err == nil || !strings.Contains(err.Error(), "build") {
			t.Errorf("%s: accepted or wrong error: %v", name, err)
		}
	}
}

// A consumer run binds its producer's logical run: a change of the build
// template's recipe (a new version) makes new producer and consumer runs,
// and the old consumer job no longer passes the dispatch check, while a
// rerun of the same producer keeps the consumer's run (review F2).
func TestBuildOnceProducerRecipeChangeSupersedesConsumers(t *testing.T) {
	ctx := context.Background()
	f := newMatrixFixture(t, buildOncePolicy())
	sha := headSHA('1')
	f.pull(matrixRepo, matrixPull(1, sha), matrixConfig)
	f.poll(t)
	f.succeedProducer(t, f.runsByCheck(t, sha)[buildCheck].JobID, "version 1 products")
	f.poll(t)
	consumer := f.runsByCheck(t, sha)[shardChecks[0]]
	job := f.job(t, consumer.JobID)
	if err := f.p.checkDispatch(ctx, job); err != nil {
		t.Fatalf("current consumer refused: %v", err)
	}
	templates := matrixTemplates()
	for i := range templates {
		if templates[i].ID == nativeBuild {
			templates[i].Version = 2
		}
	}
	registry, err := profiles.New(nil, templates)
	if err != nil {
		t.Fatal(err)
	}
	f.options.Profiles = registry
	f.restart(t)
	input, err := f.p.admission(f.p.policies[matrixRepo], matrixPull(1, sha), uiTemplate, consumer.Shard, nil)
	if err != nil {
		t.Fatal(err)
	}
	if input.Run.Key == consumer.Key {
		t.Fatal("consumer run unchanged by its producer's recipe change")
	}
	if err := f.p.checkDispatch(ctx, job); !errors.Is(err, ErrIneligible) {
		t.Fatalf("old-recipe consumer dispatch: %v", err)
	}
}

// A producer and its consumers pin one Xcode: the keyholder signs a
// consumer only for products its own Xcode built (review F5).
func TestBuildOnceRefusesProducerOfAnotherXcode(t *testing.T) {
	templates := matrixTemplates()
	for i := range templates {
		if templates[i].ID == uiTemplate {
			templates[i].Xcode.Build = "17A101"
		}
	}
	if _, err := newOrgFixture(t, templates, buildOncePolicy()); err == nil || !strings.Contains(err.Error(), "Xcode") {
		t.Fatalf("producer of another Xcode accepted or wrong error: %v", err)
	}
	policy := buildOncePolicy()
	for i := range policy.Matrix {
		policy.Matrix[i].Build = ""
	}
	if _, err := newOrgFixture(t, templates, policy); err != nil {
		t.Fatalf("Xcode pins checked without a build: %v", err)
	}
}

// A draft held at one head past metadata retention loses its succeeded
// producer's job record; marking it ready rebuilds the producer (a bounded
// rebuild of the unchanged run) and its shards wait for, then run from,
// the rebuild (review F4).
func TestBuildOncePrunedProducerIsRebuilt(t *testing.T) {
	ctx := context.Background()
	policy := buildOncePolicy()
	policy.MatrixSkipDrafts = true
	f := newMatrixFixture(t, policy)
	sha := headSHA('1')
	pull := matrixPull(1, sha)
	pull.Draft = true
	f.pull(matrixRepo, pull, matrixConfig)
	f.poll(t)
	producer := f.runsByCheck(t, sha)[buildCheck]
	f.succeedProducer(t, producer.JobID, "draft products")
	f.advance(91 * 24 * time.Hour)
	if _, err := f.s.Prune(ctx, f.options.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Get(ctx, producer.JobID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("producer job not pruned: %v", err)
	}
	f.setPull(matrixRepo, func(p *githubapi.PullRequest) { p.Draft = false })
	f.poll(t)
	runs := f.runsByCheck(t, sha)
	rebuilt := runs[buildCheck]
	if rebuilt.JobID == "" || rebuilt.JobID == producer.JobID || rebuilt.Key != producer.Key {
		t.Fatalf("producer not rebuilt: %+v", rebuilt)
	}
	for _, name := range shardChecks {
		if run := runs[name]; run.JobID != "" || run.Blocked != "" || run.Awaits != producer.Key {
			t.Fatalf("%s: %+v", name, run)
		}
	}
	digest := f.succeedProducer(t, rebuilt.JobID, "rebuilt products")
	f.poll(t)
	for _, name := range shardChecks {
		run := f.runsByCheck(t, sha)[name]
		if run.JobID == "" || f.job(t, run.JobID).Request.Products.SHA256 != digest {
			t.Fatalf("%s not admitted from the rebuild: %+v", name, run)
		}
	}
}

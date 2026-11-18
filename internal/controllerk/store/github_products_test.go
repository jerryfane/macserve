package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
)

// producerAdmission is a build-for-testing producer admission of the
// fixture repository at sha, with pull request 7.
func producerAdmission(t *testing.T, sha string) model.Admission {
	t.Helper()
	template := model.Template{ID: "org-ios-sim-build-v1", Version: 1, Kind: model.Build, Owners: []string{"example-org"}, Xcode: model.Xcode{Version: "27.0", Build: "27A100"}, DeveloperDir: "/Applications/ExampleToolchain.app/Contents/Developer"}
	registry, err := profiles.New(nil, []model.Template{template})
	if err != nil {
		t.Fatal(err)
	}
	admission, err := registry.Resolve(model.Request{Repo: "example-org/example-app", SHA: sha, Kind: model.Build, Profile: template.ID, Xcode: template.Xcode, BuildForTesting: true, Context: model.RequestContext{PullRequest: 7}})
	if err != nil {
		t.Fatal(err)
	}
	return admission
}

// A run awaiting its producer is published once while it keeps waiting, and
// again each time the producer run's current job changes (here: the
// producer, first waiting for queue space, gets its job), so its check names
// that job. It keeps no job, a run with a job cannot wait, and admitting
// the run clears what it awaited.
func TestGitHubAwaitingRunRepublishesWithItsProducersJob(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t, Options{PerPrincipalLimit: 1})
	if err := s.InitializeGitHub(ctx); err != nil {
		t.Fatal(err)
	}
	blocker, err := s.AdmitGitHub(ctx, githubFixture(), testNow)
	if err != nil {
		t.Fatal(err)
	}
	producer := githubFixture()
	producer.Run.Key, producer.Run.SHA = strings.Repeat("c", 64), strings.Repeat("c", 40)
	producer.Admission.Request.SHA = producer.Run.SHA
	if _, err = s.AdmitGitHub(ctx, producer, testNow); !errors.Is(err, ErrFull) {
		t.Fatalf("producer at a full queue: %v", err)
	}
	consumer := producer.Run
	consumer.Key, consumer.Shard = strings.Repeat("d", 64), "ipad"
	if err = s.AwaitGitHub(ctx, consumer, producer.Run.Key, 7, testNow); err != nil {
		t.Fatal(err)
	}
	waiting, err := s.GitHubRun(ctx, consumer.Key)
	if err != nil || waiting.JobID != "" || waiting.Awaits != producer.Run.Key || waiting.Blocked != "" {
		t.Fatalf("waiting run %+v %v", waiting, err)
	}
	if pulls, err := s.GitHubPulls(ctx, consumer.Key); err != nil || len(pulls) != 1 || pulls[0] != 7 {
		t.Fatalf("waiting run's pull requests %v %v", pulls, err)
	}
	drain := func() map[string]bool {
		t.Helper()
		published := map[string]bool{}
		for {
			publication, err := s.NextGitHubPublication(ctx, testNow)
			if errors.Is(err, ErrNotFound) {
				return published
			}
			if err != nil {
				t.Fatal(err)
			}
			published[publication.Run.Key] = true
			if err = s.FinishGitHubPublication(ctx, publication, 9, time.Time{}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !drain()[consumer.Key] {
		t.Fatal("new waiting run not published")
	}
	if err = s.AwaitGitHub(ctx, consumer, producer.Run.Key, 7, testNow); err != nil {
		t.Fatal(err)
	}
	if published := drain(); published[consumer.Key] {
		t.Fatalf("unchanged waiting run republished: %v", published)
	}
	if _, err = s.Cancel(ctx, blocker.JobID, "client", model.CancelReason{Source: model.CancelGitHub}, testNow); err != nil {
		t.Fatal(err)
	}
	drain()
	started, err := s.AdmitGitHub(ctx, producer, testNow)
	if err != nil || started.JobID == "" {
		t.Fatalf("producer not admitted: %+v %v", started, err)
	}
	if !drain()[consumer.Key] {
		t.Fatal("waiting run not republished when its producer got a job")
	}

	if err = s.AwaitGitHub(ctx, consumer, consumer.Key, 7, testNow); !errors.Is(err, ErrInvalid) {
		t.Fatalf("run awaiting itself: %v", err)
	}
	withJob := producer.Run
	withJob.Shard = "ipad"
	if err = s.AwaitGitHub(ctx, withJob, consumer.Key, 7, testNow); !errors.Is(err, ErrConflict) {
		t.Fatalf("run with a job awaiting: %v", err)
	}
	if err = s.BlockGitHub(ctx, consumer, "build failed", testNow); err != nil {
		t.Fatal(err)
	}
	if blocked, _ := s.GitHubRun(ctx, consumer.Key); blocked.Awaits != "" || blocked.Blocked != "build failed" {
		t.Fatalf("blocked run %+v", blocked)
	}
}

// Rebuilds (mode rebuild) are only of a build-for-testing producer, start a
// new attempt only after a terminal one, and are bounded at two per run in
// any hour, apart from requested reruns.
func TestGitHubRebuildIsBoundedApartFromReruns(t *testing.T) {
	ctx := context.Background()
	s, _ := githubStore(t)
	plain := githubFixture()
	plain.Mode = "rebuild"
	if _, err := s.AdmitGitHub(ctx, plain, testNow); !errors.Is(err, ErrInvalid) {
		t.Fatalf("rebuild of a plain build: %v", err)
	}
	producer := githubFixture()
	producer.Admission = producerAdmission(t, producer.Run.SHA)
	producer.Run.Profile = producer.Admission.Request.Profile
	run, err := s.AdmitGitHub(ctx, producer, testNow)
	if err != nil {
		t.Fatal(err)
	}
	rebuild := producer
	rebuild.Mode = "rebuild"
	if again, err := s.AdmitGitHub(ctx, rebuild, testNow); err != nil || again.JobID != run.JobID {
		t.Fatalf("rebuild of an unfinished attempt: %+v %v", again, err)
	}
	for i := range 3 {
		if _, err = s.Cancel(ctx, run.JobID, "client", model.CancelReason{Source: model.CancelGitHub}, testNow); err != nil {
			t.Fatal(err)
		}
		next, err := s.AdmitGitHub(ctx, rebuild, testNow)
		if i == 2 {
			if !errors.Is(err, ErrRerunLimit) {
				t.Fatalf("third rebuild within the hour: %+v %v", next, err)
			}
			break
		}
		if err != nil || next.JobID == run.JobID {
			t.Fatalf("rebuild %d: %+v %v", i, next, err)
		}
		run = next
	}
	rerun := producer
	rerun.Mode = "rerun"
	if next, err := s.AdmitGitHub(ctx, rerun, testNow); err != nil || next.JobID == run.JobID {
		t.Fatalf("requested rerun after the rebuild bound: %+v %v", next, err)
	}
}

// A store from before build-for-testing producers gains the awaits column,
// empty for its runs, when GitHub intake initializes.
func TestGitHubAwaitsColumnAddedToExistingRuns(t *testing.T) {
	ctx := context.Background()
	s, _ := githubStore(t)
	run, err := s.AdmitGitHub(ctx, githubFixture(), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.ExecContext(ctx, "DROP TRIGGER github_awaits_publication; DROP INDEX github_runs_awaits; ALTER TABLE github_runs DROP COLUMN awaits"); err != nil {
		t.Fatal(err)
	}
	if err = s.InitializeGitHub(ctx); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GitHubRun(ctx, run.Key); err != nil || got.Awaits != "" || got.JobID != run.JobID {
		t.Fatalf("migrated run %+v %v", got, err)
	}
}

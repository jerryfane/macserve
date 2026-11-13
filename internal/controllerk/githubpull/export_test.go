package githubpull

import (
	"context"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/controllerk/store"
	"github.com/jerryfane/macserve/internal/githubapi"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
)

// RerunFixture exposes the owner-form fixture to the external API tests
// (package githubpull_test): one eligible open PR head of themartianapp/app
// (repository 501) admitted under profile RerunProfile by a real poll.
type RerunFixture struct {
	Poller   *Poller
	Store    *store.Store
	Profiles *profiles.Registry
	Now      func() time.Time
	Repo     string
	SHA      string
	f        *ownerFixture
}

const RerunProfile = nativeBuild

func NewRerunFixture(t *testing.T) *RerunFixture {
	t.Helper()
	f, err := newOwnerFixture(t, ownerPolicy("themartianapp", martianID))
	if err != nil {
		t.Fatal(err)
	}
	const app = "themartianapp/app"
	f.remote.install(app, 501, martianID, "themartianapp")
	f.pull(app, githubapi.PullRequest{Number: 1, HeadSHA: headSHA('1'), HeadRepositoryID: 501, AuthorID: ownerAuthor, BaseRef: "main"}, nativeConfig)
	f.poll(t)
	return &RerunFixture{Poller: f.p, Store: f.s, Profiles: f.options.Profiles, Now: f.options.Now, Repo: app, SHA: headSHA('1'), f: f}
}

// Current is the head's run, whatever its attempt's state.
func (x *RerunFixture) Current(t *testing.T) store.GitHubRun {
	t.Helper()
	runs, err := x.Store.GitHubRunsByHead(context.Background(), 501, x.Repo, x.SHA, RerunProfile, "")
	if err != nil || len(runs) != 1 {
		t.Fatalf("runs = %+v %v", runs, err)
	}
	return runs[0]
}

// End makes the run's current attempt terminal (cancelled by GitHub, which
// never reruns automatically) and publishes it.
func (x *RerunFixture) End(t *testing.T) {
	t.Helper()
	if _, err := x.Store.Cancel(context.Background(), x.Current(t).JobID, "superseded", model.CancelReason{Source: model.CancelGitHub}, x.Now()); err != nil {
		t.Fatal(err)
	}
	x.f.poll(t)
}

// Close closes the head's pull request.
func (x *RerunFixture) Close() {
	x.f.remote.mu.Lock()
	x.f.remote.pulls[x.Repo][0].State = "closed"
	x.f.remote.mu.Unlock()
}

package githubpull

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/githubapi"
	"github.com/jerryfane/macserve/internal/store"
)

func TestRejectedForkPublicationFailureDoesNotRetryForever(t *testing.T) {
	f := newFixture(t)
	f.remote.pull.HeadRepositoryID = 456
	f.remote.lostCreate = true
	if err := f.p.Poll(context.Background()); err == nil {
		t.Fatal("lost rejection response not reported")
	}
	f.advance(16 * time.Minute)
	f.poll(t)
	f.remote.mu.Lock()
	created := f.remote.created
	f.remote.mu.Unlock()
	if created != 1 {
		t.Fatalf("unchanged rejected fork recreated publication: %d", created)
	}
	if _, err := f.s.NextGitHubPublication(context.Background(), f.options.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("rejected fork retained retry work: %v", err)
	}
	if _, err := f.s.Claim(context.Background(), "worker", f.options.Now()); !errors.Is(err, store.ErrNoJob) {
		t.Fatalf("missing rejection check admitted fork: %v", err)
	}
}

func TestPublicationPassIsBoundedAndMakesProgress(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for i := range 25 {
		input, err := f.p.admission(f.p.policies[testRepo], githubapi.PullRequest{Number: i + 1, HeadSHA: fmt.Sprintf("%040x", i+1)}, testProfile)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.s.BlockGitHub(ctx, input.Run, "ineligible fork", f.options.Now()); err != nil {
			t.Fatal(err)
		}
	}
	previous := 0
	for range 3 {
		if err := f.p.publish(ctx); err != nil {
			t.Fatal(err)
		}
		f.remote.mu.Lock()
		created := f.remote.created
		f.remote.mu.Unlock()
		if created-previous > 10 || created <= previous {
			t.Fatalf("publication budget/progress: before=%d after=%d", previous, created)
		}
		previous = created
	}
	if previous != 25 {
		t.Fatalf("lost rejection work: %d", previous)
	}
	if _, err := f.s.NextGitHubPublication(ctx, f.options.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("completed publications remained dirty: %v", err)
	}
}

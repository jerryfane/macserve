package controllerconfig

import (
	"errors"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/githubwire"
)

// A GitHub policy names exactly one of a pinned repository or an owner; an
// owner policy needs its numeric owner ID and a receipt owners entry, and
// each owner has at most one policy. Repository policies are unchanged.
func TestGitHubPolicyForms(t *testing.T) {
	base := Config{Receipt: ReceiptConfig{KeyID: "test", PrivateKeyFile: "/service/secrets/receipt.key", ServiceID: "test", HostID: "test", Repositories: map[string]int64{"jerryfane/macserve": 123}, Owners: []string{"jerryfane", "themartianapp"}}}
	repository := githubwire.Policy{RepositoryID: 123, Repository: "jerryfane/macserve", AuthorIDs: []int64{38183696}, BaseBranches: []string{"main"}, Profiles: []string{"build-v1"}, PolicyRevision: 1}
	owner := githubwire.Policy{Owner: "themartianapp", OwnerID: 900, AuthorIDs: []int64{38183696}, DefaultBranch: true, Profiles: []string{"org-build-v1"}, PolicyRevision: 1}
	with := func(policies ...githubwire.Policy) Config {
		c := base
		c.GitHub = &GitHubConfig{AppID: 1, Installations: map[string]int64{"jerryfane": 2, "themartianapp": 3}, PrivateKeyFile: "/service/secrets/app.pem", Policies: policies}
		return c
	}
	for _, policies := range [][]githubwire.Policy{{repository}, {owner}, {repository, owner}} {
		c := with(policies...)
		if err := c.validateIntegrations(); err != nil {
			t.Fatalf("%+v: %v", policies, err)
		}
	}
	both := owner
	both.Repository, both.RepositoryID = repository.Repository, repository.RepositoryID
	ownerOnlyID := repository
	ownerOnlyID.OwnerID = 900
	defaultOnly := repository
	defaultOnly.DefaultBranch = true
	neither := owner
	neither.Owner, neither.OwnerID, neither.DefaultBranch = "", 0, false
	for name, policy := range map[string]githubwire.Policy{"both forms": both, "repository with owner id": ownerOnlyID, "repository with default branch": defaultOnly, "neither form": neither} {
		c := with(policy)
		if err := c.validateIntegrations(); !errors.Is(err, githubwire.ErrPolicyForm) {
			t.Fatalf("%s accepted: %v", name, err)
		}
	}
	noID := owner
	noID.OwnerID = 0
	noID.Owner = "themartianapp"
	unlisted := owner
	unlisted.Owner = "someone-else"
	upper := owner
	upper.Owner = "TheMartianApp"
	for name, policies := range map[string][]githubwire.Policy{"no owner id": {noID}, "owner outside receipt owners": {unlisted}, "non-canonical owner": {upper}, "duplicate owner": {owner, owner}} {
		c := with(policies...)
		err := c.validateIntegrations()
		if err == nil || !strings.Contains(err.Error(), "owner") {
			t.Fatalf("%s accepted: %v", name, err)
		}
	}
	c := with(repository, owner)
	if ids := c.GitHub.OwnerIDs(); len(ids) != 1 || ids["themartianapp"] != 900 {
		t.Fatalf("owner IDs: %v", ids)
	}
	if ids := (*GitHubConfig)(nil).OwnerIDs(); len(ids) != 0 {
		t.Fatalf("nil GitHub owner IDs: %v", ids)
	}
}

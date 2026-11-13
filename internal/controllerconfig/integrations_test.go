package controllerconfig

import (
	"encoding/json"
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

// A repository policy's matrix names its own profiles with unique valid shards
// and complete simulators; owner policies have none, and matrix_skip_drafts
// needs a matrix.
func TestGitHubPolicyMatrix(t *testing.T) {
	base := Config{Receipt: ReceiptConfig{KeyID: "test", PrivateKeyFile: "/service/secrets/receipt.key", ServiceID: "test", HostID: "test", Repositories: map[string]int64{"themartianapp/herdrup": 1318951363}, Owners: []string{"themartianapp"}}}
	const sim = `{"runtime":"com.apple.CoreSimulator.SimRuntime.iOS-27-0","runtime_build":"24A434","device_type":"com.apple.CoreSimulator.SimDeviceType.iPhone-18-Pro"}`
	repository := func(matrix string) string {
		return `{"repository":"themartianapp/herdrup","repository_id":1318951363,"author_ids":[38183696],"base_branches":["main"],"policy_revision":1,
 "profiles":["org-ios-sim-build-v1","org-ios-sim-uitest-v1","org-ios-sim-script-v1"]` + matrix + `}`
	}
	owner := `{"owner":"themartianapp","owner_id":318875733,"author_ids":[38183696],"default_branch":true,"profiles":["org-ios-sim-build-v1"],"policy_revision":1`
	validate := func(policy string) error {
		var p githubwire.Policy
		if err := json.Unmarshal([]byte(policy), &p); err != nil {
			t.Fatal(err)
		}
		c := base
		c.GitHub = &GitHubConfig{AppID: 1, Installations: map[string]int64{"themartianapp": 3}, PrivateKeyFile: "/service/secrets/app.pem", Policies: []githubwire.Policy{p}}
		return c.validateIntegrations()
	}
	for name, policy := range map[string]string{
		"no matrix": repository(""),
		"matrix":    repository(`,"matrix_skip_drafts":true,"matrix":[{"profile":"org-ios-sim-uitest-v1","shard":"chat","simulator":` + sim + `},{"profile":"org-ios-sim-uitest-v1","shard":"gram","simulator":` + sim + `},{"profile":"org-ios-sim-script-v1","shard":"chat","simulator":` + sim + `}]`),
		"skip paths": repository(`,"matrix":[{"profile":"org-ios-sim-uitest-v1","shard":"chat","simulator":` + sim + `},{"profile":"org-ios-sim-script-v1","shard":"chat","simulator":` + sim + `}],
 "matrix_skip_paths":{"include":["docs/**",".github/ISSUE_TEMPLATE/**","LICENSE","**/*.md"],"exclude":["App/**","Vendor/**"]}`),
		"owner": owner + `}`,
	} {
		if err := validate(policy); err != nil {
			t.Errorf("%s refused: %v", name, err)
		}
	}
	entry := func(profile, shard, simulator string) string {
		return `{"profile":"` + profile + `","shard":"` + shard + `","simulator":` + simulator + `}`
	}
	for name, policy := range map[string]string{
		"profile not in profiles":    repository(`,"matrix":[` + entry("org-ios-sim-unittest-v1", "chat", sim) + `]`),
		"duplicate profile, shard":   repository(`,"matrix":[` + entry("org-ios-sim-uitest-v1", "chat", sim) + `,` + entry("org-ios-sim-uitest-v1", "chat", sim) + `]`),
		"uppercase shard":            repository(`,"matrix":[` + entry("org-ios-sim-uitest-v1", "Chat", sim) + `]`),
		"empty shard":                repository(`,"matrix":[` + entry("org-ios-sim-uitest-v1", "", sim) + `]`),
		"long shard":                 repository(`,"matrix":[` + entry("org-ios-sim-uitest-v1", strings.Repeat("a", 33), sim) + `]`),
		"no device type":             repository(`,"matrix":[` + entry("org-ios-sim-uitest-v1", "chat", `{"runtime":"r","runtime_build":"b"}`) + `]`),
		"skip drafts without matrix": repository(`,"matrix_skip_drafts":true`),
		"owner matrix":               owner + `,"matrix":[` + entry("org-ios-sim-build-v1", "chat", sim) + `]}`,
		"owner skip drafts":          owner + `,"matrix_skip_drafts":true}`,
		"skip paths without matrix":  repository(`,"matrix_skip_paths":{"include":["docs/**"]}`),
		"owner skip paths":           owner + `,"matrix_skip_paths":{"include":["docs/**"]}}`,
	} {
		if err := validate(policy); err == nil || !strings.Contains(err.Error(), "matrix") {
			t.Errorf("%s accepted or wrong error: %v", name, err)
		}
	}
	matrix := `,"matrix":[` + entry("org-ios-sim-uitest-v1", "chat", sim) + `,` + entry("org-ios-sim-script-v1", "chat", sim) + `]`
	tooMany := make([]string, 33)
	for i := range tooMany {
		tooMany[i] = `"d` + strings.Repeat("x", i) + `"`
	}
	for name, paths := range map[string]string{
		"no include":        `{"exclude":["App/**"]}`,
		"empty include":     `{"include":[]}`,
		"dot-dot segment":   `{"include":["docs/../App/**"]}`,
		"absolute":          `{"include":["/docs/**"]}`,
		"empty segment":     `{"include":["docs//x.md"]}`,
		"partial globstar":  `{"include":["docs/a**"]}`,
		"three globstars":   `{"include":["**/a/**/b/**"]}`,
		"bad class":         `{"include":["docs/[a.md"]}`,
		"repeated include":  `{"include":["docs/**","docs/**"]}`,
		"invalid exclude":   `{"include":["docs/**"],"exclude":["App/../**"]}`,
		"too long":          `{"include":["` + strings.Repeat("a", 97) + `"]}`,
		"control character": `{"include":["docs/\u0001"]}`,
		"too many include":  `{"include":[` + strings.Join(tooMany, ",") + `]}`,
	} {
		if err := validate(repository(matrix + `,"matrix_skip_paths":` + paths)); err == nil || !strings.Contains(err.Error(), "matrix_skip_paths") {
			t.Errorf("skip paths %s accepted or wrong error: %v", name, err)
		}
	}
	if err := validate(repository(matrix + `,"matrix_skip_paths":{"include":["docs/**"],"exclude":["docs/**"]}`)); err != nil {
		t.Errorf("one glob in both lists refused: %v", err)
	}
}

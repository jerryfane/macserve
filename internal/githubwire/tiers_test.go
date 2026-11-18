package githubwire

import (
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/model"
)

// A tiered entry's check is named by its tier and shard; an untiered entry
// and a build keep their names.
func TestCheckNameTiers(t *testing.T) {
	for _, tc := range []struct{ profile, tier, shard, want string }{
		{"org-ios-sim-build-v1", "", "", "mac-evidence/org-ios-sim-build-v1"},
		{"org-ios-sim-uitest-v1", "", "ipad", "mac-evidence/org-ios-sim-uitest-v1/ipad"},
		{"org-ios-sim-uitest-v1", TierFull, "ipad", "mac-evidence/full/ipad"},
		{"org-ios-sim-script-v1", TierFull, "ipad-script", "mac-evidence/full/ipad-script"},
		{"org-ios-sim-uitest-v1", TierFast, "smoke", "mac-evidence/fast/smoke"},
	} {
		if got := CheckName(tc.profile, tc.tier, tc.shard); got != tc.want {
			t.Errorf("CheckName(%q, %q, %q) = %q, want %q", tc.profile, tc.tier, tc.shard, got, tc.want)
		}
	}
}

func tieredPolicy() Policy {
	sim := model.Simulator{Runtime: "r", RuntimeBuild: "b", DeviceType: "d"}
	return Policy{RepositoryID: 1, Repository: "o/r", Profiles: []string{"build", "ui", "script"}, MatrixSkipDrafts: true, MatrixFullLabel: "ready-to-merge",
		Matrix: []MatrixEntry{
			{Profile: "ui", Shard: "smoke", Tier: TierFast, Simulator: sim},
			{Profile: "ui", Shard: "ipad", Tier: TierFull, Simulator: sim},
			{Profile: "script", Shard: "ipad-script", Tier: TierFull, Simulator: sim},
		}}
}

// CheckMatrix refuses an unknown tier, a mix of tiered and untiered entries,
// two entries with one check name, and a full-tier label that cannot trigger
// anything or is not a label name.
func TestCheckMatrixTiers(t *testing.T) {
	if err := tieredPolicy().CheckMatrix(); err != nil {
		t.Fatalf("valid tiered matrix refused: %v", err)
	}
	for name, mutate := range map[string]func(*Policy){
		"unknown tier":            func(p *Policy) { p.Matrix[0].Tier = "slow" },
		"mixed tiers":             func(p *Policy) { p.Matrix[0].Tier = "" },
		"same tier and shard":     func(p *Policy) { p.Matrix[2].Shard = "ipad" },
		"label without drafts":    func(p *Policy) { p.MatrixSkipDrafts = false },
		"label without full tier": func(p *Policy) { p.Matrix[1].Tier, p.Matrix[2].Tier = TierFast, TierFast },
		"label untiered":          func(p *Policy) { p.Matrix[0].Tier, p.Matrix[1].Tier, p.Matrix[2].Tier = "", "", "" },
		"label padded":            func(p *Policy) { p.MatrixFullLabel = " ready" },
		"label too long":          func(p *Policy) { p.MatrixFullLabel = strings.Repeat("x", 51) },
		"label control":           func(p *Policy) { p.MatrixFullLabel = "a\nb" },
		"label without matrix":    func(p *Policy) { p.Matrix, p.MatrixSkipDrafts = nil, false },
	} {
		policy := tieredPolicy()
		policy.Matrix = append([]MatrixEntry(nil), policy.Matrix...)
		mutate(&policy)
		if err := policy.CheckMatrix(); err == nil || !strings.Contains(err.Error(), "matrix") {
			t.Errorf("%s: accepted or wrong error: %v", name, err)
		}
	}
	// One shard in both tiers has two check names.
	policy := tieredPolicy()
	policy.Matrix = append(policy.Matrix, MatrixEntry{Profile: "script", Shard: "smoke", Tier: TierFull, Simulator: policy.Matrix[0].Simulator})
	if err := policy.CheckMatrix(); err != nil {
		t.Fatalf("one shard name in two tiers refused: %v", err)
	}
}

// A matrix entry's build names a profile of the policy that has no matrix
// entries of its own; Build and Producer report it.
func TestCheckMatrixBuild(t *testing.T) {
	policy := tieredPolicy()
	policy.Matrix[0].Build, policy.Matrix[1].Build = "build", "build"
	if err := policy.CheckMatrix(); err != nil {
		t.Fatalf("valid build entries refused: %v", err)
	}
	if policy.Build("ui", "ipad") != "build" || policy.Build("script", "ipad-script") != "" || !policy.Producer("build") || policy.Producer("ui") || policy.Producer("") {
		t.Fatalf("Build/Producer of %+v", policy.Matrix)
	}
	for name, build := range map[string]string{"not a profile": "other", "a matrix profile": "script"} {
		policy := tieredPolicy()
		policy.Matrix[0].Build = build
		if err := policy.CheckMatrix(); err == nil || !strings.Contains(err.Error(), "build") {
			t.Errorf("%s: accepted or wrong error: %v", name, err)
		}
	}
}

// matrix_skip_drafts holds a draft head back from untiered and full entries,
// never from fast ones; the full-tier label (any case) releases only full
// entries.
func TestHoldsBack(t *testing.T) {
	policy := tieredPolicy()
	for _, tc := range []struct {
		tier   string
		draft  bool
		labels []string
		want   bool
	}{
		{TierFast, true, nil, false},
		{TierFull, true, nil, true},
		{"", true, nil, true},
		{TierFull, false, nil, false},
		{TierFull, true, []string{"ui", "Ready-To-Merge"}, false},
		{"", true, []string{"ready-to-merge"}, true},
		{TierFull, true, []string{"ready-to-merge-later"}, true},
	} {
		if got := policy.HoldsBack(tc.tier, tc.draft, tc.labels); got != tc.want {
			t.Errorf("HoldsBack(%q, %v, %v) = %v", tc.tier, tc.draft, tc.labels, got)
		}
	}
	policy.MatrixSkipDrafts = false
	if policy.HoldsBack(TierFull, true, nil) {
		t.Error("held back without matrix_skip_drafts")
	}
}

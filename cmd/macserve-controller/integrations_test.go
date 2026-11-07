package main

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/controllerk/controller"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/worker"
)

// The GitHub receipt check expects a template test job's shard selectors,
// derived from its recorded recipe, not its snapshot's empty required tests;
// a template job whose completion lacks a deriving recipe has no expectation.
func TestReceiptExpectationUsesEffectiveRequiredTests(t *testing.T) {
	template := model.Template{ID: "org-ios-sim-uitest-v1", Version: 1, Kind: model.SimulatorUITest, Owners: []string{"themartianapp"}, Xcode: model.Xcode{Version: "27.0", Build: "27A100"}, DeveloperDir: "/Applications/Example.app/Contents/Developer", Simulators: []model.Simulator{{Runtime: "com.apple.CoreSimulator.SimRuntime.iOS-27-0", RuntimeBuild: "24A434", DeviceType: "com.apple.CoreSimulator.SimDeviceType.iPhone-18-Pro"}}}
	registry, err := profiles.New(nil, []model.Template{template})
	if err != nil {
		t.Fatal(err)
	}
	admission, err := registry.Resolve(model.Request{Repo: "themartianapp/herdrup", SHA: strings.Repeat("a", 40), Kind: template.Kind, Profile: template.ID, Xcode: template.Xcode, Shard: "terminal"})
	if err != nil {
		t.Fatal(err)
	}
	selectors := []string{"HerdrUITests/TerminalControlTests", "HerdrUITests/TerminalSearchTests"}
	config := model.RepoConfig{Version: 1, WorkDir: ".", Project: "Herdr.xcodeproj", Scheme: "Herdr", UITest: &model.TestShards{Shards: map[string][]string{"terminal": selectors}}}
	derived, err := profiles.Derive(admission.Profile, config)
	if err != nil {
		t.Fatal(err)
	}
	job := model.Job{ID: "job-1", Request: admission.Request, Profile: admission.Profile, ProfileDigest: admission.ProfileDigest}
	complete := func(recipe *model.RepoRecipe) {
		raw, err := json.Marshal(controller.Completion{Result: worker.Result{Observation: worker.Observation{Recipe: recipe}}})
		if err != nil {
			t.Fatal(err)
		}
		job.Result = raw
	}
	complete(&model.RepoRecipe{ConfigSHA256: strings.Repeat("f", 64), Config: config, WorkDir: derived.WorkDir, Prepare: derived.Prepare, Run: derived.Run, Shard: derived.Shard, RequiredTests: derived.RequiredTests})
	expected, err := receiptExpectation(map[string]int64{"themartianapp/herdrup": 42}, job)
	if err != nil || !slices.Equal(expected.RequiredTests, selectors) || expected.RepositoryID != 42 || expected.Profile != template.ID || expected.ProfileDigest != admission.ProfileDigest || expected.Simulator == nil || *expected.Simulator != template.Simulators[0] {
		t.Fatalf("template test expectation %+v %v", expected, err)
	}
	complete(nil)
	if _, err := receiptExpectation(nil, job); err == nil {
		t.Fatal("template job without a recipe had an expectation")
	}
}

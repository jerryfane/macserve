package qualification

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/maintenance"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/worker"
)

func TestTemplatesAreQualificationRecipes(t *testing.T) {
	template := model.Template{ID: "org-build-v1", Version: 1, Kind: model.Build, Owners: []string{"themartianapp"}, Xcode: model.Xcode{Version: "27.1", Build: "27A9275"}, DeveloperDir: "/Applications/Xcode.app/Contents/Developer", DefaultTimeoutSeconds: 1800, MaxTimeoutSeconds: 3600, MemoryLimitMiB: 32768}
	registry, err := profiles.New(nil, []model.Template{template})
	if err != nil {
		t.Fatal(err)
	}
	c := Challenge{Templates: registry.Templates(), Observation: maintenance.Observation{Profiles: registry.Digests()}}
	recipes := c.recipes()
	if len(recipes) != 1 || recipes[0].ID != template.ID || recipes[0].Template == nil || recipes[0].DeveloperDir != template.DeveloperDir || recipes[0].Xcode != template.Xcode {
		t.Fatalf("template is not a qualification recipe: %+v", recipes)
	}
	pin := SourcePin{Profile: template.ID, Repo: "themartianapp/fixture-app", Commit: strings.Repeat("a", 40)}
	admission, err := pinRequest(recipes[0], pin, 600)
	if err != nil || admission.ProfileDigest != c.Observation.Profiles[template.ID] || admission.Request.Repo != pin.Repo || admission.Profile.Template == nil {
		t.Fatalf("template pin admission %+v %v", admission, err)
	}
	for _, repo := range []string{"", "someone-else/app"} {
		pin.Repo = repo
		if _, err := pinRequest(recipes[0], pin, 600); err == nil {
			t.Fatalf("template pin for %q admitted", repo)
		}
	}
	// Zero templates: the challenge JSON and recipe list are unchanged.
	if (Challenge{}).recipes() != nil {
		t.Fatal("empty challenge grew recipes")
	}
}

// uiTemplate is an org UI-test template with two simulator pins.
func uiTemplate() model.Template {
	return model.Template{ID: "org-ios-sim-uitest-v1", Version: 1, Kind: model.SimulatorUITest, Owners: []string{"themartianapp"}, Xcode: model.Xcode{Version: "27.1", Build: "27A9275"}, DeveloperDir: "/Applications/Xcode.app/Contents/Developer", Simulators: []model.Simulator{
		{Runtime: "com.apple.CoreSimulator.SimRuntime.iOS-27-0", RuntimeBuild: "24A434", DeviceType: "com.apple.CoreSimulator.SimDeviceType.iPhone-17-Pro"},
		{Runtime: "com.apple.CoreSimulator.SimRuntime.tvOS-27-0", RuntimeBuild: "24J400", DeviceType: "com.apple.CoreSimulator.SimDeviceType.Apple-TV-4K-3rd-generation-4K"},
	}, DefaultTimeoutSeconds: 2400, MaxTimeoutSeconds: 3600, MemoryLimitMiB: 32768}
}

// Tool inspection checks a test template's simulator pins, and their SDKs,
// beside the explicit profiles' for the same toolchain, and only those. The
// toolchain does not exist, so every command fails, but the evidence log
// records what inspection asked for.
func TestToolEvidenceIncludesTemplateSimulatorPins(t *testing.T) {
	template := uiTemplate()
	template.DeveloperDir = "/Applications/MacserveMissingXcode.app/Contents/Developer"
	profile := model.Profile{ID: "app-ui", DeveloperDir: template.DeveloperDir, Simulator: &model.Simulator{Runtime: "com.apple.CoreSimulator.SimRuntime.watchOS-12-0", RuntimeBuild: "23R100", DeviceType: "com.apple.CoreSimulator.SimDeviceType.Apple-Watch-Series-11-46mm"}}
	other := template
	other.ID, other.DeveloperDir = "org-other-xcode", "/Applications/Xcode-26.app/Contents/Developer"
	other.Simulators = []model.Simulator{{Runtime: "com.apple.CoreSimulator.SimRuntime.xrOS-3-0", RuntimeBuild: "23N100", DeviceType: "com.apple.CoreSimulator.SimDeviceType.Apple-Vision-Pro"}}
	ok, log := inspectTools(context.Background(), Challenge{Profiles: []model.Profile{profile}, Templates: []model.Template{template, other}}, template.DeveloperDir)
	if ok {
		t.Fatal("missing toolchain passed tool inspection")
	}
	for _, want := range []string{`["--sdk" "appletvsimulator" "--show-sdk-version"]`, `["--sdk" "iphonesimulator" "--show-sdk-version"]`, `["--sdk" "watchsimulator" "--show-sdk-version"]`, `["simctl" "list" "runtimes" "--json"]`, "Pinned simulator runtime/build/device support mismatch"} {
		if !strings.Contains(log, want) {
			t.Errorf("tool evidence lacks %s:\n%s", want, log)
		}
	}
	if strings.Contains(log, "xrsimulator") {
		t.Errorf("another toolchain's template pin was inspected:\n%s", log)
	}
}

// A test template's source pin names the .macserve.json shard its
// tool-evidence run executes, on the template's first simulator; a pin
// without one does not admit.
func TestTestTemplateSourcePinRunsItsShard(t *testing.T) {
	registry, err := profiles.New(nil, []model.Template{uiTemplate()})
	if err != nil {
		t.Fatal(err)
	}
	c := Challenge{Templates: registry.Templates(), Observation: maintenance.Observation{Profiles: registry.Digests()}}
	recipe := c.recipes()[0]
	var pins SourcePins
	raw := `{"schema":1,"sources":[{"profile":"org-ios-sim-uitest-v1","repo":"themartianapp/herdrup","shard":"terminal","commit":"` + strings.Repeat("a", 40) + `","tree":"` + strings.Repeat("b", 40) + `","sha256":"` + strings.Repeat("c", 64) + `","size_bytes":1}]}`
	if err := decode([]byte(raw), &pins); err != nil {
		t.Fatal(err)
	}
	pin, _ := sourcePin(pins, recipe.ID)
	admission, err := pinRequest(recipe, pin, 600)
	if err != nil || admission.Request.Shard != "terminal" || admission.Request.Simulator == nil || *admission.Request.Simulator != uiTemplate().Simulators[0] || admission.ProfileDigest != c.Observation.Profiles[recipe.ID] {
		t.Fatalf("test template pin admission %+v %v", admission.Request, err)
	}
	unsharded := SourcePin{Profile: pin.Profile, Repo: pin.Repo, Commit: pin.Commit, Tree: pin.Tree, SHA256: pin.SHA256, SizeBytes: pin.SizeBytes}
	if _, err := pinRequest(recipe, unsharded, 600); err == nil {
		t.Fatal("test template pin without a shard admitted")
	}
}

// A script template's source pin also names its shard: the tool-evidence run
// executes that script on the template's first simulator, whose pins tool
// inspection checks; a pin without a shard does not admit.
func TestScriptTemplateSourcePinRunsItsShard(t *testing.T) {
	template := uiTemplate()
	template.ID, template.Kind, template.DefaultTimeoutSeconds, template.MaxTimeoutSeconds = "org-ios-sim-script-v1", model.SimulatorScript, 3600, 7200
	registry, err := profiles.New(nil, []model.Template{template})
	if err != nil {
		t.Fatal(err)
	}
	c := Challenge{Templates: registry.Templates(), Observation: maintenance.Observation{Profiles: registry.Digests()}}
	recipe := c.recipes()[0]
	pin := SourcePin{Profile: recipe.ID, Repo: "themartianapp/herdrup", Shard: "duo-screenshots", Commit: strings.Repeat("a", 40), Tree: strings.Repeat("b", 40), SHA256: strings.Repeat("c", 64), SizeBytes: 1}
	admission, err := pinRequest(recipe, pin, 3600)
	if err != nil || admission.Request.Kind != model.SimulatorScript || admission.Request.Shard != "duo-screenshots" || admission.Request.Simulator == nil || *admission.Request.Simulator != template.Simulators[0] || admission.Profile.Shard != "duo-screenshots" || admission.ProfileDigest != c.Observation.Profiles[recipe.ID] {
		t.Fatalf("script template pin admission %+v %v", admission, err)
	}
	unsharded := pin
	unsharded.Shard = ""
	if _, err := pinRequest(recipe, unsharded, 3600); err == nil {
		t.Fatal("script template pin without a shard admitted")
	}
	pins, _ := simulatorPins(c, template.DeveloperDir)
	if len(pins) != len(template.Simulators) || pins[0] != template.Simulators[0] {
		t.Fatalf("script template simulator pins not inspected: %+v", pins)
	}
}

// A script template's tool evidence needs exit 0 and a non-empty output
// archive, never an xcresult; other recipes are unaffected.
func TestScriptToolEvidenceRequiresOutput(t *testing.T) {
	dir := t.TempDir()
	archive := func(name string, files map[string]string) string {
		var buffer bytes.Buffer
		gz := gzip.NewWriter(&buffer)
		tw := tar.NewWriter(gz)
		if err := tw.WriteHeader(&tar.Header{Name: "output/", Typeflag: tar.TypeDir, Mode: 0700}); err != nil {
			t.Fatal(err)
		}
		for path, content := range files {
			if err := tw.WriteHeader(&tar.Header{Name: path, Typeflag: tar.TypeReg, Mode: 0600, Size: int64(len(content))}); err != nil {
				t.Fatal(err)
			}
			if _, err := tw.Write([]byte(content)); err != nil {
				t.Fatal(err)
			}
		}
		if err := errors.Join(tw.Close(), gz.Close()); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), buffer.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
		return name
	}
	locate := func(id string) (string, error) { return filepath.Join(dir, id), nil }
	zero := 0
	result := func(id string) worker.Result {
		return worker.Result{State: model.Succeeded, CleanupOK: true, ExitCode: &zero, Artifacts: []evidence.Artifact{{ID: "log", Name: "evidence/stdout.log", SizeBytes: 1}, {ID: id, Name: "output.tar.gz", SizeBytes: 10}}}
	}
	full, empty := result(archive("full", map[string]string{"output/duo/portrait.png": "png"})), result(archive("empty", nil))
	if err := scriptOutput(full, locate); err != nil {
		t.Fatal(err)
	}
	if err := scriptOutput(empty, locate); err == nil {
		t.Fatal("empty output archive accepted")
	}
	if err := scriptOutput(worker.Result{Artifacts: full.Artifacts[:1]}, locate); err == nil {
		t.Fatal("missing output archive accepted")
	}
	script := model.Profile{Kind: model.SimulatorScript}
	if !scriptRunPasses(script, full) || scriptRunPasses(script, worker.Result{ExitCode: &zero, Artifacts: full.Artifacts[:1]}) || !scriptRunPasses(model.Profile{Kind: model.SimulatorUITest}, worker.Result{}) {
		t.Fatal("script run evidence predicate")
	}
	failed := full
	one := 1
	failed.ExitCode = &one
	if scriptRunPasses(script, failed) {
		t.Fatal("failed script run passed")
	}
}

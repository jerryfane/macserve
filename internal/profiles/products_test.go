package profiles_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
)

// A build template admits a build-for-testing request: the snapshot carries
// the flag (outside the template digest), and the derived recipe is the
// arm64 build-for-testing with no test selection, prepare unchanged, and
// test-products.tar as its one required artifact.
func TestDeriveBuildForTestingArgvGolden(t *testing.T) {
	r := templatesFile(t, buildTemplate)
	plain, err := r.Resolve(templateRequest("jerryfane/herdrup"))
	if err != nil {
		t.Fatal(err)
	}
	request := templateRequest("jerryfane/herdrup")
	request.BuildForTesting = true
	a, err := r.Resolve(request)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Request.BuildForTesting || !a.Profile.BuildForTesting || a.ProfileDigest != plain.ProfileDigest {
		t.Fatalf("admission = %+v, digest %s want %s", a, a.ProfileDigest, plain.ProfileDigest)
	}
	config := model.RepoConfig{Version: 1, WorkDir: ".", Project: "Herdr.xcodeproj", Scheme: "Herdr", XcodeGen: true, ResolvePackages: true}
	derived, err := profiles.Derive(a.Profile, config)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"xcodebuild", "-project", "Herdr.xcodeproj", "-scheme", "Herdr", "-configuration", "Debug", "-sdk", "iphonesimulator", "-destination", "generic/platform=iOS Simulator", "-derivedDataPath", "${DERIVED_DATA}", "CODE_SIGNING_ALLOWED=NO", "ARCHS=arm64", "build-for-testing"}
	if derived.Run.Executable != "/usr/bin/xcrun" || !slices.Equal(derived.Run.Args, want) {
		t.Fatalf("run = %+v", derived.Run)
	}
	if slices.ContainsFunc(derived.Run.Args, func(arg string) bool { return strings.HasPrefix(arg, "-only-testing") }) {
		t.Fatal("producer selects tests")
	}
	if !reflect.DeepEqual(derived.Artifacts, []model.ArtifactRule{{Path: profiles.TestProductsArtifact, Required: true}}) || len(derived.RequiredTests) != 0 {
		t.Fatalf("artifacts %+v required tests %v", derived.Artifacts, derived.RequiredTests)
	}
	plainDerived, err := profiles.Derive(plain.Profile, config)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(derived.Prepare, plainDerived.Prepare) || len(plainDerived.Artifacts) != 0 || plainDerived.Run.Args[len(plainDerived.Run.Args)-1] != "build" {
		t.Fatalf("plain build changed: %+v", plainDerived)
	}
	// The snapshot's flag drives Effective's derivation check.
	recipe := &model.RepoRecipe{ConfigSHA256: strings.Repeat("a", 64), Config: config, WorkDir: derived.WorkDir, Prepare: derived.Prepare, Run: derived.Run}
	if _, err := profiles.Effective(a.Profile, recipe); err != nil {
		t.Fatalf("effective: %v", err)
	}
	if _, err := profiles.Effective(plain.Profile, recipe); err == nil {
		t.Fatal("a plain build snapshot accepted the build-for-testing recipe")
	}
	// The flag is omitted when false, so other requests keep their digest.
	raw, err := json.Marshal(plain.Request)
	if err != nil || strings.Contains(string(raw), "build_for_testing") {
		t.Fatalf("plain request JSON %s %v", raw, err)
	}
}

// Only a non-Flutter build template builds for testing: explicit profiles,
// test, script and archive templates and Flutter build templates refuse the
// flag, and Derive refuses a snapshot that carries it on another kind.
func TestBuildForTestingOnlyForNativeBuildTemplates(t *testing.T) {
	r := templatesFile(t, buildTemplate+","+uiTemplate)
	explicit := r.List()[0]
	cases := map[string]model.Request{
		"explicit profile": {Repo: explicit.Repo, SHA: strings.Repeat("a", 40), Kind: explicit.Kind, Profile: explicit.ID, Xcode: explicit.Xcode, BuildForTesting: true},
		"ui test template": {Repo: "jerryfane/herdrup", SHA: strings.Repeat("a", 40), Kind: model.SimulatorUITest, Profile: "org-ios-sim-uitest-v1", Xcode: model.Xcode{Version: "27.1", Build: "27A9275"}, Shard: "smoke", BuildForTesting: true},
	}
	for name, request := range cases {
		if _, err := r.Resolve(request); !errors.Is(err, profiles.ErrUnsupported) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	pin := flutterPin
	flutter, err := profiles.New(nil, []model.Template{flutterTemplate(model.Build, &pin)})
	if err != nil {
		t.Fatal(err)
	}
	request := flutterRequest(model.Build, &model.FlutterRequest{Version: "3.41.9"})
	request.BuildForTesting = true
	if _, err := flutter.Resolve(request); !errors.Is(err, profiles.ErrUnsupported) {
		t.Fatalf("flutter build template: %v", err)
	}
	ui, err := r.Resolve(model.Request{Repo: "jerryfane/herdrup", SHA: strings.Repeat("a", 40), Kind: model.SimulatorUITest, Profile: "org-ios-sim-uitest-v1", Xcode: model.Xcode{Version: "27.1", Build: "27A9275"}, Shard: "smoke"})
	if err != nil {
		t.Fatal(err)
	}
	ui.Profile.BuildForTesting = true
	config := model.RepoConfig{Version: 1, WorkDir: ".", Project: "Herdr.xcodeproj", Scheme: "Herdr", UITest: &model.TestShards{Shards: map[string][]string{"smoke": {"HerdrUITests/SmokeTests"}}}}
	if _, err := profiles.Derive(ui.Profile, config); !errors.Is(err, profiles.ErrInvalid) {
		t.Fatalf("ui snapshot with build_for_testing derived: %v", err)
	}
}

func TestValidXctestrun(t *testing.T) {
	for _, name := range []string{"Herdr_iphonesimulator27.1-arm64.xctestrun", "a.xctestrun"} {
		if !profiles.ValidXctestrun(name) {
			t.Fatalf("%q refused", name)
		}
	}
	for _, name := range []string{"", ".xctestrun", ".hidden.xctestrun", "a/b.xctestrun", `a\b.xctestrun`, "a.xctestrun.plist", "a\n.xctestrun", strings.Repeat("a", 247) + ".xctestrun", "\xff.xctestrun"} {
		if profiles.ValidXctestrun(name) {
			t.Fatalf("%q accepted", name)
		}
	}
}

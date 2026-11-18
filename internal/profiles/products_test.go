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

var consumerRef = model.ProductsRef{ProducerJobID: "j_producer", SHA256: strings.Repeat("c", 64), Xctestrun: "Herdr_iphonesimulator27.1-arm64.xctestrun"}

func consumerRequest(kind model.Kind, profile string) model.Request {
	ref := consumerRef
	return model.Request{Repo: "jerryfane/herdrup", SHA: strings.Repeat("a", 40), Kind: kind, Profile: profile, Xcode: model.Xcode{Version: "27.1", Build: "27A9275"}, Shard: "smoke", Products: &ref}
}

// A test template admits a consumer of sealed test products: the snapshot
// carries the reference (outside the template digest), and the derived
// recipe has no prepare at all (no xcodegen, package resolution or build)
// and runs test-without-building of the imported products' .xctestrun on
// the job's simulator with the shard's selectors as its required tests.
func TestDeriveConsumerTestWithoutBuildingGolden(t *testing.T) {
	r := templatesFile(t, uiTemplate)
	plainRequest := consumerRequest(model.SimulatorUITest, "org-ios-sim-uitest-v1")
	plainRequest.Products = nil
	plain, err := r.Resolve(plainRequest)
	if err != nil {
		t.Fatal(err)
	}
	a, err := r.Resolve(consumerRequest(model.SimulatorUITest, "org-ios-sim-uitest-v1"))
	if err != nil {
		t.Fatal(err)
	}
	if *a.Request.Products != consumerRef || *a.Profile.Products != consumerRef || a.ProfileDigest != plain.ProfileDigest {
		t.Fatalf("admission = %+v", a)
	}
	config := model.RepoConfig{Version: 1, WorkDir: ".", Project: "Herdr.xcodeproj", Scheme: "Herdr", XcodeGen: true, ResolvePackages: true, UITest: &model.TestShards{Shards: map[string][]string{"smoke": {"HerdrUITests/ChatUXSmokeTests", "HerdrUITests/TerminalSmokeTests/testOpens"}}}}
	derived, err := profiles.Derive(a.Profile, config)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"xcodebuild", "test-without-building", "-xctestrun", "${PRODUCTS}/macserve.xctestrun", "-destination", "id=${SIMULATOR_ID}", "-resultBundlePath", "${RESULT_BUNDLE}", "-only-testing:HerdrUITests/ChatUXSmokeTests", "-only-testing:HerdrUITests/TerminalSmokeTests/testOpens"}
	if derived.Run.Executable != "/usr/bin/xcrun" || !slices.Equal(derived.Run.Args, want) || len(derived.Prepare) != 0 {
		t.Fatalf("run = %+v prepare = %+v", derived.Run, derived.Prepare)
	}
	if !slices.Equal(derived.RequiredTests, config.UITest.Shards["smoke"]) {
		t.Fatalf("required tests %v", derived.RequiredTests)
	}
	plainDerived, err := profiles.Derive(plain.Profile, config)
	if err != nil {
		t.Fatal(err)
	}
	if len(plainDerived.Prepare) != 3 || !slices.Contains(plainDerived.Prepare[2].Args, "build-for-testing") {
		t.Fatalf("plain shard changed: %+v", plainDerived.Prepare)
	}
	// The snapshot's reference drives Effective's derivation check both
	// ways: a consumer's recipe never passes as a building shard's.
	recipe := &model.RepoRecipe{ConfigSHA256: strings.Repeat("a", 64), Config: config, WorkDir: derived.WorkDir, Prepare: derived.Prepare, Run: derived.Run, Shard: "smoke", RequiredTests: derived.RequiredTests}
	if _, err := profiles.Effective(a.Profile, recipe); err != nil {
		t.Fatalf("effective: %v", err)
	}
	if _, err := profiles.Effective(plain.Profile, recipe); err == nil {
		t.Fatal("a building shard accepted the consumer recipe")
	}
	raw, err := json.Marshal(plain.Request)
	if err != nil || strings.Contains(string(raw), "products") {
		t.Fatalf("plain request JSON %s %v", raw, err)
	}
}

// Only non-Flutter test templates consume products, never with
// build-for-testing, and only with a well-formed reference; Derive refuses
// a snapshot that carries one on another kind.
func TestProductsOnlyForNativeTestTemplates(t *testing.T) {
	r := templatesFile(t, buildTemplate+","+uiTemplate+","+unitTemplate)
	explicit := r.List()[0]
	ref := consumerRef
	unsupported := map[string]model.Request{
		"explicit profile": {Repo: explicit.Repo, SHA: strings.Repeat("a", 40), Kind: explicit.Kind, Profile: explicit.ID, Xcode: explicit.Xcode, Products: &ref},
		"build template":   {Repo: "jerryfane/herdrup", SHA: strings.Repeat("a", 40), Kind: model.Build, Profile: "org-ios-sim-build-v1", Xcode: model.Xcode{Version: "27.1", Build: "27A9275"}, Products: &ref},
	}
	producer := consumerRequest(model.SimulatorUITest, "org-ios-sim-uitest-v1")
	producer.BuildForTesting = true
	unsupported["consumer that builds for testing"] = producer
	for name, request := range unsupported {
		if _, err := r.Resolve(request); !errors.Is(err, profiles.ErrUnsupported) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := r.Resolve(consumerRequest(model.UnitTest, "org-ios-sim-unittest-v1")); err != nil {
		t.Fatalf("unit test consumer: %v", err)
	}
	for name, edit := range map[string]func(*model.ProductsRef){
		"producer id":    func(p *model.ProductsRef) { p.ProducerJobID = "../j" },
		"digest":         func(p *model.ProductsRef) { p.SHA256 = strings.Repeat("C", 64) },
		"xctestrun name": func(p *model.ProductsRef) { p.Xctestrun = "../x.xctestrun" },
		"empty":          func(p *model.ProductsRef) { *p = model.ProductsRef{} },
	} {
		request := consumerRequest(model.SimulatorUITest, "org-ios-sim-uitest-v1")
		edit(request.Products)
		if _, err := r.Resolve(request); !errors.Is(err, profiles.ErrInvalid) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	pin := flutterPin
	flutter, err := profiles.New(nil, []model.Template{flutterTemplate(model.UnitTest, &pin)})
	if err != nil {
		t.Fatal(err)
	}
	request := flutterRequest(model.UnitTest, &model.FlutterRequest{Version: "3.41.9"})
	request.Products = &ref
	if _, err := flutter.Resolve(request); !errors.Is(err, profiles.ErrUnsupported) {
		t.Fatalf("flutter test template: %v", err)
	}
	build, err := r.Resolve(model.Request{Repo: "jerryfane/herdrup", SHA: strings.Repeat("a", 40), Kind: model.Build, Profile: "org-ios-sim-build-v1", Xcode: model.Xcode{Version: "27.1", Build: "27A9275"}})
	if err != nil {
		t.Fatal(err)
	}
	build.Profile.Products = &ref
	if _, err := profiles.Derive(build.Profile, model.RepoConfig{Version: 1, WorkDir: ".", Project: "Herdr.xcodeproj", Scheme: "Herdr"}); !errors.Is(err, profiles.ErrInvalid) {
		t.Fatalf("derive build snapshot with products: %v", err)
	}
}

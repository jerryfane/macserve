package profiles_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
)

var flutterPin = model.FlutterPin{Version: "3.41.9", SDKSHA256: "d692b030a63466c44d6b2bc88583380371ecbe328f22cc4057835f59739821a1", RubySHA256: "62fe925f284cc38aac68b9a42b02cd90de753f8832e8866be3fd60558dd70f67", CocoaPodsVersion: "1.16.2", GemsSHA256: strings.Repeat("e", 64)}

const flutterRepoConfig = `{"version":1,"work_dir":"apps/mobile/ios","workspace":"Runner.xcworkspace","scheme":"Runner","flutter":{"app_dir":"apps/mobile","prepare_ruby":["scripts/add_call_directory_target.rb"]},"unit_test":{"shards":{"all":["RunnerTests/RunnerTests"]}}}`

var flutterSimulator = model.Simulator{Runtime: "com.apple.CoreSimulator.SimRuntime.iOS-27-1", RuntimeBuild: "24A94425", DeviceType: "com.apple.CoreSimulator.SimDeviceType.iPhone-18-Pro"}

func flutterTemplate(kind model.Kind, pin *model.FlutterPin) model.Template {
	t := model.Template{ID: "org-flutter-ios-sim-v1", Version: 1, Kind: kind, Owners: []string{"themartianapp"}, Xcode: model.Xcode{Version: "27.1", Build: "27A9275"}, DeveloperDir: "/Applications/Xcode.app/Contents/Developer", Flutter: pin}
	if kind != model.Build {
		t.Simulators = []model.Simulator{flutterSimulator}
	}
	return t
}

func flutterRequest(kind model.Kind, flutter *model.FlutterRequest) model.Request {
	r := model.Request{Repo: "themartianapp/among-friends", SHA: strings.Repeat("a", 40), Kind: kind, Profile: "org-flutter-ios-sim-v1", Xcode: model.Xcode{Version: "27.1", Build: "27A9275"}, Flutter: flutter}
	if kind != model.Build {
		r.Shard = "all"
	}
	return r
}

func admitFlutter(t *testing.T, kind model.Kind) model.Admission {
	t.Helper()
	pin := flutterPin
	registry, err := profiles.New(nil, []model.Template{flutterTemplate(kind, &pin)})
	if err != nil {
		t.Fatal(err)
	}
	admission, err := registry.Resolve(flutterRequest(kind, &model.FlutterRequest{Version: "3.41.9"}))
	if err != nil {
		t.Fatal(err)
	}
	return admission
}

func TestFlutterRepoConfigValidation(t *testing.T) {
	if _, err := profiles.ParseRepoConfig([]byte(flutterRepoConfig)); err != nil {
		t.Fatalf("valid flutter config refused: %v", err)
	}
	replace := func(old, new string) string { return strings.Replace(flutterRepoConfig, old, new, 1) }
	nine := `"a.rb","b.rb","c.rb","d.rb","e.rb","f.rb","g.rb","h.rb","i.rb"`
	for name, config := range map[string]string{
		"work_dir is the app dir":  replace(`"work_dir":"apps/mobile/ios"`, `"work_dir":"apps/mobile"`),
		"work_dir is another ios":  replace(`"work_dir":"apps/mobile/ios"`, `"work_dir":"apps/other/ios"`),
		"project and flutter":      replace(`"workspace":"Runner.xcworkspace"`, `"project":"Runner.xcodeproj"`),
		"project beside workspace": replace(`"scheme"`, `"project":"Runner.xcodeproj","scheme"`),
		"other workspace":          replace(`"Runner.xcworkspace"`, `"App.xcworkspace"`),
		"custom scheme":            replace(`"scheme":"Runner"`, `"scheme":"Runner-dev"`),
		"xcodegen and flutter":     replace(`"scheme"`, `"xcodegen":true,"scheme"`),
		"resolve_packages":         replace(`"scheme"`, `"resolve_packages":true,"scheme"`),
		"app_dir traversal":        strings.NewReplacer(`"app_dir":"apps/mobile"`, `"app_dir":"../mobile"`, `"work_dir":"apps/mobile/ios"`, `"work_dir":"../mobile/ios"`).Replace(flutterRepoConfig),
		"app_dir unclean":          replace(`"app_dir":"apps/mobile"`, `"app_dir":"apps//mobile"`),
		"ruby traversal":           replace(`scripts/add_call_directory_target.rb`, `../evil.rb`),
		"ruby absolute":            replace(`scripts/add_call_directory_target.rb`, `/tmp/evil.rb`),
		"ruby not .rb":             replace(`scripts/add_call_directory_target.rb`, `scripts/add.sh`),
		"ruby bare .rb":            replace(`scripts/add_call_directory_target.rb`, `scripts/.rb`),
		"ruby dollar":              replace(`scripts/add_call_directory_target.rb`, `scripts/$HOME.rb`),
		"ruby glob":                replace(`scripts/add_call_directory_target.rb`, `scripts/*.rb`),
		"ruby empty component":     replace(`scripts/add_call_directory_target.rb`, `scripts//add.rb`),
		"ruby dot component":       replace(`scripts/add_call_directory_target.rb`, `./add.rb`),
		"nine scripts":             replace(`"scripts/add_call_directory_target.rb"`, nine),
		"unknown flutter key":      replace(`"app_dir"`, `"sdk":"x","app_dir"`),
		"case-folded flutter key":  replace(`"app_dir"`, `"App_Dir"`),
		"duplicate flutter key":    replace(`"app_dir":"apps/mobile"`, `"app_dir":"apps/mobile","app_dir":"apps/mobile"`),
		"null prepare_ruby":        replace(`["scripts/add_call_directory_target.rb"]`, `null`),
		"flutter is not an object": replace(`{"app_dir":"apps/mobile","prepare_ruby":["scripts/add_call_directory_target.rb"]}`, `"apps/mobile"`),
		"missing app_dir":          replace(`"app_dir":"apps/mobile",`, ``),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := profiles.ParseRepoConfig([]byte(config)); !errors.Is(err, profiles.ErrRepoConfig) {
				t.Fatalf("config %s: %v", config, err)
			}
		})
	}
	eight := replace(`"scripts/add_call_directory_target.rb"`, `"a.rb","b.rb","c.rb","d.rb","e.rb","f.rb","g.rb","h/i.rb"`)
	if _, err := profiles.ParseRepoConfig([]byte(eight)); err != nil {
		t.Fatalf("eight scripts refused: %v", err)
	}
}

func TestFlutterTemplatePinValidation(t *testing.T) {
	pin := flutterPin
	if _, err := profiles.New(nil, []model.Template{flutterTemplate(model.SimulatorScript, &pin)}); !errors.Is(err, profiles.ErrUnsupported) {
		t.Fatalf("flutter script template: %v", err)
	}
	for name, edit := range map[string]func(*model.FlutterPin){
		"two-part version":   func(p *model.FlutterPin) { p.Version = "3.41" },
		"prerelease version": func(p *model.FlutterPin) { p.Version = "3.41.9-1.0.pre" },
		"uppercase sdk hash": func(p *model.FlutterPin) { p.SDKSHA256 = strings.ToUpper(p.SDKSHA256) },
		"short ruby hash":    func(p *model.FlutterPin) { p.RubySHA256 = p.RubySHA256[:12] },
		"missing gems hash":  func(p *model.FlutterPin) { p.GemsSHA256 = "" },
		"cocoapods path":     func(p *model.FlutterPin) { p.CocoaPodsVersion = "../1.16.2" },
	} {
		bad := flutterPin
		edit(&bad)
		if _, err := profiles.New(nil, []model.Template{flutterTemplate(model.Build, &bad)}); !errors.Is(err, profiles.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestFlutterRequestVersionMustMatchPin(t *testing.T) {
	pin := flutterPin
	for _, kind := range []model.Kind{model.Build, model.UnitTest, model.SimulatorUITest} {
		registry, err := profiles.New(nil, []model.Template{flutterTemplate(kind, &pin), {ID: "org-ios-sim-build-v1", Version: 1, Kind: model.Build, Owners: []string{"themartianapp"}, Xcode: model.Xcode{Version: "27.1", Build: "27A9275"}, DeveloperDir: "/Applications/Xcode.app/Contents/Developer"}})
		if err != nil {
			t.Fatal(err)
		}
		admission, err := registry.Resolve(flutterRequest(kind, &model.FlutterRequest{Version: "3.41.9"}))
		if err != nil || admission.Request.Flutter == nil || admission.Request.Flutter.Version != "3.41.9" || !reflect.DeepEqual(admission.Profile.Template.Flutter, &pin) {
			t.Fatalf("%s exact flutter request: %+v %v", kind, admission, err)
		}
		for _, flutter := range []*model.FlutterRequest{nil, {Version: "3.41.8"}, {Version: "3.41"}, {Version: ""}} {
			if _, err := registry.Resolve(flutterRequest(kind, flutter)); !errors.Is(err, profiles.ErrUnsupported) {
				t.Errorf("%s flutter request %+v admitted: %v", kind, flutter, err)
			}
		}
		native := flutterRequest(model.Build, &model.FlutterRequest{Version: "3.41.9"})
		native.Profile, native.Shard = "org-ios-sim-build-v1", ""
		if _, err := registry.Resolve(native); !errors.Is(err, profiles.ErrUnsupported) {
			t.Errorf("flutter request for a non-Flutter template admitted: %v", err)
		}
	}
	profile := model.Profile{ID: "app-build", Version: 1, Repo: "themartianapp/app", Kind: model.Build, Xcode: model.Xcode{Version: "27.1", Build: "27A9275"}, DeveloperDir: "/Applications/Xcode.app/Contents/Developer", WorkDir: ".", Run: model.Command{Executable: "/usr/bin/true"}}
	registry, err := profiles.New([]model.Profile{profile}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Resolve(model.Request{Repo: profile.Repo, SHA: strings.Repeat("a", 40), Kind: model.Build, Profile: profile.ID, Xcode: profile.Xcode, Flutter: &model.FlutterRequest{Version: "3.41.9"}}); !errors.Is(err, profiles.ErrUnsupported) {
		t.Fatalf("flutter request for a profile admitted: %v", err)
	}
}

func TestFlutterTemplateAndConfigMustMatch(t *testing.T) {
	flutter, err := profiles.ParseRepoConfig([]byte(flutterRepoConfig))
	if err != nil {
		t.Fatal(err)
	}
	native := flutter
	native.Flutter = nil
	if _, err := profiles.Derive(admitFlutter(t, model.Build).Profile, native); !errors.Is(err, profiles.ErrUnsupported) || !strings.Contains(err.Error(), "Flutter template") {
		t.Fatalf("flutter template derived a non-flutter config: %v", err)
	}
	registry, err := profiles.New(nil, []model.Template{flutterTemplate(model.Build, nil)})
	if err != nil {
		t.Fatal(err)
	}
	admission, err := registry.Resolve(flutterRequest(model.Build, nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := profiles.Derive(admission.Profile, flutter); !errors.Is(err, profiles.ErrUnsupported) || !strings.Contains(err.Error(), "flutter section") {
		t.Fatalf("non-flutter template derived a flutter config: %v", err)
	}
}

func TestFlutterDeriveExactCommands(t *testing.T) {
	config, err := profiles.ParseRepoConfig([]byte(flutterRepoConfig))
	if err != nil {
		t.Fatal(err)
	}
	flutter := "${WORKSPACE}/flutter-sdk/bin/flutter"
	prepare := []model.Command{
		{Executable: "/bin/cp", Args: []string{"-c", "-R", "/Library/macserve/tools/flutter/3.41.9/flutter", "${WORKSPACE}/flutter-sdk"}},
		{Executable: "/bin/bash", Args: []string{flutter, "pub", "get", "--enforce-lockfile", "--suppress-analytics"}},
		{Executable: "/bin/bash", Args: []string{flutter, "build", "ios", "--config-only", "--simulator", "--debug", "--suppress-analytics"}},
		{Executable: "/Library/macserve/tools/ruby/62fe925f284c/bin/ruby", Args: []string{"${CHECKOUT}/scripts/add_call_directory_target.rb"}},
	}
	build, err := profiles.Derive(admitFlutter(t, model.Build).Profile, config)
	if err != nil {
		t.Fatal(err)
	}
	wantBuild := model.Command{Executable: "/usr/bin/xcrun", Args: []string{"xcodebuild", "-workspace", "ios/Runner.xcworkspace", "-scheme", "Runner", "-configuration", "Debug", "-sdk", "iphonesimulator", "-destination", "generic/platform=iOS Simulator", "-derivedDataPath", "${DERIVED_DATA}", "CODE_SIGNING_ALLOWED=NO", "ARCHS=arm64", "build"}}
	if build.WorkDir != "apps/mobile" || !reflect.DeepEqual(build.Prepare, prepare) || !reflect.DeepEqual(build.Run, wantBuild) || len(build.RequiredTests) != 0 {
		t.Fatalf("flutter build recipe: %+v", build)
	}
	unit, err := profiles.Derive(admitFlutter(t, model.UnitTest).Profile, config)
	if err != nil {
		t.Fatal(err)
	}
	test := []string{"xcodebuild", "-workspace", "ios/Runner.xcworkspace", "-scheme", "Runner", "-configuration", "Debug", "-sdk", "iphonesimulator", "-destination", "id=${SIMULATOR_ID}", "-derivedDataPath", "${DERIVED_DATA}"}
	wantPrepare := append(append([]model.Command(nil), prepare...), model.Command{Executable: "/usr/bin/xcrun", Args: append(append([]string(nil), test...), "CODE_SIGNING_ALLOWED=NO", "build-for-testing", "-only-testing:RunnerTests/RunnerTests")})
	wantRun := model.Command{Executable: "/usr/bin/xcrun", Args: append(append([]string(nil), test...), "-resultBundlePath", "${RESULT_BUNDLE}", "CODE_SIGNING_ALLOWED=NO", "test-without-building", "-only-testing:RunnerTests/RunnerTests")}
	if unit.WorkDir != "apps/mobile" || !reflect.DeepEqual(unit.Prepare, wantPrepare) || !reflect.DeepEqual(unit.Run, wantRun) || !reflect.DeepEqual(unit.RequiredTests, []string{"RunnerTests/RunnerTests"}) {
		t.Fatalf("flutter unit test recipe: %+v", unit)
	}
	// The worker's reported recipe re-derives exactly.
	recipe := &model.RepoRecipe{ConfigSHA256: strings.Repeat("f", 64), Config: config, WorkDir: unit.WorkDir, Prepare: unit.Prepare, Run: unit.Run, Shard: unit.Shard, RequiredTests: unit.RequiredTests}
	if _, err := profiles.Effective(admitFlutter(t, model.UnitTest).Profile, recipe); err != nil {
		t.Fatalf("flutter recipe does not re-derive: %v", err)
	}
}

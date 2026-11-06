package worker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
)

var workerFlutterPin = model.FlutterPin{Version: "3.41.9", SDKSHA256: strings.Repeat("d", 64), RubySHA256: "62fe925f284cc38aac68b9a42b02cd90de753f8832e8866be3fd60558dd70f67", CocoaPodsVersion: "1.16.2", GemsSHA256: strings.Repeat("e", 64)}

// flutterConfig is the design's example .macserve.json with its shard
// selector spelled Target/Class, as every selector must be.
const flutterConfig = `{"version":1,"work_dir":"apps/mobile/ios","workspace":"Runner.xcworkspace","scheme":"Runner","flutter":{"app_dir":"apps/mobile","prepare_ruby":["scripts/add_call_directory_target.rb"]},"unit_test":{"shards":{"all":["RunnerTests/RunnerTests"]}}}`

func flutterCheckout() map[string]string {
	return map[string]string{
		".macserve.json":                       flutterConfig,
		"scripts/add_call_directory_target.rb": "puts 1\n",
		"apps/mobile/pubspec.lock":             "packages: {}\n",
		"apps/mobile/ios/Podfile.lock":         "PODS:\n  - Flutter (1.0.0)\n\nCOCOAPODS: 1.16.2\n",
	}
}

// flutterTemplateJob admits a Flutter template job of kind (shard "all" for
// a test kind) naming the pinned Flutter version.
func flutterTemplateJob(t *testing.T, kind model.Kind) model.Job {
	t.Helper()
	pin := workerFlutterPin
	template := model.Template{ID: "org-flutter-v1", Version: 1, Kind: kind, Owners: []string{"example-org"}, Xcode: model.Xcode{Version: "16.0", Build: "16A242d"}, DeveloperDir: "/Applications/Xcode.app/Contents/Developer", Flutter: &pin}
	request := model.Request{Repo: "example-org/new-app", SHA: strings.Repeat("a", 40), Kind: kind, Profile: template.ID, Xcode: template.Xcode, Flutter: &model.FlutterRequest{Version: pin.Version}}
	if kind.Tests() {
		template.Simulators = []model.Simulator{fixtureSimulator}
		request.Shard = "all"
	}
	registry, err := profiles.New(nil, []model.Template{template})
	if err != nil {
		t.Fatal(err)
	}
	admission, err := registry.Resolve(request)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(admission.Request)
	digest := sha256.Sum256(data)
	return model.Job{ID: "job-1", LeaseToken: "lease-1", WorkerEpoch: "epoch-1", State: model.Preparing, Request: admission.Request, Profile: admission.Profile, ProfileDigest: admission.ProfileDigest, RequestDigest: hex.EncodeToString(digest[:])}
}

// flutterHook answers the Flutter observation commands; then, when set, it
// plays the step: during `pub get` it runs mutate in the checkout.
func flutterHook(framework string, mutate func(checkout string) error) func(context.Context, Command, io.Writer, io.Writer) (bool, ProcessResult, error) {
	return func(_ context.Context, c Command, out, _ io.Writer) (bool, ProcessResult, error) {
		args := strings.Join(c.Args, " ")
		switch {
		case c.Executable == "/bin/bash" && strings.HasSuffix(args, "/flutter-sdk/bin/flutter --version --machine"):
			_, err := io.WriteString(out, `{"frameworkVersion":"`+framework+`","dartSdkVersion":"3.11.5"}`+"\n")
			return true, ProcessResult{CleanupOK: true}, err
		case strings.HasSuffix(c.Executable, "/bin/ruby") && args == "-v":
			_, err := io.WriteString(out, "ruby 3.4.6 (2025-09-16 revision dbd83256b1) +PRISM [arm64-darwin20]\n")
			return true, ProcessResult{CleanupOK: true}, err
		case strings.HasSuffix(c.Executable, "/gems/bin/pod") && args == "--version":
			_, err := io.WriteString(out, "1.16.2\n")
			return true, ProcessResult{CleanupOK: true}, err
		case mutate != nil && strings.Contains(args, " pub get "):
			return true, ProcessResult{CleanupOK: true}, mutate(filepath.Dir(filepath.Dir(c.Dir)))
		}
		return false, ProcessResult{}, nil
	}
}

func runFlutterJob(t *testing.T, runner *fakeRunner, kind model.Kind, checkout map[string]string) (Result, error) {
	t.Helper()
	engine := engineFixture(t, runner)
	source, data := checkoutFixture(t, checkout)
	return engine.Execute(context.Background(), flutterTemplateJob(t, kind), source, bytes.NewReader(data), nil)
}

func envValue(env []string, key string) string {
	for _, entry := range env {
		if value, ok := strings.CutPrefix(entry, key+"="); ok {
			return value
		}
	}
	return ""
}

// A Flutter build job runs the derived prepare and the arm64 simulator
// xcodebuild in app_dir (the worker keeps ARCHS=arm64) with the Flutter
// environment on every job command, observes the pinned Flutter, Ruby and
// CocoaPods after the SDK clone and tracks pubspec.lock.
func TestFlutterBuildJobRunsDerivedRecipeWithFlutterEnvironment(t *testing.T) {
	runner := &fakeRunner{}
	runner.hook = flutterHook("3.41.9", nil)
	result, err := runFlutterJob(t, runner, model.Build, flutterCheckout())
	if err != nil || result.State != model.Succeeded || !result.CleanupOK {
		t.Fatalf("flutter build job failed: %+v %v", result, err)
	}
	tools := profiles.FlutterToolPaths(workerFlutterPin)
	commands := checkoutCommands(runner)
	if len(commands) != 5 {
		t.Fatalf("recipe commands: %+v", commands)
	}
	workspace := filepath.Dir(filepath.Dir(filepath.Dir(commands[0].Dir)))
	flutter := filepath.Join(workspace, "flutter-sdk", "bin", "flutter")
	want := [][]string{
		{"/bin/cp", "-c", "-R", tools.SDK, filepath.Join(workspace, "flutter-sdk")},
		{"/bin/bash", flutter, "pub", "get", "--enforce-lockfile", "--suppress-analytics"},
		{"/bin/bash", flutter, "build", "ios", "--config-only", "--simulator", "--debug", "--suppress-analytics"},
		{tools.Ruby, filepath.Join(workspace, "checkout", "scripts", "add_call_directory_target.rb")},
		{"/usr/bin/xcrun", "xcodebuild", "-workspace", "ios/Runner.xcworkspace", "-scheme", "Runner", "-configuration", "Debug", "-sdk", "iphonesimulator", "-destination", "generic/platform=iOS Simulator", "-derivedDataPath", filepath.Join(workspace, "derived-data"), "ARCHS=arm64", "build", "-jobs", "4", "CODE_SIGNING_ALLOWED=NO"},
	}
	for i, c := range commands {
		if got := append([]string{c.Executable}, c.Args...); !slices.Equal(got, want[i]) || c.Dir != filepath.Join(workspace, "checkout", "apps", "mobile") {
			t.Fatalf("command %d %q in %s, want %q", i, got, c.Dir, want[i])
		}
	}
	for _, c := range runner.commands {
		if c.Executable == "/usr/bin/xcrun" && slices.Contains(c.Args, "simctl") {
			continue
		}
		root := filepath.Join(workspace, "flutter-sdk")
		if envValue(c.Env, "FLUTTER_ROOT") != root || envValue(c.Env, "PUB_CACHE") != filepath.Join(workspace, "pub-cache") || envValue(c.Env, "CP_HOME_DIR") != filepath.Join(workspace, "cocoapods") || envValue(c.Env, "GEM_HOME") != tools.Gems || envValue(c.Env, "GEM_PATH") != tools.Gems || envValue(c.Env, "FLUTTER_SUPPRESS_ANALYTICS") != "true" || envValue(c.Env, "CI") != "true" || envValue(c.Env, "LANG") != "en_US.UTF-8" {
			t.Fatalf("%s %q lacks the Flutter environment: %q", c.Executable, c.Args, c.Env)
		}
		if path := envValue(c.Env, "PATH"); path != root+"/bin:/Library/macserve/tools/ruby/62fe925f284c/bin:/Library/macserve/tools/cocoapods/1.16.2/gems/bin:/usr/bin:/bin:/usr/sbin:/sbin" || len(slices.DeleteFunc(slices.Clone(c.Env), func(e string) bool { return !strings.HasPrefix(e, "PATH=") })) != 1 {
			t.Fatalf("PATH %q in %q", path, c.Env)
		}
	}
	if f := result.Observation.Flutter; f == nil || *f != (FlutterObservation{FrameworkVersion: "3.41.9", DartSDKVersion: "3.11.5", Ruby: "ruby 3.4.6 (2025-09-16 revision dbd83256b1) +PRISM [arm64-darwin20]", CocoaPods: "1.16.2"}) {
		t.Fatalf("flutter observation: %+v", result.Observation.Flutter)
	}
	if _, ok := result.Observation.LockfileDigests["apps/mobile/pubspec.lock"]; !ok {
		t.Fatalf("pubspec.lock is not tracked: %v", result.Observation.LockfileDigests)
	}
}

// A Flutter unit_test job runs the Flutter prepare, then the template's
// build-for-testing and test-without-building on ios/Runner.xcworkspace.
func TestFlutterUnitTestJobBuildsWorkspaceInAppDir(t *testing.T) {
	runner := &fakeRunner{}
	runner.tests = `{"testPlanConfigurations":[],"devices":[],"testNodes":[{"nodeType":"Test Case","name":"testExample()","nodeIdentifier":"RunnerTests/RunnerTests/testExample()","result":"Passed","durationInSeconds":0.25}]}`
	runner.hook = flutterHook("3.41.9", nil)
	result, err := runFlutterJob(t, runner, model.UnitTest, flutterCheckout())
	if err != nil || result.State != model.Succeeded {
		t.Fatalf("flutter unit test job failed: %+v %v", result, err)
	}
	commands := checkoutCommands(runner)
	if len(commands) != 6 {
		t.Fatalf("recipe commands: %+v", commands)
	}
	for _, i := range []int{4, 5} {
		if c := commands[i]; c.Executable != "/usr/bin/xcrun" || !slices.Equal(c.Args[:3], []string{"xcodebuild", "-workspace", "ios/Runner.xcworkspace"}) || !strings.HasSuffix(c.Dir, filepath.Join("checkout", "apps", "mobile")) {
			t.Fatalf("xcode step %d: %+v", i, c)
		}
	}
	if !slices.Contains(commands[4].Args, "build-for-testing") || !slices.Contains(commands[5].Args, "test-without-building") {
		t.Fatalf("test steps: %q %q", commands[4].Args, commands[5].Args)
	}
}

// Preflight, the pin observation and lockfile tracking fail a Flutter job
// before or after its commands; a missing lockfile or a CocoaPods mismatch
// fails before any recipe command runs.
func TestFlutterJobRefusals(t *testing.T) {
	for _, tc := range []struct {
		name      string
		edit      func(map[string]string)
		framework string
		mutate    func(checkout string) error
		recipes   bool // whether any recipe command ran
	}{
		{name: "missing pubspec.lock", edit: func(c map[string]string) { delete(c, "apps/mobile/pubspec.lock") }},
		{name: "missing Podfile.lock", edit: func(c map[string]string) { delete(c, "apps/mobile/ios/Podfile.lock") }},
		{name: "pubspec.lock is a directory", edit: func(c map[string]string) {
			delete(c, "apps/mobile/pubspec.lock")
			c["apps/mobile/pubspec.lock/"] = ""
		}},
		{name: "COCOAPODS mismatch", edit: func(c map[string]string) { c["apps/mobile/ios/Podfile.lock"] = "PODS:\n\nCOCOAPODS: 1.15.2\n" }},
		{name: "no COCOAPODS line", edit: func(c map[string]string) { c["apps/mobile/ios/Podfile.lock"] = "PODS:\n" }},
		{name: "Flutter version mismatch", framework: "3.41.8", recipes: true},
		{name: "new lockfile", recipes: true, mutate: func(checkout string) error {
			return os.WriteFile(filepath.Join(checkout, "apps", "mobile", "ios", "Gemfile.lock"), []byte("GEM\n"), 0600)
		}},
		{name: "pubspec.lock changed", recipes: true, mutate: func(checkout string) error {
			return os.WriteFile(filepath.Join(checkout, "apps", "mobile", "pubspec.lock"), []byte("packages: {changed: 1}\n"), 0600)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkout := flutterCheckout()
			if tc.edit != nil {
				tc.edit(checkout)
			}
			framework := tc.framework
			if framework == "" {
				framework = "3.41.9"
			}
			runner := &fakeRunner{}
			runner.hook = flutterHook(framework, tc.mutate)
			result, err := runFlutterJob(t, runner, model.Build, checkout)
			if err == nil || result.State == model.Succeeded || !result.CleanupOK {
				t.Fatalf("refused flutter job succeeded: %+v %v", result, err)
			}
			if ran := len(checkoutCommands(runner)) > 0; ran != tc.recipes {
				t.Fatalf("recipe commands ran=%v, want %v: %v", ran, tc.recipes, err)
			}
		})
	}
}

// Preflight opens the lockfiles without following symlinks and refuses
// hardlinked ones, which a source archive cannot carry.
func TestFlutterPreflightRefusesLinkedLockfiles(t *testing.T) {
	for _, link := range []string{"symlink", "hardlink", "symlinked directory"} {
		t.Run(link, func(t *testing.T) {
			dir := t.TempDir()
			ios := filepath.Join(dir, "apps", "mobile", "ios")
			if err := os.MkdirAll(ios, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "apps", "mobile", "pubspec.lock"), []byte("packages: {}\n"), 0600); err != nil {
				t.Fatal(err)
			}
			real := filepath.Join(dir, "real.lock")
			if err := os.WriteFile(real, []byte("COCOAPODS: 1.16.2\n"), 0600); err != nil {
				t.Fatal(err)
			}
			var err error
			switch link {
			case "symlink":
				err = os.Symlink(real, filepath.Join(ios, "Podfile.lock"))
			case "hardlink":
				err = os.Link(real, filepath.Join(ios, "Podfile.lock"))
			default:
				other := filepath.Join(dir, "other")
				if err = os.MkdirAll(other, 0700); err == nil {
					err = errorsJoin(os.Rename(real, filepath.Join(other, "Podfile.lock")), os.RemoveAll(ios), os.Symlink(other, ios))
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			config := model.FlutterConfig{AppDir: "apps/mobile"}
			if err := flutterPreflight(root, config, workerFlutterPin); err == nil {
				t.Fatal("linked Podfile.lock passed preflight")
			}
		})
	}
}

func errorsJoin(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// Non-Flutter jobs get none of the Flutter environment, observation or
// pubspec.lock tracking, and may still create a lockfile.
func TestNonFlutterJobsHaveNoFlutterEnvironment(t *testing.T) {
	runner := &fakeRunner{}
	runner.hook = func(_ context.Context, c Command, _, _ io.Writer) (bool, ProcessResult, error) {
		if strings.HasSuffix(c.Dir, string(filepath.Separator)+"checkout") {
			return false, ProcessResult{}, os.WriteFile(filepath.Join(c.Dir, "Package.resolved"), []byte("{}"), 0600)
		}
		return false, ProcessResult{}, nil
	}
	engine := engineFixture(t, runner)
	source, data := checkoutFixture(t, map[string]string{".macserve.json": `{"version":1,"work_dir":".","project":"App.xcodeproj","scheme":"App"}`, "pubspec.lock": "packages: {}\n"})
	result, err := engine.Execute(context.Background(), templateJob(t), source, bytes.NewReader(data), nil)
	if err != nil || result.State != model.Succeeded {
		t.Fatalf("build job: %+v %v", result, err)
	}
	for _, c := range runner.commands {
		for _, key := range []string{"FLUTTER_ROOT", "PUB_CACHE", "CP_HOME_DIR", "GEM_HOME", "GEM_PATH", "FLUTTER_SUPPRESS_ANALYTICS", "CI"} {
			if envValue(c.Env, key) != "" {
				t.Fatalf("%s got %s: %q", c.Executable, key, c.Env)
			}
		}
		if envValue(c.Env, "PATH") != "/usr/bin:/bin:/usr/sbin:/sbin" {
			t.Fatalf("PATH changed: %q", c.Env)
		}
	}
	if result.Observation.Flutter != nil {
		t.Fatalf("flutter observation on a build job: %+v", result.Observation.Flutter)
	}
	if _, tracked := result.Observation.LockfileDigests["pubspec.lock"]; tracked {
		t.Fatalf("pubspec.lock tracked for a non-Flutter job: %v", result.Observation.LockfileDigests)
	}
}

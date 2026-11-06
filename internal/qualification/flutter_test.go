package qualification

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/worker"
)

var qualificationFlutterPin = model.FlutterPin{Version: "3.41.9", SDKSHA256: strings.Repeat("a", 64), RubySHA256: strings.Repeat("b", 64), CocoaPodsVersion: "1.16.2", GemsSHA256: strings.Repeat("c", 64)}

// A Flutter template's run passes tool evidence only with exactly the pinned
// Flutter and CocoaPods observed; any other recipe only without a Flutter
// observation.
func TestFlutterRunPassesRequiresPinnedObservation(t *testing.T) {
	pin := qualificationFlutterPin
	template := model.Template{ID: "org-flutter-build-v1", Version: 1, Kind: model.Build, Owners: []string{"themartianapp"}, Xcode: model.Xcode{Version: "27.1", Build: "27A9275"}, DeveloperDir: "/Applications/Xcode.app/Contents/Developer", Flutter: &pin}
	recipe := profiles.TemplateSnapshot(template, "")
	run := func(o *worker.FlutterObservation) worker.Result {
		return worker.Result{Observation: worker.Observation{Flutter: o}}
	}
	if !flutterRunPasses(recipe, run(&worker.FlutterObservation{FrameworkVersion: "3.41.9", DartSDKVersion: "3.11.5", Ruby: "ruby 3.4.6", CocoaPods: "1.16.2"})) {
		t.Fatal("pinned flutter run refused")
	}
	for name, o := range map[string]*worker.FlutterObservation{
		"no observation":            nil,
		"framework version differs": {FrameworkVersion: "3.41.8", DartSDKVersion: "3.11.5", Ruby: "ruby 3.4.6", CocoaPods: "1.16.2"},
		"cocoapods differs":         {FrameworkVersion: "3.41.9", DartSDKVersion: "3.11.5", Ruby: "ruby 3.4.6", CocoaPods: "1.15.2"},
	} {
		if flutterRunPasses(recipe, run(o)) {
			t.Errorf("%s: run passed", name)
		}
	}
	native := template
	native.Flutter = nil
	if !flutterRunPasses(profiles.TemplateSnapshot(native, ""), run(nil)) || flutterRunPasses(profiles.TemplateSnapshot(native, ""), run(&worker.FlutterObservation{FrameworkVersion: "3.41.9"})) {
		t.Fatal("non-flutter run flutter rule")
	}
}

// flutterToolTree lays out a Flutter pin's tools below dir as the admin
// package would, with a Ruby that prints its version.
func flutterToolTree(t *testing.T, dir string, framework string) profiles.FlutterTools {
	t.Helper()
	tools := profiles.FlutterTools{SDK: filepath.Join(dir, "flutter"), Ruby: filepath.Join(dir, "ruby", "bin", "ruby"), Gems: filepath.Join(dir, "gems")}
	tools.Pod = filepath.Join(tools.Gems, "bin", "pod")
	files := map[string]string{
		filepath.Join(tools.SDK, "bin", "flutter"):                       "#!/bin/sh\n",
		filepath.Join(tools.SDK, "bin", "cache", "flutter.version.json"): `{"frameworkVersion":"` + framework + `","dartSdkVersion":"3.11.5"}`,
		tools.Ruby: "#!/bin/sh\necho 'ruby 3.4.6 (2025-09-16 revision dbd83256b1) +PRISM [arm64-darwin20]'\n",
		tools.Pod:  "#!/bin/sh\n",
		filepath.Join(tools.Gems, "specifications", "cocoapods-1.16.2.gemspec"): "# gemspec\n",
	}
	for name, content := range files {
		if err := os.MkdirAll(filepath.Dir(name), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte(content), 0755); err != nil {
			t.Fatal(err)
		}
	}
	return tools
}

// notJobWritable stands in for the hostguard toolchain policy, which needs
// root-owned files: it refuses a world-writable path.
func notJobWritable(name string, _ bool) error {
	info, err := os.Lstat(name)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0002 != 0 {
		return errors.New("job-writable toolchain path")
	}
	return nil
}

// Tool inspection refuses a Flutter pin whose SDK names another framework
// version, whose gem tree lacks the pinned CocoaPods gem or whose tool
// directory the job could write.
func TestInspectFlutterToolsRefusesMismatchedTools(t *testing.T) {
	pin := qualificationFlutterPin
	tools := flutterToolTree(t, t.TempDir(), "3.41.9")
	if ok, log := inspectFlutter(context.Background(), pin, tools, notJobWritable); !ok {
		t.Fatalf("pinned tools refused:\n%s", log)
	}
	for name, setup := range map[string]func(t *testing.T) profiles.FlutterTools{
		"wrong framework version": func(t *testing.T) profiles.FlutterTools {
			return flutterToolTree(t, t.TempDir(), "3.41.8")
		},
		"missing cocoapods gemspec": func(t *testing.T) profiles.FlutterTools {
			tools := flutterToolTree(t, t.TempDir(), "3.41.9")
			if err := os.Remove(filepath.Join(tools.Gems, "specifications", "cocoapods-1.16.2.gemspec")); err != nil {
				t.Fatal(err)
			}
			return tools
		},
		"job-writable gem tree": func(t *testing.T) profiles.FlutterTools {
			tools := flutterToolTree(t, t.TempDir(), "3.41.9")
			if err := os.Chmod(tools.Gems, 0777); err != nil {
				t.Fatal(err)
			}
			return tools
		},
	} {
		t.Run(name, func(t *testing.T) {
			if ok, log := inspectFlutter(context.Background(), pin, setup(t), notJobWritable); ok {
				t.Fatalf("mismatched tools passed:\n%s", log)
			}
		})
	}
}

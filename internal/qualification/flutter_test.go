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

// flutterChallenge adds a Flutter build template on the environment's
// developer directory to c.
func flutterChallenge(c Challenge) (Challenge, string) {
	pin := qualificationFlutterPin
	t := model.Template{ID: "org-flutter-build-v1", Version: 1, Kind: model.Build, Owners: []string{"themartianapp"}, Xcode: model.Xcode{Version: "27.1", Build: "27A9275"}, DeveloperDir: c.Environment.DeveloperDir, Flutter: &pin}
	c.Templates = append(c.Templates, t)
	return c, flutterToolTarget(t)
}

// withFlutterRow returns r with a tool_profiles row for target appended, or
// r unchanged for an empty target.
func withFlutterRow(r Report, target string, success bool) Report {
	if target == "" {
		return r
	}
	r.Results = append(append([]Result(nil), r.Results...), Result{Category: "tool_profiles", Target: target, Attempt: 1, Success: success})
	return r
}

// The session aggregate expects one passing tool_profiles row per developer
// directory and per Flutter template: a passing Flutter row passes, a missing
// or failing one fails, and a Flutter row without a Flutter template fails.
func TestAggregateToolProfilesIncludesFlutterTemplates(t *testing.T) {
	base, j, o, receipts := phaseOneFixture()
	c, target := flutterChallenge(base)
	facts := sittingFacts{rebootOK: true, toolOK: true}
	if got := aggregate(c, withFlutterRow(j, target, true), o, receipts, facts)["tool_profiles"]; got.Status != "pass" {
		t.Fatalf("passing flutter row: %+v", got)
	}
	for name, tc := range map[string]struct {
		c      Challenge
		target string
		ok     bool
	}{
		"flutter row missing":     {c, "", true},
		"flutter row failing":     {c, target, false},
		"unexpected flutter row":  {base, target, true},
		"other template's target": {c, "org-other-v1 flutter 3.41.9", true},
	} {
		t.Run(name, func(t *testing.T) {
			if got := aggregate(tc.c, withFlutterRow(j, tc.target, tc.ok), o, receipts, facts)["tool_profiles"]; got.Status != "fail" {
				t.Fatalf("tool_profiles %+v", got)
			}
		})
	}
}

// Carry validation applies the same tool_profiles targets.
func TestCarryJobProbeIncludesFlutterTemplates(t *testing.T) {
	base := carryChallengeFixture()
	c, target := flutterChallenge(base)
	approved := c
	approved.Carry = false
	if err := checkCarryJobProbe(withFlutterRow(deniedReport(c), target, true), c, "h", approved); err != nil {
		t.Fatalf("passing flutter row refused: %v", err)
	}
	for name, report := range map[string]Report{
		"flutter row missing": deniedReport(c),
		"flutter row failing": withFlutterRow(deniedReport(c), target, false),
	} {
		if err := checkCarryJobProbe(report, c, "h", approved); err == nil || !strings.Contains(err.Error(), "tool inspection") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := checkCarryJobProbe(withFlutterRow(deniedReport(base), target, true), base, "h", approved); err == nil {
		t.Error("unexpected flutter row accepted without a Flutter template")
	}
}

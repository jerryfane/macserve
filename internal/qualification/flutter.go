package qualification

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/jerryfane/macserve/internal/hostguard"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/worker"
)

// toolDeveloperDirs are the developer directories the job probe inspects,
// one tool_profiles row each: the environment's and every recipe's, sorted
// and unique.
func (c Challenge) toolDeveloperDirs() []string {
	dirs := []string{c.Environment.DeveloperDir}
	for _, p := range c.recipes() {
		dirs = append(dirs, p.DeveloperDir)
	}
	slices.Sort(dirs)
	return slices.Compact(dirs)
}

// flutterTemplates are the challenge's templates with a Flutter pin, in
// configuration order.
func (c Challenge) flutterTemplates() []model.Template {
	var list []model.Template
	for _, t := range c.Templates {
		if t.Flutter != nil {
			list = append(list, t)
		}
	}
	return list
}

// flutterToolTarget is the tool_profiles target of a Flutter template's
// pinned-tool row.
func flutterToolTarget(t model.Template) string {
	return t.ID + " flutter " + t.Flutter.Version
}

// toolProfileTargets are every tool_profiles target a job probe must report
// once and passing: each developer directory and each Flutter template's
// pinned tools. The probe, the session aggregate and carry validation share it.
func (c Challenge) toolProfileTargets() []string {
	targets := c.toolDeveloperDirs()
	for _, t := range c.flutterTemplates() {
		targets = append(targets, flutterToolTarget(t))
	}
	return targets
}

// inspectFlutterTools is the tool_profiles check of one Flutter template's
// pinned tools, as the job account: every tool path is root-owned and not
// job-writable (the worker's own pre-use check), the SDK's
// bin/cache/flutter.version.json names the pinned framework version (the
// read-only SDK cannot run flutter itself), the pinned Ruby runs, and the gem
// tree holds the pinned CocoaPods gem specification.
func inspectFlutterTools(ctx context.Context, pin model.FlutterPin, jobUID uint32) (bool, string) {
	return inspectFlutter(ctx, pin, profiles.FlutterToolPaths(pin), func(name string, directory bool) error {
		if directory {
			return hostguard.ToolchainDirectory(name, jobUID)
		}
		return hostguard.ToolchainExecutable(name, jobUID)
	})
}

// inspectFlutter is inspectFlutterTools for the tools at tools, checked with
// toolchain.
func inspectFlutter(ctx context.Context, pin model.FlutterPin, tools profiles.FlutterTools, toolchain func(name string, directory bool) error) (bool, string) {
	var log strings.Builder
	ok := true
	fail := func(format string, args ...any) {
		ok = false
		fmt.Fprintf(&log, format+"\n", args...)
	}
	for _, check := range []struct {
		name      string
		directory bool
	}{{tools.SDK, true}, {tools.Gems, true}, {tools.SDK + "/bin/flutter", false}, {tools.Ruby, false}, {tools.Pod, false}} {
		if err := toolchain(check.name, check.directory); err != nil {
			fail("%s: %v", check.name, err)
		}
	}
	version := path.Join(tools.SDK, "bin", "cache", "flutter.version.json")
	var document struct {
		FrameworkVersion string `json:"frameworkVersion"`
	}
	if data, err := os.ReadFile(version); err != nil || json.Unmarshal(data, &document) != nil || document.FrameworkVersion != pin.Version {
		fail("%s: framework version %q, want %s (%v)", version, document.FrameworkVersion, pin.Version, err)
	}
	text, diag, err := command(ctx, "", tools.Ruby, "-v")
	if err != nil || strings.TrimSpace(text) == "" {
		fail("%s -v: %q %q %v", tools.Ruby, text, diag, err)
	}
	fmt.Fprintf(&log, "ruby -v: %s", text)
	spec := path.Join(tools.Gems, "specifications", "cocoapods-"+pin.CocoaPodsVersion+".gemspec")
	if info, err := os.Lstat(spec); err != nil || !info.Mode().IsRegular() {
		fail("%s: pinned CocoaPods gem missing (%v)", spec, err)
	}
	return ok, log.String()
}

// flutterRunPasses is the Flutter-template part of a run's tool evidence: the
// run observed exactly the pinned Flutter and CocoaPods. Other recipes pass
// only without a Flutter observation.
func flutterRunPasses(p model.Profile, r worker.Result) bool {
	if p.Template == nil || p.Template.Flutter == nil {
		return r.Observation.Flutter == nil
	}
	o := r.Observation.Flutter
	return o != nil && o.FrameworkVersion == p.Template.Flutter.Version && o.CocoaPods == p.Template.Flutter.CocoaPodsVersion
}

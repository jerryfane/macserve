package qualification

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/jerryfane/macserve/internal/hostguard"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/worker"
)

// inspectFlutterTools is the tool_profiles check of one Flutter template's
// pinned tools, as the job account: every tool path is root-owned and not
// job-writable (the worker's own pre-use check), the SDK's
// bin/cache/flutter.version.json names the pinned framework version (the
// read-only SDK cannot run flutter itself), the pinned Ruby runs, and the gem
// tree holds the pinned CocoaPods gem specification.
func inspectFlutterTools(ctx context.Context, pin model.FlutterPin, jobUID uint32) (bool, string) {
	tools := profiles.FlutterToolPaths(pin)
	var log strings.Builder
	ok := true
	fail := func(format string, args ...any) {
		ok = false
		fmt.Fprintf(&log, format+"\n", args...)
	}
	for _, directory := range []string{tools.SDK, tools.Gems} {
		if err := hostguard.ToolchainDirectory(directory, jobUID); err != nil {
			fail("%s: %v", directory, err)
		}
	}
	for _, executable := range []string{tools.SDK + "/bin/flutter", tools.Ruby, tools.Pod} {
		if err := hostguard.ToolchainExecutable(executable, jobUID); err != nil {
			fail("%s: %v", executable, err)
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
// trivially.
func flutterRunPasses(p model.Profile, r worker.Result) bool {
	if p.Template == nil || p.Template.Flutter == nil {
		return r.Observation.Flutter == nil
	}
	o := r.Observation.Flutter
	return o != nil && o.FrameworkVersion == p.Template.Flutter.Version && o.CocoaPods == p.Template.Flutter.CocoaPodsVersion
}

package profiles

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/jerryfane/macserve/internal/model"
)

// Flutter tool layout. The admin package installs each pinned tool
// root-owned below flutterToolsDir; FlutterToolPaths derives every path from
// a template's FlutterPin, and nothing else names them.
const (
	flutterToolsDir = "/Library/macserve/tools"
	// FlutterWorkspace is the Xcode workspace of every Flutter repository,
	// in <app_dir>/ios.
	FlutterWorkspace = "Runner.xcworkspace"
	// FlutterScheme is the only scheme of a Flutter repository: flutter build
	// does not take a scheme, so flavors and custom schemes are unsupported.
	FlutterScheme = "Runner"
	// FlutterSDKClone, FlutterPubCache and FlutterCocoaPodsHome are a Flutter
	// job's workspace directories: its writable APFS clone of the pinned SDK
	// (FLUTTER_ROOT), its pub cache and its CocoaPods home.
	FlutterSDKClone      = "flutter-sdk"
	FlutterPubCache      = "pub-cache"
	FlutterCocoaPodsHome = "cocoapods"
	// FlutterExecutable is the clone's flutter script; it runs with /bin/bash
	// because recipe executables are fixed absolute paths.
	FlutterExecutable = "${WORKSPACE}/" + FlutterSDKClone + "/bin/flutter"
	// maxPrepareRuby bounds flutter.prepare_ruby.
	maxPrepareRuby = 8
)

var (
	flutterVersionPattern   = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	cocoaPodsVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
)

// FlutterTools are the root-owned tools of a Flutter pin.
type FlutterTools struct {
	// SDK is the precached Flutter SDK directory a job clones,
	// /Library/macserve/tools/flutter/<version>/flutter.
	SDK string
	// Ruby is the portable Ruby,
	// /Library/macserve/tools/ruby/<ruby_sha256[:12]>/bin/ruby.
	Ruby string
	// Gems is the CocoaPods gem tree (GEM_HOME and GEM_PATH),
	// /Library/macserve/tools/cocoapods/<cocoapods_version>/gems.
	Gems string
	// Pod is the CocoaPods executable, <Gems>/bin/pod.
	Pod string
}

// FlutterToolPaths returns the tool paths of pin, which must be valid.
func FlutterToolPaths(pin model.FlutterPin) FlutterTools {
	gems := path.Join(flutterToolsDir, "cocoapods", pin.CocoaPodsVersion, "gems")
	return FlutterTools{
		SDK:  path.Join(flutterToolsDir, "flutter", pin.Version, "flutter"),
		Ruby: path.Join(flutterToolsDir, "ruby", pin.RubySHA256[:min(12, len(pin.RubySHA256))], "bin", "ruby"),
		Gems: gems,
		Pod:  path.Join(gems, "bin", "pod"),
	}
}

func validFlutterPin(pin model.FlutterPin) bool {
	return flutterVersionPattern.MatchString(pin.Version) && cocoaPodsVersionPattern.MatchString(pin.CocoaPodsVersion) && configDigest.MatchString(pin.SDKSHA256) && configDigest.MatchString(pin.RubySHA256) && configDigest.MatchString(pin.GemsSHA256)
}

// normalizeFlutterPin checks a template's optional Flutter pin: exact
// versions, lowercase sha256 digests and a kind with an Xcode build or test
// step to run after the Flutter configuration.
func normalizeFlutterPin(t model.Template) error {
	if t.Flutter == nil {
		return nil
	}
	if t.Kind != model.Build && !t.Kind.Tests() {
		return fmt.Errorf("%w: Flutter templates support only build, unit_test and simulator_ui_test jobs", ErrUnsupported)
	}
	if !validFlutterPin(*t.Flutter) {
		return fmt.Errorf("%w: exact Flutter version, CocoaPods version and lowercase sha256 digests required", ErrInvalid)
	}
	return nil
}

// sameFlutter reports whether a request's Flutter selection is exactly the
// recipe's pin: both absent, or the same version.
func sameFlutter(request *model.FlutterRequest, pin *model.FlutterPin) bool {
	if request == nil || pin == nil {
		return request == nil && pin == nil
	}
	return request.Version == pin.Version
}

// RequestFlutter is the Flutter selection a request for the recipe snapshot
// p must carry: its template's pinned version, or nil.
func RequestFlutter(p model.Profile) *model.FlutterRequest {
	if p.Template == nil || p.Template.Flutter == nil {
		return nil
	}
	return &model.FlutterRequest{Version: p.Template.Flutter.Version}
}

func cloneFlutterRequest(f *model.FlutterRequest) *model.FlutterRequest {
	if f == nil {
		return nil
	}
	copy := *f
	return &copy
}

// validateFlutter checks the flutter section's fixed layout: work_dir is
// <app_dir>/ios, the workspace is Runner.xcworkspace (no project), the scheme
// is Runner, neither xcodegen nor resolve_packages, and at most eight
// checkout-relative .rb files to run.
func validateFlutter(c model.RepoConfig) error {
	f := c.Flutter
	if f == nil {
		return nil
	}
	ios := path.Join(f.AppDir, "ios")
	switch {
	case len(f.AppDir) > 1000 || !relativePath(f.AppDir, true, false) || path.Clean(f.AppDir) != f.AppDir:
		return repoConfigError("flutter.app_dir must be a clean relative directory without '..', '$', globs or backslashes")
	case c.WorkDir != ios:
		return repoConfigError("work_dir must be flutter.app_dir's ios directory %q", ios)
	case c.Project != "" || c.Workspace != FlutterWorkspace:
		return repoConfigError("a flutter repository uses workspace %q and no project", FlutterWorkspace)
	case c.Scheme != FlutterScheme:
		return repoConfigError("a flutter repository uses scheme %q: Flutter flavors/custom schemes are not supported", FlutterScheme)
	case c.XcodeGen || c.ResolvePackages:
		return repoConfigError("a flutter repository cannot use xcodegen or resolve_packages")
	case len(f.PrepareRuby) > maxPrepareRuby:
		return repoConfigError("flutter.prepare_ruby lists at most %d scripts", maxPrepareRuby)
	}
	for _, script := range f.PrepareRuby {
		if !scriptPath(script) || !strings.HasSuffix(script, ".rb") || path.Base(script) == ".rb" {
			return repoConfigError("flutter.prepare_ruby %q must be a relative .rb file path without empty, '.' or '..' components, '$', globs or backslashes", script)
		}
	}
	return nil
}

// FlutterSDKCloneCommand is the first prepare command of every Flutter job:
// the APFS clone of the pinned SDK into the job workspace, which Flutter
// needs writable.
func FlutterSDKCloneCommand(pin model.FlutterPin) model.Command {
	return model.Command{Executable: "/bin/cp", Args: []string{"-c", "-R", FlutterToolPaths(pin).SDK, "${WORKSPACE}/" + FlutterSDKClone}}
}

func flutterCommand(args ...string) model.Command {
	return model.Command{Executable: "/bin/bash", Args: append([]string{FlutterExecutable}, args...)}
}

// flutterPrepare is a Flutter job's fixed prepare before any Xcode step, run
// in app_dir: clone the SDK, resolve exactly the committed pubspec.lock,
// write the iOS configuration (which runs pod install), then run each
// prepare_ruby script with the pinned Ruby.
func flutterPrepare(pin model.FlutterPin, f model.FlutterConfig) []model.Command {
	commands := []model.Command{
		FlutterSDKCloneCommand(pin),
		flutterCommand("pub", "get", "--enforce-lockfile", "--suppress-analytics"),
		flutterCommand("build", "ios", "--config-only", "--simulator", "--debug", "--suppress-analytics"),
	}
	ruby := FlutterToolPaths(pin).Ruby
	for _, script := range f.PrepareRuby {
		commands = append(commands, model.Command{Executable: ruby, Args: []string{ScriptCheckoutPrefix + script}})
	}
	return commands
}

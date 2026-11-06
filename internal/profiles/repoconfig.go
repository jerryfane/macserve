package profiles

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/jerryfane/macserve/internal/model"
)

const (
	// RepoConfigFile is the only repository file a template job reads.
	RepoConfigFile = ".macserve.json"
	// ScriptOutputDir is the workspace directory a script job writes its
	// outputs to; its derived recipe requires it as an artifact.
	ScriptOutputDir = "output"
	// ScriptCheckoutPrefix starts a script job's run argument; the rest is the
	// script's checkout-relative path.
	ScriptCheckoutPrefix = "${CHECKOUT}/"
	// MaxRepoConfigBytes bounds RepoConfigFile, test shards included.
	MaxRepoConfigBytes = 16384
	// XcodeGenPath is the root-installed XcodeGen the xcodegen step runs.
	XcodeGenPath = "/Library/macserve/tools/xcodegen"
)

// ErrRepoConfig prefixes every refusal of a repository's RepoConfigFile.
var ErrRepoConfig = errors.New("repository has no valid .macserve.json")

var (
	configDigest     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	projectPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _.-]*\.xcodeproj$`)
	workspacePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _.-]*\.xcworkspace$`)
	schemePattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _.-]{0,127}$`)
	// selectorPattern is an -only-testing selector Target/Class or
	// Target/Class/method, the method optionally spelled with "()". It admits
	// no ':', '$', ',', whitespace or leading '-'.
	selectorPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}/[A-Za-z_][A-Za-z0-9_]{0,127}(/[A-Za-z_][A-Za-z0-9_]{0,127}(\(\))?)?$`)
	repoConfigKeys  = map[string]bool{"version": true, "work_dir": true, "project": true, "workspace": true, "scheme": true, "xcodegen": true, "resolve_packages": true, "ui_test": true, "unit_test": true, "script": true, "flutter": true}
	// testSectionKeys, scriptSectionKeys and flutterSectionKeys are the exact
	// object keys strictJSON admits per depth of a section (nil admits any
	// key, such as a shard name).
	testSectionKeys    = [][]string{{"shards"}}
	scriptSectionKeys  = [][]string{{"shards"}, nil, {"run"}}
	flutterSectionKeys = [][]string{{"app_dir", "prepare_ruby"}}
)

// Shard limits, per ui_test, unit_test or script section.
const (
	maxShards           = 16
	maxShardSelectors   = 32
	maxSectionSelectors = 256
	maxTestSectionDepth = 3
)

func repoConfigError(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrRepoConfig}, args...)...)
}

// ParseRepoConfig decodes RepoConfigFile bytes: one JSON object with exactly
// spelled, unique, non-null known keys and no trailing data, at most
// MaxRepoConfigBytes long.
func ParseRepoConfig(data []byte) (model.RepoConfig, error) {
	var config model.RepoConfig
	if len(data) > MaxRepoConfigBytes {
		return config, repoConfigError("file exceeds %d bytes", MaxRepoConfigBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return config, repoConfigError("a JSON object is required")
	}
	seen := make(map[string]bool, len(repoConfigKeys))
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return config, repoConfigError("%v", err)
		}
		key, _ := token.(string)
		if !repoConfigKeys[key] {
			return config, repoConfigError("unknown field %q", key)
		}
		if seen[key] {
			return config, repoConfigError("duplicate field %q", key)
		}
		seen[key] = true
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return config, repoConfigError("%v", err)
		}
		if string(value) == "null" {
			return config, repoConfigError("field %q is null", key)
		}
		if key == "ui_test" || key == "unit_test" || key == "script" || key == "flutter" {
			keys := testSectionKeys
			switch key {
			case "script":
				keys = scriptSectionKeys
			case "flutter":
				keys = flutterSectionKeys
			}
			if err := strictJSON(json.NewDecoder(bytes.NewReader(value)), key, 0, keys); err != nil {
				return config, err
			}
		}
	}
	if _, err := decoder.Token(); err != nil {
		return config, repoConfigError("%v", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return config, repoConfigError("trailing data after the JSON object")
	}
	strict := json.NewDecoder(bytes.NewReader(data))
	strict.DisallowUnknownFields()
	if err := strict.Decode(&config); err != nil {
		return model.RepoConfig{}, repoConfigError("%v", err)
	}
	if err := ValidateRepoConfig(config); err != nil {
		return model.RepoConfig{}, err
	}
	return config, nil
}

// strictJSON walks one JSON value of a test, script or flutter section and
// refuses what the strict struct decode would silently accept: duplicate keys
// (the last would win), a key other than those keys fixes at its depth (a
// case-folded "shards" or "run"), nulls (a zero value) and deep nesting.
// Types and other unknown fields are left to it.
func strictJSON(decoder *json.Decoder, path string, depth int, keys [][]string) error {
	token, err := decoder.Token()
	if err != nil {
		return repoConfigError("%v", err)
	}
	switch token {
	case nil:
		return repoConfigError("%s has a null value", path)
	case json.Delim('{'), json.Delim('['):
		if depth >= maxTestSectionDepth {
			return repoConfigError("%s is nested too deeply", path)
		}
	default:
		return nil
	}
	if token == json.Delim('[') {
		for decoder.More() {
			if err := strictJSON(decoder, path+"[]", depth+1, keys); err != nil {
				return err
			}
		}
	} else {
		seen := make(map[string]bool)
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return repoConfigError("%v", err)
			}
			key, _ := token.(string)
			if seen[key] {
				return repoConfigError("%s has duplicate key %q", path, key)
			}
			// The struct decode matches field names case-insensitively.
			if depth < len(keys) && keys[depth] != nil && !slices.Contains(keys[depth], key) {
				return repoConfigError("%s has unknown field %q", path, key)
			}
			seen[key] = true
			if err := strictJSON(decoder, path+"."+key, depth+1, keys); err != nil {
				return err
			}
		}
	}
	if _, err := decoder.Token(); err != nil {
		return repoConfigError("%v", err)
	}
	return nil
}

// ValidateRepoConfig checks a parsed RepoConfigFile, including one reported back
// by a worker.
func ValidateRepoConfig(c model.RepoConfig) error {
	switch {
	case c.Version != 1:
		return repoConfigError("version must be 1")
	case len(c.WorkDir) > 1024 || !relativePath(c.WorkDir, true, false):
		return repoConfigError("work_dir must be a relative directory without '..', '$', globs or backslashes")
	case (c.Project == "") == (c.Workspace == ""):
		return repoConfigError("exactly one of project or workspace is required")
	case c.Project != "" && (len(c.Project) > 255 || !projectPattern.MatchString(c.Project)):
		return repoConfigError("project must be a single <Name>.xcodeproj path component")
	case c.Workspace != "" && (len(c.Workspace) > 255 || !workspacePattern.MatchString(c.Workspace)):
		return repoConfigError("workspace must be a single <Name>.xcworkspace path component")
	case !schemePattern.MatchString(c.Scheme):
		return repoConfigError("scheme must match %s", schemePattern)
	}
	if err := validateShards("ui_test", c.UITest); err != nil {
		return err
	}
	if err := validateShards("unit_test", c.UnitTest); err != nil {
		return err
	}
	if err := validateScripts(c.Script); err != nil {
		return err
	}
	return validateFlutter(c)
}

// validateScripts checks the script section: 1 to 16 shards named by
// shardPattern, each running a script path relative to work_dir under the
// work_dir character rules, with no empty or "." component.
func validateScripts(s *model.ScriptShards) error {
	if s == nil {
		return nil
	}
	if len(s.Shards) == 0 || len(s.Shards) > maxShards {
		return repoConfigError("script.shards must name 1 to %d shards", maxShards)
	}
	for _, name := range slices.Sorted(maps.Keys(s.Shards)) {
		if !shardPattern.MatchString(name) {
			return repoConfigError("script shard name %q must match %s", name, shardPattern)
		}
		if !scriptPath(s.Shards[name].Run) {
			return repoConfigError("script shard %q run must be a relative file path without empty, '.' or '..' components, '$', globs or backslashes", name)
		}
	}
	return nil
}

func scriptPath(value string) bool {
	if len(value) > 1024 || !relativePath(value, false, false) {
		return false
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || component == "." {
			return false
		}
	}
	return true
}

// validateShards checks one test section: 1 to 16 shards named by
// shardPattern, each 1 to 32 selectors, at most 256 in all. Within a shard a
// selector may not repeat, also as method and method(), nor be a "/"-prefix of
// another.
func validateShards(key string, s *model.TestShards) error {
	if s == nil {
		return nil
	}
	if len(s.Shards) == 0 || len(s.Shards) > maxShards {
		return repoConfigError("%s.shards must name 1 to %d shards", key, maxShards)
	}
	total := 0
	for _, name := range slices.Sorted(maps.Keys(s.Shards)) {
		selectors := s.Shards[name]
		if !shardPattern.MatchString(name) {
			return repoConfigError("%s shard name %q must match %s", key, name, shardPattern)
		}
		if len(selectors) == 0 || len(selectors) > maxShardSelectors {
			return repoConfigError("%s shard %q must list 1 to %d selectors", key, name, maxShardSelectors)
		}
		total += len(selectors)
		if total > maxSectionSelectors {
			return repoConfigError("%s lists more than %d selectors", key, maxSectionSelectors)
		}
		bare := make([]string, len(selectors))
		for i, selector := range selectors {
			if !selectorPattern.MatchString(selector) {
				return repoConfigError("%s shard %q selector %q must be Target/Class or Target/Class/method", key, name, selector)
			}
			bare[i] = strings.TrimSuffix(selector, "()")
		}
		for i, a := range bare {
			for j, b := range bare {
				if i != j && (a == b || strings.HasPrefix(b, a+"/")) {
					return repoConfigError("%s shard %q selector %q repeats or contains %q", key, name, selectors[i], selectors[j])
				}
			}
		}
	}
	return nil
}

// Derive returns the effective recipe of a template job snapshot for a
// repository configuration. Only the work directory, the project or workspace,
// the scheme, the two optional fixed steps, a test template's shard selectors,
// a script template's shard script path and a Flutter template's app
// directory and prepare_ruby script paths come from the repository; the
// executables, flags, destination and environment are fixed here and by the
// worker.
//
// A test template builds for testing on the job's own simulator in prepare and
// runs test-without-building on it, both restricted to the snapshot shard's
// selectors, which become the job's required tests.
//
// A script template builds the scheme for the job's own simulator in prepare
// and runs the snapshot shard's script with /bin/bash; it has no required
// tests, and its one required artifact is the workspace output directory
// (exported as output.tar.gz).
//
// A Flutter template (one with a Flutter pin) serves only a configuration
// with a flutter section, and a flutter section only a Flutter template. Its
// recipe runs in app_dir: the fixed Flutter prepare (see flutterPrepare),
// then a build template's run is `flutter build ios` for the simulator and a
// test template's Xcode steps are the ones above on ios/Runner.xcworkspace.
func Derive(snapshot model.Profile, c model.RepoConfig) (model.Profile, error) {
	if snapshot.Template == nil {
		return model.Profile{}, fmt.Errorf("%w: not a template job snapshot", ErrInvalid)
	}
	if err := ValidateRepoConfig(c); err != nil {
		return model.Profile{}, err
	}
	flutter := snapshot.Template.Flutter
	switch {
	case flutter != nil && c.Flutter == nil:
		return model.Profile{}, fmt.Errorf("%w: template %s is a Flutter template and serves only a .macserve.json with a flutter section", ErrUnsupported, snapshot.Template.ID)
	case flutter == nil && c.Flutter != nil:
		return model.Profile{}, fmt.Errorf("%w: .macserve.json has a flutter section but template %s has no Flutter pin", ErrUnsupported, snapshot.Template.ID)
	case flutter != nil && (!validFlutterPin(*flutter) || snapshot.Kind == model.SimulatorScript):
		return model.Profile{}, fmt.Errorf("%w: invalid Flutter template snapshot", ErrInvalid)
	}
	container := []string{"-project", c.Project}
	if c.Workspace != "" {
		container = []string{"-workspace", c.Workspace}
	}
	p := cloneProfile(snapshot)
	p.WorkDir = c.WorkDir
	p.Prepare = nil
	if flutter != nil {
		// Flutter commands run in app_dir, so Xcode names ios/<workspace>.
		container = []string{"-workspace", path.Join("ios", c.Workspace)}
		p.WorkDir = c.Flutter.AppDir
		p.Prepare = flutterPrepare(*flutter, *c.Flutter)
	}
	xcodebuild := func(args ...string) model.Command {
		return model.Command{Executable: "/usr/bin/xcrun", Args: append(append([]string{"xcodebuild"}, container...), args...)}
	}
	if c.XcodeGen {
		p.Prepare = append(p.Prepare, model.Command{Executable: XcodeGenPath, Args: []string{"generate", "--spec", "project.yml"}})
	}
	if c.ResolvePackages {
		p.Prepare = append(p.Prepare, xcodebuild("-scheme", c.Scheme, "-resolvePackageDependencies"))
	}
	switch snapshot.Kind {
	case model.Build:
		if snapshot.Shard != "" {
			return model.Profile{}, fmt.Errorf("%w: build template snapshot has a shard", ErrInvalid)
		}
		p.Run = xcodebuild("-scheme", c.Scheme, "-configuration", "Debug", "-sdk", "iphonesimulator", "-destination", "generic/platform=iOS Simulator", "-derivedDataPath", "${DERIVED_DATA}", "CODE_SIGNING_ALLOWED=NO", "build")
		if flutter != nil {
			p.Run = flutterBuild()
		}
	case model.UnitTest, model.SimulatorUITest:
		key, section := "ui_test", c.UITest
		if snapshot.Kind == model.UnitTest {
			key, section = "unit_test", c.UnitTest
		}
		if !shardPattern.MatchString(snapshot.Shard) || snapshot.Simulator == nil {
			return model.Profile{}, fmt.Errorf("%w: test template snapshot lacks its shard or simulator", ErrInvalid)
		}
		var selectors []string
		if section != nil {
			selectors = section.Shards[snapshot.Shard]
		}
		if len(selectors) == 0 {
			return model.Profile{}, repoConfigError("%s.shards has no shard %q", key, snapshot.Shard)
		}
		only := make([]string, len(selectors))
		for i, selector := range selectors {
			only[i] = "-only-testing:" + selector
		}
		test := []string{"-scheme", c.Scheme, "-configuration", "Debug", "-sdk", "iphonesimulator", "-destination", "id=${SIMULATOR_ID}", "-derivedDataPath", "${DERIVED_DATA}"}
		p.Prepare = append(p.Prepare, xcodebuild(append(append(slices.Clone(test), "CODE_SIGNING_ALLOWED=NO", "build-for-testing"), only...)...))
		p.Run = xcodebuild(append(append(slices.Clone(test), "-resultBundlePath", "${RESULT_BUNDLE}", "CODE_SIGNING_ALLOWED=NO", "test-without-building"), only...)...)
		p.RequiredTests = slices.Clone(selectors)
	case model.SimulatorScript:
		if !shardPattern.MatchString(snapshot.Shard) || snapshot.Simulator == nil {
			return model.Profile{}, fmt.Errorf("%w: script template snapshot lacks its shard or simulator", ErrInvalid)
		}
		var script model.ScriptShard
		if c.Script != nil {
			script = c.Script.Shards[snapshot.Shard]
		}
		if script.Run == "" {
			return model.Profile{}, repoConfigError("script.shards has no shard %q", snapshot.Shard)
		}
		p.Prepare = append(p.Prepare, xcodebuild("-scheme", c.Scheme, "-configuration", "Debug", "-sdk", "iphonesimulator", "-destination", "id=${SIMULATOR_ID}", "-derivedDataPath", "${DERIVED_DATA}", "build"))
		p.Run = model.Command{Executable: "/bin/bash", Args: []string{ScriptCheckoutPrefix + path.Join(c.WorkDir, script.Run)}}
		p.Artifacts = []model.ArtifactRule{{Path: ScriptOutputDir, Required: true}}
	default:
		return model.Profile{}, fmt.Errorf("%w: template job kind", ErrUnsupported)
	}
	for _, command := range append([]model.Command{p.Run}, p.Prepare...) {
		if err := validateCommand(command); err != nil {
			return model.Profile{}, err
		}
	}
	return p, nil
}

// Effective returns the recipe a job ran: the snapshot itself for a profile
// job, and for a template job the derivation from its reported repository
// configuration, which must equal the reported recipe exactly. A profile job
// must not report a recipe.
func Effective(snapshot model.Profile, recipe *model.RepoRecipe) (model.Profile, error) {
	if snapshot.Template == nil {
		if recipe != nil {
			return model.Profile{}, errors.New("unexpected repository recipe for a profile job")
		}
		return snapshot, nil
	}
	if recipe == nil || !configDigest.MatchString(recipe.ConfigSHA256) {
		return model.Profile{}, errors.New("template job lacks repository recipe evidence")
	}
	derived, err := Derive(snapshot, recipe.Config)
	if err != nil || derived.WorkDir != recipe.WorkDir || !sameCommands(append([]model.Command{derived.Run}, derived.Prepare...), append([]model.Command{recipe.Run}, recipe.Prepare...)) || recipe.Shard != derived.Shard || !slices.Equal(recipe.RequiredTests, derived.RequiredTests) {
		return model.Profile{}, errors.New("repository recipe does not match its template derivation")
	}
	return derived, nil
}

func sameCommands(a, b []model.Command) bool {
	return slices.EqualFunc(a, b, func(x, y model.Command) bool {
		return x.Executable == y.Executable && slices.Equal(x.Args, y.Args)
	})
}

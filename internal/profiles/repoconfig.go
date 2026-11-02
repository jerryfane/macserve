package profiles

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"

	"github.com/jerryfane/macserve/internal/model"
)

const (
	// RepoConfigFile is the only repository file a template job reads.
	RepoConfigFile = ".macserve.json"
	// MaxRepoConfigBytes bounds RepoConfigFile.
	MaxRepoConfigBytes = 4096
	// XcodeGenPath is the root-installed XcodeGen the xcodegen step runs.
	XcodeGenPath = "/Library/macserve/tools/xcodegen"
)

// ErrRepoConfig prefixes every refusal of a repository's RepoConfigFile.
var ErrRepoConfig = errors.New("repository has no valid .macserve.json")

var (
	projectPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _.-]*\.xcodeproj$`)
	workspacePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _.-]*\.xcworkspace$`)
	schemePattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _.-]{0,127}$`)
	repoConfigKeys   = map[string]bool{"version": true, "work_dir": true, "project": true, "workspace": true, "scheme": true, "xcodegen": true, "resolve_packages": true}
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
	return nil
}

// Derive returns the effective recipe of a template job snapshot for a
// repository configuration. Only the work directory, the project or workspace,
// the scheme and the two optional fixed steps come from the repository; the
// executables, flags and environment are fixed here and by the worker.
func Derive(snapshot model.Profile, c model.RepoConfig) (model.Profile, error) {
	if snapshot.Template == nil {
		return model.Profile{}, fmt.Errorf("%w: not a template job snapshot", ErrInvalid)
	}
	if err := ValidateRepoConfig(c); err != nil {
		return model.Profile{}, err
	}
	container := []string{"-project", c.Project}
	if c.Workspace != "" {
		container = []string{"-workspace", c.Workspace}
	}
	p := cloneProfile(snapshot)
	p.WorkDir = c.WorkDir
	p.Prepare = nil
	if c.XcodeGen {
		p.Prepare = append(p.Prepare, model.Command{Executable: XcodeGenPath, Args: []string{"generate", "--spec", "project.yml"}})
	}
	if c.ResolvePackages {
		p.Prepare = append(p.Prepare, model.Command{Executable: "/usr/bin/xcrun", Args: append(append([]string{"xcodebuild"}, container...), "-scheme", c.Scheme, "-resolvePackageDependencies")})
	}
	p.Run = model.Command{Executable: "/usr/bin/xcrun", Args: append(append([]string{"xcodebuild"}, container...), "-scheme", c.Scheme, "-configuration", "Debug", "-sdk", "iphonesimulator", "-destination", "generic/platform=iOS Simulator", "-derivedDataPath", "${DERIVED_DATA}", "CODE_SIGNING_ALLOWED=NO", "build")}
	for _, command := range append([]model.Command{p.Run}, p.Prepare...) {
		if err := validateCommand(command); err != nil {
			return model.Profile{}, err
		}
	}
	return p, nil
}

// Package profiles validates controller-owned recipes and resolves untrusted
// requests against immutable, exactly pinned recipe snapshots.
package profiles

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/jerryfane/macserve/internal/model"
)

var (
	ErrInvalid     = errors.New("invalid profile or request")
	ErrUnsupported = errors.New("unsupported profile or request")
)

const maxConfigBytes = 1 << 20

var (
	idPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
	repoPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9_.-]+$`)
	shaPattern     = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
	versionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+(\.[0-9]+)?$`)
	buildPattern   = regexp.MustCompile(`^[0-9]+[A-Za-z][0-9]+[A-Za-z]?$`)
	runtimePattern = regexp.MustCompile(`^com\.apple\.CoreSimulator\.SimRuntime\.[A-Za-z]+-[0-9]+(-[0-9]+)+$`)
	devicePattern  = regexp.MustCompile(`^com\.apple\.CoreSimulator\.SimDeviceType\.[A-Za-z0-9][A-Za-z0-9.-]*$`)
)

type entry struct {
	profile model.Profile
	digest  string
}

// Registry owns all recipe storage; its read-only methods are safe concurrently.
// List preserves configuration order. No method exposes the owned storage.
type Registry struct {
	entries []entry
	byID    map[string]int
}

// New validates and normalizes copies of controller-approved profiles. Missing
// timeouts default to 1800 seconds (2400 for UI tests), with a 3600-second maximum;
// missing memory budgets default to 32768 MiB. It does not probe installed tools.
func New(profiles []model.Profile) (*Registry, error) {
	r := &Registry{entries: make([]entry, 0, len(profiles)), byID: make(map[string]int, len(profiles))}
	for _, original := range profiles {
		p := cloneProfile(original)
		if err := normalizeProfile(&p); err != nil {
			return nil, fmt.Errorf("profile %q: %w", p.ID, err)
		}
		if _, exists := r.byID[p.ID]; exists {
			return nil, fmt.Errorf("%w: duplicate profile ID %q", ErrInvalid, p.ID)
		}
		encoded, err := json.Marshal(p)
		if err != nil {
			return nil, fmt.Errorf("%w: profile encoding: %v", ErrInvalid, err)
		}
		digest := sha256.Sum256(encoded)
		r.byID[p.ID] = len(r.entries)
		r.entries = append(r.entries, entry{profile: p, digest: hex.EncodeToString(digest[:])})
	}
	return r, nil
}

// Load reads at most 1 MiB of strict JSON shaped as {"profiles":[...]}. An
// explicit empty array disables all profiles; missing or null profiles is invalid.
func Load(filename string) (*Registry, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxConfigBytes {
		return nil, fmt.Errorf("%w: configuration exceeds 1 MiB", ErrInvalid)
	}
	var document struct {
		Profiles []model.Profile `json:"profiles"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("%w: configuration JSON: %v", ErrInvalid, err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing configuration JSON", ErrInvalid)
	}
	if document.Profiles == nil {
		return nil, fmt.Errorf("%w: profiles array is required", ErrInvalid)
	}
	return New(document.Profiles)
}

// Resolve admits only the configured repository, kind and exact toolchain pins.
// SHA and repository casing are canonicalized, but no client paths, executable
// arguments or environment are accepted. The returned recipe and request are
// independent snapshots, including their nested slices and simulator pointers.
func (r *Registry) Resolve(request model.Request) (model.Admission, error) {
	if !supportedKind(request.Kind) {
		return model.Admission{}, fmt.Errorf("%w: job kind", ErrUnsupported)
	}
	if !validRepo(request.Repo) || !shaPattern.MatchString(request.SHA) || !idPattern.MatchString(request.Profile) || request.TimeoutSeconds < 0 {
		return model.Admission{}, fmt.Errorf("%w: repository, SHA, profile ID or timeout", ErrInvalid)
	}
	request.Repo = strings.ToLower(request.Repo)
	request.SHA = strings.ToLower(request.SHA)
	index, found := r.byID[request.Profile]
	if !found {
		return model.Admission{}, fmt.Errorf("%w: profile", ErrUnsupported)
	}
	e := r.entries[index]
	p := e.profile
	if request.Repo != p.Repo || request.Kind != p.Kind || request.Xcode != p.Xcode || !sameSimulator(request.Simulator, p.Simulator) {
		return model.Admission{}, fmt.Errorf("%w: repository, kind or toolchain pins", ErrUnsupported)
	}
	if request.TimeoutSeconds == 0 {
		request.TimeoutSeconds = p.DefaultTimeoutSeconds
	}
	if request.TimeoutSeconds > p.MaxTimeoutSeconds {
		return model.Admission{}, fmt.Errorf("%w: timeout exceeds profile maximum", ErrInvalid)
	}
	request.Simulator = cloneSimulator(request.Simulator)
	return model.Admission{Request: request, Profile: cloneProfile(p), ProfileDigest: e.digest}, nil
}

func (r *Registry) List() []model.Profile {
	profiles := make([]model.Profile, len(r.entries))
	for i, e := range r.entries {
		profiles[i] = cloneProfile(e.profile)
	}
	return profiles
}

func normalizeProfile(p *model.Profile) error {
	if !idPattern.MatchString(p.ID) || p.Version <= 0 || !validRepo(p.Repo) {
		return fmt.Errorf("%w: ID, version or repository", ErrInvalid)
	}
	p.Repo = strings.ToLower(p.Repo)
	if !supportedKind(p.Kind) {
		return fmt.Errorf("%w: job kind", ErrUnsupported)
	}
	if !versionPattern.MatchString(p.Xcode.Version) || !buildPattern.MatchString(p.Xcode.Build) {
		return fmt.Errorf("%w: exact Xcode version and build required", ErrInvalid)
	}
	if !absolutePath(p.DeveloperDir) || !relativePath(p.WorkDir, true, false) {
		return fmt.Errorf("%w: developer directory or working directory", ErrInvalid)
	}
	if p.Simulator != nil {
		s := p.Simulator
		if !runtimePattern.MatchString(s.Runtime) || !buildPattern.MatchString(s.RuntimeBuild) || !devicePattern.MatchString(s.DeviceType) {
			return fmt.Errorf("%w: exact simulator runtime, build and device type required", ErrInvalid)
		}
	}
	if p.Kind != model.Build && (p.Simulator == nil || len(p.RequiredTests) == 0) {
		return fmt.Errorf("%w: test jobs require a simulator and required tests", ErrInvalid)
	}
	for _, test := range p.RequiredTests {
		if strings.TrimSpace(test) == "" || strings.ContainsRune(test, '\x00') {
			return fmt.Errorf("%w: empty or invalid required test", ErrInvalid)
		}
	}
	if err := validateCommand(p.Run); err != nil {
		return err
	}
	for _, command := range p.Prepare {
		if err := validateCommand(command); err != nil {
			return err
		}
	}
	for _, file := range p.GeneratedFiles {
		if !relativePath(file.Path, false, false) {
			return fmt.Errorf("%w: generated file path", ErrInvalid)
		}
	}
	for _, artifact := range p.Artifacts {
		if !relativePath(artifact.Path, false, true) {
			return fmt.Errorf("%w: artifact pattern", ErrInvalid)
		}
	}
	if p.DefaultTimeoutSeconds == 0 {
		p.DefaultTimeoutSeconds = 1800
		if p.Kind == model.SimulatorUITest {
			p.DefaultTimeoutSeconds = 2400
		}
	}
	if p.MaxTimeoutSeconds == 0 {
		p.MaxTimeoutSeconds = 3600
	}
	if p.DefaultTimeoutSeconds < 1 || p.MaxTimeoutSeconds < 1 || p.MaxTimeoutSeconds > 3600 || p.DefaultTimeoutSeconds > p.MaxTimeoutSeconds {
		return fmt.Errorf("%w: timeout limits", ErrInvalid)
	}
	if p.MemoryLimitMiB == 0 {
		p.MemoryLimitMiB = 32768
	}
	if p.MemoryLimitMiB < 1 {
		return fmt.Errorf("%w: memory limit", ErrInvalid)
	}
	return nil
}

func supportedKind(kind model.Kind) bool {
	return kind == model.Build || kind == model.UnitTest || kind == model.SimulatorUITest
}

func validRepo(repo string) bool {
	if !repoPattern.MatchString(repo) {
		return false
	}
	_, name, _ := strings.Cut(repo, "/")
	return name != "." && name != ".."
}

func absolutePath(value string) bool {
	return path.IsAbs(value) && safePath(value) && !strings.ContainsAny(value, "$*?[")
}

// Artifact patterns use slash-separated path.Match syntax (no recursive-glob
// extension). This is lexical validation only: the worker must constrain matches
// to its job root and reject symlink escapes when opening or creating any path.
func relativePath(value string, allowDot, pattern bool) bool {
	if value == "" || path.IsAbs(value) || !safePath(value) || strings.ContainsRune(value, '$') {
		return false
	}
	if path.Clean(value) == "." && !allowDot {
		return false
	}
	if pattern {
		_, err := path.Match(value, "")
		return err == nil
	}
	return !strings.ContainsAny(value, "*?[")
}

func safePath(value string) bool {
	if strings.ContainsAny(value, "\x00\\") {
		return false
	}
	for _, component := range strings.Split(value, "/") {
		if component == ".." {
			return false
		}
	}
	return true
}

// Command arguments support only these literal worker substitutions: CHECKOUT,
// WORKSPACE, DERIVED_DATA, RESULT_BUNDLE, SIMULATOR_ID, JOB_ID and DEVELOPER_DIR,
// each spelled ${NAME}. There is no shell expansion or inherited environment
// substitution. Executables themselves must be trusted absolute paths.
func validateCommand(command model.Command) error {
	if !absolutePath(command.Executable) {
		return fmt.Errorf("%w: command executable", ErrInvalid)
	}
	for _, arg := range command.Args {
		if strings.ContainsRune(arg, '\x00') {
			return fmt.Errorf("%w: NUL in command argument", ErrInvalid)
		}
		for {
			index := strings.IndexByte(arg, '$')
			if index < 0 {
				break
			}
			arg = arg[index:]
			if !strings.HasPrefix(arg, "${") {
				return fmt.Errorf("%w: command placeholder", ErrInvalid)
			}
			end := strings.IndexByte(arg, '}')
			if end < 0 {
				return fmt.Errorf("%w: unterminated command placeholder", ErrInvalid)
			}
			switch arg[2:end] {
			case "CHECKOUT", "WORKSPACE", "DERIVED_DATA", "RESULT_BUNDLE", "SIMULATOR_ID", "JOB_ID", "DEVELOPER_DIR":
			default:
				return fmt.Errorf("%w: command placeholder", ErrInvalid)
			}
			arg = arg[end+1:]
		}
	}
	return nil
}

func sameSimulator(a, b *model.Simulator) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func cloneSimulator(s *model.Simulator) *model.Simulator {
	if s == nil {
		return nil
	}
	copy := *s
	return &copy
}

func cloneProfile(p model.Profile) model.Profile {
	p.Simulator = cloneSimulator(p.Simulator)
	p.Run.Args = append([]string(nil), p.Run.Args...)
	p.Prepare = append([]model.Command(nil), p.Prepare...)
	for i := range p.Prepare {
		p.Prepare[i].Args = append([]string(nil), p.Prepare[i].Args...)
	}
	p.GeneratedFiles = append([]model.GeneratedFile(nil), p.GeneratedFiles...)
	p.Artifacts = append([]model.ArtifactRule(nil), p.Artifacts...)
	p.RequiredTests = append([]string(nil), p.RequiredTests...)
	return p
}

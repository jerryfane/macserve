// Package profiles validates controller-owned recipes and resolves untrusted
// requests against immutable, exactly pinned recipe snapshots.
package profiles

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"slices"
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
	ownerPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,38}$`)
	shardPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
)

type entry struct {
	profile model.Profile
	digest  string
}

type templateEntry struct {
	template model.Template
	digest   string
}

// Registry owns all recipe storage; its read-only methods are safe concurrently.
// List preserves configuration order. No method exposes the owned storage.
// Profile and template IDs share one namespace.
type Registry struct {
	entries   []entry
	byID      map[string]int
	templates []templateEntry
	byTmplID  map[string]int
}

// New validates and normalizes copies of controller-approved profiles and
// templates. Missing timeouts default to 1800 seconds (2400 for UI tests, 3600
// for scripts), with a 3600-second maximum (7200 for scripts); missing memory
// budgets default to 32768 MiB. It does not probe installed tools.
func New(profiles []model.Profile, templates []model.Template) (*Registry, error) {
	r := &Registry{entries: make([]entry, 0, len(profiles)), byID: make(map[string]int, len(profiles)), byTmplID: make(map[string]int, len(templates))}
	for _, original := range profiles {
		p := cloneProfile(original)
		if err := normalizeProfile(&p); err != nil {
			return nil, fmt.Errorf("profile %q: %w", p.ID, err)
		}
		if _, exists := r.byID[p.ID]; exists {
			return nil, fmt.Errorf("%w: duplicate profile ID %q", ErrInvalid, p.ID)
		}
		digest, err := p.SnapshotDigest()
		if err != nil {
			return nil, fmt.Errorf("%w: profile encoding: %v", ErrInvalid, err)
		}
		r.byID[p.ID] = len(r.entries)
		r.entries = append(r.entries, entry{profile: p, digest: digest})
	}
	for _, original := range templates {
		t := cloneTemplate(original)
		if err := normalizeTemplate(&t); err != nil {
			return nil, fmt.Errorf("template %q: %w", t.ID, err)
		}
		_, profile := r.byID[t.ID]
		if _, exists := r.byTmplID[t.ID]; exists || profile {
			return nil, fmt.Errorf("%w: duplicate profile or template ID %q", ErrInvalid, t.ID)
		}
		digest, err := t.Digest()
		if err != nil {
			return nil, fmt.Errorf("%w: template encoding: %v", ErrInvalid, err)
		}
		r.byTmplID[t.ID] = len(r.templates)
		r.templates = append(r.templates, templateEntry{template: t, digest: digest})
	}
	return r, nil
}

// ForSnapshot is the single-entry registry that re-admits an admitted recipe
// snapshot: its template for a template job, otherwise the profile itself.
func ForSnapshot(p model.Profile) (*Registry, error) {
	if p.Template != nil {
		return New(nil, []model.Template{*p.Template})
	}
	return New([]model.Profile{p}, nil)
}

// Load reads at most 1 MiB of strict JSON shaped as {"profiles":[...]} with an
// optional "templates" array. An explicit empty profiles array disables all
// profiles; missing or null profiles is invalid.
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
		Profiles  []model.Profile  `json:"profiles"`
		Templates []model.Template `json:"templates"`
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
	return New(document.Profiles, document.Templates)
}

// Resolve admits only the configured repository, kind and exact toolchain pins.
// SHA and repository casing are canonicalized, but no client paths, executable
// arguments or environment are accepted. The returned recipe and request are
// independent snapshots, including their nested slices and simulator pointers.
//
// A template ID admits any repository of a template owner that has no
// explicit profile of the same kind: explicit profiles keep precedence.
func (r *Registry) Resolve(request model.Request) (model.Admission, error) {
	if !request.Kind.Known() {
		return model.Admission{}, fmt.Errorf("%w: job kind", ErrUnsupported)
	}
	if !validRepo(request.Repo) || !shaPattern.MatchString(request.SHA) || !idPattern.MatchString(request.Profile) || request.TimeoutSeconds < 0 {
		return model.Admission{}, fmt.Errorf("%w: repository, SHA, profile ID or timeout", ErrInvalid)
	}
	if request.Shard != "" && !shardPattern.MatchString(request.Shard) {
		return model.Admission{}, fmt.Errorf("%w: shard must match %s", ErrInvalid, shardPattern)
	}
	request.Repo = strings.ToLower(request.Repo)
	request.SHA = strings.ToLower(request.SHA)
	index, found := r.byID[request.Profile]
	if !found {
		return r.resolveTemplate(request)
	}
	e := r.entries[index]
	p := e.profile
	if request.Repo != p.Repo || request.Kind != p.Kind || request.Xcode != p.Xcode || !sameSimulator(request.Simulator, p.Simulator) {
		return model.Admission{}, fmt.Errorf("%w: repository, kind or toolchain pins", ErrUnsupported)
	}
	if request.Shard != "" {
		return model.Admission{}, fmt.Errorf("%w: only test and script templates accept a shard", ErrUnsupported)
	}
	if request.Flutter != nil {
		return model.Admission{}, fmt.Errorf("%w: only Flutter templates accept a Flutter version", ErrUnsupported)
	}
	if request.Release != nil {
		return model.Admission{}, fmt.Errorf("%w: only ios_archive templates accept a release", ErrUnsupported)
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

func (r *Registry) resolveTemplate(request model.Request) (model.Admission, error) {
	index, found := r.byTmplID[request.Profile]
	if !found {
		return model.Admission{}, fmt.Errorf("%w: profile", ErrUnsupported)
	}
	e := r.templates[index]
	t := e.template
	owner, _, _ := strings.Cut(request.Repo, "/")
	if !slices.Contains(t.Owners, owner) {
		return model.Admission{}, fmt.Errorf("%w: repository owner is not approved for template", ErrUnsupported)
	}
	if request.Kind != t.Kind || request.Xcode != t.Xcode {
		return model.Admission{}, fmt.Errorf("%w: repository, kind or toolchain pins", ErrUnsupported)
	}
	// Like Xcode, a Flutter template's version must be named exactly.
	if !sameFlutter(request.Flutter, t.Flutter) {
		if t.Flutter == nil {
			return model.Admission{}, fmt.Errorf("%w: only Flutter templates accept a Flutter version", ErrUnsupported)
		}
		return model.Admission{}, fmt.Errorf("%w: Flutter template requires flutter version %s exactly", ErrUnsupported, t.Flutter.Version)
	}
	request.Flutter = cloneFlutterRequest(request.Flutter)
	// An archive's version, and a Flutter archive's Dart defines, are fixed
	// at admission and derive its recipe; no other kind takes a release.
	if t.Kind == model.IOSArchive {
		if request.Release == nil {
			return model.Admission{}, fmt.Errorf("%w: ios_archive templates require a release build_name and build_number", ErrInvalid)
		}
		if err := ValidateRelease(*request.Release, t.Flutter != nil); err != nil {
			return model.Admission{}, err
		}
	} else if request.Release != nil {
		return model.Admission{}, fmt.Errorf("%w: only ios_archive templates accept a release", ErrUnsupported)
	}
	request.Release = cloneRelease(request.Release)
	if !t.Kind.UsesSimulator() {
		if request.Simulator != nil {
			return model.Admission{}, fmt.Errorf("%w: repository, kind or toolchain pins", ErrUnsupported)
		}
		if request.Shard != "" {
			return model.Admission{}, fmt.Errorf("%w: only test and script templates accept a shard", ErrUnsupported)
		}
	} else {
		if request.Shard == "" {
			return model.Admission{}, fmt.Errorf("%w: test and script templates require a shard", ErrInvalid)
		}
		// The device is fixed at admission: an omitted simulator is the
		// template's first pin, any other must be one of its pins.
		if request.Simulator == nil {
			request.Simulator = &t.Simulators[0]
		} else if !slices.Contains(t.Simulators, *request.Simulator) {
			return model.Admission{}, fmt.Errorf("%w: simulator is not pinned by the template", ErrUnsupported)
		}
		request.Simulator = cloneSimulator(request.Simulator)
	}
	for _, explicit := range r.entries {
		if explicit.profile.Repo == request.Repo && explicit.profile.Kind == request.Kind {
			return model.Admission{}, fmt.Errorf("%w: repository has an explicit profile", ErrUnsupported)
		}
	}
	if request.TimeoutSeconds == 0 {
		request.TimeoutSeconds = t.DefaultTimeoutSeconds
	}
	if request.TimeoutSeconds > t.MaxTimeoutSeconds {
		return model.Admission{}, fmt.Errorf("%w: timeout exceeds profile maximum", ErrInvalid)
	}
	snapshot := TemplateSnapshot(t, request.Repo)
	snapshot.Simulator, snapshot.Shard, snapshot.Release = cloneSimulator(request.Simulator), request.Shard, cloneRelease(request.Release)
	return model.Admission{Request: request, Profile: snapshot, ProfileDigest: e.digest}, nil
}

// TemplateSnapshot is the admitted recipe snapshot of a template job for repo:
// the template's identity, pins and budgets with no recipe commands, which the
// worker derives from the repository's .macserve.json. Admission of a test or
// script template job adds the request's simulator and shard, and of an
// ios_archive template job the request's release.
func TemplateSnapshot(t model.Template, repo string) model.Profile {
	snapshot := cloneTemplate(t)
	return model.Profile{ID: t.ID, Version: t.Version, Repo: repo, Kind: t.Kind, Xcode: t.Xcode, DeveloperDir: t.DeveloperDir, DefaultTimeoutSeconds: t.DefaultTimeoutSeconds, MaxTimeoutSeconds: t.MaxTimeoutSeconds, MemoryLimitMiB: t.MemoryLimitMiB, Template: &snapshot}
}

func (r *Registry) List() []model.Profile {
	profiles := make([]model.Profile, len(r.entries))
	for i, e := range r.entries {
		profiles[i] = cloneProfile(e.profile)
	}
	return profiles
}

// Templates lists the configured templates in configuration order.
func (r *Registry) Templates() []model.Template {
	templates := make([]model.Template, len(r.templates))
	for i, e := range r.templates {
		templates[i] = cloneTemplate(e.template)
	}
	return templates
}

// Digests maps every profile and template ID to the digest that qualification,
// health and the readiness guard bind.
func (r *Registry) Digests() map[string]string {
	digests := make(map[string]string, len(r.entries)+len(r.templates))
	for _, e := range r.entries {
		digests[e.profile.ID] = e.digest
	}
	for _, e := range r.templates {
		digests[e.template.ID] = e.digest
	}
	return digests
}

func normalizeTemplate(t *model.Template) error {
	if !idPattern.MatchString(t.ID) || t.Version <= 0 {
		return fmt.Errorf("%w: ID or version", ErrInvalid)
	}
	switch t.Kind {
	case model.Build, model.IOSArchive:
		if len(t.Simulators) != 0 {
			return fmt.Errorf("%w: build and ios_archive templates pin no simulator", ErrInvalid)
		}
	case model.UnitTest, model.SimulatorUITest, model.SimulatorScript:
		if len(t.Simulators) == 0 || len(t.Simulators) > 4 {
			return fmt.Errorf("%w: test and script templates pin one to four simulators", ErrInvalid)
		}
		for i, s := range t.Simulators {
			if !validSimulator(s) || slices.Contains(t.Simulators[:i], s) {
				return fmt.Errorf("%w: exact, unique simulator runtime, build and device type required", ErrInvalid)
			}
		}
	default:
		return fmt.Errorf("%w: templates support only build, unit_test, simulator_ui_test, simulator_script and ios_archive jobs", ErrUnsupported)
	}
	if len(t.Owners) == 0 {
		return fmt.Errorf("%w: at least one owner is required", ErrInvalid)
	}
	for i, owner := range t.Owners {
		if !ownerPattern.MatchString(owner) || slices.Contains(t.Owners[:i], owner) {
			return fmt.Errorf("%w: owners must be unique lowercase GitHub account logins", ErrInvalid)
		}
	}
	if !versionPattern.MatchString(t.Xcode.Version) || !buildPattern.MatchString(t.Xcode.Build) {
		return fmt.Errorf("%w: exact Xcode version and build required", ErrInvalid)
	}
	if !absolutePath(t.DeveloperDir) {
		return fmt.Errorf("%w: developer directory", ErrInvalid)
	}
	if err := normalizeFlutterPin(*t); err != nil {
		return err
	}
	return normalizeBudgets(t.Kind, &t.DefaultTimeoutSeconds, &t.MaxTimeoutSeconds, &t.MemoryLimitMiB)
}

func normalizeProfile(p *model.Profile) error {
	if p.Template != nil || p.Shard != "" || p.Release != nil {
		return fmt.Errorf("%w: configured profiles cannot embed a template, shard or release", ErrInvalid)
	}
	if !idPattern.MatchString(p.ID) || p.Version <= 0 || !validRepo(p.Repo) {
		return fmt.Errorf("%w: ID, version or repository", ErrInvalid)
	}
	p.Repo = strings.ToLower(p.Repo)
	if !p.Kind.Known() {
		return fmt.Errorf("%w: job kind", ErrUnsupported)
	}
	if p.Kind == model.SimulatorScript || p.Kind == model.IOSArchive {
		return fmt.Errorf("%w: %s jobs run only from templates", ErrUnsupported, p.Kind)
	}
	if !versionPattern.MatchString(p.Xcode.Version) || !buildPattern.MatchString(p.Xcode.Build) {
		return fmt.Errorf("%w: exact Xcode version and build required", ErrInvalid)
	}
	if !absolutePath(p.DeveloperDir) || !relativePath(p.WorkDir, true, false) {
		return fmt.Errorf("%w: developer directory or working directory", ErrInvalid)
	}
	if p.Simulator != nil && !validSimulator(*p.Simulator) {
		return fmt.Errorf("%w: exact simulator runtime, build and device type required", ErrInvalid)
	}
	if p.Kind.Tests() && (p.Simulator == nil || len(p.RequiredTests) == 0) {
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
	return normalizeBudgets(p.Kind, &p.DefaultTimeoutSeconds, &p.MaxTimeoutSeconds, &p.MemoryLimitMiB)
}

func normalizeBudgets(kind model.Kind, defaultTimeout, maxTimeout, memory *int) error {
	if *defaultTimeout == 0 {
		*defaultTimeout = 1800
		switch kind {
		case model.SimulatorUITest:
			*defaultTimeout = 2400
		case model.SimulatorScript, model.IOSArchive:
			*defaultTimeout = 3600
		}
	}
	if *maxTimeout == 0 {
		*maxTimeout = kind.MaxTimeoutSeconds()
	}
	if *defaultTimeout < 1 || *maxTimeout < 1 || *maxTimeout > kind.MaxTimeoutSeconds() || *defaultTimeout > *maxTimeout {
		return fmt.Errorf("%w: timeout limits", ErrInvalid)
	}
	if *memory == 0 {
		*memory = 32768
	}
	if *memory < 1 {
		return fmt.Errorf("%w: memory limit", ErrInvalid)
	}
	return nil
}

func validSimulator(s model.Simulator) bool {
	return runtimePattern.MatchString(s.Runtime) && buildPattern.MatchString(s.RuntimeBuild) && devicePattern.MatchString(s.DeviceType)
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
	p.Release = cloneRelease(p.Release)
	if p.Template != nil {
		t := cloneTemplate(*p.Template)
		p.Template = &t
	}
	return p
}

func cloneTemplate(t model.Template) model.Template {
	t.Owners = append([]string(nil), t.Owners...)
	t.Simulators = append([]model.Simulator(nil), t.Simulators...)
	if t.Flutter != nil {
		pin := *t.Flutter
		t.Flutter = &pin
	}
	return t
}

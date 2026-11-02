package profiles_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
)

// installedDigests are the digests the Studio's qualification binds for the
// installed profiles.json (sha256 36ac3a2a…, Xcode 27.1 amendment). Adding
// templates must not change a byte of how such a file loads.
var installedDigests = map[string]string{
	"entmoot-ios-sim-build-v1":  "ea6bea8ec2dd10197914b68f41b0f9a4d89a7b239951af032563f1a1ccedb006",
	"keephair-ios-sim-build-v1": "f0d70dfb8db5daa3ddb2e30649a850bb074ddf14658cbd1aba7cae21ca5e90e3",
}

func TestInstalledProfilesKeepTheirDigests(t *testing.T) {
	data, err := os.ReadFile("testdata/installed-profiles.json")
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != "36ac3a2a11c3b503d25cbcfa8126ca9369e9661ce96b00e3eb61f88e0c6ce084" {
		t.Fatal("fixture is not the installed profiles.json")
	}
	r, err := profiles.Load("testdata/installed-profiles.json")
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Digests(); !maps.Equal(got, installedDigests) {
		t.Fatalf("installed profile digests changed: %v", got)
	}
	if len(r.Templates()) != 0 {
		t.Fatal("a profiles-only file configured templates")
	}
	for _, p := range r.List() {
		raw, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "template") {
			t.Fatalf("profile JSON gained a template field: %s", raw)
		}
		a, err := r.Resolve(model.Request{Repo: p.Repo, SHA: strings.Repeat("a", 40), Kind: p.Kind, Profile: p.ID, Xcode: p.Xcode})
		if err != nil || a.ProfileDigest != installedDigests[p.ID] || a.Profile.Template != nil {
			t.Fatalf("installed profile admission changed: %+v %v", a, err)
		}
	}
}

const buildTemplate = `{"id":"org-ios-sim-build-v1","version":1,"kind":"build","owners":["themartianapp","jerryfane"],"xcode":{"version":"27.1","build":"27A9275"},"developer_dir":"/Applications/Xcode.app/Contents/Developer"}`

func templatesFile(t *testing.T, templates string) *profiles.Registry {
	t.Helper()
	installed, err := os.ReadFile("testdata/installed-profiles.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Profiles json.RawMessage `json:"profiles"`
	}
	if err := json.Unmarshal(installed, &document); err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(t.TempDir(), "profiles.json")
	if err := os.WriteFile(filename, []byte(`{"profiles":`+string(document.Profiles)+`,"templates":[`+templates+`]}`), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := profiles.Load(filename)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestTemplatesLoadStrictlyBesideProfiles(t *testing.T) {
	r := templatesFile(t, buildTemplate)
	templates := r.Templates()
	if len(templates) != 1 {
		t.Fatalf("templates: %+v", templates)
	}
	got := templates[0]
	want := model.Template{ID: "org-ios-sim-build-v1", Version: 1, Kind: model.Build, Owners: []string{"themartianapp", "jerryfane"}, Xcode: model.Xcode{Version: "27.1", Build: "27A9275"}, DeveloperDir: "/Applications/Xcode.app/Contents/Developer", DefaultTimeoutSeconds: 1800, MaxTimeoutSeconds: 3600, MemoryLimitMiB: 32768}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalized template %+v, want %+v", got, want)
	}
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	digests := r.Digests()
	if digests["org-ios-sim-build-v1"] != hex.EncodeToString(sum[:]) {
		t.Fatalf("template digest is not sha256 of its canonical JSON: %v", digests)
	}
	// Profiles beside templates keep the installed digests.
	delete(digests, "org-ios-sim-build-v1")
	if !maps.Equal(digests, installedDigests) {
		t.Fatalf("templates changed profile digests: %v", digests)
	}

	dir := t.TempDir()
	cases := map[string]string{
		"unknown template field":       strings.Replace(buildTemplate, `"version":1`, `"version":1,"run":{"executable":"/bin/sh","args":[]}`, 1),
		"unsupported kind":             strings.Replace(buildTemplate, `"kind":"build"`, `"kind":"unit_test"`, 1),
		"no owners":                    strings.Replace(buildTemplate, `["themartianapp","jerryfane"]`, `[]`, 1),
		"uppercase owner":              strings.Replace(buildTemplate, `"jerryfane"`, `"JerryFane"`, 1),
		"repository as owner":          strings.Replace(buildTemplate, `"jerryfane"`, `"jerryfane/app"`, 1),
		"duplicate owner":              strings.Replace(buildTemplate, `"jerryfane"`, `"themartianapp"`, 1),
		"inexact xcode":                strings.Replace(buildTemplate, `"27A9275"`, `"latest"`, 1),
		"relative developer dir":       strings.Replace(buildTemplate, `"/Applications/Xcode.app/Contents/Developer"`, `"Xcode.app"`, 1),
		"timeout above cap":            strings.Replace(buildTemplate, `"version":1`, `"version":1,"max_timeout_seconds":7200`, 1),
		"ID shared with a profile":     strings.Replace(buildTemplate, `"org-ios-sim-build-v1"`, `"keephair-ios-sim-build-v1"`, 1),
		"duplicate template":           buildTemplate + "," + buildTemplate,
		"profile embedding a template": "",
	}
	for name, templates := range cases {
		t.Run(name, func(t *testing.T) {
			document := `{"profiles":[],"templates":[` + templates + `]}`
			if name == "ID shared with a profile" {
				installed, _ := os.ReadFile("testdata/installed-profiles.json")
				document = strings.Replace(string(installed), `"profiles": [`, `"templates":[`+templates+`],"profiles": [`, 1)
			}
			if templates == "" {
				document = `{"profiles":[{"id":"p","version":1,"repo":"a/b","kind":"build","xcode":{"version":"27.1","build":"27A9275"},"developer_dir":"/Applications/Xcode.app","work_dir":".","run":{"executable":"/usr/bin/true","args":[]},"template":` + buildTemplate + `}]}`
			}
			filename := filepath.Join(dir, "profiles.json")
			if err := os.WriteFile(filename, []byte(document), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := profiles.Load(filename); err == nil {
				t.Fatal("invalid template configuration loaded")
			}
		})
	}
}

func templateRequest(repo string) model.Request {
	return model.Request{Repo: repo, SHA: strings.Repeat("Ab", 20), Kind: model.Build, Profile: "org-ios-sim-build-v1", Xcode: model.Xcode{Version: "27.1", Build: "27A9275"}}
}

func TestTemplateAdmissionByOwnerKindAndPins(t *testing.T) {
	r := templatesFile(t, buildTemplate)
	a, err := r.Resolve(templateRequest("TheMartianApp/New-App"))
	if err != nil {
		t.Fatal(err)
	}
	template := r.Templates()[0]
	if a.Request.Repo != "themartianapp/new-app" || a.Request.SHA != strings.Repeat("ab", 20) || a.Request.TimeoutSeconds != 1800 {
		t.Fatalf("request not canonical: %+v", a.Request)
	}
	if want := profiles.TemplateSnapshot(template, "themartianapp/new-app"); !reflect.DeepEqual(a.Profile, want) || a.Profile.Run.Executable != "" || len(a.Profile.Prepare) != 0 {
		t.Fatalf("snapshot %+v, want %+v", a.Profile, want)
	}
	if a.ProfileDigest != r.Digests()[template.ID] {
		t.Fatal("template admission does not bind the template digest")
	}
	if digest, err := a.Profile.SnapshotDigest(); err != nil || digest != a.ProfileDigest {
		t.Fatalf("snapshot digest %s %v", digest, err)
	}
	if _, err := r.Resolve(templateRequest("jerryfane/tool")); err != nil {
		t.Fatalf("second owner refused: %v", err)
	}
	a.Profile.Template.Owners[0] = "mutated"
	if r.Templates()[0].Owners[0] != "themartianapp" {
		t.Fatal("admission snapshot aliases registry storage")
	}

	refused := map[string]struct {
		mutate func(*model.Request)
		want   error
	}{
		"unknown owner":     {func(q *model.Request) { q.Repo = "someone-else/app" }, profiles.ErrUnsupported},
		"owner prefix":      {func(q *model.Request) { q.Repo = "themartianapp-evil/app" }, profiles.ErrUnsupported},
		"kind":              {func(q *model.Request) { q.Kind = model.UnitTest }, profiles.ErrUnsupported},
		"xcode version":     {func(q *model.Request) { q.Xcode.Version = "27.0" }, profiles.ErrUnsupported},
		"xcode build":       {func(q *model.Request) { q.Xcode.Build = "27A266a" }, profiles.ErrUnsupported},
		"simulator":         {func(q *model.Request) { q.Simulator = &model.Simulator{} }, profiles.ErrUnsupported},
		"timeout":           {func(q *model.Request) { q.TimeoutSeconds = 3601 }, profiles.ErrInvalid},
		"unknown template":  {func(q *model.Request) { q.Profile = "org-ios-sim-build-v2" }, profiles.ErrUnsupported},
		"explicit profile":  {func(q *model.Request) { q.Repo = "themartianapp/keephair" }, profiles.ErrUnsupported},
		"explicit, cased":   {func(q *model.Request) { q.Repo = "TheMartianApp/Entmoot-App" }, profiles.ErrUnsupported},
		"invalid repo name": {func(q *model.Request) { q.Repo = "themartianapp/.." }, profiles.ErrInvalid},
	}
	for name, tc := range refused {
		t.Run(name, func(t *testing.T) {
			q := templateRequest("themartianapp/new-app")
			tc.mutate(&q)
			if _, err := r.Resolve(q); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
	// Explicit profiles keep their exact admission beside templates.
	plain, err := profiles.Load("testdata/installed-profiles.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range plain.List() {
		q := model.Request{Repo: p.Repo, SHA: strings.Repeat("a", 40), Kind: p.Kind, Profile: p.ID, Xcode: p.Xcode}
		withTemplates, err1 := r.Resolve(q)
		without, err2 := plain.Resolve(q)
		if err1 != nil || err2 != nil || !reflect.DeepEqual(withTemplates, without) {
			t.Fatalf("explicit profile admission changed: %v %v", err1, err2)
		}
	}
}

func TestForSnapshotReadmitsTemplateJobs(t *testing.T) {
	r := templatesFile(t, buildTemplate)
	a, err := r.Resolve(templateRequest("jerryfane/tool"))
	if err != nil {
		t.Fatal(err)
	}
	single, err := profiles.ForSnapshot(a.Profile)
	if err != nil {
		t.Fatal(err)
	}
	again, err := single.Resolve(a.Request)
	if err != nil || !reflect.DeepEqual(again, a) {
		t.Fatalf("snapshot does not re-admit identically: %+v %v", again, err)
	}
}

func TestParseRepoConfig(t *testing.T) {
	valid := map[string]model.RepoConfig{
		`{"version":1,"work_dir":"ios","project":"Entmoot.xcodeproj","scheme":"Entmoot","xcodegen":true,"resolve_packages":true}`: {Version: 1, WorkDir: "ios", Project: "Entmoot.xcodeproj", Scheme: "Entmoot", XcodeGen: true, ResolvePackages: true},
		`{"version":1,"work_dir":".","workspace":"My App.xcworkspace","scheme":"My App-Dev_1.0"}`:                                 {Version: 1, WorkDir: ".", Workspace: "My App.xcworkspace", Scheme: "My App-Dev_1.0"},
		" \n{\"scheme\":\"A\",\"project\":\"A.xcodeproj\",\"work_dir\":\"apps/ios\",\"version\":1,\"xcodegen\":false}\n":          {Version: 1, WorkDir: "apps/ios", Project: "A.xcodeproj", Scheme: "A"},
	}
	for data, want := range valid {
		got, err := profiles.ParseRepoConfig([]byte(data))
		if err != nil || got != want {
			t.Fatalf("%s: got %+v %v", data, got, err)
		}
	}
	base := `{"version":1,"work_dir":"ios","project":"App.xcodeproj","scheme":"App"}`
	invalid := map[string]string{
		"empty":                ``,
		"not an object":        `[]`,
		"null":                 `null`,
		"both":                 `{"version":1,"work_dir":"ios","project":"App.xcodeproj","workspace":"App.xcworkspace","scheme":"App"}`,
		"neither":              `{"version":1,"work_dir":"ios","scheme":"App"}`,
		"missing scheme":       `{"version":1,"work_dir":"ios","project":"App.xcodeproj"}`,
		"missing work_dir":     `{"version":1,"project":"App.xcodeproj","scheme":"App"}`,
		"missing version":      `{"work_dir":"ios","project":"App.xcodeproj","scheme":"App"}`,
		"version 2":            strings.Replace(base, `"version":1`, `"version":2`, 1),
		"unknown field":        strings.Replace(base, `"scheme"`, `"configuration":"Release","scheme"`, 1),
		"case-folded field":    strings.Replace(base, `"scheme"`, `"Scheme"`, 1),
		"duplicate field":      strings.Replace(base, `"scheme":"App"`, `"scheme":"App","scheme":"Other"`, 1),
		"null field":           strings.Replace(base, `"version":1`, `"version":1,"xcodegen":null`, 1),
		"trailing object":      base + `{}`,
		"trailing garbage":     base + ` x`,
		"project slash":        strings.Replace(base, `App.xcodeproj`, `sub/App.xcodeproj`, 1),
		"project dotdot":       strings.Replace(base, `App.xcodeproj`, `../App.xcodeproj`, 1),
		"project absolute":     strings.Replace(base, `App.xcodeproj`, `/tmp/App.xcodeproj`, 1),
		"project dollar":       strings.Replace(base, `App.xcodeproj`, `${CHECKOUT}.xcodeproj`, 1),
		"project wrong suffix": strings.Replace(base, `App.xcodeproj`, `App.xcworkspace`, 1),
		"project leading dash": strings.Replace(base, `App.xcodeproj`, `-App.xcodeproj`, 1),
		"project leading dot":  strings.Replace(base, `App.xcodeproj`, `.xcodeproj`, 1),
		"workspace slash":      `{"version":1,"work_dir":"ios","workspace":"a/App.xcworkspace","scheme":"App"}`,
		"scheme flag":          strings.Replace(base, `"scheme":"App"`, `"scheme":"-allowProvisioningUpdates"`, 1),
		"scheme setting":       strings.Replace(base, `"scheme":"App"`, `"scheme":"CODE_SIGNING_ALLOWED=YES"`, 1),
		"scheme dollar":        strings.Replace(base, `"scheme":"App"`, `"scheme":"App${JOB_ID}"`, 1),
		"scheme too long":      strings.Replace(base, `"scheme":"App"`, `"scheme":"`+strings.Repeat("a", 129)+`"`, 1),
		"work_dir dotdot":      strings.Replace(base, `"work_dir":"ios"`, `"work_dir":"ios/../.."`, 1),
		"work_dir absolute":    strings.Replace(base, `"work_dir":"ios"`, `"work_dir":"/Users"`, 1),
		"work_dir dollar":      strings.Replace(base, `"work_dir":"ios"`, `"work_dir":"${HOME}"`, 1),
		"work_dir glob":        strings.Replace(base, `"work_dir":"ios"`, `"work_dir":"i*"`, 1),
		"work_dir backslash":   strings.Replace(base, `"work_dir":"ios"`, `"work_dir":"ios\\\\x"`, 1),
		"work_dir empty":       strings.Replace(base, `"work_dir":"ios"`, `"work_dir":""`, 1),
		"string boolean":       strings.Replace(base, `"version":1`, `"version":1,"xcodegen":"true"`, 1),
		"oversized":            base + strings.Repeat(" ", profiles.MaxRepoConfigBytes),
	}
	for name, data := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := profiles.ParseRepoConfig([]byte(data)); !errors.Is(err, profiles.ErrRepoConfig) {
				t.Fatalf("got %v, want a .macserve.json refusal", err)
			}
		})
	}
	// Exactly MaxRepoConfigBytes, including whitespace, is accepted.
	exact := base + strings.Repeat(" ", profiles.MaxRepoConfigBytes-len(base))
	if _, err := profiles.ParseRepoConfig([]byte(exact)); err != nil {
		t.Fatal(err)
	}
}

func TestDeriveFixedArgv(t *testing.T) {
	r := templatesFile(t, buildTemplate)
	a, err := r.Resolve(templateRequest("themartianapp/new-app"))
	if err != nil {
		t.Fatal(err)
	}
	build := []string{"-configuration", "Debug", "-sdk", "iphonesimulator", "-destination", "generic/platform=iOS Simulator", "-derivedDataPath", "${DERIVED_DATA}", "CODE_SIGNING_ALLOWED=NO", "build"}
	xcodegen := model.Command{Executable: "/Library/macserve/tools/xcodegen", Args: []string{"generate", "--spec", "project.yml"}}
	cases := []struct {
		name    string
		config  model.RepoConfig
		prepare []model.Command
		run     model.Command
	}{
		{"project", model.RepoConfig{Version: 1, WorkDir: ".", Project: "App.xcodeproj", Scheme: "App"}, nil,
			model.Command{Executable: "/usr/bin/xcrun", Args: append([]string{"xcodebuild", "-project", "App.xcodeproj", "-scheme", "App"}, build...)}},
		{"workspace", model.RepoConfig{Version: 1, WorkDir: "apps/ios", Workspace: "My App.xcworkspace", Scheme: "My App"}, nil,
			model.Command{Executable: "/usr/bin/xcrun", Args: append([]string{"xcodebuild", "-workspace", "My App.xcworkspace", "-scheme", "My App"}, build...)}},
		{"project with xcodegen", model.RepoConfig{Version: 1, WorkDir: "ios", Project: "KeepHair.xcodeproj", Scheme: "KeepHair", XcodeGen: true}, []model.Command{xcodegen},
			model.Command{Executable: "/usr/bin/xcrun", Args: append([]string{"xcodebuild", "-project", "KeepHair.xcodeproj", "-scheme", "KeepHair"}, build...)}},
		{"project with both steps", model.RepoConfig{Version: 1, WorkDir: "ios", Project: "Entmoot.xcodeproj", Scheme: "Entmoot", XcodeGen: true, ResolvePackages: true},
			[]model.Command{xcodegen, {Executable: "/usr/bin/xcrun", Args: []string{"xcodebuild", "-project", "Entmoot.xcodeproj", "-scheme", "Entmoot", "-resolvePackageDependencies"}}},
			model.Command{Executable: "/usr/bin/xcrun", Args: append([]string{"xcodebuild", "-project", "Entmoot.xcodeproj", "-scheme", "Entmoot"}, build...)}},
		{"workspace with package resolution", model.RepoConfig{Version: 1, WorkDir: ".", Workspace: "W.xcworkspace", Scheme: "S", ResolvePackages: true},
			[]model.Command{{Executable: "/usr/bin/xcrun", Args: []string{"xcodebuild", "-workspace", "W.xcworkspace", "-scheme", "S", "-resolvePackageDependencies"}}},
			model.Command{Executable: "/usr/bin/xcrun", Args: append([]string{"xcodebuild", "-workspace", "W.xcworkspace", "-scheme", "S"}, build...)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			derived, err := profiles.Derive(a.Profile, tc.config)
			if err != nil {
				t.Fatal(err)
			}
			if derived.WorkDir != tc.config.WorkDir || !reflect.DeepEqual(derived.Prepare, tc.prepare) || !reflect.DeepEqual(derived.Run, tc.run) {
				t.Fatalf("derived %q %+v %+v", derived.WorkDir, derived.Prepare, derived.Run)
			}
			// Identity, pins, budgets and the template binding stay the snapshot's.
			derived.WorkDir, derived.Prepare, derived.Run = "", nil, model.Command{}
			if !reflect.DeepEqual(derived, a.Profile) {
				t.Fatalf("derivation changed the snapshot: %+v", derived)
			}
		})
	}
	// The installed entmoot recipe is exactly the template derivation for the
	// equivalent .macserve.json: same shape as the approved per-repo profiles.
	installed, err := profiles.Load("testdata/installed-profiles.json")
	if err != nil {
		t.Fatal(err)
	}
	entmoot := installed.List()[0]
	derived, err := profiles.Derive(a.Profile, model.RepoConfig{Version: 1, WorkDir: "ios", Project: "Entmoot.xcodeproj", Scheme: "Entmoot", XcodeGen: true, ResolvePackages: true})
	if err != nil || derived.WorkDir != entmoot.WorkDir || !reflect.DeepEqual(derived.Prepare, entmoot.Prepare) || !reflect.DeepEqual(derived.Run, entmoot.Run) {
		t.Fatalf("derivation differs from the installed entmoot recipe: %+v %v", derived, err)
	}
	if _, err := profiles.Derive(entmoot, model.RepoConfig{Version: 1, WorkDir: ".", Project: "A.xcodeproj", Scheme: "A"}); !errors.Is(err, profiles.ErrInvalid) {
		t.Fatalf("derived a recipe for a profile job: %v", err)
	}
	if _, err := profiles.Derive(a.Profile, model.RepoConfig{Version: 1, WorkDir: ".", Project: "../A.xcodeproj", Scheme: "A"}); !errors.Is(err, profiles.ErrRepoConfig) {
		t.Fatalf("derived from an invalid configuration: %v", err)
	}
}

// Health, the readiness guard, maintenance and qualification all bind
// Registry.Digests(); any template change must change its digest there.
func TestTemplateChangeChangesQualifiedDigest(t *testing.T) {
	base := templatesFile(t, buildTemplate).Digests()
	for name, changed := range map[string]string{
		"owners":  strings.Replace(buildTemplate, `,"jerryfane"`, ``, 1),
		"xcode":   strings.Replace(buildTemplate, `"27A9275"`, `"27A9276"`, 1),
		"version": strings.Replace(buildTemplate, `"version":1`, `"version":2`, 1),
		"budget":  strings.Replace(buildTemplate, `"version":1`, `"version":1,"memory_limit_mib":16384`, 1),
		"devdir":  strings.Replace(buildTemplate, `/Applications/Xcode.app`, `/Applications/Xcode-27.app`, 1),
	} {
		digests := templatesFile(t, changed).Digests()
		if digests["org-ios-sim-build-v1"] == base["org-ios-sim-build-v1"] {
			t.Fatalf("%s change kept the qualified digest", name)
		}
		delete(digests, "org-ios-sim-build-v1")
		if !maps.Equal(digests, installedDigests) {
			t.Fatalf("%s change moved profile digests", name)
		}
	}
}

package profiles_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
)

// Like the test-template tests, these reach the script fields (kind, shard,
// script section, recipe) through their JSON spelling.

// scriptTemplate leaves its budgets to the kind's defaults.
const scriptTemplate = `{"id":"org-ios-sim-script-v1","version":1,"kind":"simulator_script","owners":["jerryfane","themartianapp"],"xcode":{"version":"27.1","build":"27A9275"},"developer_dir":"/Applications/Xcode.app/Contents/Developer",` +
	`"simulators":[{"runtime":"com.apple.CoreSimulator.SimRuntime.iOS-27-1","runtime_build":"24B100","device_type":"com.apple.CoreSimulator.SimDeviceType.iPhone-Duo"},{"runtime":"com.apple.CoreSimulator.SimRuntime.iOS-27-0","runtime_build":"24A434","device_type":"com.apple.CoreSimulator.SimDeviceType.iPhone-18-Pro"}],"memory_limit_mib":32768}`

var duo = model.Simulator{Runtime: "com.apple.CoreSimulator.SimRuntime.iOS-27-1", RuntimeBuild: "24B100", DeviceType: "com.apple.CoreSimulator.SimDeviceType.iPhone-Duo"}

const duoConfig = `{"version":1,"work_dir":".","project":"Herdr.xcodeproj","scheme":"Herdr","xcodegen":true,"resolve_packages":true,"script":{"shards":{"duo-screenshots":{"run":"Tools/ci/duo-screenshots.sh"}}}}`

func scriptRequest(t *testing.T, shard string) model.Request {
	return decode[model.Request](t, `{"repo":"themartianapp/herdrup","sha":"`+strings.Repeat("ab", 20)+`","kind":"simulator_script","profile":"org-ios-sim-script-v1","xcode":{"version":"27.1","build":"27A9275"},"shard":"`+shard+`"}`)
}

func TestNormalizeScriptTemplatePinsAndBudgets(t *testing.T) {
	r := templatesFile(t, buildTemplate+","+uiTemplate+","+scriptTemplate)
	got := r.Templates()[2]
	if got.Kind != model.SimulatorScript || len(got.Simulators) != 2 || got.DefaultTimeoutSeconds != 3600 || got.MaxTimeoutSeconds != 7200 {
		t.Fatalf("script template: %+v", got)
	}
	// The other kinds keep their defaults and 3600-second cap.
	ui := r.Templates()[1]
	if ui.MaxTimeoutSeconds != 3600 {
		t.Fatalf("UI template budget changed: %+v", ui)
	}
	defaults, err := loadTemplates(strings.Replace(uiTemplate, `"default_timeout_seconds":2400,"max_timeout_seconds":3600,`, ``, 1))
	if err != nil || defaults.Templates()[0].DefaultTimeoutSeconds != 2400 || defaults.Templates()[0].MaxTimeoutSeconds != 3600 {
		t.Fatalf("UI template defaults: %+v %v", defaults, err)
	}
	if _, err := loadTemplates(strings.Replace(scriptTemplate, `"memory_limit_mib"`, `"max_timeout_seconds":7200,"memory_limit_mib"`, 1)); err != nil {
		t.Fatalf("7200-second script maximum refused: %v", err)
	}
	pin := pinJSON(duo)
	invalid := map[string]string{
		"no simulators":           withScriptSimulators(``),
		"empty simulators":        withScriptSimulators(`"simulators":[],`),
		"five simulators":         withScriptSimulators(`"simulators":[` + strings.Repeat(pin+",", 4) + strings.Replace(pin, "Duo", "Duo-2", 1) + `],`),
		"duplicate simulator":     withScriptSimulators(`"simulators":[` + pin + `,` + pin + `],`),
		"timeout above 7200":      strings.Replace(scriptTemplate, `"memory_limit_mib"`, `"max_timeout_seconds":7201,"memory_limit_mib"`, 1),
		"default above maximum":   strings.Replace(scriptTemplate, `"memory_limit_mib"`, `"default_timeout_seconds":5000,"max_timeout_seconds":4000,"memory_limit_mib"`, 1),
		"UI timeout above 3600":   strings.Replace(uiTemplate, `"max_timeout_seconds":3600`, `"max_timeout_seconds":7200`, 1),
		"unknown script spelling": strings.Replace(scriptTemplate, `"simulator_script"`, `"script"`, 1),
	}
	for name, template := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := loadTemplates(template); err == nil {
				t.Fatalf("invalid template loaded: %s", template)
			}
		})
	}
}

func withScriptSimulators(member string) string {
	start, end := strings.Index(scriptTemplate, `"simulators"`), strings.Index(scriptTemplate, `"memory_limit_mib"`)
	return scriptTemplate[:start] + member + scriptTemplate[end:]
}

func TestExplicitProfilesCannotBeScriptJobs(t *testing.T) {
	installed, err := profiles.Load("testdata/installed-profiles.json")
	if err != nil {
		t.Fatal(err)
	}
	p := installed.List()[0]
	p.Kind, p.Simulator = model.SimulatorScript, &duo
	if _, err := profiles.New([]model.Profile{p}, nil); !errors.Is(err, profiles.ErrUnsupported) {
		t.Fatalf("explicit script profile: %v", err)
	}
}

func TestResolveScriptTemplateRequiresShardAndDefaultsSimulator(t *testing.T) {
	r := templatesFile(t, buildTemplate+","+scriptTemplate)
	a, err := r.Resolve(scriptRequest(t, "duo-screenshots"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Request.Simulator == nil || *a.Request.Simulator != duo || member(t, a.Request, "shard") != `"duo-screenshots"` || a.Request.TimeoutSeconds != 3600 {
		t.Fatalf("request not normalized: %+v", a.Request)
	}
	if a.Profile.Simulator == nil || *a.Profile.Simulator != duo || member(t, a.Profile, "shard") != `"duo-screenshots"` || member(t, a.Profile, "kind") != `"simulator_script"` || a.ProfileDigest != r.Digests()[a.Profile.ID] {
		t.Fatalf("snapshot: %+v", a.Profile)
	}
	single, err := profiles.ForSnapshot(a.Profile)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := single.Resolve(a.Request); err != nil || !reflect.DeepEqual(again, a) {
		t.Fatalf("snapshot does not re-admit identically: %+v %v", again, err)
	}
	// The kind's 7200-second maximum admits; one second more does not.
	long := scriptRequest(t, "duo-screenshots")
	long.TimeoutSeconds = 7200
	if b, err := r.Resolve(long); err != nil || b.Request.TimeoutSeconds != 7200 {
		t.Fatalf("7200-second script job: %+v %v", b.Request, err)
	}
	long.TimeoutSeconds = 7201
	if _, err := r.Resolve(long); !errors.Is(err, profiles.ErrInvalid) {
		t.Fatalf("timeout above the script maximum: %v", err)
	}
	unlisted := duo
	unlisted.RuntimeBuild = "24B101"
	refused := map[string]struct {
		request model.Request
		want    error
	}{
		"missing shard":      {scriptRequest(t, ""), profiles.ErrInvalid},
		"bad shard":          {scriptRequest(t, "Duo"), profiles.ErrInvalid},
		"unlisted simulator": {edit(t, scriptRequest(t, "duo-screenshots"), func(m map[string]any) { m["simulator"] = unlisted }), profiles.ErrUnsupported},
		"wrong kind":         {edit(t, scriptRequest(t, "duo-screenshots"), func(m map[string]any) { m["kind"] = "simulator_ui_test" }), profiles.ErrUnsupported},
		"kind on build":      {edit(t, templateRequest("themartianapp/herdrup"), func(m map[string]any) { m["kind"] = "simulator_script" }), profiles.ErrUnsupported},
		"unknown kind":       {edit(t, scriptRequest(t, "duo-screenshots"), func(m map[string]any) { m["kind"] = "script" }), profiles.ErrUnsupported},
	}
	for name, tc := range refused {
		t.Run(name, func(t *testing.T) {
			if _, err := r.Resolve(tc.request); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestParseRepoConfigScriptGrammar(t *testing.T) {
	got := parseConfig(t, duoConfig)
	if member(t, got, "script") != `{"shards":{"duo-screenshots":{"run":"Tools/ci/duo-screenshots.sh"}}}` {
		t.Fatalf("script section: %s", member(t, got, "script"))
	}
	// A configuration without a script section keeps its JSON shape.
	if member(t, parseConfig(t, herdrupConfig), "script") != "" {
		t.Fatal("script section appeared in a test configuration")
	}
	section := func(script string) string {
		return `{"version":1,"work_dir":".","project":"A.xcodeproj","scheme":"A","script":` + script + `}`
	}
	run := func(path string) string {
		return section(`{"shards":{"a":{"run":"` + path + `"}}}`)
	}
	parseConfig(t, run("run.sh"))
	parseConfig(t, run("a-b/c_d/e.f.sh"))
	many := make([]string, 17)
	for i := range many {
		many[i] = `"s` + string(rune('a'+i)) + `":{"run":"x.sh"}`
	}
	refused := map[string]string{
		"absolute run":           run("/bin/run.sh"),
		"parent component":       run("../run.sh"),
		"inner parent component": run("a/../../run.sh"),
		"empty run":              run(""),
		"dot run":                run("."),
		"dot component":          run("./run.sh"),
		"inner dot component":    run("a/./run.sh"),
		"empty component":        run("a//run.sh"),
		"trailing slash":         run("tools/"),
		"dollar":                 run("$HOME/run.sh"),
		"glob":                   run("*.sh"),
		"backslash":              run(`a\\run.sh`),
		"NUL":                    run(`a\u0000.sh`),
		"too long":               run(strings.Repeat("a", 1025)),
		"no shards":              section(`{"shards":{}}`),
		"null shards":            section(`{"shards":null}`),
		"seventeen shards":       section(`{"shards":{` + strings.Join(many, ",") + `}}`),
		"bad shard name":         section(`{"shards":{"Duo":{"run":"x.sh"}}}`),
		"missing run":            section(`{"shards":{"a":{}}}`),
		"null run":               section(`{"shards":{"a":{"run":null}}}`),
		"run array":              section(`{"shards":{"a":{"run":["x.sh"]}}}`),
		"case-folded run":        section(`{"shards":{"a":{"Run":"x.sh"}}}`),
		"case-folded shards":     section(`{"Shards":{"a":{"run":"x.sh"}}}`),
		"unknown shard field":    section(`{"shards":{"a":{"run":"x.sh","args":["-x"]}}}`),
		"duplicate run":          section(`{"shards":{"a":{"run":"x.sh","run":"y.sh"}}}`),
		"duplicate shard":        section(`{"shards":{"a":{"run":"x.sh"},"a":{"run":"y.sh"}}}`),
		"selector list":          section(`{"shards":{"a":["T/C"]}}`),
		"null section":           section(`null`),
	}
	for name, data := range refused {
		t.Run(name, func(t *testing.T) {
			if _, err := profiles.ParseRepoConfig([]byte(data)); !errors.Is(err, profiles.ErrRepoConfig) {
				t.Fatalf("got %v for %s", err, data)
			}
		})
	}
}

func TestDeriveScriptArgvGolden(t *testing.T) {
	r := templatesFile(t, buildTemplate+","+scriptTemplate)
	a, err := r.Resolve(scriptRequest(t, "duo-screenshots"))
	if err != nil {
		t.Fatal(err)
	}
	derived, err := profiles.Derive(a.Profile, parseConfig(t, duoConfig))
	if err != nil {
		t.Fatal(err)
	}
	wantPrepare := []model.Command{
		{Executable: "/Library/macserve/tools/xcodegen", Args: []string{"generate", "--spec", "project.yml"}},
		{Executable: "/usr/bin/xcrun", Args: []string{"xcodebuild", "-project", "Herdr.xcodeproj", "-scheme", "Herdr", "-resolvePackageDependencies"}},
		{Executable: "/usr/bin/xcrun", Args: []string{"xcodebuild", "-project", "Herdr.xcodeproj", "-scheme", "Herdr", "-configuration", "Debug", "-sdk", "iphonesimulator", "-destination", "id=${SIMULATOR_ID}", "-derivedDataPath", "${DERIVED_DATA}", "build"}},
	}
	wantRun := model.Command{Executable: "/bin/bash", Args: []string{"${CHECKOUT}/Tools/ci/duo-screenshots.sh"}}
	if derived.WorkDir != "." || !reflect.DeepEqual(derived.Prepare, wantPrepare) || !reflect.DeepEqual(derived.Run, wantRun) || len(derived.RequiredTests) != 0 || !reflect.DeepEqual(derived.Artifacts, []model.ArtifactRule{{Path: "output", Required: true}}) {
		t.Fatalf("derived %q\nprepare %q\nrun %q\nrequired %q", derived.WorkDir, derived.Prepare, derived.Run, derived.RequiredTests)
	}
	derived.WorkDir, derived.Prepare, derived.Run, derived.Artifacts = "", nil, model.Command{}, nil
	if !reflect.DeepEqual(derived, a.Profile) {
		t.Fatalf("derivation changed the snapshot: %+v", derived)
	}
	// The script path is resolved against work_dir; without the optional
	// steps prepare is the simulator build alone.
	minimal := parseConfig(t, `{"version":1,"work_dir":"ios/app","workspace":"W.xcworkspace","scheme":"S","script":{"shards":{"duo-screenshots":{"run":"ci/shots.sh"}}}}`)
	got, err := profiles.Derive(a.Profile, minimal)
	if err != nil || got.WorkDir != "ios/app" || !reflect.DeepEqual(got.Run, model.Command{Executable: "/bin/bash", Args: []string{"${CHECKOUT}/ios/app/ci/shots.sh"}}) ||
		!reflect.DeepEqual(got.Prepare, []model.Command{{Executable: "/usr/bin/xcrun", Args: []string{"xcodebuild", "-workspace", "W.xcworkspace", "-scheme", "S", "-configuration", "Debug", "-sdk", "iphonesimulator", "-destination", "id=${SIMULATOR_ID}", "-derivedDataPath", "${DERIVED_DATA}", "build"}}}) {
		t.Fatalf("minimal derivation %+v %v", got, err)
	}
	for name, c := range map[string]string{
		"no script section":    `{"version":1,"work_dir":".","project":"A.xcodeproj","scheme":"A"}`,
		"test sections only":   herdrupConfig,
		"shard not configured": `{"version":1,"work_dir":".","project":"A.xcodeproj","scheme":"A","script":{"shards":{"other":{"run":"x.sh"}}}}`,
		"unparsed bad path":    `{"version":1,"work_dir":".","project":"A.xcodeproj","scheme":"A","script":{"shards":{"duo-screenshots":{"run":"../x.sh"}}}}`,
	} {
		if _, err := profiles.Derive(a.Profile, decode[model.RepoConfig](t, c)); !errors.Is(err, profiles.ErrRepoConfig) {
			t.Fatalf("%s: got %v, want a .macserve.json refusal", name, err)
		}
	}
	for name, snapshot := range map[string]model.Profile{
		"no shard":     edit(t, a.Profile, func(m map[string]any) { delete(m, "shard") }),
		"no simulator": edit(t, a.Profile, func(m map[string]any) { delete(m, "simulator") }),
	} {
		if _, err := profiles.Derive(snapshot, minimal); !errors.Is(err, profiles.ErrInvalid) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// Build derivation ignores the script section.
	b, err := r.Resolve(templateRequest("themartianapp/herdrup"))
	if err != nil {
		t.Fatal(err)
	}
	withScript, err1 := profiles.Derive(b.Profile, parseConfig(t, duoConfig))
	without, err2 := profiles.Derive(b.Profile, edit(t, parseConfig(t, duoConfig), func(m map[string]any) { delete(m, "script") }))
	if err1 != nil || err2 != nil || !reflect.DeepEqual(withScript, without) {
		t.Fatalf("build derivation saw the script section: %+v %v %v", withScript, err1, err2)
	}
}

func TestEffectiveScriptRecipe(t *testing.T) {
	config := parseConfig(t, duoConfig)
	r := templatesFile(t, scriptTemplate)
	a, err := r.Resolve(scriptRequest(t, "duo-screenshots"))
	if err != nil {
		t.Fatal(err)
	}
	derived, err := profiles.Derive(a.Profile, config)
	if err != nil {
		t.Fatal(err)
	}
	recipe := map[string]any{"config_sha256": strings.Repeat("0", 64), "config": config, "work_dir": derived.WorkDir, "prepare": derived.Prepare, "run": derived.Run, "shard": "duo-screenshots"}
	reported := func(change func(map[string]any)) *model.RepoRecipe {
		r := edit(t, model.RepoRecipe{}, func(m map[string]any) {
			for k, v := range recipe {
				m[k] = v
			}
			if change != nil {
				change(m)
			}
		})
		return &r
	}
	effective, err := profiles.Effective(a.Profile, reported(nil))
	if err != nil || !reflect.DeepEqual(effective, derived) || len(effective.RequiredTests) != 0 {
		t.Fatalf("effective %+v %v", effective, err)
	}
	other := parseConfig(t, strings.Replace(duoConfig, "duo-screenshots.sh", "other.sh", 1))
	for name, change := range map[string]func(map[string]any){
		"other script": func(m map[string]any) {
			m["run"] = model.Command{Executable: "/bin/bash", Args: []string{"${CHECKOUT}/other.sh"}}
		},
		"other shell":          func(m map[string]any) { m["run"] = model.Command{Executable: "/bin/zsh", Args: derived.Run.Args} },
		"build cut":            func(m map[string]any) { m["prepare"] = derived.Prepare[:len(derived.Prepare)-1] },
		"required tests":       func(m map[string]any) { m["required_tests"] = []string{"T/C"} },
		"no shard":             func(m map[string]any) { delete(m, "shard") },
		"config script edited": func(m map[string]any) { m["config"] = other },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := profiles.Effective(a.Profile, reported(change)); err == nil {
				t.Fatal("mismatched recipe accepted")
			}
		})
	}
}

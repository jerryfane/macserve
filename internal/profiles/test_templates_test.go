package profiles_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
)

// These tests reach the test-template fields (shard, simulators, ui_test,
// unit_test, the recipe's shard and required tests) only through their JSON
// spelling, the form clients, profiles.json and .macserve.json use.

var (
	iPhone = model.Simulator{Runtime: "com.apple.CoreSimulator.SimRuntime.iOS-27-0", RuntimeBuild: "24A434", DeviceType: "com.apple.CoreSimulator.SimDeviceType.iPhone-18-Pro"}
	iPad   = model.Simulator{Runtime: "com.apple.CoreSimulator.SimRuntime.iOS-27-0", RuntimeBuild: "24A434", DeviceType: "com.apple.CoreSimulator.SimDeviceType.iPad-Pro-13-inch-M5-12GB"}
)

func testTemplate(kind model.Kind, id string) string {
	return `{"id":"` + id + `","version":1,"kind":"` + string(kind) + `","owners":["jerryfane","themartianapp"],"xcode":{"version":"27.1","build":"27A9275"},"developer_dir":"/Applications/Xcode.app/Contents/Developer",` +
		`"simulators":[` + pinJSON(iPhone) + `,` + pinJSON(iPad) + `],` +
		`"default_timeout_seconds":2400,"max_timeout_seconds":3600,"memory_limit_mib":32768}`
}

var (
	uiTemplate   = testTemplate(model.SimulatorUITest, "org-ios-sim-uitest-v1")
	unitTemplate = testTemplate(model.UnitTest, "org-ios-sim-unittest-v1")
)

func pinJSON(s model.Simulator) string {
	data, _ := json.Marshal(s)
	return string(data)
}

// withSimulators replaces a test template's "simulators" member.
func withSimulators(template, member string) string {
	start, end := strings.Index(template, `"simulators"`), strings.Index(template, `"default_timeout`)
	return template[:start] + member + template[end:]
}

func loadTemplates(templates string) (*profiles.Registry, error) {
	dir, err := os.MkdirTemp("", "templates")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	filename := filepath.Join(dir, "profiles.json")
	if err := os.WriteFile(filename, []byte(`{"profiles":[],"templates":[`+templates+`]}`), 0600); err != nil {
		return nil, err
	}
	return profiles.Load(filename)
}

// decode builds a value from its JSON spelling.
func decode[T any](t *testing.T, data string) T {
	t.Helper()
	var v T
	if err := json.Unmarshal([]byte(data), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// edit round-trips v through its JSON object form, applying change on the way.
func edit[T any](t *testing.T, v T, change func(map[string]any)) T {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	object := decode[map[string]any](t, string(data))
	change(object)
	data, err = json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return decode[T](t, string(data))
}

// member is the compact JSON of v's key member, or "" when it is absent.
func member(t *testing.T, v any, key string) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	raw, ok := decode[map[string]json.RawMessage](t, string(data))[key]
	if !ok {
		return ""
	}
	return string(raw)
}

func testRequest(t *testing.T, kind model.Kind, shard string) model.Request {
	id := "org-ios-sim-uitest-v1"
	if kind == model.UnitTest {
		id = "org-ios-sim-unittest-v1"
	}
	return decode[model.Request](t, `{"repo":"themartianapp/herdrup","sha":"`+strings.Repeat("ab", 20)+`","kind":"`+string(kind)+`","profile":"`+id+`","xcode":{"version":"27.1","build":"27A9275"},"shard":"`+shard+`"}`)
}

func TestNormalizeTemplateAcceptsUITestKind(t *testing.T) {
	r := templatesFile(t, buildTemplate+","+uiTemplate+","+unitTemplate)
	templates := r.Templates()
	if len(templates) != 3 {
		t.Fatalf("templates: %+v", templates)
	}
	for i, kind := range []model.Kind{model.SimulatorUITest, model.UnitTest} {
		got := templates[i+1]
		if got.Kind != kind || member(t, got, "simulators") != `[`+pinJSON(iPhone)+`,`+pinJSON(iPad)+`]` || got.DefaultTimeoutSeconds != 2400 || got.MaxTimeoutSeconds != 3600 {
			t.Fatalf("%s template: %+v", kind, got)
		}
	}
	// Build templates keep their canonical JSON: no simulators member.
	if member(t, templates[0], "simulators") != "" {
		t.Fatal("build template JSON changed")
	}
	pin := pinJSON(iPhone)
	invalid := map[string]string{
		"no simulators":           withSimulators(uiTemplate, ``),
		"empty simulators":        withSimulators(uiTemplate, `"simulators":[],`),
		"null simulators":         withSimulators(uiTemplate, `"simulators":null,`),
		"five simulators":         strings.Replace(uiTemplate, `"simulators":[`, `"simulators":[`+strings.Replace(pin, "iPhone-18-Pro", "iPhone-17", 1)+`,`+strings.Replace(pin, "iPhone-18-Pro", "iPhone-16", 1)+`,`+strings.Replace(pin, "iPhone-18-Pro", "iPhone-15", 1)+`,`, 1),
		"duplicate simulator":     strings.Replace(uiTemplate, `"simulators":[`, `"simulators":[`+pin+`,`, 1),
		"inexact runtime build":   strings.Replace(uiTemplate, `"24A434"`, `"latest"`, 1),
		"runtime pattern":         strings.Replace(uiTemplate, `SimRuntime.iOS-27-0`, `SimRuntime/../iOS`, 1),
		"device pattern":          strings.Replace(uiTemplate, `SimDeviceType.iPhone-18-Pro`, `SimDeviceType.`, 1),
		"build with a simulator":  strings.Replace(buildTemplate, `"developer_dir"`, `"simulators":[`+pin+`],"developer_dir"`, 1),
		"unit test no simulators": withSimulators(unitTemplate, ``),
		"unknown kind":            strings.Replace(uiTemplate, `"kind":"simulator_ui_test"`, `"kind":"ui_test"`, 1),
		"timeout above cap":       strings.Replace(uiTemplate, `"max_timeout_seconds":3600`, `"max_timeout_seconds":7201`, 1),
		"unit test above cap":     strings.Replace(unitTemplate, `"max_timeout_seconds":3600`, `"max_timeout_seconds":7200`, 1),
	}
	for name, template := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := loadTemplates(template); err == nil {
				t.Fatalf("invalid template loaded: %s", template)
			}
		})
	}
}

// A UI-test template may raise its maximum timeout to 7200 seconds and admits
// requests up to it, beside a template keeping 3600; an omitted maximum stays
// 3600, so templates that omit it keep their digests.
func TestUITestTemplateMaxTimeoutUpTo7200(t *testing.T) {
	long := strings.Replace(strings.Replace(uiTemplate, `"max_timeout_seconds":3600`, `"max_timeout_seconds":7200`, 1), "org-ios-sim-uitest-v1", "org-ios-sim-uitest-long-v1", 1)
	r := templatesFile(t, uiTemplate+","+long)
	templates := r.Templates()
	if len(templates) != 2 || templates[0].MaxTimeoutSeconds != 3600 || templates[1].MaxTimeoutSeconds != 7200 {
		t.Fatalf("templates: %+v", templates)
	}
	q := testRequest(t, model.SimulatorUITest, "iphone-terminal")
	q.Profile, q.TimeoutSeconds = "org-ios-sim-uitest-long-v1", 7200
	if a, err := r.Resolve(q); err != nil || a.Request.TimeoutSeconds != 7200 || a.Profile.MaxTimeoutSeconds != 7200 {
		t.Fatalf("7200-second request: %+v %v", a.Request, err)
	}
	q.TimeoutSeconds = 7201
	if _, err := r.Resolve(q); err == nil {
		t.Fatal("request above the template maximum admitted")
	}
	q.Profile, q.TimeoutSeconds = "org-ios-sim-uitest-v1", 3601
	if _, err := r.Resolve(q); err == nil {
		t.Fatal("request above the 3600-second template maximum admitted")
	}
	omitted := strings.Replace(uiTemplate, `"default_timeout_seconds":2400,"max_timeout_seconds":3600,`, ``, 1)
	defaulted := templatesFile(t, omitted)
	if got := defaulted.Templates()[0]; got.DefaultTimeoutSeconds != 2400 || got.MaxTimeoutSeconds != 3600 {
		t.Fatalf("omitted budgets: %+v", got)
	}
	if defaulted.Digests()["org-ios-sim-uitest-v1"] != r.Digests()["org-ios-sim-uitest-v1"] {
		t.Fatal("omitted maximum changed the template digest")
	}
}

func TestResolveTemplateAdmitsPinnedSimulatorAndShard(t *testing.T) {
	r := templatesFile(t, buildTemplate+","+uiTemplate+","+unitTemplate)
	for _, kind := range []model.Kind{model.SimulatorUITest, model.UnitTest} {
		// An omitted simulator is the template's first pin.
		a, err := r.Resolve(testRequest(t, kind, "iphone-terminal"))
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if a.Request.Simulator == nil || *a.Request.Simulator != iPhone || member(t, a.Request, "shard") != `"iphone-terminal"` || a.Request.TimeoutSeconds != 2400 {
			t.Fatalf("%s request not normalized: %+v", kind, a.Request)
		}
		if a.ProfileDigest != r.Digests()[a.Profile.ID] {
			t.Fatalf("%s admission does not bind the template digest", kind)
		}
		// A listed simulator is admitted as given, not aliased.
		q := testRequest(t, kind, "ipad-1")
		q.Simulator = &model.Simulator{Runtime: iPad.Runtime, RuntimeBuild: iPad.RuntimeBuild, DeviceType: iPad.DeviceType}
		b, err := r.Resolve(q)
		if err != nil || *b.Request.Simulator != iPad || b.Request.Simulator == q.Simulator {
			t.Fatalf("%s listed simulator: %+v %v", kind, b.Request, err)
		}
		// The admitted request re-admits identically through its snapshot.
		single, err := profiles.ForSnapshot(b.Profile)
		if err != nil {
			t.Fatal(err)
		}
		if again, err := single.Resolve(b.Request); err != nil || !reflect.DeepEqual(again, b) {
			t.Fatalf("%s snapshot does not re-admit identically: %+v %v", kind, again, err)
		}
	}
	ui := func(shard string, change func(*model.Request)) model.Request {
		q := testRequest(t, model.SimulatorUITest, shard)
		if change != nil {
			change(&q)
		}
		return q
	}
	build := func(change func(map[string]any)) model.Request {
		return edit(t, templateRequest("themartianapp/herdrup"), change)
	}
	unlisted := iPhone
	unlisted.RuntimeBuild = "24A435"
	refused := map[string]struct {
		request model.Request
		want    error
	}{
		"unlisted simulator":          {ui("a", func(q *model.Request) { q.Simulator = &unlisted }), profiles.ErrUnsupported},
		"missing shard":               {ui("", nil), profiles.ErrInvalid},
		"unit missing shard":          {testRequest(t, model.UnitTest, ""), profiles.ErrInvalid},
		"uppercase shard":             {ui("iPhone", nil), profiles.ErrInvalid},
		"long shard":                  {ui(strings.Repeat("a", 33), nil), profiles.ErrInvalid},
		"leading hyphen shard":        {ui("-a", nil), profiles.ErrInvalid},
		"shard with colon":            {ui("a:b", nil), profiles.ErrInvalid},
		"timeout above max":           {ui("a", func(q *model.Request) { q.TimeoutSeconds = 3601 }), profiles.ErrInvalid},
		"wrong kind for template":     {ui("a", func(q *model.Request) { q.Kind = model.UnitTest }), profiles.ErrUnsupported},
		"unknown owner":               {ui("a", func(q *model.Request) { q.Repo = "someone/app" }), profiles.ErrUnsupported},
		"shard on a build template":   {build(func(m map[string]any) { m["shard"] = "a" }), profiles.ErrUnsupported},
		"simulator on build template": {build(func(m map[string]any) { m["simulator"] = iPhone }), profiles.ErrUnsupported},
	}
	for name, tc := range refused {
		t.Run(name, func(t *testing.T) {
			if _, err := r.Resolve(tc.request); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
	// Build templates and explicit profiles still admit without a shard, and
	// explicit profiles never take one.
	if _, err := r.Resolve(templateRequest("themartianapp/herdrup")); err != nil {
		t.Fatal(err)
	}
	installed, err := profiles.Load("testdata/installed-profiles.json")
	if err != nil {
		t.Fatal(err)
	}
	p := installed.List()[0]
	explicit := model.Request{Repo: p.Repo, SHA: strings.Repeat("a", 40), Kind: p.Kind, Profile: p.ID, Xcode: p.Xcode}
	if _, err := installed.Resolve(explicit); err != nil {
		t.Fatal(err)
	}
	if _, err := installed.Resolve(edit(t, explicit, func(m map[string]any) { m["shard"] = "a" })); !errors.Is(err, profiles.ErrUnsupported) {
		t.Fatalf("explicit profile took a shard: %v", err)
	}
}

func TestTemplateSnapshotCarriesSimulator(t *testing.T) {
	r := templatesFile(t, uiTemplate)
	q := testRequest(t, model.SimulatorUITest, "iphone-chrome")
	q.Simulator = &iPad
	a, err := r.Resolve(q)
	if err != nil {
		t.Fatal(err)
	}
	template := r.Templates()[0]
	want := profiles.TemplateSnapshot(template, "themartianapp/herdrup")
	want.Simulator = &iPad
	want = edit(t, want, func(m map[string]any) { m["shard"] = "iphone-chrome" })
	if !reflect.DeepEqual(a.Profile, want) || member(t, a.Profile, "shard") != `"iphone-chrome"` || *a.Profile.Simulator != iPad {
		t.Fatalf("snapshot %+v, want %+v", a.Profile, want)
	}
	if a.Profile.Simulator == a.Request.Simulator || a.Profile.Simulator == &iPad || a.Profile.Template == nil {
		t.Fatal("snapshot aliases request storage")
	}
	if digest, err := a.Profile.SnapshotDigest(); err != nil || digest == "" {
		t.Fatalf("snapshot digest %q %v", digest, err)
	}
	// Configured profiles cannot claim a shard.
	installed, err := os.ReadFile("testdata/installed-profiles.json")
	if err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(t.TempDir(), "profiles.json")
	if err := os.WriteFile(filename, []byte(strings.Replace(string(installed), `"id":`, `"shard":"a","id":`, 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := profiles.Load(filename); !errors.Is(err, profiles.ErrInvalid) {
		t.Fatalf("configured profile with a shard loaded: %v", err)
	}
}

const herdrupConfig = `{"version":1,"work_dir":".","project":"Herdr.xcodeproj","scheme":"Herdr","xcodegen":true,"resolve_packages":true,
"ui_test":{"shards":{
 "iphone-terminal":["HerdrUITests/TerminalControlTests","HerdrUITests/TerminalResizeTests","HerdrUITests/TerminalSearchTests","HerdrUITests/TerminalSelectionTests"],
 "iphone-chrome":["HerdrUITests/AgentListChromeTests","HerdrUITests/GramTests","HerdrUITests/SettingsTests/testCompactSettingsSurviveResizeAndResume()"]}},
"unit_test":{"shards":{"fonts":["HerdrFontTests/FontTests"]}}}`

var (
	terminalShard = []string{"HerdrUITests/TerminalControlTests", "HerdrUITests/TerminalResizeTests", "HerdrUITests/TerminalSearchTests", "HerdrUITests/TerminalSelectionTests"}
	chromeShard   = []string{"HerdrUITests/AgentListChromeTests", "HerdrUITests/GramTests", "HerdrUITests/SettingsTests/testCompactSettingsSurviveResizeAndResume()"}
)

func parseConfig(t *testing.T, data string) model.RepoConfig {
	t.Helper()
	config, err := profiles.ParseRepoConfig([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func TestParseRepoConfigUITestGrammar(t *testing.T) {
	got := parseConfig(t, herdrupConfig)
	if got.Version != 1 || got.WorkDir != "." || got.Project != "Herdr.xcodeproj" || got.Scheme != "Herdr" || !got.XcodeGen || !got.ResolvePackages {
		t.Fatalf("build fields: %+v", got)
	}
	shards, err := json.Marshal(map[string]any{"shards": map[string][]string{"iphone-chrome": chromeShard, "iphone-terminal": terminalShard}})
	if err != nil {
		t.Fatal(err)
	}
	if member(t, got, "ui_test") != string(shards) || member(t, got, "unit_test") != `{"shards":{"fonts":["HerdrFontTests/FontTests"]}}` {
		t.Fatalf("test sections: %s %s", member(t, got, "ui_test"), member(t, got, "unit_test"))
	}
	base := `{"version":1,"work_dir":".","project":"A.xcodeproj","scheme":"A","ui_test":`
	generated := func(n, per int) string {
		var b strings.Builder
		b.WriteString(`{"shards":{`)
		for i := range n {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, `"s%d":[`, i)
			for j := range per {
				if j > 0 {
					b.WriteByte(',')
				}
				fmt.Fprintf(&b, `"T/C%d_%d"`, i, j)
			}
			b.WriteByte(']')
		}
		b.WriteString(`}}`)
		return b.String()
	}
	valid := []string{
		`{"shards":{"a":["T/C"]}}`,
		`{"shards":{"a":["T/C/m"],"b":["T/C/m()"]}}`,
		`{"shards":{"a":["My.Target-2_x/_Class9/test_Method1()"]}}`,
		`{"shards":{"z9-":["T/C","T/D"]}}`,
		`{"shards":{"a":["T/C"],"b":["T/C/m"]}},"unit_test":{"shards":{"a":["T/C"]}}`,
		`{"shards":{"` + strings.Repeat("a", 32) + `":["` + strings.Repeat("T", 128) + `/` + strings.Repeat("C", 128) + `/` + strings.Repeat("m", 128) + `()"]}}`,
		generated(16, 16),
		generated(8, 32),
	}
	for _, section := range valid {
		if _, err := profiles.ParseRepoConfig([]byte(base + section + `}`)); err != nil {
			t.Fatalf("%s: %v", section, err)
		}
	}
	invalid := map[string]string{
		"null section":          `null`,
		"empty section":         `{}`,
		"unknown section key":   `{"shards":{"a":["T/C"]},"test_plan":"P"}`,
		"duplicate section key": `{"shards":{"a":["T/C"]},"shards":{"b":["T/C"]}}`,
		"case-folded key":       `{"Shards":{"a":["T/C"]}}`,
		"case-folded duplicate": `{"shards":{"a":["T/C"]},"SHARDS":{"b":["T/C"]}}`,
		"null shards":           `{"shards":null}`,
		"no shards":             `{"shards":{}}`,
		"shards not an object":  `{"shards":["T/C"]}`,
		"duplicate shard":       `{"shards":{"a":["T/C"],"a":["T/D"]}}`,
		"null shard":            `{"shards":{"a":null}}`,
		"empty shard":           `{"shards":{"a":[]}}`,
		"null selector":         `{"shards":{"a":[null]}}`,
		"number selector":       `{"shards":{"a":[1]}}`,
		"nested selector":       `{"shards":{"a":[["T/C"]]}}`,
		"too many shards":       generated(17, 1),
		"too many in a shard":   generated(1, 33),
		"too many in all":       generated(9, 32),
		"uppercase shard":       `{"shards":{"A":["T/C"]}}`,
		"hyphen-led shard":      `{"shards":{"-a":["T/C"]}}`,
		"long shard":            `{"shards":{"` + strings.Repeat("a", 33) + `":["T/C"]}}`,
		"target only":           `{"shards":{"a":["T"]}}`,
		"four components":       `{"shards":{"a":["T/C/m/x"]}}`,
		"empty class":           `{"shards":{"a":["T//m"]}}`,
		"trailing slash":        `{"shards":{"a":["T/C/"]}}`,
		"leading hyphen":        `{"shards":{"a":["-T/C"]}}`,
		"option injection":      `{"shards":{"a":["-only-testing:T/C"]}}`,
		"colon":                 `{"shards":{"a":["T/C:m"]}}`,
		"dollar":                `{"shards":{"a":["T/${CHECKOUT}"]}}`,
		"space":                 `{"shards":{"a":["T/C m"]}}`,
		"comma":                 `{"shards":{"a":["T/C,T/D"]}}`,
		"newline":               `{"shards":{"a":["T/C\nD"]}}`,
		"digit-led class":       `{"shards":{"a":["T/9C"]}}`,
		"hyphen in class":       `{"shards":{"a":["T/C-D"]}}`,
		"dot in method":         `{"shards":{"a":["T/C/m.n"]}}`,
		"class parentheses":     `{"shards":{"a":["T/C()"]}}`,
		"half parentheses":      `{"shards":{"a":["T/C/m("]}}`,
		"parenthesised args":    `{"shards":{"a":["T/C/m(x)"]}}`,
		"long target":           `{"shards":{"a":["` + strings.Repeat("T", 129) + `/C"]}}`,
		"long class":            `{"shards":{"a":["T/` + strings.Repeat("C", 129) + `"]}}`,
		"duplicate selector":    `{"shards":{"a":["T/C","T/C"]}}`,
		"method spelled twice":  `{"shards":{"a":["T/C/m","T/C/m()"]}}`,
		"class and its method":  `{"shards":{"a":["T/C/m()","T/C"]}}`,
		"invalid unit_test":     `{"shards":{"a":["T/C"]}},"unit_test":{"shards":{"a":["T C"]}}`,
	}
	for name, section := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := profiles.ParseRepoConfig([]byte(base + section + `}`)); !errors.Is(err, profiles.ErrRepoConfig) {
				t.Fatalf("got %v, want a .macserve.json refusal", err)
			}
		})
	}
	// The largest valid section fits the raised bound.
	if profiles.MaxRepoConfigBytes != 16384 || len(base+generated(8, 32)+`}`) >= profiles.MaxRepoConfigBytes {
		t.Fatalf("bound %d", profiles.MaxRepoConfigBytes)
	}
}

func TestDeriveUITestArgvGolden(t *testing.T) {
	config := parseConfig(t, herdrupConfig)
	r := templatesFile(t, buildTemplate+","+uiTemplate+","+unitTemplate)
	project := []string{"xcodebuild", "-project", "Herdr.xcodeproj"}
	test := []string{"-scheme", "Herdr", "-configuration", "Debug", "-sdk", "iphonesimulator", "-destination", "id=${SIMULATOR_ID}", "-derivedDataPath", "${DERIVED_DATA}"}
	fixed := []model.Command{
		{Executable: "/Library/macserve/tools/xcodegen", Args: []string{"generate", "--spec", "project.yml"}},
		{Executable: "/usr/bin/xcrun", Args: []string{"xcodebuild", "-project", "Herdr.xcodeproj", "-scheme", "Herdr", "-resolvePackageDependencies"}},
	}
	cases := []struct {
		kind      model.Kind
		shard     string
		selectors []string
	}{
		{model.SimulatorUITest, "iphone-terminal", terminalShard},
		{model.SimulatorUITest, "iphone-chrome", chromeShard},
		{model.UnitTest, "fonts", []string{"HerdrFontTests/FontTests"}},
	}
	for _, tc := range cases {
		t.Run(string(tc.kind)+"/"+tc.shard, func(t *testing.T) {
			a, err := r.Resolve(testRequest(t, tc.kind, tc.shard))
			if err != nil {
				t.Fatal(err)
			}
			derived, err := profiles.Derive(a.Profile, config)
			if err != nil {
				t.Fatal(err)
			}
			only := make([]string, len(tc.selectors))
			for i, s := range tc.selectors {
				only[i] = "-only-testing:" + s
			}
			prepare := append(slices.Clone(fixed), model.Command{Executable: "/usr/bin/xcrun", Args: slices.Concat(project, test, []string{"CODE_SIGNING_ALLOWED=NO", "build-for-testing"}, only)})
			run := model.Command{Executable: "/usr/bin/xcrun", Args: slices.Concat(project, test, []string{"-resultBundlePath", "${RESULT_BUNDLE}", "CODE_SIGNING_ALLOWED=NO", "test-without-building"}, only)}
			if derived.WorkDir != "." || !reflect.DeepEqual(derived.Prepare, prepare) || !reflect.DeepEqual(derived.Run, run) || !slices.Equal(derived.RequiredTests, tc.selectors) {
				t.Fatalf("derived %q\nprepare %q\nrun %q\nrequired %q", derived.WorkDir, derived.Prepare, derived.Run, derived.RequiredTests)
			}
			// Identity, pins, simulator, shard and budgets stay the snapshot's.
			derived.WorkDir, derived.Prepare, derived.Run, derived.RequiredTests = "", nil, model.Command{}, nil
			if !reflect.DeepEqual(derived, a.Profile) {
				t.Fatalf("derivation changed the snapshot: %+v", derived)
			}
		})
	}
	// Without the optional steps, prepare is build-for-testing alone.
	a, err := r.Resolve(testRequest(t, model.SimulatorUITest, "a"))
	if err != nil {
		t.Fatal(err)
	}
	minimal := parseConfig(t, `{"version":1,"work_dir":"ios","workspace":"W.xcworkspace","scheme":"S","ui_test":{"shards":{"a":["T/C"]}}}`)
	derived, err := profiles.Derive(a.Profile, minimal)
	workspace := []string{"xcodebuild", "-workspace", "W.xcworkspace", "-scheme", "S", "-configuration", "Debug", "-sdk", "iphonesimulator", "-destination", "id=${SIMULATOR_ID}", "-derivedDataPath", "${DERIVED_DATA}"}
	wantPrepare := []model.Command{{Executable: "/usr/bin/xcrun", Args: slices.Concat(workspace, []string{"CODE_SIGNING_ALLOWED=NO", "build-for-testing", "-only-testing:T/C"})}}
	wantRun := model.Command{Executable: "/usr/bin/xcrun", Args: slices.Concat(workspace, []string{"-resultBundlePath", "${RESULT_BUNDLE}", "CODE_SIGNING_ALLOWED=NO", "test-without-building", "-only-testing:T/C"})}
	if err != nil || derived.WorkDir != "ios" || !reflect.DeepEqual(derived.Prepare, wantPrepare) || !reflect.DeepEqual(derived.Run, wantRun) {
		t.Fatalf("minimal derivation %+v %v", derived, err)
	}
	refused := map[string]string{
		"no ui_test section":     `{"version":1,"work_dir":".","project":"A.xcodeproj","scheme":"A"}`,
		"unit_test section only": `{"version":1,"work_dir":".","project":"A.xcodeproj","scheme":"A","unit_test":{"shards":{"a":["T/C"]}}}`,
		"shard not configured":   `{"version":1,"work_dir":".","project":"A.xcodeproj","scheme":"A","ui_test":{"shards":{"b":["T/C"]}}}`,
		"unparsed bad selector":  `{"version":1,"work_dir":".","project":"A.xcodeproj","scheme":"A","ui_test":{"shards":{"a":["T/C:x"]}}}`,
	}
	for name, c := range refused {
		if _, err := profiles.Derive(a.Profile, decode[model.RepoConfig](t, c)); !errors.Is(err, profiles.ErrRepoConfig) {
			t.Fatalf("%s: got %v, want a .macserve.json refusal", name, err)
		}
	}
	// A snapshot that lost its shard or simulator derives nothing.
	for name, snapshot := range map[string]model.Profile{
		"no shard":     edit(t, a.Profile, func(m map[string]any) { delete(m, "shard") }),
		"no simulator": edit(t, a.Profile, func(m map[string]any) { delete(m, "simulator") }),
	} {
		if _, err := profiles.Derive(snapshot, minimal); !errors.Is(err, profiles.ErrInvalid) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// Build templates ignore test sections; their golden argv is unchanged.
	b, err := r.Resolve(templateRequest("themartianapp/herdrup"))
	if err != nil {
		t.Fatal(err)
	}
	withTests, err1 := profiles.Derive(b.Profile, config)
	without, err2 := profiles.Derive(b.Profile, edit(t, config, func(m map[string]any) { delete(m, "ui_test"); delete(m, "unit_test") }))
	if err1 != nil || err2 != nil || !reflect.DeepEqual(withTests, without) || len(withTests.RequiredTests) != 0 || withTests.Run.Args[len(withTests.Run.Args)-1] != "build" {
		t.Fatalf("build derivation saw test sections: %+v %v %v", withTests, err1, err2)
	}
	if _, err := profiles.Derive(edit(t, b.Profile, func(m map[string]any) { m["shard"] = "a" }), config); !errors.Is(err, profiles.ErrInvalid) {
		t.Fatalf("build snapshot with a shard derived: %v", err)
	}
}

func TestEffectiveUITestRequiredTests(t *testing.T) {
	config := parseConfig(t, herdrupConfig)
	r := templatesFile(t, uiTemplate)
	a, err := r.Resolve(testRequest(t, model.SimulatorUITest, "iphone-terminal"))
	if err != nil {
		t.Fatal(err)
	}
	derived, err := profiles.Derive(a.Profile, config)
	if err != nil {
		t.Fatal(err)
	}
	recipe := map[string]any{"config_sha256": strings.Repeat("0", 64), "config": config, "work_dir": derived.WorkDir, "prepare": derived.Prepare, "run": derived.Run, "shard": "iphone-terminal", "required_tests": terminalShard}
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
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(effective.RequiredTests, terminalShard) || len(a.Profile.RequiredTests) != 0 {
		t.Fatalf("effective required tests %q, snapshot %q", effective.RequiredTests, a.Profile.RequiredTests)
	}
	other := parseConfig(t, strings.Replace(herdrupConfig, `"HerdrUITests/TerminalSelectionTests"`, `"HerdrUITests/GramTests"`, 1))
	for name, change := range map[string]func(map[string]any){
		"fewer required tests": func(m map[string]any) { m["required_tests"] = terminalShard[:1] },
		"no required tests":    func(m map[string]any) { delete(m, "required_tests") },
		"other required tests": func(m map[string]any) { m["required_tests"] = chromeShard },
		"other shard":          func(m map[string]any) { m["shard"] = "iphone-chrome" },
		"no shard":             func(m map[string]any) { delete(m, "shard") },
		"selector dropped": func(m map[string]any) {
			run := derived.Run
			run.Args = run.Args[:len(run.Args)-1]
			m["run"] = run
		},
		"build-for-testing cut": func(m map[string]any) { m["prepare"] = derived.Prepare[:len(derived.Prepare)-1] },
		"config shard edited":   func(m map[string]any) { m["config"] = other },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := profiles.Effective(a.Profile, reported(change)); err == nil {
				t.Fatal("mismatched recipe accepted")
			}
		})
	}
}

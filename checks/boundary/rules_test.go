package boundary

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The fixture module mirrors the shapes the rules protect: a root package
// (internal/worker) with B execution internals and a C observation file, a
// G file in internal/maintenance, a non-root C package and a banned B
// package.
const fixtureModule = "example.com/fx"

var fixtureBase = map[string]string{
	"go.mod": "module " + fixtureModule + "\n\ngo 1.26\n",
	"internal/worker/exec.go": `package worker

import (
	"context"
	"os"
)

type execution struct{ ran []string }

type Runner interface{ Run() error }

var Hook = "boundary"

func (x *execution) invoke(ctx context.Context, name string) error {
	x.ran = append(x.ran, name)
	return ctx.Err()
}

func (x *execution) quarantine() error { return os.Remove("/nonexistent") }

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func Root() error { return os.Remove("/nonexistent") }
`,
	"internal/worker/observe.go": `package worker

import (
	"context"
	"errors"
	"strings"
)

var errEmpty = errors.New("empty")

type report struct{ Lines []string }

func (r *report) add(s string) { r.Lines = append(r.Lines, strings.TrimSpace(s)) }

func observe(ctx context.Context, x *execution, r *report) error {
	if x == nil {
		return errEmpty
	}
	r.add(clip("Xcode 26", 64))
	return x.invoke(ctx, "/usr/bin/xcodebuild")
}
`,
	"internal/maintenance/run.go": `package maintenance

import "syscall"

func uid() int { return syscall.Getuid() }
`,
	"internal/hostguard/guard.go": "package hostguard\n\nfunc Check() error { return nil }\n",
	"internal/store/store.go": `package store

import "os"

func Save(path string) error { return os.WriteFile(path, nil, 0o600) }
`,
}

func fixtureManifest() map[string]any {
	return map[string]any{
		"schema": 1,
		"classes": map[string][]string{
			"B": {"go.mod", "BOUNDARY.json", "internal/**"},
			"G": {"internal/maintenance/run.go"},
			"C": {"internal/worker/observe.go", "internal/store/**"},
			"T": {"docs/**"},
		},
		"seams":   map[string][]string{"internal/worker": {"(*execution).invoke", "clip"}},
		"g_calls": map[string][]string{"internal/maintenance": {"syscall.Getuid"}},
	}
}

// runFixture writes the base fixture with overrides (an empty value deletes
// a file), then runs the full check.
func runFixture(t *testing.T, overrides map[string]string, manifest map[string]any) []string {
	t.Helper()
	root := t.TempDir()
	files := maps.Clone(fixtureBase)
	for name, content := range overrides {
		if content == "" {
			delete(files, name)
			continue
		}
		files[name] = content
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	files[ManifestFile] = string(data)
	var tracked []File
	for name, content := range files {
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		tracked = append(tracked, File{Path: name, Mode: "100644"})
	}
	_, problems, err := Check(root, tracked)
	if err != nil {
		t.Fatal(err)
	}
	return problems
}

func TestCarryFileRulesAcceptCleanFixture(t *testing.T) {
	if problems := runFixture(t, nil, fixtureManifest()); len(problems) > 0 {
		t.Fatalf("clean fixture rejected:\n%s", strings.Join(problems, "\n"))
	}
}

// TestCarryFileRules seeds one violation per case into the clean fixture;
// every one must be reported.
func TestCarryFileRules(t *testing.T) {
	const observe = "internal/worker/observe.go"
	const header = "package worker\n\nimport \"context\"\n\n"
	withObserve := func(extra string) map[string]string {
		return map[string]string{observe: fixtureBase[observe] + "\n" + extra + "\n"}
	}
	cases := []struct {
		name      string
		overrides map[string]string
		manifest  func(map[string]any)
		want      string
	}{
		{name: "init function", overrides: withObserve("func init() {}"), want: "init function"},
		{name: "method on B type", overrides: withObserve("func (x *execution) helper() {}"), want: "method helper declared on"},
		{name: "method on B type via alias", overrides: withObserve("type alias = execution\n\nfunc (a *alias) helper() {}"), want: "method helper declared on"},
		{name: "syscall import", overrides: map[string]string{observe: header + "import \"syscall\"\n\nfunc pid(context.Context) int { return syscall.Getpid() }\n"}, want: "imports syscall"},
		{name: "unsafe import", overrides: map[string]string{observe: header + "import \"unsafe\"\n\nfunc size(context.Context) uintptr { return unsafe.Sizeof(0) }\n"}, want: "imports unsafe"},
		{name: "os/exec import", overrides: map[string]string{observe: header + "import \"os/exec\"\n\nfunc run(ctx context.Context) error { return exec.CommandContext(ctx, \"true\").Run() }\n"}, want: "imports os/exec"},
		{name: "banned internal import", overrides: map[string]string{observe: header + "import \"" + fixtureModule + "/internal/hostguard\"\n\nfunc check(context.Context) error { return hostguard.Check() }\n"}, want: "imports " + fixtureModule + "/internal/hostguard"},
		{name: "linkname directive", overrides: map[string]string{observe: header + "import _ \"unsafe\"\n\n//go:linkname now time.now\nfunc now() (int64, int32, int64)\n\nfunc use(context.Context) { now() }\n"}, want: "compiler directive \"//go:linkname\""},
		{name: "generate directive", overrides: withObserve("//go:generate echo hi"), want: "compiler directive \"//go:generate\""},
		{name: "call to non-seam B method", overrides: withObserve("func q(x *execution) error { return x.quarantine() }"), want: "quarantine, which is not C/G"},
		{name: "method value of non-seam", overrides: withObserve("func q(x *execution) func() error { return x.quarantine }"), want: "quarantine, which is not C/G"},
		{name: "call to B function", overrides: withObserve("func r() error { return Root() }"), want: "worker.Root, which is not C/G"},
		{name: "call to B interface method", overrides: withObserve("func r(run Runner) error { return run.Run() }"), want: "Run, which is not C/G"},
		{name: "call to non-allowlisted std", overrides: map[string]string{observe: strings.Replace(fixtureBase[observe], "\"strings\"", "\"os\"\n\t\"strings\"", 1) + "\nfunc pid() int { return os.Getpid() }\n"}, want: "uses os.Getpid"},
		{name: "package var initializer", overrides: withObserve("var computed = len(clip(\"a\", 1))"), want: "package-level var initializer"},
		{name: "assignment to B variable", overrides: withObserve("func set() { Hook = \"carry\" }"), want: "assigns package-level variable worker.Hook"},
		{name: "address of B variable", overrides: withObserve("func ref() *string { return &Hook }"), want: "takes the address of package-level variable worker.Hook"},
		{name: "assignment to std variable", overrides: map[string]string{"internal/store/store.go": fixtureBase["internal/store/store.go"] + "\nfunc reset() { os.Args = nil }\n"}, want: "assigns package-level variable os.Args"},
		{name: "call through B function variable", overrides: map[string]string{
			"internal/worker/exec.go": fixtureBase["internal/worker/exec.go"] + "\nvar hook = func() {}\n",
			observe:                   fixtureBase[observe] + "\nfunc h() { hook() }\n",
		}, want: "calls function value hook"},
		{name: "cgo file", overrides: map[string]string{observe: header + "// #include <stdio.h>\nimport \"C\"\n\nfunc f(context.Context) {}\n"}, want: "not part of the darwin/arm64 build"},
		{name: "excluded by build tag", overrides: map[string]string{observe: "//go:build linux\n\n" + fixtureBase[observe]}, want: "not part of the darwin/arm64 build"},
		{name: "G syscall not in g_calls", overrides: map[string]string{"internal/maintenance/run.go": "package maintenance\n\nimport \"syscall\"\n\nfunc pid() int { return syscall.Getpid() }\n"}, want: "uses syscall.Getpid, which is not listed in g_calls"},
		{name: "unknown seam", manifest: func(m map[string]any) {
			m["seams"] = map[string][]string{"internal/worker": {"(*execution).invoke", "clip", "(*execution).missing"}}
		}, want: "seam \"(*execution).missing\" does not name a declaration"},
		{name: "seam receiver kind must match", manifest: func(m map[string]any) {
			m["seams"] = map[string][]string{"internal/worker": {"execution.invoke", "clip"}}
		}, want: "seam \"execution.invoke\" does not name a declaration"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			manifest := fixtureManifest()
			if tc.manifest != nil {
				tc.manifest(manifest)
			}
			problems := runFixture(t, tc.overrides, manifest)
			if !slices.ContainsFunc(problems, func(p string) bool { return strings.Contains(p, tc.want) }) {
				t.Fatalf("want a problem containing %q, got:\n%s", tc.want, strings.Join(problems, "\n"))
			}
		})
	}
}

func TestClassifyMostSpecificFirst(t *testing.T) {
	m, err := ParseManifest([]byte(`{"schema":1,"classes":{
		"B":["internal/**","internal/worker/*_test.go"],
		"G":[],
		"C":["internal/worker/job_observation.go","internal/store/**"],
		"T":["internal/worker/job_observation_*_test.go","docs/**"]},
		"seams":{},"g_calls":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	for file, want := range map[string]string{
		"internal/worker/job_observation.go":           ClassC,
		"internal/worker/job_observation_test.go":      ClassB,
		"internal/worker/job_observation_xml_test.go":  ClassT,
		"internal/worker/broker.go":                    ClassB,
		"internal/store/store.go":                      ClassC,
		"internal/store/nested/deep/file.go":           ClassC,
		"docs/install.md":                              ClassT,
		"internal/worker/simulator_test.go":            ClassB,
		"internal/worker/job_observation.go.orig":      ClassB,
		"internal/worker/sub/job_observation_test.go":  ClassB,
		"internal/worker/job_observation_x_test.go.go": ClassB,
	} {
		got, err := m.Classify(file)
		if err != nil || got != want {
			t.Errorf("%s: got %q %v, want %s", file, got, err, want)
		}
	}
	for _, file := range []string{"README.md", "internalx/a.go", "doc/install.md"} {
		if got, err := m.Classify(file); err == nil {
			t.Errorf("%s: unlisted file classified %s", file, got)
		}
	}
}

func TestClassifyFileLevelRules(t *testing.T) {
	m, err := ParseManifest([]byte(`{"schema":1,"classes":{
		"B":["go.mod","a/x*.go","internal/**"],
		"G":[],
		"C":["a/*x.go","internal/store/**"],
		"T":["internal/store/store_test.go","internal/store/other_test.go","internal/worker/main.go","docs/**"]},
		"seams":{},"g_calls":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		file File
		want string
	}{
		"unlisted":            {File{"extra/thing.txt", "100644"}, "not classified"},
		"same specificity":    {File{"a/xx.go", "100644"}, "match at the same specificity"},
		"symlink":             {File{"go.mod", "120000"}, "symlinks are not allowed"},
		"submodule":           {File{"internal/vendor", "160000"}, "submodules are not allowed"},
		"T test not named":    {File{"internal/store/other_test.go", "100644"}, "not named for a C or G file"},
		"C test file":         {File{"internal/store/store_x_test.go", "100644"}, "test files are B or T"},
		"T Go source":         {File{"internal/worker/main.go", "100644"}, "cannot be T"},
		"non-Go C file":       {File{"internal/store/testdata/fixture.json", "100644"}, "only Go source files can be C"},
		"unsupported mode":    {File{"go.mod", "100664"}, "unsupported git mode"},
		"listed twice (dupe)": {File{"go.mod", "100644"}, "listed twice"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			files := []File{{"internal/store/store.go", "100644"}, {"internal/store/store_test.go", "100644"}, tc.file}
			if name == "listed twice (dupe)" {
				files = append(files, tc.file)
			}
			_, problems := m.ClassifyFiles(files)
			if !slices.ContainsFunc(problems, func(p string) bool { return strings.Contains(p, tc.want) }) {
				t.Fatalf("want %q, got %v", tc.want, problems)
			}
		})
	}
	_, problems := m.ClassifyFiles([]File{{"internal/store/store.go", "100644"}, {"internal/store/store_test.go", "100755"}, {"go.mod", "100644"}})
	if len(problems) > 0 {
		t.Fatalf("valid files rejected: %v", problems)
	}
}

func TestParseManifestRejectsMalformed(t *testing.T) {
	valid := func() map[string]any { return fixtureManifest() }
	cases := map[string]func(map[string]any){
		"schema 2":            func(m map[string]any) { m["schema"] = 2 },
		"unknown field":       func(m map[string]any) { m["extra"] = true },
		"missing class":       func(m map[string]any) { delete(m["classes"].(map[string][]string), "G") },
		"unknown class":       func(m map[string]any) { m["classes"].(map[string][]string)["X"] = nil },
		"pattern in two":      func(m map[string]any) { m["classes"].(map[string][]string)["T"] = []string{"internal/**"} },
		"question wildcard":   func(m map[string]any) { m["classes"].(map[string][]string)["T"] = []string{"docs/?.md"} },
		"partial double star": func(m map[string]any) { m["classes"].(map[string][]string)["T"] = []string{"docs/a**"} },
		"absolute pattern":    func(m map[string]any) { m["classes"].(map[string][]string)["T"] = []string{"/docs/**"} },
		"dot-dot pattern":     func(m map[string]any) { m["classes"].(map[string][]string)["T"] = []string{"docs/../go.mod"} },
		"g_calls not pkg.Name": func(m map[string]any) {
			m["g_calls"] = map[string][]string{"internal/maintenance": {"Getuid"}}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := valid()
			mutate(m)
			data, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseManifest(data); err == nil {
				t.Fatal("malformed manifest accepted")
			}
		})
	}
	data, _ := json.Marshal(valid())
	if _, err := ParseManifest(append(data, []byte(" {}")...)); err == nil {
		t.Fatal("trailing data accepted")
	}
}

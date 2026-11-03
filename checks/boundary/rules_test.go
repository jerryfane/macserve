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
// (internal/worker) with B execution internals and a C observation file that
// gets only values and capabilities, a G file in internal/maintenance, a
// non-root C package and a banned B package.
const fixtureModule = "example.com/fx"

var fixtureBase = map[string]string{
	"go.mod": "module " + fixtureModule + "\n\ngo 1.26\n",
	"internal/worker/exec.go": `package worker

import (
	"context"
	"os"
)

type Profile struct {
	Executable   string
	DeveloperDir string
	Args         []string
}

type Xcode struct{ Version, Build string }

type Result struct {
	State       string
	Observation Observation
}

type execution struct {
	ran     []string
	profile Profile
	result  Result
	done    chan string
}

type Runner interface{ Run() error }

type stateError struct{ state string }

func (e *stateError) Error() string { return e.state }

var Hook = "boundary"

var Registry = map[string]string{}

var ErrBoundary error = &stateError{"boundary"}

func (x *execution) invoke(ctx context.Context, name string) error {
	x.ran = append(x.ran, name)
	return ctx.Err()
}

func (x *execution) quarantine() error { return os.Remove("/nonexistent") }

func (x *execution) capture(ctx context.Context, name string) ([]byte, error) {
	return []byte(name), x.invoke(ctx, name)
}

// observe is the B side: it hands the C code values and a capability and
// writes what comes back.
func (x *execution) observe(ctx context.Context) error {
	o, err := observeToolchain(ctx, Xcode{Version: "26"}, x.capture)
	x.result.Observation = o
	return err
}

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

type Observation struct {
	Xcode Xcode
	Lines []string
}

func addLine(lines []string, s string) []string { return append(lines, strings.TrimSpace(s)) }

func observeToolchain(ctx context.Context, pins Xcode, capture func(context.Context, string) ([]byte, error)) (Observation, error) {
	var o Observation
	out, err := capture(ctx, "/usr/bin/xcodebuild")
	if err != nil {
		return o, err
	}
	if len(out) == 0 {
		return o, errEmpty
	}
	o.Xcode = pins
	o.Lines = addLine(o.Lines, clip(string(out), 64))
	return o, nil
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
	"internal/store/state.go": `package store

var Limits = []int{1, 2}

func limit() int { return 3 }
`,
}

func fixtureManifest() map[string]any {
	return map[string]any{
		"schema": 1,
		"classes": map[string][]string{
			"B": {"go.mod", "BOUNDARY.json", "internal/**", "internal/store/state.go"},
			"G": {"internal/maintenance/run.go"},
			"C": {"internal/worker/observe.go", "internal/store/**"},
			"T": {"docs/**"},
		},
		"seams":   map[string][]string{"internal/worker": {"(*execution).invoke", "clip"}},
		"g_calls": map[string][]string{"internal/maintenance": {"syscall.Getuid"}},
	}
}

// writeFixture writes the base fixture with overrides (an empty value
// deletes a file) and returns its root and tracked files.
func writeFixture(t *testing.T, overrides map[string]string, manifest map[string]any) (string, []File) {
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
	return root, tracked
}

// runFixture writes the fixture and runs the full check on its absolute root.
func runFixture(t *testing.T, overrides map[string]string, manifest map[string]any) []string {
	t.Helper()
	root, tracked := writeFixture(t, overrides, manifest)
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

// TestCheckRelativeRoot runs the check as `Check(".")` and through a
// relative path from a subdirectory: the clean fixture passes and a seeded
// violation is still reported.
func TestCheckRelativeRoot(t *testing.T) {
	const observe = "internal/worker/observe.go"
	for name, tc := range map[string]struct {
		overrides map[string]string
		want      string
	}{
		"clean":     {nil, ""},
		"violation": {map[string]string{observe: fixtureBase[observe] + "\nfunc init() {}\n"}, "init function"},
	} {
		for _, dir := range []string{".", "internal/worker"} {
			t.Run(name+" from "+dir, func(t *testing.T) {
				root, tracked := writeFixture(t, tc.overrides, fixtureManifest())
				t.Chdir(filepath.Join(root, filepath.FromSlash(dir)))
				rel, err := filepath.Rel(filepath.Join(root, filepath.FromSlash(dir)), root)
				if err != nil {
					t.Fatal(err)
				}
				_, problems, err := Check(rel, tracked)
				if err != nil {
					t.Fatal(err)
				}
				if tc.want == "" && len(problems) > 0 {
					t.Fatalf("Check(%q) rejected the clean fixture:\n%s", rel, strings.Join(problems, "\n"))
				}
				if tc.want != "" && !slices.ContainsFunc(problems, func(p string) bool { return strings.Contains(p, tc.want) }) {
					t.Fatalf("Check(%q): want %q, got %v", rel, tc.want, problems)
				}
			})
		}
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
	store := func(extra string) map[string]string {
		return map[string]string{"internal/store/store.go": fixtureBase["internal/store/store.go"] + "\n" + extra + "\n"}
	}
	cases := []struct {
		name      string
		overrides map[string]string
		extra     string // a second C file in internal/worker
		manifest  func(map[string]any)
		want      string
	}{
		{name: "init function", overrides: withObserve("func init() {}"), want: "init function"},
		{name: "method on B type", overrides: withObserve("func (x *execution) helper() {}"), want: "method helper declared on *execution"},
		{name: "method on B type via alias", overrides: withObserve("type alias = execution\n\nfunc (a *alias) helper() {}"), want: "method helper declared on *alias"},
		// Review F2 mutant C: a value-receiver method on a C report type
		// silently changes how boundary code encodes the result.
		{name: "MarshalJSON on C type", overrides: withObserve("func (o Observation) MarshalJSON() ([]byte, error) { return []byte(`{\"state\":\"succeeded\"}`), nil }"), want: "method MarshalJSON declared on Observation"},
		{name: "String on C type", overrides: withObserve("func (o Observation) String() string { return \"\" }"), want: "method String declared on Observation"},
		{name: "Error on C type", overrides: withObserve("type obsError struct{}\n\nfunc (obsError) Error() string { return \"\" }"), want: "method Error declared on obsError"},
		// Review F2 mutant A: the observation rewrites what the boundary
		// executes after the toolchain guard.
		{name: "mutant A: rewrite the profile", overrides: withObserve("func tamper(x *execution) {\n\tx.profile.Executable = \"/bin/sh\"\n\tx.profile.DeveloperDir = \"/tmp\"\n}"), want: "assigns x.profile.Executable, which is rooted in x.profile of boundary type Profile"},
		{name: "mutant A: B pointer parameter", overrides: withObserve("func tamper(x *execution) {}"), want: "func tamper parameter x has type *execution, which can reference boundary state"},
		// Review F2 mutant B: the observation marks the job succeeded.
		{name: "mutant B: rewrite the result state", overrides: withObserve("func finish(r *Result) { r.State = \"succeeded\" }"), want: "assigns r.State, which is rooted in r of boundary type Result"},
		{name: "B value with references as parameter", overrides: withObserve("func args(p Profile) { a := p.Args; a[0] = \"rm\" }"), want: "parameter p has type Profile, which can reference boundary state"},
		{name: "B map parameter", overrides: withObserve("func runs(m map[string]*execution) {}"), want: "parameter m has type map[string]*execution"},
		{name: "B slice parameter", overrides: withObserve("func runs(s []Result) {}"), want: "parameter s has type []Result"},
		{name: "B interface parameter", overrides: withObserve("func runs(r Runner) {}"), want: "parameter r has type Runner"},
		{name: "func with B parameter", overrides: withObserve("func runs(f func(*execution) error) {}"), want: "parameter f has type func(*execution) error"},
		{name: "empty interface parameter", overrides: withObserve("func runs(v any) {}"), want: "parameter v has type any"},
		{name: "B pointer result", overrides: withObserve("func next() *execution { return nil }"), want: "result _ has type *execution"},
		{name: "C struct holding a B pointer", overrides: withObserve("type holder struct{ x *execution }\n\nfunc use(h holder) {}"), want: "parameter h has type holder"},
		{name: "closure capture", overrides: withObserve("func later(x *execution) func() { return func() { x.ran = nil } }"), want: "assigns x.ran, which is rooted in x of boundary type execution"},
		{name: "func literal with B parameter", overrides: withObserve("func later() { _ = func(x *execution) { x.ran = nil } }"), want: "func literal parameter x has type *execution"},
		{name: "write to C-local B value", overrides: withObserve("func local() { var p Profile; p.Args = nil }"), want: "assigns p.Args, which is rooted in p of boundary type Profile"},
		{name: "append to B-rooted slice", overrides: withObserve("func local() []string { var p Profile; return append(p.Args, \"x\") }"), want: "append writes p.Args, which is rooted in p of boundary type Profile"},
		{name: "copy into B-rooted slice", overrides: withObserve("func local() { var p Profile; copy(p.Args, []string{\"x\"}) }"), want: "copy writes p.Args, which is rooted in p of boundary type Profile"},
		{name: "send on B-rooted channel", overrides: withObserve("func local() { var x execution; x.done <- \"ok\" }"), want: "sends on x.done, which is rooted in x of boundary type execution"},
		{name: "pointer method call on B value", overrides: withObserve("func local(ctx context.Context) error { var x execution; return x.invoke(ctx, \"a\") }"), want: "calls pointer method invoke on x, which is rooted in x of boundary type execution"},
		{name: "pointer method value on B value", overrides: withObserve("func local() { var x execution; f := x.invoke; _ = f }"), want: "calls pointer method invoke on x"},
		{name: "address of B-rooted field", overrides: withObserve("func local() *string { var p Profile; return &p.Executable }"), want: "takes the address of p.Executable, which is rooted in p of boundary type Profile"},
		{name: "map alias of B package variable", overrides: withObserve("func alias() { r := Registry; r[\"k\"] = \"v\" }"), want: "uses package-level variable worker.Registry"},
		{name: "type assertion to B type", overrides: withObserve("func recover2(err error) { if e, ok := err.(*stateError); ok { _ = e } }"), want: "asserts to *stateError"},
		{name: "type switch to B type", overrides: withObserve("func recover2(err error) {\n\tswitch err.(type) {\n\tcase *stateError:\n\t}\n}"), want: "asserts to *stateError"},
		{name: "syscall import", extra: header + "import \"syscall\"\n\nfunc pid(context.Context) int { return syscall.Getpid() }\n", want: "imports syscall"},
		{name: "unsafe import", extra: header + "import \"unsafe\"\n\nfunc size(context.Context) uintptr { return unsafe.Sizeof(0) }\n", want: "imports unsafe"},
		{name: "os/exec import", extra: header + "import \"os/exec\"\n\nfunc run(ctx context.Context) error { return exec.CommandContext(ctx, \"true\").Run() }\n", want: "imports os/exec"},
		{name: "banned internal import", extra: header + "import \"" + fixtureModule + "/internal/hostguard\"\n\nfunc check(context.Context) error { return hostguard.Check() }\n", want: "imports " + fixtureModule + "/internal/hostguard"},
		{name: "linkname directive", extra: header + "import _ \"unsafe\"\n\n//go:linkname now time.now\nfunc now() (int64, int32, int64)\n\nfunc use(context.Context) { now() }\n", want: "compiler directive \"//go:linkname\""},
		{name: "generate directive", overrides: withObserve("//go:generate echo hi"), want: "compiler directive \"//go:generate\""},
		{name: "call to non-seam B method", overrides: withObserve("func q() func() error { var x execution; return x.quarantine }"), want: "quarantine, which is not C/G"},
		{name: "method expression of non-seam", overrides: withObserve("var q = (*execution).quarantine"), want: "quarantine, which is not C/G"},
		{name: "call to B function", overrides: withObserve("func r() error { return Root() }"), want: "worker.Root, which is not C/G"},
		{name: "call to non-allowlisted std", overrides: map[string]string{observe: strings.Replace(fixtureBase[observe], "\"strings\"", "\"os\"\n\t\"strings\"", 1) + "\nfunc pid() int { return os.Getpid() }\n"}, want: "uses os.Getpid"},
		{name: "package var initializer", overrides: withObserve("var computed = len(clip(\"a\", 1))"), want: "package-level var initializer"},
		{name: "assignment to B variable", overrides: withObserve("func set() { Hook = \"carry\" }"), want: "assigns package-level variable worker.Hook"},
		{name: "address of B variable", overrides: withObserve("func ref() *string { return &Hook }"), want: "takes the address of package-level variable worker.Hook"},
		{name: "assignment to std variable", overrides: store("func reset() { os.Args = nil }"), want: "assigns package-level variable os.Args"},
		{name: "std reference variable", overrides: store("func args() []string { return os.Args }"), want: "uses package-level variable os.Args"},
		{name: "non-root C calls B function", overrides: store("func l() int { return limit() }"), want: "store.limit, which is boundary code"},
		{name: "non-root C aliases B variable", overrides: store("func l() { Limits[0] = 9 }"), want: "uses package-level variable store.Limits"},
		{name: "call through B function variable", overrides: map[string]string{
			"internal/worker/exec.go": fixtureBase["internal/worker/exec.go"] + "\nvar hook = func() {}\n",
			observe:                   fixtureBase[observe] + "\nfunc h() { hook() }\n",
		}, want: "calls function value hook"},
		{name: "cgo file", extra: header + "// #include <stdio.h>\nimport \"C\"\n\nfunc f(context.Context) {}\n", want: "not part of the darwin/arm64 build"},
		{name: "excluded by build tag", extra: "//go:build linux\n\npackage worker\n\nfunc tagged() {}\n", want: "not part of the darwin/arm64 build"},
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
			overrides := tc.overrides
			if tc.extra != "" {
				const extra = "internal/worker/observe_extra.go"
				overrides = map[string]string{extra: tc.extra}
				classes := manifest["classes"].(map[string][]string)
				classes["C"] = append(classes["C"], extra)
			}
			problems := runFixture(t, overrides, manifest)
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

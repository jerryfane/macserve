package profiles_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
)

func recipe() model.Profile {
	return model.Profile{
		ID:           "example-unit-v1",
		Version:      1,
		Repo:         "example-org/example-app",
		Kind:         model.UnitTest,
		Xcode:        model.Xcode{Version: "26.0", Build: "17A100"},
		DeveloperDir: "/Applications/Xcode_26.0.app/Contents/Developer",
		Simulator: &model.Simulator{
			Runtime:      "com.apple.CoreSimulator.SimRuntime.iOS-26-0",
			RuntimeBuild: "23A100",
			DeviceType:   "com.apple.CoreSimulator.SimDeviceType.iPhone-16",
		},
		WorkDir: ".",
		Prepare: []model.Command{{Executable: "/usr/bin/true", Args: []string{"${CHECKOUT}"}}},
		Run: model.Command{Executable: "/usr/bin/xcrun", Args: []string{
			"xcodebuild", "test", "-derivedDataPath", "${DERIVED_DATA}",
			"-resultBundlePath", "${RESULT_BUNDLE}", "-destination", "id=${SIMULATOR_ID}",
		}},
		GeneratedFiles: []model.GeneratedFile{{Path: "Config/Test.xcconfig", Content: "TEST_ONLY = YES\n"}},
		Artifacts:      []model.ArtifactRule{{Path: "Results/*.xcresult", Required: true}},
		RequiredTests:  []string{"ExampleTests"},
	}
}

func request(p model.Profile) model.Request {
	var simulator *model.Simulator
	if p.Simulator != nil {
		copy := *p.Simulator
		simulator = &copy
	}
	return model.Request{
		Repo:      p.Repo,
		SHA:       strings.Repeat("aB", 20),
		Kind:      p.Kind,
		Profile:   p.ID,
		Xcode:     p.Xcode,
		Simulator: simulator,
	}
}

func registry(t *testing.T, p model.Profile) *profiles.Registry {
	t.Helper()
	r, err := profiles.New([]model.Profile{p})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func resolve(t *testing.T, r *profiles.Registry, req model.Request) model.Admission {
	t.Helper()
	a, err := r.Resolve(req)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestResolveCanonicalSnapshotAndDigest(t *testing.T) {
	p := recipe()
	p.Repo = "Example-Org/Example-App"
	r := registry(t, p)
	req := request(p)
	a := resolve(t, r, req)
	if a.Request.Repo != "example-org/example-app" || a.Profile.Repo != "example-org/example-app" || a.Request.SHA != strings.Repeat("ab", 20) {
		t.Fatalf("request not canonical: %+v", a)
	}
	if a.Request.TimeoutSeconds != 1800 || a.Profile.DefaultTimeoutSeconds != 1800 || a.Profile.MaxTimeoutSeconds != 3600 || a.Profile.MemoryLimitMiB != 32768 {
		t.Fatalf("resource normalization: %+v", a)
	}
	data, err := json.Marshal(a.Profile)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	if a.ProfileDigest != hex.EncodeToString(digest[:]) {
		t.Fatalf("digest is not the admitted recipe digest: %q", a.ProfileDigest)
	}
	canonical := a.Profile
	canonical.Run.Args = append([]string{}, canonical.Run.Args...)
	other := resolve(t, registry(t, canonical), request(canonical))
	if other.ProfileDigest != a.ProfileDigest {
		t.Fatal("equivalent normalized recipes have different digests")
	}
	canonical.GeneratedFiles[0].Content = "TEST_ONLY = NO\n"
	changed := resolve(t, registry(t, canonical), request(canonical))
	if changed.ProfileDigest == a.ProfileDigest {
		t.Fatal("recipe content change did not change digest")
	}
}

func TestResolveRejectsMismatches(t *testing.T) {
	p := recipe()
	r := registry(t, p)
	cases := []struct {
		name   string
		change func(*model.Request)
		want   error
	}{
		{"unknown profile", func(r *model.Request) { r.Profile = "unknown" }, profiles.ErrUnsupported},
		{"unknown repository", func(r *model.Request) { r.Repo = "example-org/other-app" }, profiles.ErrUnsupported},
		{"wrong kind", func(r *model.Request) { r.Kind = model.Build }, profiles.ErrUnsupported},
		{"archive reserved", func(r *model.Request) { r.Kind = "archive" }, profiles.ErrUnsupported},
		{"xcode version", func(r *model.Request) { r.Xcode.Version = "26.1" }, profiles.ErrUnsupported},
		{"xcode build", func(r *model.Request) { r.Xcode.Build = "17A101" }, profiles.ErrUnsupported},
		{"xcode alias", func(r *model.Request) { r.Xcode.Version = "latest" }, profiles.ErrUnsupported},
		{"runtime", func(r *model.Request) { r.Simulator.Runtime += "-1" }, profiles.ErrUnsupported},
		{"runtime build", func(r *model.Request) { r.Simulator.RuntimeBuild = "23A101" }, profiles.ErrUnsupported},
		{"device type", func(r *model.Request) { r.Simulator.DeviceType += "-Pro" }, profiles.ErrUnsupported},
		{"missing simulator", func(r *model.Request) { r.Simulator = nil }, profiles.ErrUnsupported},
		{"short SHA", func(r *model.Request) { r.SHA = "abcdef0" }, profiles.ErrInvalid},
		{"long SHA", func(r *model.Request) { r.SHA += "0" }, profiles.ErrInvalid},
		{"nonhex SHA", func(r *model.Request) { r.SHA = strings.Repeat("g", 40) }, profiles.ErrInvalid},
		{"branch ref", func(r *model.Request) { r.SHA = "refs/heads/main" }, profiles.ErrInvalid},
		{"repository URL", func(r *model.Request) { r.Repo = "https://github.com/example-org/example-app" }, profiles.ErrInvalid},
		{"repository traversal", func(r *model.Request) { r.Repo = "example-org/.." }, profiles.ErrInvalid},
		{"negative timeout", func(r *model.Request) { r.TimeoutSeconds = -1 }, profiles.ErrInvalid},
		{"over maximum timeout", func(r *model.Request) { r.TimeoutSeconds = 3601 }, profiles.ErrInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := request(p)
			tc.change(&req)
			if _, err := r.Resolve(req); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want error class %v", err, tc.want)
			}
		})
	}
}

func TestKindsDestinationsAndTimeoutBounds(t *testing.T) {
	for _, kind := range []model.Kind{model.Build, model.UnitTest, model.SimulatorUITest} {
		t.Run(string(kind), func(t *testing.T) {
			p := recipe()
			p.Kind = kind
			r := registry(t, p)
			wantDefault := 1800
			if kind == model.SimulatorUITest {
				wantDefault = 2400
			}
			for _, timeout := range []int{0, 1, 3600} {
				req := request(p)
				req.TimeoutSeconds = timeout
				a := resolve(t, r, req)
				want := timeout
				if want == 0 {
					want = wantDefault
				}
				if a.Request.TimeoutSeconds != want {
					t.Fatalf("timeout %d resolved to %d, want %d", timeout, a.Request.TimeoutSeconds, want)
				}
			}
		})
	}
	p := recipe()
	p.Kind = model.Build
	p.Simulator = nil
	p.RequiredTests = nil
	p.DefaultTimeoutSeconds = 60
	p.MaxTimeoutSeconds = 120
	p.MemoryLimitMiB = 4096
	r := registry(t, p)
	a := resolve(t, r, request(p))
	if a.Request.Simulator != nil || a.Request.TimeoutSeconds != 60 || a.Profile.MemoryLimitMiB != 4096 {
		t.Fatalf("non-simulator build overrides not preserved: %+v", a)
	}
	req := request(p)
	req.Simulator = recipe().Simulator
	if _, err := r.Resolve(req); !errors.Is(err, profiles.ErrUnsupported) {
		t.Fatalf("unexpected simulator accepted: %v", err)
	}
	req = request(p)
	req.TimeoutSeconds = 120
	resolve(t, r, req)
	req.TimeoutSeconds++
	if _, err := r.Resolve(req); !errors.Is(err, profiles.ErrInvalid) {
		t.Fatalf("profile-specific timeout maximum ignored: %v", err)
	}
}

func TestRejectInvalidRecipes(t *testing.T) {
	cases := []struct {
		name   string
		change func(*model.Profile)
	}{
		{"empty ID", func(p *model.Profile) { p.ID = "" }},
		{"version zero", func(p *model.Profile) { p.Version = 0 }},
		{"missing xcode version", func(p *model.Profile) { p.Xcode.Version = "" }},
		{"xcode alias", func(p *model.Profile) { p.Xcode.Version = "latest" }},
		{"missing xcode build", func(p *model.Profile) { p.Xcode.Build = "" }},
		{"build alias", func(p *model.Profile) { p.Xcode.Build = "stable" }},
		{"relative developer dir", func(p *model.Profile) { p.DeveloperDir = "Applications/Xcode.app" }},
		{"developer dir traversal", func(p *model.Profile) { p.DeveloperDir = "/Applications/../Other" }},
		{"developer dir substitution", func(p *model.Profile) { p.DeveloperDir = "/Applications/${JOB_ID}" }},
		{"missing runtime", func(p *model.Profile) { p.Simulator.Runtime = "" }},
		{"runtime alias", func(p *model.Profile) { p.Simulator.Runtime = "latest" }},
		{"missing runtime build", func(p *model.Profile) { p.Simulator.RuntimeBuild = "" }},
		{"missing device", func(p *model.Profile) { p.Simulator.DeviceType = "" }},
		{"test without simulator", func(p *model.Profile) { p.Simulator = nil }},
		{"test without required tests", func(p *model.Profile) { p.RequiredTests = nil }},
		{"empty required test", func(p *model.Profile) { p.RequiredTests = []string{" "} }},
		{"negative default timeout", func(p *model.Profile) { p.DefaultTimeoutSeconds = -1 }},
		{"default exceeds max", func(p *model.Profile) { p.DefaultTimeoutSeconds = 120; p.MaxTimeoutSeconds = 60 }},
		{"max timeout exceeds service limit", func(p *model.Profile) { p.MaxTimeoutSeconds = 3601 }},
		{"negative max timeout", func(p *model.Profile) { p.MaxTimeoutSeconds = -1 }},
		{"negative memory", func(p *model.Profile) { p.MemoryLimitMiB = -1 }},
		{"relative executable", func(p *model.Profile) { p.Run.Executable = "xcodebuild" }},
		{"executable substitution", func(p *model.Profile) { p.Run.Executable = "${CHECKOUT}/build" }},
		{"executable traversal", func(p *model.Profile) { p.Run.Executable = "/usr/bin/../other" }},
		{"unsafe prepare", func(p *model.Profile) { p.Prepare[0].Executable = "script" }},
		{"unknown placeholder", func(p *model.Profile) { p.Run.Args = []string{"${HOME}"} }},
		{"shell environment", func(p *model.Profile) { p.Run.Args = []string{"$HOME"} }},
		{"shell substitution", func(p *model.Profile) { p.Run.Args = []string{"$(whoami)"} }},
		{"unterminated placeholder", func(p *model.Profile) { p.Run.Args = []string{"${CHECKOUT"} }},
		{"placeholder suffix injection", func(p *model.Profile) { p.Run.Args = []string{"${CHECKOUT}${HOME}"} }},
		{"NUL argument", func(p *model.Profile) { p.Run.Args = []string{"a\x00b"} }},
		{"empty workdir", func(p *model.Profile) { p.WorkDir = "" }},
		{"malformed artifact glob", func(p *model.Profile) { p.Artifacts[0].Path = "Results/[" }},
		{"generated directory", func(p *model.Profile) { p.GeneratedFiles[0].Path = "." }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := recipe()
			tc.change(&p)
			if _, err := profiles.New([]model.Profile{p}); !errors.Is(err, profiles.ErrInvalid) {
				t.Fatalf("got %v, want invalid profile", err)
			}
		})
	}
	p := recipe()
	p.Kind = "archive"
	if _, err := profiles.New([]model.Profile{p}); !errors.Is(err, profiles.ErrUnsupported) {
		t.Fatalf("archive profile accepted: %v", err)
	}
	p = recipe()
	if _, err := profiles.New([]model.Profile{p, p}); !errors.Is(err, profiles.ErrInvalid) {
		t.Fatalf("duplicate profile IDs accepted: %v", err)
	}
}

func TestPathsCannotEscape(t *testing.T) {
	for _, value := range []string{"../outside", "sub/../../outside", "sub/../inside", "/absolute", "sub/\x00file", "${CHECKOUT}/file", "sub\\..\\outside"} {
		for _, field := range []string{"workdir", "generated", "artifact"} {
			t.Run(field+"/"+value, func(t *testing.T) {
				p := recipe()
				switch field {
				case "workdir":
					p.WorkDir = value
				case "generated":
					p.GeneratedFiles[0].Path = value
				case "artifact":
					p.Artifacts[0].Path = value
				}
				if _, err := profiles.New([]model.Profile{p}); !errors.Is(err, profiles.ErrInvalid) {
					t.Fatalf("unsafe %s path accepted: %v", field, err)
				}
			})
		}
	}
	p := recipe()
	p.WorkDir = "projects/app"
	p.Run.Args = []string{"${CHECKOUT}/${JOB_ID}", "${WORKSPACE}", "${DERIVED_DATA}", "${RESULT_BUNDLE}", "${SIMULATOR_ID}", "${DEVELOPER_DIR}"}
	r := registry(t, p)
	resolve(t, r, request(p))
}

func TestLoadStrictBoundedJSON(t *testing.T) {
	valid, err := json.Marshal(struct {
		Profiles []model.Profile `json:"profiles"`
	}{Profiles: []model.Profile{recipe()}})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		data string
	}{
		{"malformed", `{"profiles":[`},
		{"unknown top level", `{"profiles":[],"environment":{}}`},
		{"unknown profile field", strings.Replace(string(valid), `"version":1`, `"version":1,"environment":{"HOME":"/tmp"}`, 1)},
		{"unknown nested command", strings.Replace(string(valid), `"executable":"/usr/bin/true"`, `"executable":"/usr/bin/true","shell":true`, 1)},
		{"trailing value", string(valid) + ` {}`},
		{"trailing garbage", string(valid) + ` not-json`},
		{"missing profiles", `{}`},
		{"null profiles", `{"profiles":null}`},
		{"null document", `null`},
		{"oversized", string(valid) + strings.Repeat(" ", 1<<20)},
	}
	dir := t.TempDir()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			filename := filepath.Join(dir, "profiles.json")
			if err := os.WriteFile(filename, []byte(tc.data), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := profiles.Load(filename); !errors.Is(err, profiles.ErrInvalid) {
				t.Fatalf("got %v, want invalid configuration", err)
			}
		})
	}
	filename := filepath.Join(dir, "valid.json")
	// Exactly 1 MiB, including insignificant whitespace, is accepted.
	data := append(valid, []byte(strings.Repeat(" ", (1<<20)-len(valid)))...)
	if err := os.WriteFile(filename, data, 0600); err != nil {
		t.Fatal(err)
	}
	r, err := profiles.Load(filename)
	if err != nil {
		t.Fatal(err)
	}
	fromFile := resolve(t, r, request(recipe()))
	fromMemory := resolve(t, registry(t, recipe()), request(recipe()))
	if !reflect.DeepEqual(fromFile, fromMemory) {
		t.Fatal("loaded profile does not resolve like in-memory profile")
	}
	if err := os.WriteFile(filename, []byte(`{"profiles":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	empty, err := profiles.Load(filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := empty.Resolve(request(recipe())); !errors.Is(err, profiles.ErrUnsupported) {
		t.Fatalf("empty registry admitted a request: %v", err)
	}
	if _, err := profiles.Load(filepath.Join(dir, "missing.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("file error not preserved: %v", err)
	}
}

func TestImmutableSnapshots(t *testing.T) {
	original := recipe()
	req := request(original)
	r := registry(t, original)
	baseline := resolve(t, r, req)
	first := resolve(t, r, req)
	mutate := func(p *model.Profile) {
		p.Repo = "example-org/other-app"
		p.Simulator.Runtime = "changed"
		p.Run.Args[0] = "changed"
		p.Prepare[0].Executable = "/other"
		p.Prepare[0].Args[0] = "changed"
		p.GeneratedFiles[0].Content = "changed"
		p.Artifacts[0].Path = "changed"
		p.RequiredTests[0] = "changed"
	}
	mutate(&original)
	listed := r.List()
	mutate(&listed[0])
	req.Simulator.Runtime = "changed"
	if !reflect.DeepEqual(first, baseline) {
		t.Fatal("input or list mutation changed a previously resolved admission")
	}
	mutate(&first.Profile)
	if first.Request.Simulator.Runtime != baseline.Request.Simulator.Runtime {
		t.Fatal("profile mutation changed admission request simulator")
	}
	first.Request.Simulator.Runtime = "changed"
	fresh := resolve(t, r, request(recipe()))
	if !reflect.DeepEqual(fresh, baseline) {
		t.Fatal("caller mutation changed registry storage")
	}
	if !reflect.DeepEqual(r.List()[0], baseline.Profile) {
		t.Fatal("registry list no longer matches admitted recipe")
	}
}

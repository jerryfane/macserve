package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/checks/boundary"
)

// fixtureBoundary classifies the fixture module: the root binary links
// internal/lib (B) and internal/lib/c.go (C); the controller is K.
const fixtureBoundary = `{
  "schema": 2,
  "classes": {
    "B": ["BOUNDARY.json", "go.mod", "cmd/macserve/**", "internal/lib/**", ".github/**"],
    "G": [],
    "C": ["internal/lib/c.go"],
    "T": ["docs/**"],
    "K": ["cmd/macserve-controller/**", "internal/controllerk/**"]
  },
  "seams": {},
  "g_calls": {},
  "k_packages": ["cmd/macserve-controller", "internal/controllerk/store"],
  "k_allowed_imports": ["internal/lib"],
  "binaries": {
    "macserve": {"package": "cmd/macserve", "classes": ["B", "G", "C"]},
    "macserve-controller": {"package": "cmd/macserve-controller", "classes": ["B", "G", "C", "K"]}
  }
}
`

func fixtureFiles(schema int) map[string]string {
	return map[string]string{
		"BOUNDARY.json":          fixtureBoundary,
		"go.mod":                 "module example.com/fixture\n\ngo 1.22\n",
		"cmd/macserve/main.go":   "package main\n\nimport \"example.com/fixture/internal/lib\"\n\nfunc main() { println(lib.Name()) }\n",
		"internal/lib/lib.go":    "package lib\n\nfunc Name() string { return \"root\" }\n",
		"internal/lib/c.go":      "package lib\n\nconst Carried = 1\n",
		"internal/lib/x_test.go": "package lib\n",
		"cmd/macserve-controller/main.go": "package main\n\nimport (\n\t\"fmt\"\n\n\t\"example.com/fixture/internal/controllerk/store\"\n)\n\n" +
			"func main() { fmt.Printf(\"{\\\"version\\\":\\\"(devel)\\\",\\\"commit\\\":\\\"\\\",\\\"store_schema_version\\\":%d}\\n\", store.SchemaVersion) }\n",
		"internal/controllerk/store/store.go": fmt.Sprintf("package store\n\nconst SchemaVersion = %d\n", schema),
		"docs/release.md":                     "# release\n",
	}
}

type fixture struct {
	t    *testing.T
	dir  string
	dist string
	sums string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	f := &fixture{t: t, dir: t.TempDir(), dist: t.TempDir()}
	f.git("init", "-q", "-b", "main")
	f.write(fixtureFiles(6))
	f.commit("base")
	f.git("tag", "-a", "-m", "v1.0.0: base", "v1.0.0")
	// Base release: its root binary bytes and SHA256SUMS.
	root := []byte("root binary built from v1.0.0")
	f.sums = filepath.Join(t.TempDir(), "SHA256SUMS")
	if err := os.WriteFile(f.sums, []byte(sha256Hex(root)+"  "+RootAsset+"\n"+sha256Hex([]byte("old controller"))+"  "+ControllerAsset+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.dist = t.TempDir()
	f.writeDist(root, []byte("controller binary built from v1.1.0"))
	return f
}

func (f *fixture) git(args ...string) string {
	f.t.Helper()
	cmd := exec.Command("git", append([]string{"-C", f.dir, "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "tag.gpgSign=false", "-c", "commit.gpgSign=false"}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		f.t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func (f *fixture) write(files map[string]string) {
	f.t.Helper()
	for name, content := range files {
		p := filepath.Join(f.dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			f.t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			f.t.Fatal(err)
		}
	}
}

func (f *fixture) commit(msg string) string {
	f.git("add", "-A")
	f.git("commit", "-q", "--allow-empty", "-m", msg)
	return f.git("rev-parse", "HEAD")
}

// release commits files changed over the base and tags v1.1.0 with message.
func (f *fixture) release(files map[string]string, message string) string {
	f.write(files)
	commit := f.commit("change")
	f.git("tag", "-a", "-m", message, "v1.1.0")
	return commit
}

func (f *fixture) writeDist(root, controller []byte) {
	f.t.Helper()
	for name, data := range map[string][]byte{RootAsset: root, ControllerAsset: controller} {
		if err := os.WriteFile(filepath.Join(f.dist, name), data, 0o644); err != nil {
			f.t.Fatal(err)
		}
	}
}

// fakeSchema reads SchemaVersion from the tree's store package, like the
// tree's own `macserve-controller version --json` would print.
func fakeSchema(_ context.Context, dir string) (int, error) {
	data, err := os.ReadFile(filepath.Join(dir, "internal/controllerk/store/store.go"))
	if err != nil {
		return 0, err
	}
	_, value, ok := strings.Cut(string(data), "SchemaVersion = ")
	if !ok {
		return 0, errors.New("no SchemaVersion")
	}
	return strconv.Atoi(strings.TrimSpace(value))
}

func (f *fixture) params(commit string) createParams {
	return createParams{
		gitDir: f.dir, tag: "v1.1.0", commit: commit, dist: f.dist,
		baseTag: "v1.0.0", baseSums: f.sums,
		now:    time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC),
		list:   goListDeps,
		schema: fakeSchema,
		check:  func(string, []boundary.File) error { return nil },
	}
}

func requireRefusal(t *testing.T, err error, want string) {
	t.Helper()
	var r *refusal
	if !errors.As(err, &r) {
		t.Fatalf("err = %v, want a refusal containing %q", err, want)
	}
	if !strings.Contains(r.reason, want) {
		t.Fatalf("refusal %q, want %q", r.reason, want)
	}
}

func TestCreateFull(t *testing.T) {
	f := newFixture(t)
	commit := f.release(map[string]string{"cmd/macserve/main.go": "package main\n\nfunc main() {}\n"}, "v1.1.0: full")
	p := f.params(commit)
	p.baseTag, p.baseSums = "", ""
	p.schema = controllerSchema // the tree's own controller, run on this host
	p.binarySchema = 6
	m, err := create(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	want := Manifest{
		Schema: Schema, Tag: "v1.1.0", Commit: commit, Kind: KindFull, BaseTag: "v1.1.0",
		Binaries: Binaries{
			Macserve:   Digest{SHA256: sha256Hex([]byte("root binary built from v1.0.0"))},
			Controller: Digest{SHA256: sha256Hex([]byte("controller binary built from v1.1.0"))},
		},
		StoreSchemaVersion: 6, CreatedAt: "2026-11-07T12:00:00Z",
	}
	if m != want {
		t.Fatalf("manifest %+v\nwant %+v", m, want)
	}

	p.binarySchema = 7
	_, err = create(context.Background(), p)
	requireRefusal(t, err, "reports store schema version 7")

	p.binarySchema = 0
	p.commit = strings.Repeat("0", 40)
	_, err = create(context.Background(), p)
	requireRefusal(t, err, "not the built commit")
}

func TestCreateCarry(t *testing.T) {
	f := newFixture(t)
	commit := f.release(map[string]string{
		"internal/controllerk/store/store.go": "package store\n\n// SchemaVersion is unchanged.\nconst SchemaVersion = 6\n",
		"cmd/macserve-controller/extra.go":    "package main\n",
		"docs/release.md":                     "# release, revised\n",
	}, "v1.1.0: controller fix\n\nMacserve-Carry-Base: v1.0.0\n")
	base, err := carryBase(gitRepo{dir: f.dir}, "v1.1.0")
	if err != nil || base != "v1.0.0" {
		t.Fatalf("carryBase = %q, %v", base, err)
	}
	m, err := create(context.Background(), f.params(commit))
	if err != nil {
		t.Fatal(err)
	}
	if m.Kind != KindCarry || m.BaseTag != "v1.0.0" || m.Binaries.Macserve.SHA256 != sha256Hex([]byte("root binary built from v1.0.0")) || m.StoreSchemaVersion != 6 {
		t.Fatalf("manifest %+v", m)
	}
	data, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(testKey(), data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(testKey().Public().(ed25519.PublicKey), data, sig); err != nil {
		t.Fatal(err)
	}
}

func TestCreateCarryRefusals(t *testing.T) {
	carryTag := "v1.1.0: carry\n\nMacserve-Carry-Base: v1.0.0\n"
	for name, tc := range map[string]struct {
		files  map[string]string
		adjust func(f *fixture, p *createParams)
		want   string
	}{
		"closure: C file the root binary links": {
			files: map[string]string{"internal/lib/c.go": "package lib\n\nconst Carried = 2\n"},
			want:  "source closure of ./cmd/macserve differs",
		},
		"closure: go list fake links one more dependency module": {
			files: map[string]string{"cmd/macserve-controller/extra.go": "package main\n"},
			adjust: func(f *fixture, p *createParams) {
				// go list fake: the new tree links one more dependency module.
				p.list = func(ctx context.Context, dir string) ([]listedPackage, error) {
					pkgs, err := goListDeps(ctx, dir)
					if strings.HasSuffix(dir, "new") {
						pkgs = append(pkgs, listedPackage{ImportPath: "golang.org/x/sys/unix", Module: &listedModule{Path: "golang.org/x/sys", Version: "v0.48.0"}})
					}
					return pkgs, err
				}
			},
			want: "module golang.org/x/sys@v0.48.0",
		},
		"closure: dependency version": {
			files: map[string]string{"docs/release.md": "# changed\n"},
			adjust: func(f *fixture, p *createParams) {
				p.list = func(ctx context.Context, dir string) ([]listedPackage, error) {
					version := "v1.0.0"
					if strings.HasSuffix(dir, "new") {
						version = "v1.0.1"
					}
					return []listedPackage{
						{ImportPath: "fmt", Standard: true},
						{ImportPath: "example.com/dep", Module: &listedModule{Path: "example.com/dep", Version: version}},
					}, nil
				}
			},
			want: "module example.com/dep@v1.0.1",
		},
		"store schema": {
			files: map[string]string{"internal/controllerk/store/store.go": "package store\n\nconst SchemaVersion = 7\n"},
			want:  "store schema version 7 of v1.1.0 differs from 6 of v1.0.0",
		},
		"B path": {
			files: map[string]string{".github/workflows/release.yml": "name: x\n"},
			want:  ".github/workflows/release.yml is class B",
		},
		"root package (B) change": {
			files: map[string]string{"cmd/macserve/main.go": "package main\n\nfunc main() {}\n"},
			want:  "cmd/macserve/main.go is class B",
		},
		"unclassified path": {
			files: map[string]string{"stray.txt": "x\n"},
			want:  "stray.txt",
		},
		"boundary manifest changed": {
			files: map[string]string{"BOUNDARY.json": strings.Replace(fixtureBoundary, `"docs/**"`, `"docs/**", "notes/**"`, 1)},
			want:  "changes BOUNDARY.json",
		},
		"root binary is not base's": {
			files: map[string]string{"docs/release.md": "# changed\n"},
			adjust: func(f *fixture, p *createParams) {
				f.writeDist([]byte("root binary built from v1.1.0"), []byte("controller"))
			},
			want: "not v1.0.0's published",
		},
		"boundary check fails": {
			files: map[string]string{"docs/release.md": "# changed\n"},
			adjust: func(f *fixture, p *createParams) {
				p.check = func(string, []boundary.File) error { return refuse("boundary check: K imports B") }
			},
			want: "boundary check: K imports B",
		},
		"base is a carry": {
			files: map[string]string{"docs/release.md": "# changed\n"},
			adjust: func(f *fixture, p *createParams) {
				base := goldenManifest()
				base.Tag, base.BaseTag = "v1.0.0", "v0.9.0"
				base.Commit = f.git("rev-parse", "v1.0.0^{commit}")
				base.Binaries.Macserve.SHA256 = sha256Hex([]byte("root binary built from v1.0.0"))
				data, err := Encode(base)
				if err != nil {
					f.t.Fatal(err)
				}
				p.baseManifest = filepath.Join(f.t.TempDir(), ManifestAsset)
				if err := os.WriteFile(p.baseManifest, data, 0o644); err != nil {
					f.t.Fatal(err)
				}
				sums, _ := os.ReadFile(f.sums)
				sums = append(sums, []byte(sha256Hex(data)+"  "+ManifestAsset+"\n")...)
				if err := os.WriteFile(f.sums, sums, 0o644); err != nil {
					f.t.Fatal(err)
				}
			},
			want: "a carry's base must be a full release",
		},
		"base manifest not in SHA256SUMS": {
			files: map[string]string{"docs/release.md": "# changed\n"},
			adjust: func(f *fixture, p *createParams) {
				p.baseManifest = filepath.Join(f.t.TempDir(), ManifestAsset)
				if err := os.WriteFile(p.baseManifest, []byte("{}\n"), 0o644); err != nil {
					f.t.Fatal(err)
				}
			},
			want: "SHA256SUMS has no release-manifest.json entry",
		},
		"base does not precede": {
			files: map[string]string{"docs/release.md": "# changed\n"},
			adjust: func(f *fixture, p *createParams) {
				f.git("tag", "-a", "-m", "later", "v1.2.0", "v1.0.0")
				p.baseTag = "v1.2.0"
			},
			want: "does not precede",
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			p := f.params(f.release(tc.files, carryTag))
			if tc.adjust != nil {
				tc.adjust(f, &p)
			}
			_, err := create(context.Background(), p)
			requireRefusal(t, err, tc.want)
		})
	}
}

func TestCarryBase(t *testing.T) {
	f := newFixture(t)
	f.commit("next")
	g := gitRepo{dir: f.dir}
	for name, tc := range map[string]struct {
		message string
		want    string
		err     bool
	}{
		"full":         {message: "v1.1.0: notes mentioning Macserve-Carry-Base: in prose", want: ""},
		"carry":        {message: "v1.1.0\n\nMacserve-Carry-Base: v1.0.0\n", want: "v1.0.0"},
		"two trailers": {message: "v1.1.0\n\nMacserve-Carry-Base: v1.0.0\nMacserve-Carry-Base: v0.9.0\n", err: true},
		"not semver":   {message: "v1.1.0\n\nMacserve-Carry-Base: main\n", err: true},
		"lightweight":  {want: ""},
	} {
		if tc.message == "" {
			f.git("tag", "v1.1.0")
		} else {
			f.git("tag", "-a", "-m", tc.message, "v1.1.0")
		}
		got, err := carryBase(g, "v1.1.0")
		if (err != nil) != tc.err || got != tc.want {
			t.Errorf("%s: carryBase = %q, %v", name, got, err)
		}
		f.git("tag", "-d", "v1.1.0")
	}
}

func TestClosureCoversRootFiles(t *testing.T) {
	f := newFixture(t)
	entries, err := closure(context.Background(), f.dir, goListDeps)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"go.mod", "go.sum", "file cmd/macserve/main.go", "file internal/lib/lib.go", "file internal/lib/c.go", "package example.com/fixture/internal/lib"} {
		if _, ok := entries[key]; !ok {
			t.Errorf("closure lacks %q: %v", key, entries)
		}
	}
	for key := range entries {
		if strings.Contains(key, "controllerk") || strings.Contains(key, "_test.go") || strings.Contains(key, "docs/") {
			t.Errorf("closure has %q", key)
		}
	}
	if entries["go.sum"] != "absent" {
		t.Errorf("go.sum = %q", entries["go.sum"])
	}
	before := closureDigest(entries)
	f.write(map[string]string{"internal/lib/lib.go": "package lib\n\nfunc Name() string { return \"other\" }\n"})
	after, err := closure(context.Background(), f.dir, goListDeps)
	if err != nil {
		t.Fatal(err)
	}
	if closureDigest(after) == before || !bytes.Equal([]byte(strings.Join(closureDiff(entries, after), ",")), []byte("file internal/lib/lib.go")) {
		t.Fatalf("diff = %v", closureDiff(entries, after))
	}
}

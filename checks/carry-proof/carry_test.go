package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/qualification"
)

var update = flag.Bool("update", false, "rewrite testdata/golden-proof.json")

const (
	testRepo  = "jerryfane/macserve"
	testToken = "test-token"
	prevTag   = "v0.1.0"
	nextTag   = "v0.2.0"
)

var (
	fromBinary = digest("macserve v0.1.0")
	toBinary   = digest("macserve v0.2.0")
)

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// file is one fixture file: content with mode 0644 or 0755, or a symlink.
type file struct {
	content string
	exec    bool
	link    string
}

func fixtureManifest(t *testing.T, extraT ...string) string {
	t.Helper()
	data, err := json.Marshal(map[string]any{
		"schema": 1,
		"classes": map[string][]string{
			"B": {"BOUNDARY.json", "go.mod", "internal/**"},
			"G": {},
			"C": {"internal/evidence/types.go"},
			"T": append([]string{"README.md", "docs/**"}, extraT...),
		},
		"seams":   map[string][]string{},
		"g_calls": map[string][]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(data) + "\n"
}

func baseFiles(t *testing.T) map[string]*file {
	return map[string]*file{
		"BOUNDARY.json":              {content: fixtureManifest(t)},
		"go.mod":                     {content: "module example.com/fixture\n\ngo 1.26\n"},
		"README.md":                  {content: "fixture\n"},
		"docs/run.sh":                {content: "#!/bin/sh\necho fixture\n", exec: true},
		"internal/evidence/types.go": {content: "package evidence\n\n// Version names the fixture.\nfunc Version() string { return \"1\" }\n"},
		"internal/store/store.go":    {content: "package store\n\nfunc Name() string { return \"store\" }\n"},
	}
}

// carryChanges is the golden release: one C and one T change.
func carryChanges() map[string]*file {
	return map[string]*file{
		"internal/evidence/types.go": {content: "package evidence\n\n// Version names the fixture.\nfunc Version() string { return \"2\" }\n"},
		"README.md":                  {content: "fixture, release two\n"},
	}
}

type fixture struct {
	t      *testing.T
	dir    string
	served map[string][]byte
	header map[string]http.Header
}

func (f *fixture) git(date string, args ...string) string {
	f.t.Helper()
	cmd := exec.Command("git", append([]string{"-C", f.dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=Fixture", "GIT_AUTHOR_EMAIL=fixture@example.com", "GIT_AUTHOR_DATE="+date,
		"GIT_COMMITTER_NAME=Fixture", "GIT_COMMITTER_EMAIL=fixture@example.com", "GIT_COMMITTER_DATE="+date,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		f.t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func (f *fixture) write(files map[string]*file) {
	f.t.Helper()
	for name, spec := range files {
		full := filepath.Join(f.dir, filepath.FromSlash(name))
		if err := os.RemoveAll(full); err != nil {
			f.t.Fatal(err)
		}
		if spec == nil {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			f.t.Fatal(err)
		}
		var err error
		switch {
		case spec.link != "":
			err = os.Symlink(spec.link, full)
		case spec.exec:
			err = os.WriteFile(full, []byte(spec.content), 0o755)
		default:
			err = os.WriteFile(full, []byte(spec.content), 0o644)
		}
		if err != nil {
			f.t.Fatal(err)
		}
	}
}

func (f *fixture) release(tag, date string, files map[string]*file) {
	f.t.Helper()
	f.write(files)
	f.git(date, "add", "-A")
	f.git(date, "commit", "-q", "--allow-empty", "-m", "release "+tag)
	f.git(date, "tag", "-a", "-m", tag, tag)
}

// archive is the codeload archive of tag: git archive, gzipped.
func (f *fixture) archive(tag string) []byte {
	f.t.Helper()
	cmd := exec.Command("git", "-C", f.dir, "archive", "--format=tar", "--prefix=macserve-"+strings.TrimPrefix(tag, "v")+"/", tag)
	tarball, err := cmd.Output()
	if err != nil {
		f.t.Fatal(err)
	}
	return gzipBytes(f.t, tarball)
}

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func codeloadURL(tag string) string {
	return "https://codeload.github.com/" + testRepo + "/tar.gz/refs/tags/" + tag
}

func ciURL(commit string) string {
	return "https://api.github.com/repos/" + testRepo + "/actions/workflows/ci.yml/runs?head_sha=" + commit + "&per_page=100&status=success"
}

func ciRuns(commit string) []byte {
	return []byte(fmt.Sprintf(`{"total_count":2,"workflow_runs":[`+
		`{"id":41,"name":"CI","path":".github/workflows/ci.yml","head_sha":%q,"status":"completed","conclusion":"success","repository":{"full_name":%q}},`+
		`{"id":4242,"name":"CI","path":".github/workflows/ci.yml","head_sha":%q,"status":"completed","conclusion":"success","repository":{"full_name":%q}}]}`,
		commit, testRepo, commit, testRepo))
}

// newFixture builds a repository with v0.1.0 (base, after edits to it) and
// v0.2.0 (changes on top), and serves both releases' GitHub endpoints.
func newFixture(t *testing.T, base, changes map[string]*file) *fixture {
	t.Helper()
	f := &fixture{t: t, dir: t.TempDir(), served: map[string][]byte{}, header: map[string]http.Header{}}
	f.git("", "init", "-q", "-b", "main")
	f.release(prevTag, "2026-01-01T00:00:00Z", base)
	f.release(nextTag, "2026-02-01T00:00:00Z", changes)
	f.served["https://github.com/"+testRepo+"/releases/download/"+prevTag+"/SHA256SUMS"] = []byte(fromBinary + "  " + releaseAsset + "\n" + digest("rb") + "  macserve.rb\n")
	f.served[codeloadURL(prevTag)] = f.archive(prevTag)
	f.served[codeloadURL(nextTag)] = f.archive(nextTag)
	f.served[ciURL(f.git("", "rev-parse", nextTag+"^{commit}"))] = ciRuns(f.git("", "rev-parse", nextTag+"^{commit}"))
	return f
}

func (f *fixture) get(_ context.Context, u string, header http.Header) ([]byte, error) {
	f.header[u] = header
	body, ok := f.served[u]
	if !ok {
		return nil, fmt.Errorf("GET %s: 404 Not Found", u)
	}
	return body, nil
}

// run runs the command and returns its exit code, stdout and the proof
// bytes (nil when no file was written).
func (f *fixture) run(extra ...string) (int, string, []byte) {
	f.t.Helper()
	out := filepath.Join(f.t.TempDir(), "carry-proof.json")
	args := append([]string{"-repo", testRepo, "-tag", nextTag, "-binary-sha256", toBinary, "-rebuilt-sha256", toBinary, "-out", out, "-git", f.dir}, extra...)
	var stdout, stderr bytes.Buffer
	getenv := func(k string) string {
		if k == "GH_TOKEN" {
			return testToken
		}
		return ""
	}
	code := run(context.Background(), args, &stdout, &stderr, getenv, f.get)
	if stderr.Len() > 0 {
		f.t.Logf("stderr: %s", stderr.String())
	}
	data, err := os.ReadFile(out)
	if errors.Is(err, os.ErrNotExist) {
		return code, stdout.String(), nil
	}
	if err != nil {
		f.t.Fatal(err)
	}
	return code, stdout.String(), data
}

func TestCarryProofGolden(t *testing.T) {
	f := newFixture(t, baseFiles(t), carryChanges())
	code, stdout, data := f.run()
	if code != 0 || data == nil {
		t.Fatalf("exit %d, no proof: %s", code, stdout)
	}
	// The proof passes qualify carry's own checks, from the predecessor's
	// published binary to this release's.
	proof, err := qualification.ValidateCarryProof(data, fromBinary, toBinary)
	if err != nil {
		t.Fatalf("ValidateCarryProof: %v\n%s", err, data)
	}
	if want := digest(string(f.served[codeloadURL(prevTag)])); proof.From.SourceSHA256 != want {
		t.Fatalf("from source_sha256 %s, want the served archive's %s", proof.From.SourceSHA256, want)
	}
	if want := digest(string(f.served[codeloadURL(nextTag)])); proof.To.SourceSHA256 != want {
		t.Fatalf("to source_sha256 %s, want the served archive's %s", proof.To.SourceSHA256, want)
	}
	if got := f.header[ciURL(proof.To.Commit)].Get("Authorization"); got != "Bearer "+testToken {
		t.Fatalf("CI runs request Authorization %q", got)
	}
	// Everything but the archive digests (gzip output of the test's git and
	// Go) is fixed by the deterministic repository.
	var normalized qualification.CarryProof
	if err := json.Unmarshal(data, &normalized); err != nil {
		t.Fatal(err)
	}
	normalized.From.SourceSHA256 = "sha256 of the served v0.1.0 archive"
	normalized.To.SourceSHA256 = "sha256 of the served v0.2.0 archive"
	got, err := json.MarshalIndent(normalized, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	golden := filepath.Join("testdata", "golden-proof.json")
	if *update {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("proof differs from %s:\n%s", golden, got)
	}
	if !bytes.Equal(data, append(must(json.MarshalIndent(proof, "", "  ")), '\n')) {
		t.Fatal("proof is not canonical MarshalIndent output")
	}
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

func TestCarryProofTOnly(t *testing.T) {
	f := newFixture(t, baseFiles(t), map[string]*file{"docs/guide.md": {content: "guide\n"}})
	code, stdout, data := f.run()
	if code != 0 || data == nil {
		t.Fatalf("exit %d, no proof: %s", code, stdout)
	}
	proof, err := qualification.ValidateCarryProof(data, fromBinary, toBinary)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof.Changed) != 1 || proof.Changed[0].Path != "docs/guide.md" || proof.Changed[0].Old != nil || proof.Changed[0].New[0] != "100644" {
		t.Fatalf("changed %+v", proof.Changed)
	}
}

func TestNoCarryProof(t *testing.T) {
	tests := []struct {
		name    string
		base    func(map[string]*file)
		changes map[string]*file
		serve   func(*fixture)
		want    string
	}{
		{
			name:    "B change",
			changes: map[string]*file{"internal/store/store.go": {content: "package store\n\nfunc Name() string { return \"store2\" }\n"}},
			want:    "internal/store/store.go is class B",
		},
		{
			name:    "unlisted path",
			changes: map[string]*file{"extra.txt": {content: "x\n"}},
			want:    "extra.txt: not classified in BOUNDARY.json (default-deny)",
		},
		{
			name:    "predecessor without BOUNDARY.json",
			base:    func(m map[string]*file) { delete(m, "BOUNDARY.json") },
			changes: map[string]*file{"BOUNDARY.json": {content: "{}\n"}, "README.md": {content: "two\n"}},
			want:    "v0.1.0 has no BOUNDARY.json",
		},
		{
			name:    "BOUNDARY.json changed",
			changes: map[string]*file{"BOUNDARY.json": {content: fixtureManifest(t, "notes/**")}, "README.md": {content: "two\n"}},
			want:    "v0.2.0 changes BOUNDARY.json",
		},
		{
			name:    "symlink added",
			changes: map[string]*file{"docs/link": {link: "../README.md"}},
			want:    "docs/link: mode 120000 change is not carryable",
		},
		{
			name:    "mode change to symlink",
			changes: map[string]*file{"README.md": {link: "docs/run.sh"}},
			want:    "README.md: mode 120000 change is not carryable",
		},
		{
			name:    "no change",
			changes: map[string]*file{},
			want:    "no path changed",
		},
		{
			name:    "codeload archive differs from the git tree",
			changes: carryChanges(),
			serve: func(f *fixture) {
				f.served[codeloadURL(nextTag)] = tamper(f.t, f.served[codeloadURL(nextTag)], "macserve-0.2.0/README.md", "tampered\n")
			},
			want: "v0.2.0 source archive differs from the git tree at README.md",
		},
		{
			name:    "codeload archive has an extra file",
			changes: carryChanges(),
			serve: func(f *fixture) {
				f.served[codeloadURL(prevTag)] = tamper(f.t, f.served[codeloadURL(prevTag)], "macserve-0.1.0/docs/extra.md", "extra\n")
			},
			want: "v0.1.0 source archive has docs/extra.md, absent from the git tree",
		},
		{
			name:    "codeload archive unavailable",
			changes: carryChanges(),
			serve:   func(f *fixture) { delete(f.served, codeloadURL(nextTag)) },
			want:    "v0.2.0 source archive: GET",
		},
		{
			name:    "CI run missing",
			changes: carryChanges(),
			serve: func(f *fixture) {
				commit := f.git("", "rev-parse", nextTag+"^{commit}")
				f.served[ciURL(commit)] = []byte(`{"total_count":0,"workflow_runs":[]}`)
			},
			want: "no successful .github/workflows/ci.yml run on",
		},
		{
			name:    "CI run on another commit",
			changes: carryChanges(),
			serve: func(f *fixture) {
				commit := f.git("", "rev-parse", nextTag+"^{commit}")
				f.served[ciURL(commit)] = ciRuns(f.git("", "rev-parse", prevTag+"^{commit}"))
			},
			want: "no successful .github/workflows/ci.yml run on",
		},
		{
			name:    "predecessor SHA256SUMS without the binary",
			changes: carryChanges(),
			serve: func(f *fixture) {
				f.served["https://github.com/"+testRepo+"/releases/download/"+prevTag+"/SHA256SUMS"] = []byte(digest("rb") + "  macserve.rb\n")
			},
			want: "v0.1.0 SHA256SUMS: lists macserve-darwin-arm64 0 times",
		},
		{
			name:    "same binary as the predecessor",
			changes: carryChanges(),
			serve: func(f *fixture) {
				f.served["https://github.com/"+testRepo+"/releases/download/"+prevTag+"/SHA256SUMS"] = []byte(toBinary + "  " + releaseAsset + "\n")
			},
			want: "v0.1.0 and v0.2.0 publish the same binary",
		},
		{
			name:    "C source breaks the boundary rules",
			changes: map[string]*file{"internal/evidence/types.go": {content: "package evidence\n\nimport \"os/exec\"\n\nfunc Version() string { return exec.Command(\"true\").Path }\n"}},
			want:    "imports os/exec",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			base := baseFiles(t)
			if tc.base != nil {
				tc.base(base)
			}
			f := newFixture(t, base, tc.changes)
			if tc.serve != nil {
				tc.serve(f)
			}
			code, stdout, data := f.run()
			if code != 0 || data != nil {
				t.Fatalf("exit %d, proof written: %s", code, data)
			}
			if !strings.HasPrefix(stdout, "no carry proof: ") || !strings.Contains(stdout, tc.want) {
				t.Fatalf("stdout %q, want a refusal containing %q", stdout, tc.want)
			}
		})
	}
}

// tamper rewrites a gzipped tar, setting name's content (adding it if
// absent).
func tamper(t *testing.T, archive []byte, name, content string) []byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	replaced := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		if hdr.Name == name {
			body, replaced = []byte(content), true
			hdr.Size = int64(len(body))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if !replaced {
		hdr := &tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(content))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return gzipBytes(t, buf.Bytes())
}

func TestOperationalAndUsageErrors(t *testing.T) {
	f := newFixture(t, baseFiles(t), carryChanges())
	if code, _, data := f.run("-rebuilt-sha256", digest("other")); code != 1 || data != nil {
		t.Fatalf("binary differing from the rebuild: exit %d, proof %v", code, data != nil)
	}
	if code, _, _ := f.run("-prev", "0.1.0"); code != 2 {
		t.Fatalf("malformed -prev: exit %d", code)
	}
	if code, _, _ := f.run("-binary-sha256", "ABC"); code != 2 {
		t.Fatalf("malformed -binary-sha256: exit %d", code)
	}
	if code, _, _ := f.run("-prev", "v0.0.9"); code != 1 {
		t.Fatalf("missing predecessor tag: exit %d", code)
	}
	if code, stdout, _ := f.run("-prev", "v0.3.0"); code != 0 || !strings.Contains(stdout, "predecessor v0.3.0 does not precede v0.2.0") {
		t.Fatalf("later -prev: exit %d %q", code, stdout)
	}
}

func TestPredecessor(t *testing.T) {
	tags := []string{"v0.1.9", "v0.1.10", "v0.2.0", "v0.10.0", "v1.0.0-rc1", "v0.1.11x", "latest"}
	for tag, want := range map[string]string{"v0.2.0": "v0.1.10", "v0.1.10": "v0.1.9", "v1.0.0": "v0.10.0", "v0.1.9": ""} {
		if got := predecessor(tags, tag); got != want {
			t.Errorf("predecessor(%s) = %q, want %q", tag, got, want)
		}
	}
}

func TestReleaseDigest(t *testing.T) {
	a := digest("a")
	for sums, want := range map[string]string{
		a + "  macserve-darwin-arm64\n":                                   a,
		a + " *macserve-darwin-arm64\n" + a + "  carry-proof.json\n":      a,
		a + "  macserve-darwin-arm64\n\n":                                 "",
		a + " macserve-darwin-arm64\n":                                    "",
		strings.ToUpper(a) + "  macserve-darwin-arm64\n":                  "",
		a + "  macserve-darwin-arm64\n" + a + "  macserve-darwin-arm64\n": "",
		a + "  macserve-darwin-arm64\r\n":                                 "",
		"":                                                                "",
	} {
		got, err := releaseDigest([]byte(sums))
		if got != want || (want == "") != (err != nil) {
			t.Errorf("releaseDigest(%q) = %q, %v; want %q", sums, got, err, want)
		}
	}
}

func TestReadArchiveRefusesEscapes(t *testing.T) {
	for name, hdr := range map[string]*tar.Header{
		"dot-dot":  {Name: "p/../x", Typeflag: tar.TypeReg, Mode: 0o644},
		"absolute": {Name: "/p/x", Typeflag: tar.TypeReg, Mode: 0o644},
		"hardlink": {Name: "p/x", Typeflag: tar.TypeLink, Linkname: "p/y"},
		"outside":  {Name: "q/x", Typeflag: tar.TypeReg, Mode: 0o644},
	} {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		for _, h := range []*tar.Header{{Name: "p/", Typeflag: tar.TypeDir, Mode: 0o755}, hdr} {
			if err := tw.WriteHeader(h); err != nil {
				t.Fatal(err)
			}
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		if _, _, err := readArchive(gzipBytes(t, buf.Bytes()), "c", "sha1"); err == nil {
			t.Errorf("%s: archive accepted", name)
		}
	}
	// A symlink is recorded, not followed.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, h := range []*tar.Header{{Name: "p/", Typeflag: tar.TypeDir}, {Name: "p/l", Typeflag: tar.TypeSymlink, Linkname: "../../etc/passwd"}} {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	files, data, err := readArchive(gzipBytes(t, buf.Bytes()), "c", "sha1")
	if err != nil || files["l"].mode != "120000" || data["l"] != nil {
		t.Fatalf("symlink entry: %v %v %v", files, data, err)
	}
}

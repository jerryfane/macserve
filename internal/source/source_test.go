package source

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/model"
)

func fixtureGit(t *testing.T, dir, input string, args ...string) string {
	t.Helper()
	command := gitCommand(context.Background(), dir, nil, args...)
	command.Env = append(command.Env, "GIT_AUTHOR_NAME=Example", "GIT_AUTHOR_EMAIL=example@example.invalid", "GIT_COMMITTER_NAME=Example", "GIT_COMMITTER_EMAIL=example@example.invalid", "GIT_AUTHOR_DATE=2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2026-01-01T00:00:00Z")
	command.Stdin = strings.NewReader(input)
	var output, diagnostic bytes.Buffer
	command.Stdout, command.Stderr = &output, &diagnostic
	if err := command.Run(); err != nil {
		t.Fatalf("fixture git %v: %v: %s", args, err, diagnostic.String())
	}
	return strings.TrimSpace(output.String())
}

func fixtureStage(t *testing.T) (string, *os.Root) {
	t.Helper()
	dir := t.TempDir()
	fixtureGit(t, dir, "", "init", "--bare", "--template=", "--object-format=sha1", "repo.git")
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return dir, root
}

func fixtureBlob(t *testing.T, dir, contents string) string {
	t.Helper()
	return fixtureGit(t, dir, contents, "--git-dir=repo.git", "hash-object", "-w", "--stdin")
}

func fixtureTree(t *testing.T, dir string, entries ...string) string {
	t.Helper()
	return fixtureGit(t, dir, strings.Join(entries, "\x00")+"\x00", "--git-dir=repo.git", "mktree", "-z", "--missing")
}

func fixtureCommit(t *testing.T, dir, tree string) string {
	t.Helper()
	return fixtureGit(t, dir, "example commit\n", "--git-dir=repo.git", "commit-tree", "--no-gpg-sign", tree)
}

func fixtureExporter(t *testing.T) *Exporter {
	t.Helper()
	e, err := New(Options{Root: filepath.Join(t.TempDir(), "source")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

func TestExportExactFullTreeIgnoresArchiveAttributes(t *testing.T) {
	dir, stage := fixtureStage(t)
	files := map[string]string{
		".gitattributes": "hidden export-ignore\nversion export-subst\n",
		"hidden":         "must remain in the full tree\n",
		"version":        "$Format:%H$\n",
		"run.sh":         "#!/bin/sh\nexit 0\n",
		"nested/data":    "raw\x00bytes\n",
	}
	child := fixtureTree(t, dir, "100644 blob "+fixtureBlob(t, dir, files["nested/data"])+"\tdata")
	var records []string
	for name, data := range files {
		if name == "nested/data" {
			continue
		}
		mode := "100644"
		if name == "run.sh" {
			mode = "100755"
		}
		records = append(records, mode+" blob "+fixtureBlob(t, dir, data)+"\t"+name)
	}
	records = append(records, "040000 tree "+child+"\tnested")
	tree := fixtureTree(t, dir, records...)
	commit := fixtureCommit(t, dir, tree)
	otherTree := fixtureTree(t, dir, "100644 blob "+fixtureBlob(t, dir, "new branch state")+"\tother")
	otherCommit := fixtureCommit(t, dir, otherTree)
	fixtureGit(t, dir, "", "--git-dir=repo.git", "update-ref", "refs/heads/main", otherCommit)
	identity, err := exportTree(context.Background(), dir, stage, commit, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Commit != commit || identity.Tree != tree {
		t.Fatalf("wrong source identity: %+v", identity)
	}
	archive, err := os.ReadFile(filepath.Join(dir, "source.tar"))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(archive)
	if identity.SizeBytes != int64(len(archive)) || identity.SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatal("archive stream digest or size mismatch")
	}
	tr := tar.NewReader(bytes.NewReader(archive))
	seen := make(map[string]bool)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if header.Typeflag == tar.TypeDir {
			if strings.TrimSuffix(header.Name, "/") != "nested" {
				t.Fatalf("unexpected directory %q", header.Name)
			}
			continue
		}
		want, ok := files[header.Name]
		if !ok || seen[header.Name] {
			t.Fatalf("unexpected archive entry %q", header.Name)
		}
		seen[header.Name] = true
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != want {
			t.Fatalf("modified raw Git bytes for %q", header.Name)
		}
		wantMode := int64(0644)
		if header.Name == "run.sh" {
			wantMode = 0755
		}
		if header.Mode != wantMode {
			t.Fatalf("wrong executable mode for %q", header.Name)
		}
	}
	for name := range files {
		if !seen[name] {
			t.Errorf("missing Git tree path %q", name)
		}
	}
	if err := stage.Remove("source.tar"); err != nil {
		t.Fatal(err)
	}
	again, err := exportTree(context.Background(), dir, stage, commit, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if again != identity {
		t.Fatalf("export is not deterministic: %+v versus %+v", again, identity)
	}
	info, err := stage.Stat("source.tar")
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("archive must be private")
	}
}

func TestExportRejectsUnsupportedTreeAndBoundaries(t *testing.T) {
	for _, scenario := range []struct {
		name, mode, kind, path, data string
		limit                        int64
	}{
		{"symlink", "120000", "blob", "link", "../../outside", 1 << 20},
		{"submodule", "160000", "commit", "module", "", 1 << 20},
		{"lfs", "100644", "blob", "asset", "version https://git-lfs.github.com/spec/v1\noid sha256:123\nsize 1\n", 1 << 20},
		{"git-metadata", "100644", "blob", ".GiT", "not metadata", 1 << 20},
		{"lfs-config", "100644", "blob", ".lfsconfig", "[lfs]\nurl=elsewhere", 1 << 20},
		{"traversal", "100644", "blob", "..", "outside", 1 << 20},
		{"blob-limit", "100644", "blob", "large", strings.Repeat("x", 4096), 2048},
		{"tar-overhead-limit", "100644", "blob", "small", "x", 1024},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			dir, stage := fixtureStage(t)
			oid := fixtureBlob(t, dir, scenario.data)
			if scenario.kind == "commit" {
				oid = strings.Repeat("1", 40)
			}
			tree := fixtureTree(t, dir, scenario.mode+" "+scenario.kind+" "+oid+"\t"+scenario.path)
			commit := fixtureCommit(t, dir, tree)
			if _, err := exportTree(context.Background(), dir, stage, commit, scenario.limit); err == nil {
				t.Fatal("unsafe or oversized source accepted")
			}
		})
	}
}

func TestExportRejectsCaseCollisionsAndNonCommit(t *testing.T) {
	dir, stage := fixtureStage(t)
	blob := fixtureBlob(t, dir, "content")
	tree := fixtureTree(t, dir, "100644 blob "+blob+"\tName", "100644 blob "+blob+"\tname")
	commit := fixtureCommit(t, dir, tree)
	if _, err := exportTree(context.Background(), dir, stage, commit, 1<<20); err == nil {
		t.Fatal("case-colliding tree accepted")
	}
	if _, err := exportTree(context.Background(), dir, stage, blob, 1<<20); err == nil {
		t.Fatal("blob accepted as commit")
	}
}

func TestGitEnvironmentCannotInjectConfigurationOrObjectStore(t *testing.T) {
	dir, stage := fixtureStage(t)
	blob := fixtureBlob(t, dir, "safe raw bytes")
	tree := fixtureTree(t, dir, "100644 blob "+blob+"\tfile")
	commit := fixtureCommit(t, dir, tree)
	outside := t.TempDir()
	config := filepath.Join(outside, "global")
	if err := os.WriteFile(config, []byte("[core]\nrepositoryformatversion=999\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", config)
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "core.repositoryformatversion")
	t.Setenv("GIT_CONFIG_VALUE_0", "999")
	t.Setenv("GIT_OBJECT_DIRECTORY", outside)
	t.Setenv("GIT_TRACE", filepath.Join(outside, "trace"))
	identity, err := exportTree(context.Background(), dir, stage, commit, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Tree != tree {
		t.Fatal("inherited environment changed tree")
	}
	if _, err := os.Stat(filepath.Join(outside, "trace")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("Git tracing leaked outside service root")
	}
}

func TestRemoveRetainsOwnershipAcrossRestart(t *testing.T) {
	e := fixtureExporter(t)
	jobID := "j_example"
	if err := e.root.Mkdir("jobs/"+jobID, 0700); err != nil {
		t.Fatal(err)
	}
	if err := e.record(jobID); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "sentinel")
	if err := os.WriteFile(outside, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(e.options.Root, "jobs", jobID, "link")); err != nil {
		t.Fatal(err)
	}
	root := e.options.Root
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.Remove(jobID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "jobs", jobID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("recorded subtree was not removed")
	}
	data, err := os.ReadFile(outside)
	if err != nil || string(data) != "keep" {
		t.Fatal("cleanup followed a symlink")
	}
	if err := reopened.Remove(jobID); err != nil {
		t.Fatal(err)
	}
}

func TestRemoveRefusesUnrecordedReplacedAndInvalidPaths(t *testing.T) {
	e := fixtureExporter(t)
	if err := e.root.Mkdir("jobs/unrecorded", 0700); err != nil {
		t.Fatal(err)
	}
	if err := e.Remove("unrecorded"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.root.Stat("jobs/unrecorded"); err != nil {
		t.Fatal("unrecorded directory removed")
	}
	if err := e.root.Mkdir("jobs/recorded", 0700); err != nil {
		t.Fatal(err)
	}
	if err := e.record("recorded"); err != nil {
		t.Fatal(err)
	}
	if err := e.root.Rename("jobs/recorded", "jobs/original"); err != nil {
		t.Fatal(err)
	}
	if err := e.root.Mkdir("jobs/recorded", 0700); err != nil {
		t.Fatal(err)
	}
	if err := e.Remove("recorded"); err == nil {
		t.Fatal("replacement subtree removed")
	}
	for _, id := range []string{"", "..", "../records", "a/b", "/absolute", "a\\b"} {
		if err := e.Remove(id); err == nil {
			t.Errorf("invalid job ID accepted: %q", id)
		}
	}
	if _, err := e.root.Stat("jobs/recorded"); err != nil {
		t.Fatal("replacement was touched")
	}
}

func TestPrepareRejectsUnadmittedIdentityBeforeCredentials(t *testing.T) {
	e := fixtureExporter(t)
	called := false
	e.options.Token = func(context.Context, string) (string, error) { called = true; return "", nil }
	for _, job := range []model.Job{
		{ID: "j_test", Request: model.Request{Repo: "example-org/example-app", SHA: strings.Repeat("a", 40)}, Profile: model.Profile{Repo: "example-org/other"}},
		{ID: "../outside", Request: model.Request{Repo: "example-org/example-app", SHA: strings.Repeat("a", 40)}, Profile: model.Profile{Repo: "example-org/example-app"}},
		{ID: "j_test", Request: model.Request{Repo: "https://github.com/example-org/example-app", SHA: strings.Repeat("a", 40)}, Profile: model.Profile{Repo: "https://github.com/example-org/example-app"}},
		{ID: "j_test", Request: model.Request{Repo: "example-org/example-app", SHA: "refs/heads/main"}, Profile: model.Profile{Repo: "example-org/example-app"}},
	} {
		if _, err := e.Prepare(context.Background(), job); err == nil {
			t.Fatal("invalid source request accepted")
		}
	}
	if called {
		t.Fatal("credentials requested for invalid source")
	}
}

func TestRootPrivacyAndExclusiveOwnership(t *testing.T) {
	e := fixtureExporter(t)
	if second, err := New(Options{Root: e.options.Root}); err == nil {
		second.Close()
		t.Fatal("source root shared by exporters")
	}
	public := filepath.Join(t.TempDir(), "public")
	if err := os.Mkdir(public, 0755); err != nil {
		t.Fatal(err)
	}
	if exporter, err := New(Options{Root: public}); err == nil {
		exporter.Close()
		t.Fatal("nonprivate source root accepted")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(e.options.Root, link); err != nil {
		t.Fatal(err)
	}
	if exporter, err := New(Options{Root: link}); err == nil {
		exporter.Close()
		t.Fatal("symlink source root accepted")
	}
}

func TestPrepareRollsBackCredentialFailureWithoutLeakingSecrets(t *testing.T) {
	e := fixtureExporter(t)
	const secret = "example-sensitive-token"
	e.options.Token = func(context.Context, string) (string, error) {
		return "", errors.New("provider rejected " + secret)
	}
	job := model.Job{ID: "j_rollback", Request: model.Request{Repo: "example-org/example-app", SHA: strings.Repeat("a", 40)}, Profile: model.Profile{Repo: "example-org/example-app"}}
	if _, err := e.Prepare(context.Background(), job); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatal("credential failure was accepted or leaked its secret")
	}
	for _, name := range []string{"jobs/" + job.ID, "records/" + job.ID + ".json"} {
		if _, err := e.root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("partial source state remains: %s", name)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.Prepare(ctx, job); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled preparation was not rejected")
	}
	if _, err := e.root.Lstat("jobs/" + job.ID); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancelled preparation created a subtree")
	}
}

package evidence

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
	"golang.org/x/sys/unix"
)

func artifactExportDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "exports")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func artifactFile(t *testing.T, root, name, data string) {
	t.Helper()
	filename := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}

func assertNoExports(t *testing.T, dest string) {
	t.Helper()
	entries, err := os.ReadDir(dest)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("partial exports remain: %v", entries)
	}
}

func TestCollectCopiesRegularFilesWithContentIdentity(t *testing.T) {
	root, dest := t.TempDir(), artifactExportDir(t)
	artifactFile(t, root, "logs/build.txt", "exact log bytes\n")
	artifactFile(t, root, "unapproved.txt", "not exported")
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.FixedZone("offset", 3600))
	artifacts, err := Collect(root, []model.ArtifactRule{{Path: "logs/*.txt", Required: true}}, dest, Limits{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(artifacts) != 1 {
		t.Fatalf("selection: %+v", artifacts)
	}
	a := artifacts[0]
	digest := sha256.Sum256([]byte("exact log bytes\n"))
	if a.ID != hex.EncodeToString(digest[:]) || a.SHA256 != a.ID || a.Name != "logs/build.txt" || a.SizeBytes != 16 || a.MediaType != "text/plain; charset=utf-8" || !a.ExpiresAt.Equal(now.Add(7*24*time.Hour)) {
		t.Fatalf("artifact metadata: %+v", a)
	}
	sealed, err := os.ReadFile(filepath.Join(dest, a.ID))
	if err != nil || string(sealed) != "exact log bytes\n" {
		t.Fatalf("sealed contents: %q %v", sealed, err)
	}
	info, err := os.Stat(filepath.Join(dest, a.ID))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("export permissions: %v %v", info, err)
	}
	// A later call can append/deduplicate without deleting a previous export.
	artifactFile(t, root, "other.txt", "different")
	if _, err := Collect(root, []model.ArtifactRule{{Path: "logs/*.txt"}, {Path: "other.txt"}}, dest, Limits{}, now); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dest)
	if err != nil || len(entries) != 2 {
		t.Fatalf("append exports: %v %v", entries, err)
	}
}

func TestCollectDeterministicArchiveHasRecoverableSortedContents(t *testing.T) {
	root := t.TempDir()
	artifactFile(t, root, "results/z.txt", "last")
	artifactFile(t, root, "results/nested/b.txt", "second")
	artifactFile(t, root, "results/a.txt", "first")
	var previous []byte
	for iteration := 0; iteration < 2; iteration++ {
		dest := artifactExportDir(t)
		if iteration == 1 {
			if err := os.Chtimes(filepath.Join(root, "results/a.txt"), time.Unix(123, 0), time.Unix(456, 0)); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Join(root, "results/a.txt"), 0755); err != nil {
				t.Fatal(err)
			}
		}
		artifacts, err := Collect(root, []model.ArtifactRule{{Path: "results", Required: true}}, dest, Limits{}, time.Unix(1, 0))
		if err != nil {
			t.Fatal(err)
		}
		if len(artifacts) != 1 || artifacts[0].Name != "results.tar.gz" || artifacts[0].MediaType != "application/gzip" {
			t.Fatalf("archive metadata: %+v", artifacts)
		}
		data, err := os.ReadFile(filepath.Join(dest, artifacts[0].ID))
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		if artifacts[0].SHA256 != hex.EncodeToString(digest[:]) || artifacts[0].SizeBytes != int64(len(data)) {
			t.Fatal("archive size or hash mismatch")
		}
		if previous != nil && !bytes.Equal(previous, data) {
			t.Fatal("host timestamps or modes changed archive identity")
		}
		previous = data
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		tr := tar.NewReader(gz)
		var names []string
		contents := make(map[string]string)
		for {
			h, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			names = append(names, h.Name)
			if h.Uid != 0 || h.Gid != 0 || h.Uname != "" || h.Gname != "" || !h.ModTime.Equal(time.Unix(0, 0)) || filepath.IsAbs(h.Name) {
				t.Fatalf("host metadata leaked: %+v", h)
			}
			if h.Typeflag == tar.TypeReg {
				body, err := io.ReadAll(tr)
				if err != nil {
					t.Fatal(err)
				}
				contents[h.Name] = string(body)
			}
		}
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(names, []string{"results/", "results/a.txt", "results/nested/", "results/nested/b.txt", "results/z.txt"}) {
			t.Fatalf("archive order: %v", names)
		}
		if !reflect.DeepEqual(contents, map[string]string{"results/a.txt": "first", "results/nested/b.txt": "second", "results/z.txt": "last"}) {
			t.Fatalf("archive contents: %v", contents)
		}
	}
}

func TestCollectRejectsTraversalAndUnsafeExportRoots(t *testing.T) {
	for _, pattern := range []string{"", "/etc/passwd", "../secret", "a/../secret", "./a", "a//b", "a\\b", "[", "a\x00b"} {
		t.Run(pattern, func(t *testing.T) {
			root, dest := t.TempDir(), artifactExportDir(t)
			if _, err := Collect(root, []model.ArtifactRule{{Path: pattern}}, dest, Limits{}, time.Time{}); !errors.Is(err, ErrArtifact) {
				t.Fatalf("unsafe pattern accepted: %v", err)
			}
			assertNoExports(t, dest)
		})
	}
	root := t.TempDir()
	artifactFile(t, root, "a", "data")
	for _, dest := range []string{root, filepath.Join(root, "export"), filepath.Dir(root)} {
		if _, err := Collect(root, []model.ArtifactRule{{Path: "a"}}, dest, Limits{}, time.Time{}); !errors.Is(err, ErrArtifact) {
			t.Fatalf("overlapping export root accepted: %q %v", dest, err)
		}
	}
	dest := t.TempDir()
	if err := os.Chmod(dest, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := Collect(root, nil, dest, Limits{}, time.Time{}); !errors.Is(err, ErrArtifact) {
		t.Fatalf("public export directory accepted: %v", err)
	}
	private := artifactExportDir(t)
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(private, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := Collect(root, nil, alias, Limits{}, time.Time{}); !errors.Is(err, ErrArtifact) {
		t.Fatalf("symlink export root accepted: %v", err)
	}
}

func TestCollectRejectsSymlinksAndSpecialFiles(t *testing.T) {
	for _, scenario := range []string{"file", "parent", "archive child", "fifo", "source root"} {
		t.Run(scenario, func(t *testing.T) {
			root, outside, dest := t.TempDir(), t.TempDir(), artifactExportDir(t)
			artifactFile(t, outside, "secret", "outside data")
			pattern := "selected"
			switch scenario {
			case "file":
				if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(root, "selected")); err != nil {
					t.Fatal(err)
				}
			case "parent":
				if err := os.Symlink(outside, filepath.Join(root, "selected")); err != nil {
					t.Fatal(err)
				}
				pattern = "selected/secret"
			case "archive child":
				if err := os.Mkdir(filepath.Join(root, "selected"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(root, "selected/link")); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := unix.Mkfifo(filepath.Join(root, "selected"), 0600); err != nil {
					t.Fatal(err)
				}
			case "source root":
				alias := filepath.Join(t.TempDir(), "alias")
				if err := os.Symlink(root, alias); err != nil {
					t.Fatal(err)
				}
				root = alias
			}
			if _, err := Collect(root, []model.ArtifactRule{{Path: pattern}}, dest, Limits{}, time.Time{}); !errors.Is(err, ErrArtifact) {
				t.Fatalf("unsafe input accepted: %v", err)
			}
			assertNoExports(t, dest)
		})
	}
}

func TestCollectRequiredAndBudgetsCleanPartialExports(t *testing.T) {
	for _, tc := range []struct {
		name     string
		rules    []model.ArtifactRule
		limits   Limits
		sentinel error
	}{
		{"required missing", []model.ArtifactRule{{Path: "missing", Required: true}}, Limits{}, ErrArtifact},
		{"file cap", []model.ArtifactRule{{Path: "*.txt"}}, Limits{MaxFileBytes: 5}, ErrArtifactLimit},
		{"total cap", []model.ArtifactRule{{Path: "*.txt"}}, Limits{MaxTotalBytes: 8}, ErrArtifactLimit},
		{"count cap", []model.ArtifactRule{{Path: "*.txt"}}, Limits{MaxEntries: 1}, ErrArtifactLimit},
		{"archive entries", []model.ArtifactRule{{Path: "directory"}}, Limits{MaxEntries: 2}, ErrArtifactLimit},
		{"archive expanded size", []model.ArtifactRule{{Path: "directory"}}, Limits{MaxTotalBytes: 300, MaxFileBytes: 300}, ErrArtifactLimit},
		{"archive output size", []model.ArtifactRule{{Path: "empty"}}, Limits{MaxFileBytes: 16}, ErrArtifactLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, dest := t.TempDir(), artifactExportDir(t)
			artifactFile(t, root, "a.txt", "tiny")
			artifactFile(t, root, "z.txt", "larger content")
			artifactFile(t, root, "directory/one", strings.Repeat("x", 200))
			artifactFile(t, root, "directory/two", strings.Repeat("y", 200))
			if err := os.Mkdir(filepath.Join(root, "empty"), 0700); err != nil {
				t.Fatal(err)
			}
			artifacts, err := Collect(root, tc.rules, dest, tc.limits, time.Time{})
			if !errors.Is(err, tc.sentinel) || artifacts != nil {
				t.Fatalf("budget result: %+v %v", artifacts, err)
			}
			assertNoExports(t, dest)
		})
	}
	root, dest := t.TempDir(), artifactExportDir(t)
	artifacts, err := Collect(root, []model.ArtifactRule{{Path: "optional"}}, dest, Limits{}, time.Time{})
	if err != nil || len(artifacts) != 0 {
		t.Fatalf("optional missing: %+v %v", artifacts, err)
	}
}

func TestCollectRollbackLeavesPreexistingExportsUntouched(t *testing.T) {
	root, dest := t.TempDir(), artifactExportDir(t)
	artifactFile(t, root, "kept.txt", "prior export")
	prior, err := Collect(root, []model.ArtifactRule{{Path: "kept.txt"}}, dest, Limits{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	artifactFile(t, root, "a.txt", "new export")
	if err := os.Mkdir(filepath.Join(root, "zdir"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "kept.txt"), filepath.Join(root, "zdir/link")); err != nil {
		t.Fatal(err)
	}
	if _, err := Collect(root, []model.ArtifactRule{{Path: "a.txt"}, {Path: "kept.txt"}, {Path: "zdir"}}, dest, Limits{}, time.Time{}); !errors.Is(err, ErrArtifact) {
		t.Fatalf("unsafe archive accepted: %v", err)
	}
	entries, err := os.ReadDir(dest)
	if err != nil || len(entries) != 1 || entries[0].Name() != prior[0].ID {
		t.Fatalf("rollback changed prior exports: %v %v", entries, err)
	}
	data, err := os.ReadFile(filepath.Join(dest, prior[0].ID))
	if err != nil || string(data) != "prior export" {
		t.Fatalf("prior content changed: %q %v", data, err)
	}
}

type mutateArtifactWriter struct {
	mutate func()
	data   bytes.Buffer
}

func (w *mutateArtifactWriter) Write(data []byte) (int, error) {
	if w.mutate != nil {
		fn := w.mutate
		w.mutate = nil
		fn()
	}
	return w.data.Write(data)
}

func TestCopyDetectsConcurrentContentChange(t *testing.T) {
	root := t.TempDir()
	artifactFile(t, root, "file", "original")
	file, err := os.Open(filepath.Join(root, "file"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	writer := &mutateArtifactWriter{mutate: func() {
		if err := os.WriteFile(filepath.Join(root, "file"), []byte("modified and longer"), 0600); err != nil {
			t.Fatal(err)
		}
	}}
	collector := artifactCollector{limits: Limits{MaxTotalBytes: 1024, MaxFileBytes: 1024, MaxEntries: 10}, buffer: make([]byte, 128)}
	if err := collector.copyFile(writer, file, before); !errors.Is(err, ErrArtifact) {
		t.Fatalf("concurrent mutation accepted: %v", err)
	}
}

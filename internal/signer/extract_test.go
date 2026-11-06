package signer

import (
	"archive/tar"
	"bytes"
	"os"
	"slices"
	"testing"

	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/worker"
)

func extractInto(t *testing.T, entries []tarEntry, executables []string) error {
	t.Helper()
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	data := buildTar(t, entries)
	m := worker.SigningManifest{Archive: worker.SealedArchive{Root: profiles.ArchivePath, SizeBytes: int64(len(data)), Entries: len(entries)}, Executables: executables}
	return extractArchive(t.Context(), bytes.NewReader(data), root, m)
}

func TestExtractAcceptsSealedTree(t *testing.T) {
	entries := sortedEntries(archiveEntries())
	if err := extractInto(t, entries, executablesOf(entries)); err != nil {
		t.Fatal(err)
	}
}

// Extraction refuses anything the sealer never writes.
func TestExtractRefusals(t *testing.T) {
	r := profiles.ArchivePath + "/"
	base := sortedEntries(archiveEntries())
	with := func(extra ...tarEntry) []tarEntry { return append(slices.Clone(base), extra...) }
	cases := []struct {
		name    string
		entries []tarEntry
		want    string
	}{
		{"symlink", with(tarEntry{name: r + "link", typeflag: tar.TypeSymlink, mode: 0o755, link: "/etc/passwd"}), "not a directory or regular file"},
		{"hard link", with(tarEntry{name: r + "hard", typeflag: tar.TypeLink, mode: 0o644, link: r + "Info.plist"}), "not a directory or regular file"},
		{"fifo", with(tarEntry{name: r + "fifo", typeflag: tar.TypeFifo, mode: 0o644}), "not a directory or regular file"},
		{"device", with(tarEntry{name: r + "dev", typeflag: tar.TypeChar, mode: 0o644}), "not a directory or regular file"},
		{"traversal", with(fileEntry(r+"../escape", 0o644, "x")), "name"},
		{"absolute", with(fileEntry("/"+r+"abs", 0o644, "x")), "name"},
		{"outside root", with(fileEntry("Other/file", 0o644, "x")), "name"},
		{"duplicate", with(fileEntry(r+"Info.plist", 0o644, "again")), "duplicated"},
		{"case collision", with(fileEntry(r+"INFO.plist", 0o644, "x")), "collide by case"},
		{"missing parent", with(fileEntry(r+"Missing/file", 0o644, "x")), "precedes its directory"},
		{"world-writable mode", with(fileEntry(r+"loose", 0o666, "x")), "mode"},
		{"setuid mode", with(fileEntry(r+"setuid", 0o4755, "x")), "mode"},
		{"directory mode", with(tarEntry{name: r + "Private/", typeflag: tar.TypeDir, mode: 0o700}), "mode"},
		{"owner", with(tarEntry{name: r + "owned", typeflag: tar.TypeReg, mode: 0o644, body: []byte("x"), uid: 501}), "ownership"},
		{"root not first", append([]tarEntry{fileEntry(r+"early", 0o644, "x")}, base...), "precedes its directory"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			requireRefusal(t, extractInto(t, c.entries, executablesOf(base)), c.want)
		})
	}
}

// The 0755 files must be exactly the manifest's executables.
func TestExtractRefusesModeMismatch(t *testing.T) {
	entries := sortedEntries(archiveEntries())
	executables := executablesOf(entries)
	t.Run("listed executable stored 0644", func(t *testing.T) {
		changed := slices.Clone(entries)
		for i := range changed {
			if changed[i].name == profiles.ArchivePath+"/"+appPath+"/Example" {
				changed[i].mode = 0o644
			}
		}
		requireRefusal(t, extractInto(t, changed, executables), "executables")
	})
	t.Run("unlisted 0755 file", func(t *testing.T) {
		changed := slices.Clone(entries)
		for i := range changed {
			if changed[i].name == profiles.ArchivePath+"/Info.plist" {
				changed[i].mode = 0o755
			}
		}
		requireRefusal(t, extractInto(t, changed, executables), "executables")
	})
	t.Run("entry count", func(t *testing.T) {
		dir := t.TempDir()
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		data := buildTar(t, entries)
		m := worker.SigningManifest{Archive: worker.SealedArchive{Root: profiles.ArchivePath, SizeBytes: int64(len(data)), Entries: len(entries) + 1}, Executables: executables}
		requireRefusal(t, extractArchive(t.Context(), bytes.NewReader(data), root, m), "entries")
	})
}

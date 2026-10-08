package worker

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArchiveIdentityAndConfinement(t *testing.T) {
	source, valid := sourceFixture(t)
	for _, scenario := range []struct {
		name   string
		change func(*Source)
	}{
		{"valid", func(*Source) {}},
		{"hash", func(s *Source) { s.SHA256 = strings.Repeat("0", 64) }},
		{"tree", func(s *Source) { s.Tree = strings.Repeat("0", 40) }},
		{"truncated", func(s *Source) { s.SizeBytes++ }},
		{"oversize", func(s *Source) { s.SizeBytes = 1 << 21 }},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			copy := source
			scenario.change(&copy)
			root, err := os.OpenRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			err = extractSource(context.Background(), root, bytes.NewReader(valid), copy, 1<<20)
			if scenario.name == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				contents, err := root.ReadFile("README.txt")
				if err != nil || string(contents) != "hello\n" {
					t.Fatalf("contents %q err %v", contents, err)
				}
			} else if err == nil {
				t.Fatal("invalid source accepted")
			}
		})
	}
}

func TestArchiveRejectsUnsafeEntries(t *testing.T) {
	cases := []struct {
		name    string
		headers []*tar.Header
		payload string
	}{
		{"traversal", []*tar.Header{{Name: "../escaped", Typeflag: tar.TypeReg, Size: 1}}, "x"},
		{"absolute", []*tar.Header{{Name: "/escaped", Typeflag: tar.TypeReg, Size: 1}}, "x"},
		{"symlink", []*tar.Header{{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "../escaped"}}, ""},
		{"hardlink", []*tar.Header{{Name: "link", Typeflag: tar.TypeLink, Linkname: "README.txt"}}, ""},
		{"fifo", []*tar.Header{{Name: "pipe", Typeflag: tar.TypeFifo}}, ""},
		{"duplicate", []*tar.Header{{Name: "same", Typeflag: tar.TypeReg, Size: 1}, {Name: "same", Typeflag: tar.TypeReg, Size: 1}}, "x"},
		{"git-metadata", []*tar.Header{{Name: ".git/config", Typeflag: tar.TypeReg, Size: 1}}, "x"},
		{"lfs", []*tar.Header{{Name: "asset", Typeflag: tar.TypeReg, Size: int64(len("version https://git-lfs.github.com/spec/v1\n"))}}, "version https://git-lfs.github.com/spec/v1\n"},
	}
	for _, scenario := range cases {
		t.Run(scenario.name, func(t *testing.T) {
			var buf bytes.Buffer
			writer := tar.NewWriter(&buf)
			for _, header := range scenario.headers {
				header.Mode = 0600
				if err := writer.WriteHeader(header); err != nil {
					t.Fatal(err)
				}
				if header.Size > 0 {
					if _, err := writer.Write([]byte(scenario.payload)); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(buf.Bytes())
			source := Source{Commit: strings.Repeat("a", 40), Tree: strings.Repeat("b", 40), SHA256: hex.EncodeToString(digest[:]), SizeBytes: int64(buf.Len())}
			base := t.TempDir()
			checkout := filepath.Join(base, "checkout")
			if err := os.Mkdir(checkout, 0700); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(checkout)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			err = extractSource(context.Background(), root, bytes.NewReader(buf.Bytes()), source, 1<<20)
			if err == nil {
				t.Fatal("unsafe archive accepted")
			}
			if strings.Contains(err.Error(), "tree mismatch") {
				t.Fatalf("entry was accepted until tree validation: %v", err)
			}
			if _, err := os.Stat(filepath.Join(base, "escaped")); !os.IsNotExist(err) {
				t.Fatal("archive escaped root")
			}
		})
	}
}

func TestArchiveSizeAndCancellationBoundExtraction(t *testing.T) {
	source, data := sourceFixture(t)
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := extractSource(ctx, root, bytes.NewReader(data), source, 1<<20); err != context.Canceled {
		t.Fatalf("cancellation: %v", err)
	}
	if err := extractSource(context.Background(), root, bytes.NewReader(data), source, source.SizeBytes-1); err == nil {
		t.Fatal("source exceeds disk budget")
	}
	if _, err := root.Stat("README.txt"); !os.IsNotExist(err) {
		t.Fatal("rejected source extracted a file")
	}
}

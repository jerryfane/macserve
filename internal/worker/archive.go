package worker

import (
	"archive/tar"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
)

const maxArchiveEntries = 100000

type treeEntry struct {
	mode     string
	digest   []byte
	children map[string]*treeEntry
}

func safeRelative(name string) bool {
	if name == "" || name == "." || strings.ContainsAny(name, "\\\x00") || path.IsAbs(name) || path.Clean(name) != name {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." || part == ".git" {
			return false
		}
	}
	return true
}

func gitHash(kind string, data []byte) []byte {
	h := sha1.New()
	fmt.Fprintf(h, "%s %d\x00", kind, len(data))
	h.Write(data)
	return h.Sum(nil)
}

func treeDigest(node *treeEntry) []byte {
	names := make([]string, 0, len(node.children))
	for name := range node.children {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		a, b := names[i], names[j]
		if node.children[a].children != nil {
			a += "/"
		}
		if node.children[b].children != nil {
			b += "/"
		}
		return a < b
	})
	var body []byte
	for _, name := range names {
		child := node.children[name]
		digest := child.digest
		if child.children != nil {
			digest = treeDigest(child)
		}
		body = append(body, []byte(child.mode+" "+name+"\x00")...)
		body = append(body, digest...)
	}
	return gitHash("tree", body)
}

// extractSource validates the byte stream before any recipe is run, then checks
// the Git tree identity including executable bits. Symlinks and submodules are
// deliberately unsupported rather than being materialized outside confinement.
func extractSource(ctx context.Context, root *os.Root, input io.Reader, source Source, budget int64) error {
	if input == nil || source.SizeBytes <= 0 || source.SizeBytes > budget {
		return errors.New("source archive exceeds workspace budget")
	}
	h := sha256.New()
	limited := &io.LimitedReader{R: input, N: source.SizeBytes + 1}
	reader := io.TeeReader(limited, h)
	tr := tar.NewReader(reader)
	tree := &treeEntry{mode: "40000", children: make(map[string]*treeEntry)}
	seen := make(map[string]bool)
	var extracted int64
	entries := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("source tar: %w", err)
		}
		if header.Typeflag == tar.TypeXGlobalHeader {
			if commit := header.PAXRecords["comment"]; commit != "" && commit != source.Commit {
				return errors.New("git archive commit mismatch")
			}
			continue
		}
		entries++
		if entries > maxArchiveEntries {
			return errors.New("source archive entry limit exceeded")
		}
		name := strings.TrimSuffix(header.Name, "/")
		if !safeRelative(name) || seen[name] {
			return fmt.Errorf("unsafe or duplicate source entry %q", header.Name)
		}
		seen[name] = true
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA && header.Typeflag != tar.TypeDir {
			return fmt.Errorf("unsupported source entry %q", name)
		}
		if header.Size < 0 || header.Size > budget-extracted {
			return errors.New("extracted source exceeds workspace budget")
		}
		if header.Typeflag == tar.TypeDir && header.Size != 0 {
			return errors.New("directory has file payload")
		}
		extracted += header.Size
		parts := strings.Split(name, "/")
		node := tree
		for _, part := range parts[:len(parts)-1] {
			child := node.children[part]
			if child == nil {
				child = &treeEntry{mode: "40000", children: make(map[string]*treeEntry)}
				node.children[part] = child
			}
			if child.children == nil {
				return errors.New("source file used as directory")
			}
			node = child
		}
		leaf := parts[len(parts)-1]
		if header.Typeflag == tar.TypeDir {
			if child := node.children[leaf]; child != nil && child.children == nil {
				return errors.New("source directory collides with file")
			}
			if node.children[leaf] == nil {
				node.children[leaf] = &treeEntry{mode: "40000", children: make(map[string]*treeEntry)}
			}
			if err := root.MkdirAll(name, 0700); err != nil {
				return err
			}
			continue
		}
		if node.children[leaf] != nil {
			return errors.New("source file collides with directory")
		}
		if parent := path.Dir(name); parent != "." {
			if err := root.MkdirAll(parent, 0700); err != nil {
				return err
			}
		}
		mode := os.FileMode(0600)
		gitMode := "100644"
		if header.Mode&0111 != 0 {
			mode = 0700
			gitMode = "100755"
		}
		file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
		if err != nil {
			return err
		}
		blob := sha1.New()
		fmt.Fprintf(blob, "blob %d\x00", header.Size)
		prefix := &sourcePrefix{}
		_, copyErr := io.Copy(io.MultiWriter(file, blob, prefix), &contextReader{ctx: ctx, reader: tr})
		closeErr := file.Close()
		if err := errors.Join(copyErr, closeErr); err != nil {
			return err
		}
		if strings.HasPrefix(string(prefix.data), "version https://git-lfs.github.com/spec/v1\n") {
			return errors.New("Git LFS source pointers are unsupported")
		}
		node.children[leaf] = &treeEntry{mode: gitMode, digest: blob.Sum(nil)}
	}
	// tar stops at its end marker; hash and count the entire controller stream,
	// rejecting appended bytes instead of silently accepting a prefix.
	if _, err := io.Copy(io.Discard, &contextReader{ctx: ctx, reader: reader}); err != nil {
		return err
	}
	if limited.N != 1 || hex.EncodeToString(h.Sum(nil)) != source.SHA256 {
		return errors.New("source archive size or SHA256 mismatch")
	}
	if hex.EncodeToString(treeDigest(tree)) != source.Tree {
		return errors.New("source Git tree mismatch")
	}
	return nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

type sourcePrefix struct{ data []byte }

func (p *sourcePrefix) Write(data []byte) (int, error) {
	n := min(128-len(p.data), len(data))
	p.data = append(p.data, data[:n]...)
	return len(data), nil
}

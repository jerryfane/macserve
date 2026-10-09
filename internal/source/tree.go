package source

import (
	"archive/tar"
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/jerryfane/macserve/internal/worker"
)

const maxEntries = 100000

type entry struct {
	name string
	mode string
	oid  string
}

type treeNode struct {
	mode     string
	oid      string
	children map[string]*treeNode
}

func safePath(name string) bool {
	if name == "" || len(name) > 4096 || !utf8.ValidString(name) || path.IsAbs(name) || path.Clean(name) != name || strings.ContainsAny(name, "\\\x00:") {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		lower := strings.ToLower(strings.TrimRight(part, " ."))
		if part == "." || part == ".." || lower == "" || lower == ".git" || lower == "git~1" || lower == ".gitmodules" || lower == ".lfsconfig" {
			return false
		}
	}
	return true
}

func listTree(ctx context.Context, dir, tree string, limit int64) ([]entry, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	command := gitCommand(ctx, dir, nil, "--git-dir=repo.git", "ls-tree", "-r", "-t", "-z", "--full-tree", tree)
	command.Stdout = nil
	output, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := command.Start(); err != nil {
		return nil, sourceError("tree listing", err)
	}
	var entries []entry
	seen := make(map[string]bool)
	reader := bufio.NewReaderSize(output, 8192)
	var total int64
	var listErr error
	for {
		record, err := reader.ReadSlice(0)
		if err == io.EOF && len(record) == 0 {
			break
		}
		if err != nil {
			listErr = errors.New("invalid or oversized source tree entry")
			break
		}
		total += int64(len(record))
		if total > min(limit, 64<<20) || len(entries) >= maxEntries {
			listErr = errors.New("source tree listing exceeds limit")
			break
		}
		metadata, name, found := strings.Cut(string(record[:len(record)-1]), "\t")
		fields := strings.Split(metadata, " ")
		if !found || len(fields) != 3 || !safePath(name) || !shaPattern.MatchString(fields[2]) {
			listErr = errors.New("unsafe source tree entry")
			break
		}
		mode, kind := fields[0], fields[1]
		if !(mode == "040000" && kind == "tree" || (mode == "100644" || mode == "100755") && kind == "blob") {
			listErr = errors.New("source links, submodules and special modes are unsupported")
			break
		}
		key := strings.ToLower(name)
		if seen[key] {
			listErr = errors.New("duplicate or case-colliding source path")
			break
		}
		seen[key] = true
		entries = append(entries, entry{name: name, mode: mode, oid: fields[2]})
	}
	if listErr != nil {
		cancel()
	}
	waitErr := command.Wait()
	if listErr != nil {
		return nil, listErr
	}
	if waitErr != nil {
		return nil, sourceError("tree listing", waitErr)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	if err := verifyTree(entries, tree); err != nil {
		return nil, err
	}
	return entries, nil
}

func verifyTree(entries []entry, expected string) error {
	root := &treeNode{mode: "40000", oid: expected, children: make(map[string]*treeNode)}
	for _, item := range entries {
		parts := strings.Split(item.name, "/")
		node := root
		for _, part := range parts[:len(parts)-1] {
			child := node.children[part]
			if child == nil || child.children == nil {
				return errors.New("source tree directory collision")
			}
			node = child
		}
		leaf := parts[len(parts)-1]
		if node.children[leaf] != nil {
			return errors.New("duplicate source tree entry")
		}
		child := &treeNode{mode: item.mode, oid: item.oid}
		if item.mode == "040000" {
			child.mode = "40000"
			child.children = make(map[string]*treeNode)
		}
		node.children[leaf] = child
	}
	_, err := verifyNode(root)
	return err
}

func verifyNode(node *treeNode) ([]byte, error) {
	if node.children == nil {
		return hex.DecodeString(node.oid)
	}
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
	var size int
	for _, name := range names {
		size += len(node.children[name].mode) + 1 + len(name) + 1 + 20
	}
	hash := sha1.New()
	fmt.Fprintf(hash, "tree %d\x00", size)
	for _, name := range names {
		child := node.children[name]
		digest, err := verifyNode(child)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(hash, "%s %s\x00", child.mode, name)
		hash.Write(digest)
	}
	digest := hash.Sum(nil)
	if hex.EncodeToString(digest) != node.oid {
		return nil, errors.New("source Git tree identity mismatch")
	}
	return digest, nil
}

func exportTree(ctx context.Context, dir string, stage *os.Root, commit string, limit int64) (result worker.Source, resultErr error) {
	tree, err := inspectCommit(ctx, dir, commit)
	if err != nil {
		return result, err
	}
	entries, err := listTree(ctx, dir, tree, limit)
	if err != nil {
		return result, err
	}
	file, output, hash, err := archiveFile(stage, limit)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	tw := tar.NewWriter(output)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	command := gitCommand(ctx, dir, nil, "--git-dir=repo.git", "cat-file", "--batch")
	command.Stdout = nil
	stdout, err := command.StdoutPipe()
	if err != nil {
		return result, err
	}
	stdin, err := command.StdinPipe()
	if err != nil {
		return result, err
	}
	if err := command.Start(); err != nil {
		return result, sourceError("blob export", err)
	}
	defer func() {
		stdin.Close()
		if resultErr != nil {
			cancel()
		}
		resultErr = errors.Join(resultErr, sourceError("blob export", command.Wait()))
	}()
	reader := bufio.NewReaderSize(stdout, 8192)
	for _, item := range entries {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		header := &tar.Header{Name: item.name, Typeflag: tar.TypeReg, Mode: 0644, Format: tar.FormatPAX}
		if item.mode == "040000" {
			header.Typeflag, header.Mode = tar.TypeDir, 0755
			if err := tw.WriteHeader(header); err != nil {
				return result, err
			}
			continue
		}
		if item.mode == "100755" {
			header.Mode = 0755
		}
		if _, err := io.WriteString(stdin, item.oid+"\n"); err != nil {
			return result, sourceError("blob request", err)
		}
		line, err := reader.ReadSlice('\n')
		if err != nil {
			return result, errors.New("invalid source blob response")
		}
		fields := strings.Split(strings.TrimSuffix(string(line), "\n"), " ")
		if len(fields) != 3 || fields[0] != item.oid || fields[1] != "blob" {
			return result, errors.New("source blob identity mismatch")
		}
		size, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil || size < 0 || size > output.remaining {
			return result, errors.New("source blob exceeds byte limit")
		}
		prefix, err := reader.Peek(int(min(size, 128)))
		if err != nil {
			return result, errors.New("truncated source blob")
		}
		if strings.HasPrefix(string(prefix), "version https://git-lfs.github.com/spec/") {
			return result, errors.New("Git LFS source pointers are unsupported")
		}
		header.Size = size
		if err := tw.WriteHeader(header); err != nil {
			return result, err
		}
		blob := sha1.New()
		fmt.Fprintf(blob, "blob %d\x00", size)
		if _, err := io.CopyN(io.MultiWriter(tw, blob), &contextReader{ctx: ctx, reader: reader}, size); err != nil {
			return result, err
		}
		if hex.EncodeToString(blob.Sum(nil)) != item.oid {
			return result, errors.New("source blob hash mismatch")
		}
		separator, err := reader.ReadByte()
		if err != nil || separator != '\n' {
			return result, errors.New("invalid source blob delimiter")
		}
	}
	if err := tw.Close(); err != nil {
		return result, err
	}
	if err := file.Sync(); err != nil {
		return result, err
	}
	return sourceIdentity(commit, tree, output.written, hash.Sum(nil)), nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(data)
}

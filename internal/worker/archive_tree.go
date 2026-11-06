package worker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

// maxArchivePath bounds a path below the .xcarchive (macOS PATH_MAX).
const maxArchivePath = 1024

// archiveNode is one entry of a scanned archive tree: its slash path below
// the tree root ("" is the root) and the lstat facts sealing re-checks.
type archiveNode struct {
	rel  string
	dir  bool
	perm uint32
	size int64
	dev  uint64
	ino  uint64
}

// archiveTree is an opened .xcarchive directory and its scanned entries,
// sorted by path.
type archiveTree struct {
	root   *os.File
	device uint64
	nodes  []archiveNode
	index  map[string]int
}

func (t *archiveTree) node(rel string) (archiveNode, bool) {
	i, ok := t.index[rel]
	if !ok {
		return archiveNode{}, false
	}
	return t.nodes[i], true
}

// children lists the direct entries of the directory rel, sorted by name.
// Nodes are sorted by path, so every path below rel is one contiguous run.
func (t *archiveTree) children(rel string) []archiveNode {
	prefix := rel + "/"
	if rel == "" {
		prefix = ""
	}
	start, _ := slices.BinarySearchFunc(t.nodes, prefix, func(n archiveNode, target string) int { return strings.Compare(n.rel, target) })
	var out []archiveNode
	for _, n := range t.nodes[start:] {
		if !strings.HasPrefix(n.rel, prefix) {
			break
		}
		if n.rel != "" && !strings.Contains(n.rel[len(prefix):], "/") {
			out = append(out, n)
		}
	}
	return out
}

type archiveLimits struct {
	entries int
	bytes   int64
}

func archiveRefusal(format string, args ...any) error {
	return fmt.Errorf("archive refused: "+format, args...)
}

// validArchiveName reports whether a directory entry name may appear in a
// sealed archive: valid UTF-8 without control characters or backslashes.
func validArchiveName(name string) bool {
	if name == "" || name == "." || name == ".." || !utf8.ValidString(name) || strings.ContainsRune(name, '\\') {
		return false
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// walkDescriptors visits every entry beneath dir, each directory's names in
// byte order, with its lstat facts and slash path. It works on directory
// descriptors: it never follows a symlink, and it refuses any entry or opened
// directory on a device other than device. visit decides whether to descend
// a directory. Nothing may still write the tree (the job UID has been
// stopped), so a vanished entry is refused, not skipped; maxEntries bounds
// the walk.
func walkDescriptors(ctx context.Context, dir *os.File, device uint64, maxEntries int, statat statAt, visit func(parent *os.File, name, rel string, stat *unix.Stat_t) (bool, error)) error {
	var top unix.Stat_t
	if err := fstatFD(int(dir.Fd()), &top); err != nil {
		return err
	}
	if uint64(top.Dev) != device {
		return archiveRefusal("tree root is on another device")
	}
	entries := 0
	var walk func(*os.File, string) error
	walk = func(dir *os.File, prefix string) error {
		var names []string
		for {
			batch, readErr := dir.Readdirnames(256)
			if readErr != nil && readErr != io.EOF {
				return readErr
			}
			if entries += len(batch); entries > maxEntries {
				return archiveRefusal("more than %d entries", maxEntries)
			}
			names = append(names, batch...)
			if readErr == io.EOF || len(batch) == 0 {
				break
			}
		}
		slices.Sort(names)
		for _, name := range names {
			if err := ctx.Err(); err != nil {
				return err
			}
			rel := path.Join(prefix, name)
			var stat unix.Stat_t
			if err := statat(int(dir.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return fmt.Errorf("archive entry %s: %w", strconv.Quote(rel), err)
			}
			if uint64(stat.Dev) != device {
				return archiveRefusal("mount point at %s", strconv.Quote(rel))
			}
			descend, err := visit(dir, name, rel, &stat)
			if err != nil {
				return err
			}
			if !descend || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
				continue
			}
			child, err := openDirAt(dir, name, device)
			if err != nil {
				return fmt.Errorf("archive entry %s: %w", strconv.Quote(rel), err)
			}
			var opened unix.Stat_t
			if err = fstatFD(int(child.Fd()), &opened); err == nil && (uint64(opened.Ino) != uint64(stat.Ino) || uint64(opened.Dev) != uint64(stat.Dev)) {
				err = archiveRefusal("%s changed while walking", strconv.Quote(rel))
			}
			if err == nil {
				err = walk(child, rel)
			}
			child.Close()
			if err != nil {
				return err
			}
		}
		return nil
	}
	return walk(dir, "")
}

// openDirAt opens the directory name below parent without following a
// symlink and refuses one on another device.
func openDirAt(parent *os.File, name string, device uint64) (*os.File, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), name)
	var stat unix.Stat_t
	if err := fstatFD(fd, &stat); err != nil {
		dir.Close()
		return nil, err
	}
	if uint64(stat.Dev) != device {
		dir.Close()
		return nil, archiveRefusal("mount point at %s", strconv.Quote(name))
	}
	return dir, nil
}

// openPathAt opens the slash path rel below root one component at a time
// (see openDirAt); the last component is opened as a regular file, never a
// symlink, FIFO or device.
func openPathAt(root *os.File, rel string, device uint64) (*os.File, error) {
	parts := strings.Split(rel, "/")
	dir := root
	for _, part := range parts[:len(parts)-1] {
		next, err := openDirAt(dir, part, device)
		if dir != root {
			dir.Close()
		}
		if err != nil {
			return nil, err
		}
		dir = next
	}
	fd, err := unix.Openat(int(dir.Fd()), parts[len(parts)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if dir != root {
		dir.Close()
	}
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), rel), nil
}

// scanArchive lists the tree below root, refusing what a sealed archive may
// not hold: symlinks, hard-linked files, special files, mount points, names
// that are not UTF-8 or hold control characters or backslashes, names that
// collide case-insensitively within a directory, paths over maxArchivePath,
// and more entries or regular-file bytes than limits.
func scanArchive(ctx context.Context, root *os.File, device uint64, limits archiveLimits, statat statAt) (*archiveTree, error) {
	var top unix.Stat_t
	if err := fstatFD(int(root.Fd()), &top); err != nil {
		return nil, err
	}
	tree := &archiveTree{root: root, device: device, nodes: []archiveNode{{rel: "", dir: true, perm: uint32(top.Mode) & 0o7777, dev: uint64(top.Dev), ino: uint64(top.Ino)}}}
	folded := map[string]string{}
	var total int64
	err := walkDescriptors(ctx, root, device, limits.entries-1, statat, func(_ *os.File, name, rel string, stat *unix.Stat_t) (bool, error) {
		if !validArchiveName(name) {
			return false, archiveRefusal("entry name %s", strconv.Quote(rel))
		}
		if len(rel) > maxArchivePath {
			return false, archiveRefusal("path longer than %d bytes", maxArchivePath)
		}
		key := path.Join(path.Dir(rel), strings.ToLower(name))
		if other, ok := folded[key]; ok {
			return false, archiveRefusal("%s and %s collide case-insensitively", strconv.Quote(other), strconv.Quote(rel))
		}
		folded[key] = rel
		node := archiveNode{rel: rel, perm: uint32(stat.Mode) & 0o7777, size: stat.Size, dev: uint64(stat.Dev), ino: uint64(stat.Ino)}
		switch stat.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			node.dir = true
		case unix.S_IFREG:
			if uint64(stat.Nlink) != 1 {
				return false, archiveRefusal("hard link at %s", strconv.Quote(rel))
			}
			if stat.Size < 0 || stat.Size > limits.bytes-total {
				return false, archiveRefusal("more than %d bytes", limits.bytes)
			}
			total += stat.Size
		case unix.S_IFLNK:
			return false, archiveRefusal("symlink at %s", strconv.Quote(rel))
		default:
			return false, archiveRefusal("special file at %s", strconv.Quote(rel))
		}
		tree.nodes = append(tree.nodes, node)
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(tree.nodes, func(a, b archiveNode) int { return strings.Compare(a.rel, b.rel) })
	tree.index = make(map[string]int, len(tree.nodes))
	for i, n := range tree.nodes {
		tree.index[n.rel] = i
	}
	return tree, nil
}

// open opens a scanned regular file and verifies it is the scanned inode,
// unchanged in size and mode, still singly linked.
func (t *archiveTree) open(n archiveNode) (*os.File, error) {
	if n.dir || n.rel == "" {
		return nil, errors.New("not a regular archive file")
	}
	file, err := openPathAt(t.root, n.rel, t.device)
	if err != nil {
		return nil, fmt.Errorf("archive entry %s: %w", strconv.Quote(n.rel), err)
	}
	var stat unix.Stat_t
	if err := fstatFD(int(file.Fd()), &stat); err != nil {
		file.Close()
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || uint64(stat.Dev) != n.dev || uint64(stat.Ino) != n.ino || stat.Size != n.size || uint32(stat.Mode)&0o7777 != n.perm || uint64(stat.Nlink) != 1 {
		file.Close()
		return nil, archiveRefusal("%s changed after scanning", strconv.Quote(n.rel))
	}
	return file, nil
}

// read returns a scanned regular file's bytes, at most limit of them.
func (t *archiveTree) read(ctx context.Context, n archiveNode, limit int64) ([]byte, error) {
	if n.size > limit {
		return nil, archiveRefusal("%s exceeds %d bytes", strconv.Quote(n.rel), limit)
	}
	file, err := t.open(n)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(&contextReader{ctx: ctx, reader: file}, n.size+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != n.size {
		return nil, archiveRefusal("%s changed while reading", strconv.Quote(n.rel))
	}
	return data, nil
}

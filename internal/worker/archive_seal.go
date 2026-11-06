package worker

import (
	"archive/tar"
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jerryfane/macserve/internal/profiles"
)

// limitedWriter fails a write that would take its total past max.
type limitedWriter struct {
	w     io.Writer
	max   int64
	count int64
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > l.max-l.count {
		return 0, archiveRefusal("sealed archive exceeds %d bytes", l.max)
	}
	n, err := l.w.Write(p)
	l.count += int64(n)
	return n, err
}

// archiveTarName is a node's name in the sealed tar: below the single
// top-level directory profiles.ArchivePath, directories with a slash.
func archiveTarName(n archiveNode) string {
	name := profiles.ArchivePath
	if n.rel != "" {
		name += "/" + n.rel
	}
	if n.dir {
		name += "/"
	}
	return name
}

// sealArchive writes the deterministic tar of a scanned tree to out, at most
// maxBytes of it, and returns its identity and the paths it stores with mode
// 0755. Entries are in byte order of their tar names (a directory precedes
// its contents), owned by uid and gid 0 with empty owner names, mtime the
// Unix epoch and no access or change times; directories are 0755, regular
// files 0755 when any execute bit is set and 0644 otherwise. Each file is
// re-opened and must be the scanned inode, unchanged. The same tree always
// yields the same bytes.
func sealArchive(ctx context.Context, tree *archiveTree, out io.Writer, maxBytes int64) (SealedArchive, []string, error) {
	sealed := SealedArchive{Name: profiles.ArchiveArtifact, Root: profiles.ArchivePath}
	type entry struct {
		name string
		node archiveNode
	}
	entries := make([]entry, len(tree.nodes))
	for i, n := range tree.nodes {
		entries[i] = entry{archiveTarName(n), n}
	}
	slices.SortFunc(entries, func(a, b entry) int { return strings.Compare(a.name, b.name) })
	hash := sha256.New()
	counted := &limitedWriter{w: io.MultiWriter(out, hash), max: maxBytes}
	buffered := bufio.NewWriterSize(counted, 1<<20)
	tw := tar.NewWriter(buffered)
	buffer := make([]byte, 1<<20)
	executables := []string{}
	epoch := time.Unix(0, 0)
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return sealed, nil, err
		}
		header := &tar.Header{Name: e.name, Mode: 0o755, ModTime: epoch, Format: tar.FormatPAX}
		if e.node.dir {
			header.Typeflag = tar.TypeDir
			if err := tw.WriteHeader(header); err != nil {
				return sealed, nil, err
			}
			continue
		}
		header.Typeflag = tar.TypeReg
		header.Size = e.node.size
		if e.node.perm&0o111 != 0 {
			executables = append(executables, e.node.rel)
		} else {
			header.Mode = 0o644
		}
		if err := sealFile(ctx, tree, tw, header, e.node, buffer); err != nil {
			return sealed, nil, err
		}
	}
	if err := errors.Join(tw.Close(), buffered.Flush()); err != nil {
		return sealed, nil, err
	}
	slices.Sort(executables)
	sealed.SHA256 = hex.EncodeToString(hash.Sum(nil))
	sealed.SizeBytes = counted.count
	sealed.Entries = len(entries)
	return sealed, executables, nil
}

func sealFile(ctx context.Context, tree *archiveTree, tw *tar.Writer, header *tar.Header, n archiveNode, buffer []byte) error {
	file, err := tree.open(n)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	written, err := io.CopyBuffer(tw, io.LimitReader(&contextReader{ctx: ctx, reader: file}, n.size), buffer)
	if err != nil {
		return err
	}
	var extra [1]byte
	if count, readErr := file.Read(extra[:]); written != n.size || count != 0 || readErr != io.EOF {
		return archiveRefusal("%s changed while sealing", strconv.Quote(n.rel))
	}
	return nil
}

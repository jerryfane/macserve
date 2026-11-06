package signer

import (
	"archive/tar"
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

	"github.com/jerryfane/macserve/internal/worker"
)

const (
	noFollow       = unix.O_NOFOLLOW
	maxExtractPath = 1024
)

// extractArchive extracts the sealed archive tar into the empty directory
// dest, refusing anything the sealer never writes: a type other than a
// directory or regular file (links, devices, FIFOs), an entry outside the
// single top-level directory m.Archive.Root, a traversal or unclean name, an
// entry whose parent was not extracted before it, a duplicate or
// case-colliding path, ownership other than root with empty names, PAX
// records other than path, and modes other than 0755 directories and 0755
// or 0644 files. Every entry is created exclusively and without following
// links, relative to dest (os.Root). The set of 0755 files must be exactly
// m.Executables and the entry count m.Archive.Entries.
func extractArchive(ctx context.Context, archive io.Reader, dest *os.Root, m worker.SigningManifest) error {
	root := m.Archive.Root
	reader := tar.NewReader(archive)
	seen := map[string]bool{}
	folded := map[string]string{}
	dirs := map[string]bool{}
	var executables []string
	entries := 0
	buffer := make([]byte, 1<<20)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return refusal("archive tar: %v", err)
		}
		entries++
		if entries > m.Archive.Entries {
			return refusal("archive has more than the manifest's %d entries", m.Archive.Entries)
		}
		name := header.Name
		isDir := header.Typeflag == tar.TypeDir
		if isDir {
			name = strings.TrimSuffix(name, "/")
		} else if header.Typeflag != tar.TypeReg {
			return refusal("archive entry %s is not a directory or regular file", strconv.Quote(header.Name))
		}
		if !safeArchiveName(name) || (name != root && !strings.HasPrefix(name, root+"/")) || isDir != strings.HasSuffix(header.Name, "/") {
			return refusal("archive entry name %s", strconv.Quote(header.Name))
		}
		if seen[name] {
			return refusal("archive entry %s is duplicated", strconv.Quote(name))
		}
		key := strings.ToLower(name)
		if other, collides := folded[key]; collides {
			return refusal("archive entries %s and %s collide by case", strconv.Quote(other), strconv.Quote(name))
		}
		seen[name], folded[key] = true, name
		if name == root {
			if !isDir || entries != 1 {
				return refusal("archive root %s must be the first entry, a directory", strconv.Quote(root))
			}
		} else if !dirs[path.Dir(name)] {
			return refusal("archive entry %s precedes its directory", strconv.Quote(name))
		}
		if header.Uid != 0 || header.Gid != 0 || header.Uname != "" || header.Gname != "" {
			return refusal("archive entry %s ownership", strconv.Quote(name))
		}
		for record := range header.PAXRecords {
			if record != "path" {
				return refusal("archive entry %s has PAX record %s", strconv.Quote(name), strconv.Quote(record))
			}
		}
		mode := os.FileMode(header.Mode)
		if header.Mode&^0o777 != 0 || isDir && mode != 0o755 || !isDir && mode != 0o755 && mode != 0o644 {
			return refusal("archive entry %s mode %o", strconv.Quote(name), header.Mode)
		}
		if isDir {
			if err := dest.Mkdir(name, 0o700); err != nil {
				return refusal("archive directory %s: %v", strconv.Quote(name), err)
			}
			if err := dest.Chmod(name, 0o755); err != nil {
				return err
			}
			dirs[name] = true
			continue
		}
		if header.Size < 0 || header.Size > m.Archive.SizeBytes {
			return refusal("archive entry %s size", strconv.Quote(name))
		}
		if mode == 0o755 {
			executables = append(executables, strings.TrimPrefix(name, root+"/"))
		}
		if err := extractFile(ctx, reader, dest, name, header.Size, mode, buffer); err != nil {
			return err
		}
	}
	if entries != m.Archive.Entries {
		return refusal("archive has %d entries, the manifest %d", entries, m.Archive.Entries)
	}
	slices.Sort(executables)
	if !slices.Equal(executables, m.Executables) {
		return refusal("archive 0755 files differ from the manifest's executables")
	}
	return nil
}

func extractFile(ctx context.Context, reader io.Reader, dest *os.Root, name string, size int64, mode os.FileMode, buffer []byte) error {
	file, err := dest.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|noFollow, 0o600)
	if err != nil {
		return refusal("archive file %s: %v", strconv.Quote(name), err)
	}
	written, copyErr := io.CopyBuffer(file, io.LimitReader(reader, size), buffer)
	if copyErr == nil && written != size {
		copyErr = refusal("archive file %s is truncated", strconv.Quote(name))
	}
	if copyErr == nil {
		copyErr = file.Chmod(mode)
	}
	if err := errors.Join(copyErr, file.Close()); err != nil {
		return err
	}
	return ctx.Err()
}

// safeArchiveName accepts a clean relative slash path of valid UTF-8
// without empty, ".", ".." or control-character components.
func safeArchiveName(name string) bool {
	if name == "" || len(name) > maxExtractPath || !utf8.ValidString(name) || path.IsAbs(name) || path.Clean(name) != name {
		return false
	}
	for part := range strings.SplitSeq(name, "/") {
		if part == "" || part == "." || part == ".." || len(part) > 255 {
			return false
		}
		for _, c := range part {
			if c < 0x20 || c == 0x7f || c == '\\' {
				return false
			}
		}
	}
	return true
}

// refusal is a RefusalError: an input the signer refuses to sign.
func refusal(format string, args ...any) error {
	return &RefusalError{Reason: fmt.Sprintf(format, args...)}
}

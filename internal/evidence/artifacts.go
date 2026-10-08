package evidence

import (
	"archive/tar"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"mime"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jerryfane/macserve/internal/model"
	"golang.org/x/sys/unix"
)

var (
	ErrArtifact      = errors.New("invalid or unsafe artifact")
	ErrArtifactLimit = errors.New("artifact budget exceeded")
)

const defaultArtifactBytes int64 = 5 << 30
const defaultArtifactEntries = 10000

type artifactCandidate struct {
	name string
	info os.FileInfo
}

type artifactCollector struct {
	source      *os.File
	dest        *os.File
	limits      Limits
	entries     int
	inputBytes  int64
	outputBytes int64
	created     []string
	buffer      []byte
}

func artifactError(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrArtifact, fmt.Sprintf(format, args...))
}

func normalizeLimits(l Limits) (Limits, error) {
	if l.MaxTotalBytes < 0 || l.MaxFileBytes < 0 || l.MaxEntries < 0 {
		return l, artifactError("negative limit")
	}
	if l.MaxTotalBytes == 0 {
		l.MaxTotalBytes = defaultArtifactBytes
	}
	if l.MaxFileBytes == 0 {
		l.MaxFileBytes = defaultArtifactBytes
	}
	if l.MaxEntries == 0 {
		l.MaxEntries = defaultArtifactEntries
	}
	return l, nil
}

func validArtifactPattern(pattern string) bool {
	if pattern == "" || path.IsAbs(pattern) || strings.ContainsAny(pattern, "\\\x00") {
		return false
	}
	for _, part := range strings.Split(pattern, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	_, err := path.Match(pattern, "")
	return err == nil
}

func pathWithin(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// OpenRoot supplies the confinement boundary. All subsequent traversal uses
// directory descriptors with O_NOFOLLOW, including intermediate components;
// neither a symlink swap nor a FIFO can redirect or block a source open.
func openArtifactRoot(name string, private bool) (*os.File, error) {
	before, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, artifactError("root is not a real directory")
	}
	if private && before.Mode().Perm()&0077 != 0 {
		return nil, artifactError("export directory is not private")
	}
	root, err := os.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	file, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || (private && after.Mode().Perm()&0077 != 0) {
		file.Close()
		return nil, artifactError("root changed while opening")
	}
	if private {
		var stat unix.Stat_t
		if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
			file.Close()
			return nil, err
		}
		if stat.Uid != uint32(os.Geteuid()) {
			file.Close()
			return nil, artifactError("export directory is not service-owned")
		}
	}
	return file, nil
}

func openArtifactAt(parent *os.File, name string) (*os.File, os.FileInfo, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, artifactError("open %q: %v", name, err)
	}
	file := os.NewFile(uintptr(fd), name)
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, nil, err
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		file.Close()
		return nil, nil, artifactError("special entry %q", name)
	}
	return file, info, nil
}

func openArtifactPath(root *os.File, relative string) (*os.File, os.FileInfo, error) {
	parent := root
	owned := false
	parts := strings.Split(relative, "/")
	for i, part := range parts {
		file, info, err := openArtifactAt(parent, part)
		if owned {
			parent.Close()
		}
		if err != nil {
			return nil, nil, err
		}
		if i == len(parts)-1 {
			return file, info, nil
		}
		if !info.IsDir() {
			file.Close()
			return nil, nil, artifactError("non-directory path component")
		}
		parent, owned = file, true
	}
	return nil, nil, artifactError("empty artifact path")
}

func unchanged(a, b os.FileInfo) bool {
	return os.SameFile(a, b) && a.Size() == b.Size() && a.Mode() == b.Mode() && a.ModTime().Equal(b.ModTime())
}

func changeTime(file *os.File) (unix.Timespec, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return unix.Timespec{}, err
	}
	return stat.Ctim, nil
}

func directoryNames(dir *os.File, limit int) ([]string, error) {
	var names []string
	for {
		batch, err := dir.Readdirnames(128)
		if len(names)+len(batch) > limit {
			return nil, fmt.Errorf("%w: directory entry count", ErrArtifactLimit)
		}
		names = append(names, batch...)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(names)
	return names, nil
}

func matchArtifacts(dir *os.File, prefix string, parts []string, candidates map[string]artifactCandidate, seen map[string]bool, limit int) (int, error) {
	// Re-open rather than dup: duplicated directory descriptors share offsets.
	walk, _, err := openArtifactAt(dir, ".")
	if err != nil {
		return 0, err
	}
	defer walk.Close()
	matched := 0
	for {
		names, readErr := walk.Readdirnames(128)
		for _, name := range names {
			ok, _ := path.Match(parts[0], name)
			if !ok {
				continue
			}
			relative := name
			if prefix != "" {
				relative = prefix + "/" + name
			}
			if !seen[relative] {
				seen[relative] = true
				if len(seen) > limit {
					return 0, fmt.Errorf("%w: matching entry count", ErrArtifactLimit)
				}
			}
			file, info, err := openArtifactAt(walk, name)
			if err != nil {
				return 0, err
			}
			if len(parts) == 1 {
				candidates[relative] = artifactCandidate{name: relative, info: info}
				matched++
			} else if info.IsDir() {
				count, err := matchArtifacts(file, relative, parts[1:], candidates, seen, limit)
				file.Close()
				if err != nil {
					return 0, err
				}
				matched += count
				continue
			}
			file.Close()
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return 0, readErr
		}
	}
	return matched, nil
}

func (c *artifactCollector) accountEntry(info os.FileInfo) error {
	c.entries++
	if c.entries > c.limits.MaxEntries {
		return fmt.Errorf("%w: entry count", ErrArtifactLimit)
	}
	if info.Mode().IsRegular() {
		if info.Size() < 0 || info.Size() > c.limits.MaxFileBytes || info.Size() > c.limits.MaxTotalBytes-c.inputBytes {
			return fmt.Errorf("%w: input size", ErrArtifactLimit)
		}
		c.inputBytes += info.Size()
	}
	return nil
}

func (c *artifactCollector) copyFile(dst io.Writer, file *os.File, before os.FileInfo) error {
	if err := c.accountEntry(before); err != nil {
		return err
	}
	ctime, err := changeTime(file)
	if err != nil {
		return err
	}
	written, err := io.CopyBuffer(dst, io.LimitReader(file, before.Size()), c.buffer)
	if err != nil {
		return err
	}
	if written != before.Size() {
		return artifactError("file shortened during collection")
	}
	var extra [1]byte
	count, readErr := file.Read(extra[:])
	if count != 0 || readErr != io.EOF {
		return artifactError("file grew or changed during collection")
	}
	after, err := file.Stat()
	if err != nil {
		return err
	}
	if !unchanged(before, after) {
		return artifactError("file changed during collection")
	}
	afterTime, err := changeTime(file)
	if err != nil {
		return err
	}
	if ctime != afterTime {
		return artifactError("file metadata changed during collection")
	}
	return nil
}

func (c *artifactCollector) archive(tw *tar.Writer, dir *os.File, before os.FileInfo, name string, depth int) error {
	if depth > 128 {
		return fmt.Errorf("%w: directory nesting", ErrArtifactLimit)
	}
	if err := c.accountEntry(before); err != nil {
		return err
	}
	ctime, err := changeTime(dir)
	if err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: name + "/", Typeflag: tar.TypeDir, Mode: 0755, ModTime: time.Unix(0, 0), Format: tar.FormatPAX}); err != nil {
		return err
	}
	names, err := directoryNames(dir, c.limits.MaxEntries-c.entries)
	if err != nil {
		return err
	}
	for _, child := range names {
		file, info, err := openArtifactAt(dir, child)
		if err != nil {
			return err
		}
		if info.IsDir() {
			err = c.archive(tw, file, info, name+"/"+child, depth+1)
		} else {
			if info.Size() > c.limits.MaxFileBytes || info.Size() > c.limits.MaxTotalBytes-c.inputBytes {
				err = fmt.Errorf("%w: input size", ErrArtifactLimit)
			} else {
				err = tw.WriteHeader(&tar.Header{Name: name + "/" + child, Typeflag: tar.TypeReg, Mode: 0644, Size: info.Size(), ModTime: time.Unix(0, 0), Format: tar.FormatPAX})
				if err == nil {
					err = c.copyFile(tw, file, info)
				}
			}
		}
		closeErr := file.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	after, err := dir.Stat()
	if err != nil {
		return err
	}
	if !unchanged(before, after) {
		return artifactError("directory changed during collection")
	}
	afterTime, err := changeTime(dir)
	if err != nil {
		return err
	}
	if ctime != afterTime {
		return artifactError("directory metadata changed during collection")
	}
	return nil
}

type artifactWriter struct {
	collector *artifactCollector
	file      *os.File
	hash      hash.Hash
	size      int64
}

func (w *artifactWriter) Write(data []byte) (int, error) {
	count := int64(len(data))
	if count > w.collector.limits.MaxFileBytes-w.size || count > w.collector.limits.MaxTotalBytes-w.collector.outputBytes {
		return 0, fmt.Errorf("%w: output size", ErrArtifactLimit)
	}
	n, err := w.file.Write(data)
	w.hash.Write(data[:n])
	w.size += int64(n)
	w.collector.outputBytes += int64(n)
	return n, err
}

func (c *artifactCollector) temporary() (*os.File, string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, "", err
	}
	name := ".partial-" + hex.EncodeToString(random[:])
	fd, err := unix.Openat(int(c.dest.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, "", err
	}
	return os.NewFile(uintptr(fd), name), name, nil
}

func (c *artifactCollector) existingDigest(name string, size int64) error {
	file, before, err := openArtifactAt(c.dest, name)
	if err != nil {
		return err
	}
	defer file.Close()
	if !before.Mode().IsRegular() || before.Size() != size || before.Mode().Perm()&0077 != 0 {
		return artifactError("invalid existing export")
	}
	digest := sha256.New()
	n, err := io.CopyBuffer(digest, io.LimitReader(file, size+1), c.buffer)
	if err != nil {
		return err
	}
	after, err := file.Stat()
	if err != nil {
		return err
	}
	if n != size || hex.EncodeToString(digest.Sum(nil)) != name || !unchanged(before, after) {
		return artifactError("existing export digest mismatch")
	}
	return nil
}

func (c *artifactCollector) collect(candidate artifactCandidate, now time.Time) (artifact Artifact, resultErr error) {
	file, before, err := openArtifactPath(c.source, candidate.name)
	if err != nil {
		return artifact, err
	}
	defer file.Close()
	if !unchanged(candidate.info, before) {
		return artifact, artifactError("selected entry changed")
	}
	temp, tempName, err := c.temporary()
	if err != nil {
		return artifact, err
	}
	defer func() {
		temp.Close()
		if err := unix.Unlinkat(int(c.dest.Fd()), tempName, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			resultErr = errors.Join(resultErr, err)
		}
	}()
	writer := &artifactWriter{collector: c, file: temp, hash: sha256.New()}
	name := candidate.name
	mediaType := mime.TypeByExtension(path.Ext(name))
	if mediaType == "" {
		mediaType = "application/octet-stream"
	}
	if before.IsDir() {
		name += ".tar.gz"
		mediaType = "application/gzip"
		gz := gzip.NewWriter(writer)
		gz.Header.ModTime = time.Unix(0, 0)
		gz.Header.OS = 255
		tw := tar.NewWriter(gz)
		err = c.archive(tw, file, before, path.Base(candidate.name), 0)
		err = errors.Join(err, tw.Close(), gz.Close())
	} else {
		err = c.copyFile(writer, file, before)
	}
	if err != nil {
		return artifact, err
	}
	if err = temp.Sync(); err != nil {
		return artifact, err
	}
	if err = temp.Close(); err != nil {
		return artifact, err
	}
	id := hex.EncodeToString(writer.hash.Sum(nil))
	if err = unix.Linkat(int(c.dest.Fd()), tempName, int(c.dest.Fd()), id, 0); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return artifact, err
		}
		if err = c.existingDigest(id, writer.size); err != nil {
			return artifact, err
		}
	} else {
		c.created = append(c.created, id)
	}
	return Artifact{ID: id, Name: name, MediaType: mediaType, SizeBytes: writer.size, SHA256: id, ExpiresAt: now.UTC().Add(7 * 24 * time.Hour)}, nil
}

// Collect exports only approved path.Match selections. Both source bytes and
// sealed bytes are independently bounded. On any failure every export created
// by this call is removed; pre-existing content-addressed exports are untouched.
func Collect(root string, rules []model.ArtifactRule, dest string, limits Limits, now time.Time) (artifacts []Artifact, resultErr error) {
	limits, err := normalizeLimits(limits)
	if err != nil {
		return nil, err
	}
	for _, rule := range rules {
		if !validArtifactPattern(rule.Path) {
			return nil, artifactError("invalid pattern %q", rule.Path)
		}
	}
	rootPath, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	rootPath, err = filepath.Abs(rootPath)
	if err != nil {
		return nil, err
	}
	// Mkdir never adopts a symlink as a new export directory; existing roots are
	// checked below. The service owns its parent directory.
	if err = os.Mkdir(dest, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	destPath, err := filepath.EvalSymlinks(dest)
	if err != nil {
		return nil, err
	}
	destPath, err = filepath.Abs(destPath)
	if err != nil {
		return nil, err
	}
	if pathWithin(rootPath, destPath) || pathWithin(destPath, rootPath) {
		return nil, artifactError("export and source directories must be separate")
	}
	source, err := openArtifactRoot(root, false)
	if err != nil {
		return nil, err
	}
	defer source.Close()
	export, err := openArtifactRoot(dest, true)
	if err != nil {
		return nil, err
	}
	defer export.Close()
	c := artifactCollector{source: source, dest: export, limits: limits, buffer: make([]byte, 128<<10)}
	defer func() {
		if resultErr == nil {
			return
		}
		artifacts = nil
		for _, name := range c.created {
			if err := unix.Unlinkat(int(export.Fd()), name, 0); err != nil {
				resultErr = errors.Join(resultErr, err)
			}
		}
	}()
	candidates := make(map[string]artifactCandidate)
	seen := make(map[string]bool)
	for _, rule := range rules {
		count, err := matchArtifacts(source, "", strings.Split(rule.Path, "/"), candidates, seen, limits.MaxEntries)
		if err != nil {
			return nil, err
		}
		if count == 0 && rule.Required {
			return nil, artifactError("required pattern %q did not match", rule.Path)
		}
	}
	names := make([]string, 0, len(candidates))
	for name := range candidates {
		names = append(names, name)
	}
	sort.Strings(names)
	artifacts = make([]Artifact, 0, len(names))
	for _, name := range names {
		artifact, err := c.collect(candidates[name], now)
		if err != nil {
			return nil, err
		}
		artifacts = append(artifacts, artifact)
	}
	if err := export.Sync(); err != nil {
		return nil, err
	}
	return artifacts, nil
}

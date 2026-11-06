package signer

import (
	"archive/zip"
	"compress/flate"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

// zipEpoch is the earliest MS-DOS timestamp; every ipa entry carries it.
var zipEpoch = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)

// maxIPAExpandedBytes bounds the uncompressed content a re-parsed ipa may
// expand to.
const maxIPAExpandedBytes = 8 << 30

// writeIPA writes the deterministic ipa of the signed app directory app
// (a slash path below src) to out: entries Payload/, Payload/<name>/ and the
// app's tree in byte order of their names, directories 0755 and stored,
// files deflated with mode 0755 when any execute bit is set and 0644
// otherwise, every timestamp zipEpoch. Links and special files refuse. The
// same tree always yields the same bytes.
func writeIPA(ctx context.Context, src *os.Root, app string, out io.Writer) error {
	name := path.Base(app)
	zw := zip.NewWriter(out)
	zw.RegisterCompressor(zip.Deflate, func(w io.Writer) (io.WriteCloser, error) {
		return flate.NewWriter(w, flate.DefaultCompression)
	})
	directory := func(entry string) error {
		header := &zip.FileHeader{Name: entry + "/", Method: zip.Store, Modified: zipEpoch}
		header.SetMode(fs.ModeDir | 0o755)
		_, err := zw.CreateHeader(header)
		return err
	}
	if err := directory("Payload"); err != nil {
		return err
	}
	buffer := make([]byte, 1<<20)
	err := fs.WalkDir(src.FS(), app, func(current string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		entry := "Payload/" + name + strings.TrimPrefix(current, app)
		if d.IsDir() {
			return directory(entry)
		}
		if !d.Type().IsRegular() {
			return refusal("signed app has a non-regular file %s", strconv.Quote(current))
		}
		file, err := src.OpenFile(current, os.O_RDONLY|noFollow, 0)
		if err != nil {
			return err
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() {
			return refusal("signed app file %s changed type", strconv.Quote(current))
		}
		mode := fs.FileMode(0o644)
		if info.Mode().Perm()&0o111 != 0 {
			mode = 0o755
		}
		header := &zip.FileHeader{Name: entry, Method: zip.Deflate, Modified: zipEpoch}
		header.SetMode(mode)
		w, err := zw.CreateHeader(header)
		if err != nil {
			return err
		}
		_, err = io.CopyBuffer(w, file, buffer)
		return err
	})
	if err != nil {
		return err
	}
	return zw.Close()
}

// extractIPA re-parses an ipa into the empty directory dest: exactly one
// Payload/<name>.app tree of directories and regular files with clean,
// unique, case-distinct names, created exclusively relative to dest. It
// returns the app's slash path below dest.
func extractIPA(ctx context.Context, ipa *os.File, size int64, dest *os.Root) (string, error) {
	reader, err := zip.NewReader(ipa, size)
	if err != nil {
		return "", refusal("signed ipa: %v", err)
	}
	app := ""
	folded := map[string]bool{}
	var expanded uint64
	buffer := make([]byte, 1<<20)
	for _, f := range reader.File {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		mode := f.Mode()
		isDir := mode.IsDir()
		name := strings.TrimSuffix(f.Name, "/")
		if isDir != strings.HasSuffix(f.Name, "/") || !safeArchiveName(name) || (name != "Payload" && !strings.HasPrefix(name, "Payload/")) {
			return "", refusal("signed ipa entry %s", strconv.Quote(f.Name))
		}
		key := strings.ToLower(name)
		if folded[key] {
			return "", refusal("signed ipa entry %s is duplicated or collides by case", strconv.Quote(f.Name))
		}
		folded[key] = true
		parts := strings.Split(name, "/")
		if len(parts) >= 2 {
			if app == "" {
				app = path.Join(parts[0], parts[1])
			}
			if path.Join(parts[0], parts[1]) != app || !strings.HasSuffix(app, ".app") {
				return "", refusal("signed ipa holds more than one app")
			}
		}
		if isDir {
			if mode.Perm() != 0o755 {
				return "", refusal("signed ipa directory %s mode", strconv.Quote(name))
			}
			if err := dest.Mkdir(name, 0o755); err != nil {
				return "", refusal("signed ipa directory %s: %v", strconv.Quote(name), err)
			}
			continue
		}
		if !mode.IsRegular() || mode.Perm() != 0o755 && mode.Perm() != 0o644 {
			return "", refusal("signed ipa entry %s is not a 0755 or 0644 regular file", strconv.Quote(name))
		}
		expanded += f.UncompressedSize64
		if expanded > maxIPAExpandedBytes {
			return "", refusal("signed ipa expands beyond %d bytes", maxIPAExpandedBytes)
		}
		if err := extractZipFile(f, dest, name, mode.Perm(), buffer); err != nil {
			return "", err
		}
	}
	if app == "" {
		return "", refusal("signed ipa has no Payload app")
	}
	return app, nil
}

func extractZipFile(f *zip.File, dest *os.Root, name string, mode fs.FileMode, buffer []byte) error {
	in, err := f.Open()
	if err != nil {
		return refusal("signed ipa entry %s: %v", strconv.Quote(name), err)
	}
	defer in.Close()
	out, err := dest.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|noFollow, 0o600)
	if err != nil {
		return refusal("signed ipa entry %s: %v", strconv.Quote(name), err)
	}
	written, copyErr := io.CopyBuffer(out, io.LimitReader(in, int64(f.UncompressedSize64)+1), buffer)
	if copyErr == nil && uint64(written) != f.UncompressedSize64 {
		copyErr = refusal("signed ipa entry %s size", strconv.Quote(name))
	}
	if copyErr == nil {
		copyErr = out.Chmod(mode)
	}
	return errors.Join(copyErr, out.Close())
}

package worker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"golang.org/x/sys/unix"
)

// ArchiveEvidenceTimeout bounds an ios_archive job's root-side archive
// evidence: building the signing manifest, sealing the archive and
// collecting both exports. A multi-gigabyte archive does not fit the
// cleanup budget, so this is a separate window after the job's processes
// have stopped; the controller's finalizing window must include it.
const ArchiveEvidenceTimeout = 15 * time.Minute

// Plist decoding bounds for the default decoder.
const (
	plistTimeout       = 30 * time.Second
	maxPlistJSONBytes  = 4 << 20
	maxIntermediateRun = 1_000_000
)

// archiveIntermediates is where xcodebuild archive, run with
// -derivedDataPath ${DERIVED_DATA}, keeps each target's intermediates,
// including the requested entitlements <bundle>.xcent.
var archiveIntermediates = []string{"derived-data", "Build", "Intermediates.noindex", "ArchiveIntermediates"}

// plutilJSON is the default Options.PlistJSON: /usr/bin/plutil, run by the
// worker itself (never as the job user, never through the job runner) with
// the plist on stdin, a fixed environment, a short timeout and bounded
// output.
func plutilJSON(ctx context.Context, data []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, plistTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/plutil", "-convert", "json", "-o", "-", "-")
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"}
	cmd.WaitDelay = 100 * time.Millisecond
	cmd.Stdin = bytes.NewReader(data)
	stdout, stderr := &boundedBuffer{max: maxPlistJSONBytes}, &boundedBuffer{max: 64 << 10}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil {
		return nil, errors.Join(fmt.Errorf("plutil: %w: %s", err, strings.TrimSpace(stderr.String())), stdout.err, ctx.Err())
	}
	return stdout.Bytes(), nil
}

// archiveEvidence builds an ios_archive job's signing manifest and sealed
// archive root-side, after the job UID has stopped, and writes both into the
// protected evidence root as profiles.ArchiveArtifact and
// profiles.SigningManifestArtifact. The workspace is hostile: its archive
// and derived data are opened descriptor-relative on the workspace device,
// and nothing the job could plant in the workspace is exported.
func (x *execution) archiveEvidence(ctx context.Context) (returned error) {
	release := x.job.Profile.Release
	if release == nil {
		return errors.New("ios_archive job has no release")
	}
	workspace, err := x.engine.workspaces.OpenFile(x.job.ID, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer workspace.Close()
	maxBytes := x.engine.options.MaxArtifactBytes
	tree, m, err := archiveManifest(ctx, workspace, *release, x.engine.options.PlistJSON, archiveLimits{entries: maxArchiveEntries, bytes: maxBytes})
	if err != nil {
		return err
	}
	defer tree.root.Close()
	file, err := x.evidenceRoot.OpenFile(profiles.ArchiveArtifact, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if returned != nil {
			returned = errors.Join(returned, x.evidenceRoot.Remove(profiles.ArchiveArtifact))
		}
	}()
	m.Archive, m.Executables, err = sealArchive(ctx, tree, file, maxBytes)
	if err == nil {
		err = file.Sync()
	}
	if err = errors.Join(err, file.Close()); err != nil {
		return err
	}
	encoded, err := EncodeSigningManifest(m, *release)
	if err != nil {
		return err
	}
	manifest, err := x.evidenceRoot.OpenFile(profiles.SigningManifestArtifact, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = manifest.Write(encoded)
	if err == nil {
		err = manifest.Sync()
	}
	if err = errors.Join(err, manifest.Close()); err != nil {
		return errors.Join(err, x.evidenceRoot.Remove(profiles.SigningManifestArtifact))
	}
	x.archiveSealed = true
	return nil
}

// archiveManifest opens the workspace's profiles.ArchivePath on the
// workspace device, scans it within limits and returns the scanned tree
// (whose root the caller closes) with its signing manifest, entitlements
// included; Archive and Executables are left to the sealer.
func archiveManifest(ctx context.Context, workspace *os.File, release model.ReleaseRequest, decode PlistDecoder, limits archiveLimits) (*archiveTree, SigningManifest, error) {
	var top unix.Stat_t
	if err := fstatFD(int(workspace.Fd()), &top); err != nil {
		return nil, SigningManifest{}, err
	}
	device := uint64(top.Dev)
	root, err := openDirAt(workspace, profiles.ArchivePath, device)
	if err != nil {
		return nil, SigningManifest{}, fmt.Errorf("open %s: %w", profiles.ArchivePath, err)
	}
	tree, err := scanArchive(ctx, root, device, limits, unix.Fstatat)
	var m SigningManifest
	if err == nil {
		m, err = buildSigningManifest(ctx, tree, release, decode)
	}
	if err == nil {
		names := make(map[string]bool, len(m.Bundles))
		for _, b := range m.Bundles {
			names[path.Base(b.Path)] = true
		}
		var requested requestedEntitlements
		requested, err = archiveEntitlements(ctx, workspace, device, names, decode)
		for i := 0; err == nil && i < len(m.Bundles); i++ {
			if canonical, ok := requested[path.Base(m.Bundles[i].Path)]; ok {
				m.Bundles[i].Entitlements, m.Bundles[i].EntitlementsSHA256, err = canonicalEntitlements(canonical)
			}
		}
	}
	if err != nil {
		root.Close()
		return nil, m, err
	}
	return tree, m, nil
}

// archiveEntitlements reads the entitlements each named bundle's build
// requested: every regular file <name>.xcent below derived data's
// ArchiveIntermediates with a Release-iphoneos path component, decoded with
// decode and canonicalized. A bundle without one requested none; differing
// files for one bundle name refuse the archive. Symlinks are never followed
// (Xcode links products into BuildProductsPath); an .xcent symlink, hard
// link or special file, and any mount point, refuse.
func archiveEntitlements(ctx context.Context, workspace *os.File, device uint64, names map[string]bool, decode PlistDecoder) (requestedEntitlements, error) {
	found := requestedEntitlements{}
	dir := workspace
	for _, part := range archiveIntermediates {
		next, err := openDirAt(dir, part, device)
		if dir != workspace {
			dir.Close()
		}
		if errors.Is(err, unix.ENOENT) {
			return found, nil
		}
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", strconv.Quote(part), err)
		}
		dir = next
	}
	defer dir.Close()
	err := walkDescriptors(ctx, dir, device, maxIntermediateRun, unix.Fstatat, func(parent *os.File, name, rel string, stat *unix.Stat_t) (bool, error) {
		kind := stat.Mode & unix.S_IFMT
		bundle, isXcent := strings.CutSuffix(name, ".xcent")
		if !isXcent || !names[bundle] || !slices.Contains(strings.Split(path.Dir(rel), "/"), "Release-iphoneos") {
			return kind == unix.S_IFDIR, nil
		}
		if kind != unix.S_IFREG || uint64(stat.Nlink) != 1 {
			return false, archiveRefusal("entitlements %s are not a singly linked regular file", strconv.Quote(rel))
		}
		if stat.Size > maxInfoPlistBytes {
			return false, archiveRefusal("entitlements %s exceed %d bytes", strconv.Quote(rel), maxInfoPlistBytes)
		}
		fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return false, err
		}
		file := os.NewFile(uintptr(fd), name)
		defer file.Close()
		var opened unix.Stat_t
		if err := fstatFD(fd, &opened); err != nil {
			return false, err
		}
		if opened.Mode&unix.S_IFMT != unix.S_IFREG || uint64(opened.Ino) != uint64(stat.Ino) || uint64(opened.Dev) != device || uint64(opened.Nlink) != 1 {
			return false, archiveRefusal("entitlements %s changed while reading", strconv.Quote(rel))
		}
		raw, err := io.ReadAll(io.LimitReader(&contextReader{ctx: ctx, reader: file}, maxInfoPlistBytes+1))
		if err != nil {
			return false, err
		}
		if len(raw) > maxInfoPlistBytes {
			return false, archiveRefusal("entitlements %s exceed %d bytes", strconv.Quote(rel), maxInfoPlistBytes)
		}
		decoded, err := decode(ctx, raw)
		if err != nil {
			return false, fmt.Errorf("decode %s: %w", strconv.Quote(rel), err)
		}
		canonical, _, err := canonicalEntitlements(decoded)
		if err != nil {
			return false, fmt.Errorf("entitlements %s: %w", strconv.Quote(rel), err)
		}
		if previous, ok := found[bundle]; ok && !bytes.Equal(previous, canonical) {
			return false, archiveRefusal("conflicting entitlements for %s", strconv.Quote(bundle))
		}
		found[bundle] = canonical
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	return found, nil
}

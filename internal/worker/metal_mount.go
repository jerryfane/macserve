package worker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/jerryfane/macserve/internal/mounttable"
	"golang.org/x/sys/unix"
)

// metalToolchainMounts is where Xcode mounts the Metal toolchain disk image
// for a job, relative to its workspace (the job's HOME is <workspace>/home).
//
// Xcode 27 installs the Metal toolchain once per host, as a MobileAsset
// cryptex under /System/Library/AssetsV2. After every boot the first
// xcodebuild or xcrun that needs it asks cryptexd to personalize and mount it
// system-wide (/private/var/run/com.apple.security.cryptexd/mnt); a job's
// HOME has no personalization manifest of its own
// (~/Library/Developer/DVTDownloads/Personalization). When that attempt
// fails, Xcode's automatic mount method (IDEMetalToolchainMountMethod) falls
// back to attaching the asset's disk image itself, as the job user, at
// $HOME/Library/Developer/DVTDownloads/MetalToolchain/mounts/<asset ID>: a
// read-only, nodev, nosuid apfs volume mounted by the job UID. It outlives
// the Xcode process, and the job's later commands use it; once the
// system-wide cryptex is mounted, later jobs mount nothing.
const metalToolchainMounts = "home/Library/Developer/DVTDownloads/MetalToolchain/mounts"

var (
	metalAssetID = regexp.MustCompile(`^[0-9a-f]{40}$`)
	diskSlice    = regexp.MustCompile(`^/dev/disk[0-9]+s[0-9]+$`)
)

// MetalToolchainMountPoint reports whether the absolute path at has the shape
// of Xcode's Metal toolchain mount point in a job workspace under
// workspaceRoot: <workspaceRoot>/<job>/home/Library/Developer/DVTDownloads/
// MetalToolchain/mounts/<40 lowercase hex digit asset ID>.
func MetalToolchainMountPoint(workspaceRoot, at string) bool {
	rel, ok := strings.CutPrefix(at, workspaceRoot+"/")
	if !ok {
		return false
	}
	job, rest, ok := strings.Cut(rel, "/")
	if !ok || job == "" || job == "." || job == ".." {
		return false
	}
	asset, ok := strings.CutPrefix(rest, metalToolchainMounts+"/")
	return ok && metalAssetID.MatchString(asset)
}

// MetalToolchainMount reports whether m is Xcode's Metal toolchain image in a
// job workspace under workspaceRoot: an apfs volume on a /dev/disk slice,
// mounted read-only, nodev and nosuid by jobUID at a MetalToolchainMountPoint.
// Its bytes are Apple's asset, stored outside the workspace; nothing in it
// is writable, and only its owner or root can unmount it. Every other mount
// in a workspace stays refused.
func MetalToolchainMount(m mounttable.Entry, workspaceRoot string, jobUID uint32) bool {
	const required = mounttable.ReadOnly | mounttable.NoDev | mounttable.NoSUID
	return MetalToolchainMountPoint(workspaceRoot, m.On) && m.FSType == "apfs" && m.Owner == jobUID && m.Flags&required == required && diskSlice.MatchString(m.From)
}

// nestedMountCheck reports whether the mounted directory at a
// workspace-relative path, whose mounted root is on device dev, is one a
// workspace walk records but never opens, descends or charges.
type nestedMountCheck func(rel string, dev uint64) bool

// metalToolchainCheck is the nestedMountCheck of jobID's workspace walks
// while the job may hold Xcode's Metal toolchain image (its budget and
// evidence passes): true only when the unique mount-table record of dev is a
// MetalToolchainMount exactly at that path, mounted by the job UID. Cleanup
// unmounts it (unmountMetalToolchain).
func (e *Engine) metalToolchainCheck(jobID string) nestedMountCheck {
	workspace := filepath.Join(e.options.WorkspaceRoot, jobID)
	return func(rel string, dev uint64) bool {
		if path.Dir(rel) != metalToolchainMounts {
			return false
		}
		table, err := e.mounts()
		if err != nil {
			return false
		}
		m, ok := mounttable.Unique(table, dev)
		return ok && m.On == workspace+"/"+rel && MetalToolchainMount(m, e.options.WorkspaceRoot, e.options.JobUID)
	}
}

// unmountMetalToolchain unmounts Xcode's Metal toolchain image from m's
// workspace before cleanup removes it, once the job's processes are gone. It
// opens the mounts directory one component at a time, never following a link
// or leaving the workspace device, and unmounts an entry only if it is a
// directory whose device's unique mount-table record is a
// MetalToolchainMount exactly at that path. The unmount runs as the job
// (/sbin/umount, never forced): the kernel lets only a mount's owner or root
// unmount it, so it can do nothing the job could not. Every other mount is
// left to the cleanup pass, which refuses it as contamination. An unmount
// that fails leaves the workspace in place for recovery to retry, without
// contamination.
func (e *Engine) unmountMetalToolchain(ctx context.Context, m *manifest) error {
	dir, err := e.workspaces.OpenFile(m.JobID, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	// A mount at the job directory itself is left to the cleanup pass, which
	// refuses it (workspacePass).
	parent, err := e.workspaces.Open(".")
	if err != nil {
		dir.Close()
		return err
	}
	var workspaces, workspace unix.Stat_t
	err = errors.Join(fstatFD(int(parent.Fd()), &workspaces), fstatFD(int(dir.Fd()), &workspace))
	parent.Close()
	if err != nil || workspace.Dev != workspaces.Dev {
		dir.Close()
		return err
	}
	for _, name := range strings.Split(metalToolchainMounts, "/") {
		fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		dir.Close()
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP) {
			return nil
		}
		if err != nil {
			return err
		}
		dir = os.NewFile(uintptr(fd), name)
		var opened unix.Stat_t
		if err := fstatFD(fd, &opened); err != nil {
			dir.Close()
			return err
		}
		if opened.Dev != workspace.Dev {
			dir.Close()
			return nil
		}
	}
	defer dir.Close()
	type mounted struct {
		name string
		dev  uint64
	}
	var found []mounted
	for count := 0; ; {
		names, readErr := dir.Readdirnames(128)
		if readErr != nil && readErr != io.EOF {
			return readErr
		}
		for _, name := range names {
			if count++; count > maxArchiveEntries {
				return errors.New("workspace entry limit exceeded")
			}
			var st unix.Stat_t
			if err := lstatAt(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return err
			}
			if st.Dev != workspace.Dev && st.Mode&unix.S_IFMT == unix.S_IFDIR {
				found = append(found, mounted{name, uint64(st.Dev)})
			}
		}
		if readErr == io.EOF {
			break
		}
	}
	if len(found) == 0 {
		return nil
	}
	table, err := e.mounts()
	if err != nil {
		return fmt.Errorf("read mount table: %w", err)
	}
	root := filepath.Join(e.options.WorkspaceRoot, m.JobID)
	for _, f := range found {
		point := root + "/" + metalToolchainMounts + "/" + f.name
		if record, ok := mounttable.Unique(table, f.dev); !ok || record.On != point || !MetalToolchainMount(record, e.options.WorkspaceRoot, e.options.JobUID) {
			continue
		}
		output := &boundedBuffer{max: 1 << 20}
		stderr := &boundedBuffer{max: 1 << 20}
		result, err := e.run(ctx, Command{Executable: "/sbin/umount", Args: []string{point}, Dir: "/", Env: environment(root, m.DeveloperDir, e.options.JobUser), JobID: m.JobID}, output, stderr)
		if !result.CleanupOK {
			return errors.Join(err, ErrRecovery)
		}
		if err != nil || result.ExitCode != 0 || result.Signal != "" || output.err != nil || stderr.err != nil {
			return fmt.Errorf("unmount Xcode Metal toolchain image %s: %w", strconv.Quote(point), errors.Join(err, output.err, stderr.err, fmt.Errorf("exit %d signal %s: %s %s", result.ExitCode, result.Signal, output.String(), stderr.String())))
		}
		var after unix.Stat_t
		if err := lstatAt(int(dir.Fd()), f.name, &after, unix.AT_SYMLINK_NOFOLLOW); err != nil || after.Dev != workspace.Dev {
			return errors.Join(err, fmt.Errorf("unmount Xcode Metal toolchain image %s: still mounted", strconv.Quote(point)))
		}
	}
	return nil
}

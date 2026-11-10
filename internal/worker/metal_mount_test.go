package worker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/mounttable"
	"golang.org/x/sys/unix"
)

// studioMetalAsset is the MetalToolchain asset ID Xcode 27.1 mounted at the
// v0.1.40 and v0.1.42 after-reboot qualification rounds on the build host.
const studioMetalAsset = "389a215aea89fda945178f9fb8bcdc6aa0e20570"

// metalImage presents a directory as Xcode's Metal toolchain image mounted
// over it until the job runs /sbin/umount on it: lstatAt reports the mounted
// root's device for it, and the engine's mount table holds record (filled in
// with that device and the directory's path).
type metalImage struct {
	t        *testing.T
	mu       sync.Mutex
	point    string
	dev, ino uint64
	mounted  bool
	record   mounttable.Entry
	// unmountExit is the umount command's exit status; nonzero fails it.
	unmountExit int
	// sticky keeps the image mounted after a successful umount.
	sticky   bool
	unmounts []Command
}

// studioMetalRecord is the record of the Studio's leftover mount (`mount`:
// apfs, local, nodev, nosuid, read-only, journaled, noowners, mounted by the
// job user) for jobUID.
func studioMetalRecord(jobUID uint32) mounttable.Entry {
	return mounttable.Entry{Owner: jobUID, Flags: mounttable.ReadOnly | mounttable.NoSUID | mounttable.NoDev | 0x1000 | 0x200000 | 0x800000, FSType: "apfs", From: "/dev/disk12s1"}
}

// presentMetalImage creates point (and a shadowed file beneath it, which no
// walk may reach) and presents record mounted there.
func presentMetalImage(t *testing.T, engine *Engine, point string, record mounttable.Entry) *metalImage {
	t.Helper()
	m := &metalImage{t: t, record: record}
	m.create(point)
	saved := lstatAt
	lstatAt = func(fd int, name string, st *unix.Stat_t, flags int) error {
		var dir unix.Stat_t
		if err := unix.Fstat(fd, &dir); err != nil {
			return err
		}
		if err := unix.Fstatat(fd, name, st, flags); err != nil {
			return err
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		if !m.mounted {
			return nil
		}
		if uint64(dir.Ino) == m.ino && uint64(dir.Dev)+1 == m.dev {
			t.Errorf("walk descended into the mounted Metal toolchain image: stat %q", name)
		}
		if uint64(st.Ino) == m.ino && uint64(st.Dev)+1 == m.dev {
			st.Dev++
		}
		return nil
	}
	engine.mounts = func() ([]mounttable.Entry, error) {
		m.mu.Lock()
		defer m.mu.Unlock()
		if !m.mounted {
			return []mounttable.Entry{{FSID: 1, FSType: "apfs", On: "/"}}, nil
		}
		return []mounttable.Entry{{FSID: 1, FSType: "apfs", On: "/"}, m.entry()}, nil
	}
	t.Cleanup(func() { lstatAt = saved })
	return m
}

func (m *metalImage) create(point string) {
	if err := os.MkdirAll(point, 0700); err != nil {
		m.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(point, "shadowed"), []byte("on the workspace device, under the mount"), 0600); err != nil {
		m.t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Lstat(point, &st); err != nil {
		m.t.Fatal(err)
	}
	m.mu.Lock()
	m.point, m.ino, m.dev, m.mounted = point, uint64(st.Ino), uint64(st.Dev)+1, true
	m.mu.Unlock()
}

func (m *metalImage) entry() mounttable.Entry {
	e := m.record
	if e.FSID == 0 {
		e.FSID = m.dev
	}
	if e.On == "" {
		e.On = m.point
	}
	return e
}

// hook answers the job's /sbin/umount of the image.
func (m *metalImage) hook(_ context.Context, c Command, _, stderr io.Writer) (bool, ProcessResult, error) {
	if c.Executable != "/sbin/umount" {
		return false, ProcessResult{}, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.unmounts = append(m.unmounts, c)
	if m.unmountExit != 0 {
		io.WriteString(stderr, "umount: unmount("+m.point+"): Resource busy\n")
		return true, ProcessResult{ExitCode: m.unmountExit, CleanupOK: true}, &exitStatusError{code: m.unmountExit}
	}
	if len(c.Args) == 1 && c.Args[0] == m.point && !m.sticky {
		m.mounted = false
	}
	return true, ProcessResult{CleanupOK: true}, nil
}

func (m *metalImage) umounts() []Command {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.unmounts)
}

func metalPoint(workspace string) string {
	return filepath.Join(workspace, metalToolchainMounts, studioMetalAsset)
}

// v0.1.40/v0.1.42 after-reboot qualification failure: the job's first
// xcodebuild after boot attached Xcode's Metal toolchain image under the job
// HOME. The budget monitor refused it (`mount point in workspace:
// "home/Library/Developer/DVTDownloads/MetalToolchain/mounts/<asset>"`) and
// cleanup quarantined the workspace (`foreign workspace entry`). Now the job
// succeeds, no walk enters the image, and cleanup unmounts it as the job
// before removing the workspace.
func TestJobMetalToolchainImageIsUnmountedNotContamination(t *testing.T) {
	runner := &fakeRunner{}
	engine := engineFixture(t, runner)
	var image *metalImage
	runner.hook = func(ctx context.Context, c Command, out, stderr io.Writer) (bool, ProcessResult, error) {
		if isMetalProbe(c) {
			// Xcode falls back to attaching the asset image in the job HOME.
			image.create(metalPoint(c.Dir))
			_, err := io.WriteString(out, "Asset Path: /System/Library/AssetsV2/com_apple_MobileAsset_MetalToolchain/"+studioMetalAsset+".asset/AssetData\nBuild Version: 27A266a\nStatus: installed\n")
			return true, ProcessResult{CleanupOK: true}, err
		}
		return image.hook(ctx, c, out, stderr)
	}
	image = presentMetalImage(t, engine, filepath.Join(t.TempDir(), "unused"), studioMetalRecord(engine.options.JobUID))
	image.mu.Lock()
	image.mounted = false
	image.mu.Unlock()
	job := fixtureJob(t, model.Build)
	source, data := sourceFixture(t)
	result, err := engine.Execute(context.Background(), job, source, bytes.NewReader(data), nil)
	if err != nil || result.State != model.Succeeded || !result.CleanupOK {
		t.Fatalf("job with Xcode's Metal toolchain image: %+v %v", result, err)
	}
	workspace := filepath.Join(engine.options.WorkspaceRoot, job.ID)
	umounts := image.umounts()
	if len(umounts) != 1 || umounts[0].JobID != job.ID || umounts[0].Dir != "/" || !slices.Equal(umounts[0].Args, []string{metalPoint(workspace)}) || !slices.Equal(umounts[0].Env, environment(workspace, job.Profile.DeveloperDir, engine.options.JobUser)) {
		t.Fatalf("umount commands %+v, want one job umount of %s", umounts, metalPoint(workspace))
	}
	if _, err := os.Lstat(workspace); !os.IsNotExist(err) {
		t.Fatalf("workspace not removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(engine.options.Root, quarantineRecord)); !os.IsNotExist(err) {
		t.Fatalf("quarantined: %v", err)
	}
}

// After a crash (or the owner's worker reset), recovery unmounts a leftover
// image the same way instead of refusing the workspace.
func TestRecoverUnmountsLeftoverMetalToolchainImage(t *testing.T) {
	runner := &fakeRunner{}
	engine := engineFixture(t, runner)
	if err := engine.saveManifest(manifest{JobID: "job", DeveloperDir: "/Applications/Xcode.app/Contents/Developer"}); err != nil {
		t.Fatal(err)
	}
	workspace := filepath.Join(engine.options.WorkspaceRoot, "job")
	image := presentMetalImage(t, engine, metalPoint(workspace), studioMetalRecord(engine.options.JobUID))
	runner.hook = image.hook
	if err := engine.Recover(context.Background()); err != nil {
		t.Fatalf("recover with a leftover Metal toolchain image: %v", err)
	}
	if umounts := image.umounts(); len(umounts) != 1 || umounts[0].JobID != "job" {
		t.Fatalf("umount commands %+v", umounts)
	}
	if _, err := os.Lstat(workspace); !os.IsNotExist(err) {
		t.Fatalf("workspace not removed: %v", err)
	}
}

// Only that exact mount is unmounted. Anything else at or near its path stays
// a mount in the workspace: cleanup runs no umount, refuses it as
// contamination (or, when the mount table cannot be read, fails) and removes
// nothing beneath it.
func TestCleanupRefusesEveryOtherWorkspaceMount(t *testing.T) {
	change := func(f func(*mounttable.Entry)) func(uint32) mounttable.Entry {
		return func(jobUID uint32) mounttable.Entry {
			e := studioMetalRecord(jobUID)
			f(&e)
			return e
		}
	}
	for name, tc := range map[string]struct {
		point  func(workspace string) string
		record func(jobUID uint32) mounttable.Entry
		table  func(image mounttable.Entry) ([]mounttable.Entry, error)
		want   string
	}{
		"writable image":          {record: change(func(e *mounttable.Entry) { e.Flags &^= mounttable.ReadOnly })},
		"device nodes allowed":    {record: change(func(e *mounttable.Entry) { e.Flags &^= mounttable.NoDev })},
		"setuid allowed":          {record: change(func(e *mounttable.Entry) { e.Flags &^= mounttable.NoSUID })},
		"another owner":           {record: change(func(e *mounttable.Entry) { e.Owner++ })},
		"not apfs":                {record: change(func(e *mounttable.Entry) { e.FSType = "hfs" })},
		"FSKit volume":            {record: change(func(e *mounttable.Entry) { e.FSType = "devicefs"; e.From = "devices -- file:///tmp/" })},
		"network source":          {record: change(func(e *mounttable.Entry) { e.FSType = "apfs"; e.From = "//user@host/share" })},
		"whole disk source":       {record: change(func(e *mounttable.Entry) { e.From = "/dev/disk12" })},
		"record for another path": {record: change(func(e *mounttable.Entry) { e.On = "/Volumes/MetalToolchain" })},
		"not an asset ID":         {point: func(w string) string { return filepath.Join(w, metalToolchainMounts, "volume") }},
		"uppercase asset ID": {point: func(w string) string {
			return filepath.Join(w, metalToolchainMounts, strings.ToUpper(studioMetalAsset))
		}},
		"elsewhere in the home": {point: func(w string) string {
			return filepath.Join(w, "home/Library/Developer/DVTDownloads", studioMetalAsset)
		}},
		"below an asset mount point": {point: func(w string) string { return filepath.Join(w, metalToolchainMounts, studioMetalAsset, "nested") }},
		"in the checkout":            {point: func(w string) string { return filepath.Join(w, "checkout", metalToolchainMounts, studioMetalAsset) }},
		"ambiguous record":           {table: func(e mounttable.Entry) ([]mounttable.Entry, error) { return []mounttable.Entry{e, e}, nil }},
		"no record":                  {table: func(mounttable.Entry) ([]mounttable.Entry, error) { return nil, nil }},
		"mount table unavailable":    {table: func(mounttable.Entry) ([]mounttable.Entry, error) { return nil, unix.EIO }, want: "read mount table: input/output error"},
	} {
		t.Run(name, func(t *testing.T) {
			runner := &fakeRunner{}
			engine := engineFixture(t, runner)
			m := &manifest{JobID: "job", DeveloperDir: "/Applications/Xcode.app/Contents/Developer"}
			workspace := filepath.Join(engine.options.WorkspaceRoot, m.JobID)
			point := metalPoint(workspace)
			if tc.point != nil {
				point = tc.point(workspace)
			}
			record := studioMetalRecord(engine.options.JobUID)
			if tc.record != nil {
				record = tc.record(engine.options.JobUID)
			}
			image := presentMetalImage(t, engine, point, record)
			runner.hook = image.hook
			if tc.table != nil {
				engine.mounts = func() ([]mounttable.Entry, error) { return tc.table(image.entry()) }
			}
			err := engine.cleanup(context.Background(), m)
			if tc.want != "" {
				if err == nil || errors.Is(err, ErrContamination) || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("cleanup = %v, want %q", err, tc.want)
				}
			} else if !errors.Is(err, ErrContamination) || !strings.Contains(err.Error(), "foreign workspace entry") {
				t.Fatalf("cleanup = %v, want contamination", err)
			}
			if umounts := image.umounts(); len(umounts) != 0 {
				t.Fatalf("unmounted another mount: %+v", umounts)
			}
			if _, err := os.Stat(filepath.Join(point, "shadowed")); err != nil {
				t.Fatalf("cleanup removed beneath the mount: %v", err)
			}
		})
	}
}

// An unmount that fails, or leaves the image mounted, fails cleanup without
// contamination and keeps the workspace for recovery to retry.
func TestCleanupKeepsWorkspaceWhenMetalToolchainUnmountFails(t *testing.T) {
	for name, configure := range map[string]func(*metalImage){
		"umount fails":  func(m *metalImage) { m.unmountExit = 1 },
		"still mounted": func(m *metalImage) { m.sticky = true },
	} {
		t.Run(name, func(t *testing.T) {
			runner := &fakeRunner{}
			engine := engineFixture(t, runner)
			m := &manifest{JobID: "job", DeveloperDir: "/Applications/Xcode.app/Contents/Developer"}
			point := metalPoint(filepath.Join(engine.options.WorkspaceRoot, m.JobID))
			image := presentMetalImage(t, engine, point, studioMetalRecord(engine.options.JobUID))
			configure(image)
			runner.hook = image.hook
			err := engine.cleanup(context.Background(), m)
			if err == nil || errors.Is(err, ErrContamination) || !strings.Contains(err.Error(), "unmount Xcode Metal toolchain image") {
				t.Fatalf("cleanup = %v, want an unmount failure", err)
			}
			if len(image.umounts()) != 1 {
				t.Fatalf("umount commands %+v", image.umounts())
			}
			if _, err := os.Stat(filepath.Join(point, "shadowed")); err != nil {
				t.Fatalf("workspace changed: %v", err)
			}
		})
	}
}

// The budget walk and the evidence pass skip only the exact image; the
// lockfile walk and every other mount still refuse.
func TestWorkspaceWalksSkipOnlyTheMetalToolchainImage(t *testing.T) {
	engine := engineFixture(t, &fakeRunner{})
	workspace := filepath.Join(engine.options.WorkspaceRoot, "job")
	if err := os.MkdirAll(filepath.Join(workspace, "checkout"), 0700); err != nil {
		t.Fatal(err)
	}
	image := presentMetalImage(t, engine, metalPoint(workspace), studioMetalRecord(engine.options.JobUID))
	root, err := os.OpenRoot(workspace)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	check := engine.metalToolchainCheck("job")
	if err := workspaceBudgetWith(root, 1<<40, lstatAt, check); err != nil {
		t.Fatalf("budget walk with the Metal toolchain image: %v", err)
	}
	if err := workspaceBudgetWith(root, 1<<40, lstatAt, nil); !errors.Is(err, errWorkspaceMount) || !strings.Contains(err.Error(), `"home/Library/Developer/DVTDownloads/MetalToolchain/mounts/`+studioMetalAsset+`"`) {
		t.Fatalf("budget walk without the check = %v, want the v0.1.42 refusal", err)
	}
	if err := engine.workspacePass(context.Background(), "job", false, false); err != nil {
		t.Fatalf("evidence pass with the Metal toolchain image: %v", err)
	}
	if err := engine.workspacePass(context.Background(), "job", false, true); !errors.Is(err, ErrContamination) {
		t.Fatalf("repair pass = %v, want contamination (cleanup unmounts first)", err)
	}
	if checkWrongJob := engine.metalToolchainCheck("other"); checkWrongJob("home/Library/Developer/DVTDownloads/MetalToolchain/mounts/"+studioMetalAsset, image.dev) {
		t.Fatal("another job's check accepted this job's image")
	}
	image.mu.Lock()
	image.record.Flags &^= mounttable.ReadOnly
	image.mu.Unlock()
	if err := workspaceBudgetWith(root, 1<<40, lstatAt, check); !errors.Is(err, errWorkspaceMount) {
		t.Fatalf("budget walk with a writable image = %v, want refusal", err)
	}
	if err := engine.workspacePass(context.Background(), "job", false, false); !errors.Is(err, ErrContamination) {
		t.Fatalf("evidence pass with a writable image = %v, want contamination", err)
	}
}

func TestMetalToolchainMountPoint(t *testing.T) {
	const root = "/Library/macserve/var/workspaces"
	for at, want := range map[string]bool{
		root + "/job/home/Library/Developer/DVTDownloads/MetalToolchain/mounts/" + studioMetalAsset:        true,
		root + "/job/home/Library/Developer/DVTDownloads/MetalToolchain/mounts/" + studioMetalAsset + "/x": false,
		root + "/job/home/Library/Developer/DVTDownloads/MetalToolchain/mounts/" + studioMetalAsset[1:]:    false,
		root + "/job/checkout/Library/Developer/DVTDownloads/MetalToolchain/mounts/" + studioMetalAsset:    false,
		root + "/home/Library/Developer/DVTDownloads/MetalToolchain/mounts/" + studioMetalAsset:            false,
		root + "/../job/home/Library/Developer/DVTDownloads/MetalToolchain/mounts/" + studioMetalAsset:     false,
		"/Users/macservejob/Library/Developer/DVTDownloads/MetalToolchain/mounts/" + studioMetalAsset:      false,
	} {
		if got := MetalToolchainMountPoint(root, at); got != want {
			t.Errorf("MetalToolchainMountPoint(%q) = %v, want %v", at, got, want)
		}
	}
}

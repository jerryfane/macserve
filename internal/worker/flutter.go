package worker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/jerryfane/macserve/internal/hostguard"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"golang.org/x/sys/unix"
)

// maxLockfileBytes bounds every tracked dependency lockfile.
const maxLockfileBytes = 16 << 20

// flutterPin is the Flutter pin of a Flutter template job's snapshot, or nil.
func flutterPin(p model.Profile) *model.FlutterPin {
	if p.Template == nil {
		return nil
	}
	return p.Template.Flutter
}

// checkFlutterTools requires every pinned Flutter tool to be root-owned and
// not job-writable, like the developer directory, before a job uses them.
func checkFlutterTools(pin model.FlutterPin, jobUID uint32) error {
	tools := profiles.FlutterToolPaths(pin)
	for _, check := range []struct {
		path      string
		directory bool
	}{{tools.SDK, true}, {tools.SDK + "/bin/flutter", false}, {tools.Ruby, false}, {tools.Gems, true}, {tools.Pod, false}} {
		var err error
		if check.directory {
			err = hostguard.ToolchainDirectory(check.path, jobUID)
		} else {
			err = hostguard.ToolchainExecutable(check.path, jobUID)
		}
		if err != nil {
			return fmt.Errorf("pinned Flutter tool %s: %w", check.path, err)
		}
	}
	return nil
}

// flutterEnvironment is env, a job's environment, for a Flutter job: FLUTTER_ROOT
// is the job's SDK clone, the pub cache and CocoaPods home are in the
// workspace, the gem tree is only the pinned one, and PATH starts with the
// clone's, the pinned Ruby's and the gem tree's bin directories.
func flutterEnvironment(env []string, workspace string, pin model.FlutterPin) []string {
	tools := profiles.FlutterToolPaths(pin)
	root := filepath.Join(workspace, profiles.FlutterSDKClone)
	env = slices.DeleteFunc(slices.Clone(env), func(entry string) bool { return strings.HasPrefix(entry, "PATH=") })
	return append([]string{"PATH=" + strings.Join([]string{filepath.Join(root, "bin"), path.Dir(tools.Ruby), path.Dir(tools.Pod), "/usr/bin:/bin:/usr/sbin:/sbin"}, ":")}, append(env,
		"FLUTTER_ROOT="+root,
		"PUB_CACHE="+filepath.Join(workspace, profiles.FlutterPubCache),
		"CP_HOME_DIR="+filepath.Join(workspace, profiles.FlutterCocoaPodsHome),
		"GEM_HOME="+tools.Gems,
		"GEM_PATH="+tools.Gems,
		"FLUTTER_SUPPRESS_ANALYTICS=true",
		"CI=true",
	)...)
}

// flutterPreflight runs before any command of a Flutter job: the app's
// pubspec.lock and ios/Podfile.lock must be regular, single-link files
// reached without a symlink under the checkout, and Podfile.lock must name the
// pinned CocoaPods version.
func flutterPreflight(checkout *os.Root, f model.FlutterConfig, pin model.FlutterPin) error {
	if _, err := readSourceLockfile(checkout, path.Join(f.AppDir, "pubspec.lock")); err != nil {
		return err
	}
	name := path.Join(f.AppDir, "ios", "Podfile.lock")
	podfile, err := readSourceLockfile(checkout, name)
	if err != nil {
		return err
	}
	var versions []string
	for _, line := range strings.Split(string(podfile), "\n") {
		if version, ok := strings.CutPrefix(line, "COCOAPODS:"); ok {
			versions = append(versions, strings.TrimSpace(version))
		}
	}
	if len(versions) != 1 || versions[0] != pin.CocoaPodsVersion {
		return fmt.Errorf("flutter preflight: %s must have one COCOAPODS: %s line, found %q", name, pin.CocoaPodsVersion, versions)
	}
	return nil
}

func readSourceLockfile(checkout *os.Root, name string) ([]byte, error) {
	fail := func(err error) ([]byte, error) {
		return nil, fmt.Errorf("flutter preflight: %s must be a committed regular single-link file: %w", name, err)
	}
	if err := noSymlinkPath(checkout, name); err != nil {
		return fail(err)
	}
	file, err := checkout.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return fail(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fail(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || !ok || stat.Nlink != 1 || info.Size() > maxLockfileBytes {
		return fail(errors.New("not a regular single-link file within the size limit"))
	}
	data, err := io.ReadAll(io.LimitReader(file, maxLockfileBytes+1))
	if err == nil && len(data) > maxLockfileBytes {
		err = errors.New("grew beyond the size limit")
	}
	if err != nil {
		return fail(err)
	}
	return data, nil
}

// observeFlutter records the Flutter, Ruby and CocoaPods identity of a
// Flutter job right after its SDK clone (observeFlutterToolchain in
// job_observation.go, class C); a mismatch with the pin fails the job.
func (x *execution) observeFlutter(ctx context.Context, pin model.FlutterPin) error {
	tools := profiles.FlutterToolPaths(pin)
	observed, err := observeFlutterToolchain(ctx, pin, filepath.Join(x.workspace, profiles.FlutterSDKClone, "bin", "flutter"), tools.Ruby, tools.Pod, x.capture)
	x.result.Observation.Flutter = observed
	return err
}

// checkCheckoutFile requires a checkout-relative file a recipe command runs
// to be a regular source file reached without any symlink, immediately
// before the command runs.
func (x *execution) checkCheckoutFile(relative string) error {
	if !safeRelative(relative) {
		return fmt.Errorf("script %s is not a checkout path", relative)
	}
	name := "checkout/" + relative
	if err := noSymlinkPath(x.root, name); err != nil {
		return fmt.Errorf("script %s: %w", relative, err)
	}
	file, err := x.root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("script %s: %w", relative, err)
	}
	info, err := file.Stat()
	closeErr := file.Close()
	if err = errors.Join(err, closeErr); err != nil {
		return fmt.Errorf("script %s: %w", relative, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("script %s is not a regular file", relative)
	}
	return nil
}

// flutterStep runs what a Flutter job needs around one prepare command:
// before a prepare_ruby script, the script check; after the SDK clone, the
// Flutter toolchain observation.
func (x *execution) flutterStep(ctx context.Context, command model.Command, after bool) error {
	pin := flutterPin(x.job.Profile)
	if pin == nil {
		return nil
	}
	if after {
		if sameCommand(command, profiles.FlutterSDKCloneCommand(*pin)) {
			return x.observeFlutter(ctx, *pin)
		}
		return nil
	}
	if command.Executable != profiles.FlutterToolPaths(*pin).Ruby {
		return nil
	}
	relative, ok := "", len(command.Args) == 1
	if ok {
		relative, ok = strings.CutPrefix(command.Args[0], profiles.ScriptCheckoutPrefix)
	}
	if !ok {
		return errors.New("prepare_ruby recipe is not a checkout script")
	}
	return x.checkCheckoutFile(relative)
}

func sameCommand(a, b model.Command) bool {
	return a.Executable == b.Executable && slices.Equal(a.Args, b.Args)
}

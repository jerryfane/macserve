package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"
)

func (x *execution) observe(ctx context.Context) error {
	version, err := x.capture(ctx, "/usr/bin/xcodebuild", "-version")
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimSpace(string(version)), "\n")
	if len(lines) != 2 || strings.TrimSpace(lines[0]) != "Xcode "+x.job.Profile.Xcode.Version || strings.TrimSpace(lines[1]) != "Build version "+x.job.Profile.Xcode.Build {
		return errors.New("installed Xcode does not match exact profile pins")
	}
	x.result.Observation.Xcode = x.job.Profile.Xcode
	sdk := "macosx"
	if x.job.Profile.Simulator != nil {
		sdk = "iphonesimulator"
		if strings.Contains(x.job.Profile.Simulator.Runtime, "tvOS-") {
			sdk = "appletvsimulator"
		}
		if strings.Contains(x.job.Profile.Simulator.Runtime, "watchOS-") {
			sdk = "watchsimulator"
		}
		if strings.Contains(x.job.Profile.Simulator.Runtime, "xrOS-") {
			sdk = "xrsimulator"
		}
	}
	probes := []struct {
		executable string
		args       []string
		target     *string
	}{
		{"/usr/bin/xcrun", []string{"--sdk", sdk, "--show-sdk-version"}, &x.result.Observation.SDKVersion},
		{"/usr/bin/xcrun", []string{"--sdk", sdk, "--show-sdk-build-version"}, &x.result.Observation.SDKBuild},
		{"/usr/bin/xcrun", []string{"swift", "--version"}, &x.result.Observation.SwiftVersion},
		{"/usr/bin/sw_vers", []string{"-productVersion"}, &x.result.Observation.OSVersion},
		{"/usr/bin/sw_vers", []string{"-buildVersion"}, &x.result.Observation.OSBuild},
	}
	for _, probe := range probes {
		output, err := x.capture(ctx, probe.executable, probe.args...)
		if err != nil {
			return err
		}
		*probe.target = strings.TrimSpace(string(output))
		if *probe.target == "" {
			return errors.New("toolchain observation is empty")
		}
	}
	x.result.Observation.Architecture = runtime.GOARCH
	return nil
}

func (x *execution) simulator(ctx context.Context) error {
	pin := x.job.Profile.Simulator
	if pin == nil {
		return nil
	}
	data, err := x.capture(ctx, "/usr/bin/xcrun", "simctl", "list", "runtimes", "--json")
	if err != nil {
		return err
	}
	var listing struct {
		Runtimes []struct {
			Identifier string `json:"identifier"`
			Version    string `json:"version"`
			Build      string `json:"buildversion"`
			Available  bool   `json:"isAvailable"`
			Supported  []struct {
				Identifier string `json:"identifier"`
			} `json:"supportedDeviceTypes"`
		} `json:"runtimes"`
	}
	if err := json.Unmarshal(data, &listing); err != nil {
		return fmt.Errorf("runtime listing: %w", err)
	}
	matched := false
	for _, item := range listing.Runtimes {
		if item.Identifier != pin.Runtime {
			continue
		}
		if matched || !item.Available || item.Build != pin.RuntimeBuild {
			return errors.New("pinned simulator runtime unavailable or build mismatch")
		}
		compatible := false
		for _, device := range item.Supported {
			if device.Identifier == pin.DeviceType {
				compatible = true
			}
		}
		if !compatible {
			return errors.New("pinned device type is not supported by runtime")
		}
		matched = true
		x.result.Observation.RuntimeVersion = item.Version
		x.result.Observation.RuntimeBuild = item.Build
	}
	if !matched {
		return errors.New("pinned simulator runtime missing")
	}
	// Record the inventory before creation. An interrupted create must never
	// infer ownership from a device name or delete an unrecorded UDID.
	before, err := x.engine.deviceInventory(ctx, &x.manifest)
	if err != nil {
		return err
	}
	x.manifest.DevicesBefore = before
	x.manifest.DeviceCreatePending = true
	if err := x.engine.saveManifest(x.manifest); err != nil {
		return err
	}
	output, err := x.capture(ctx, "/usr/bin/xcrun", "simctl", "create", "macserve-"+x.job.ID, pin.DeviceType, pin.Runtime)
	id := strings.TrimSpace(string(output))
	if !udidPattern.MatchString(id) {
		return errors.Join(err, errors.New("simulator creation did not return a valid owned UDID"))
	}
	x.manifest.DeviceUDID = id
	x.manifest.DeviceCreatePending = false
	x.manifest.DevicesBefore = nil
	x.result.Observation.DeviceUDID = id
	if saveErr := x.engine.saveManifest(x.manifest); saveErr != nil {
		return errors.Join(err, saveErr)
	}
	if err != nil {
		return err
	}
	if _, err := x.capture(ctx, "/usr/bin/xcrun", "simctl", "boot", id); err != nil {
		return err
	}
	_, err = x.capture(ctx, "/usr/bin/xcrun", "simctl", "bootstatus", id, "-b")
	return err
}

func environment(workspace, developer string) []string {
	return []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "DEVELOPER_DIR=" + developer, "HOME=" + filepath.Join(workspace, "home"), "TMPDIR=" + filepath.Join(workspace, "tmp"), "TMP=" + filepath.Join(workspace, "tmp"), "TEMP=" + filepath.Join(workspace, "tmp"), "CFFIXED_USER_HOME=" + filepath.Join(workspace, "home"), "XDG_CACHE_HOME=" + filepath.Join(workspace, "caches"), "CLANG_MODULE_CACHE_PATH=" + filepath.Join(workspace, "caches", "clang"), "SWIFT_MODULECACHE_PATH=" + filepath.Join(workspace, "caches", "swift"), "LANG=en_US.UTF-8", "LC_ALL=en_US.UTF-8"}
}

func (e *Engine) stopWriters(ctx context.Context, m *manifest) error {
	ctx, cancel := context.WithTimeout(ctx, e.options.CleanupTimeout)
	defer cancel()
	var simulatorErr error
	if err := e.verifyDeviceCreation(ctx, m); err != nil {
		return err
	}
	if m.DeviceUDID != "" {
		if err := e.reconcileDevice(ctx, m); err != nil {
			return err
		}
		simulatorErr = e.stopDevice(ctx, m)
	}
	quietErr := e.options.Runner.Quiesce(ctx)
	if quietErr != nil {
		return errors.Join(ErrRecovery, simulatorErr, quietErr)
	}
	return simulatorErr
}

func (e *Engine) stopDevice(ctx context.Context, m *manifest) error {
	if m.DeviceUDID != "" {
		if !udidPattern.MatchString(m.DeviceUDID) {
			return ErrRecovery
		}
		command := Command{Executable: "/usr/bin/xcrun", Dir: "/", Env: environment(filepath.Join(e.options.WorkspaceRoot, m.JobID), m.DeveloperDir)}
		var failures []error
		for _, action := range []string{"shutdown", "delete"} {
			command.Args = []string{"simctl", action, m.DeviceUDID}
			output := &boundedBuffer{max: 1 << 20}
			stderr := &boundedBuffer{max: 1 << 20}
			result, err := e.run(ctx, command, output, stderr)
			if !result.CleanupOK {
				return errors.Join(err, ErrRecovery)
			}
			if err != nil || result.ExitCode != 0 || result.Signal != "" || output.err != nil || stderr.err != nil {
				failures = append(failures, fmt.Errorf("simulator %s failed: %w", action, errors.Join(err, output.err, stderr.err, fmt.Errorf("exit %d signal %s: %s %s", result.ExitCode, result.Signal, output.String(), stderr.String()))))
			}
		}
		if len(failures) != 0 {
			return errors.Join(failures...)
		}
		if err := e.reconcileDevice(ctx, m); err != nil {
			return err
		}
		if m.DeviceUDID != "" {
			return fmt.Errorf("%w: recorded simulator remains after deletion", ErrContamination)
		}
	}
	return nil
}

func (e *Engine) cleanup(ctx context.Context, m *manifest) error {
	ctx, cancel := context.WithTimeout(ctx, e.options.CleanupTimeout)
	defer cancel()
	if m.DeviceCreatePending || m.DeviceUDID != "" {
		return fmt.Errorf("%w: unresolved simulator ownership", ErrRecovery)
	}
	if err := e.workspacePass(ctx, m.JobID, false, true); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := e.workspaces.RemoveAll(m.JobID); err != nil {
		return err
	}
	if err := e.root.RemoveAll("evidence/" + m.JobID); err != nil {
		return err
	}
	if err := e.root.Remove("manifests/" + m.JobID + ".json"); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// A prior delete may have succeeded just before a crash or registry write
// failure. Recovery proves that exact UDID absent, without matching device names
// or touching any unrecorded simulator.
func (e *Engine) deviceInventory(ctx context.Context, m *manifest) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, e.options.CleanupTimeout)
	defer cancel()
	output := &boundedBuffer{max: 16 << 20}
	stderr := &boundedBuffer{max: 1 << 20}
	result, err := e.run(ctx, Command{Executable: "/usr/bin/xcrun", Args: []string{"simctl", "list", "devices", "--json"}, Dir: "/", Env: environment(filepath.Join(e.options.WorkspaceRoot, m.JobID), m.DeveloperDir)}, output, stderr)
	if err != nil || result.ExitCode != 0 || result.Signal != "" || !result.CleanupOK || output.err != nil || stderr.err != nil {
		return nil, errors.Join(err, output.err, stderr.err, errors.New("cannot verify recorded simulator inventory"))
	}
	var listing struct {
		Devices map[string][]struct {
			UDID string `json:"udid"`
		} `json:"devices"`
	}
	if err := json.Unmarshal(output.Bytes(), &listing); err != nil {
		return nil, err
	}
	if listing.Devices == nil {
		return nil, errors.New("simulator inventory has no devices object")
	}
	ids := make([]string, 0)
	for _, devices := range listing.Devices {
		for _, device := range devices {
			if !udidPattern.MatchString(device.UDID) {
				return nil, errors.New("simulator inventory contains an invalid UDID")
			}
			ids = append(ids, device.UDID)
		}
	}
	return ids, nil
}

func (e *Engine) reconcileDevice(ctx context.Context, m *manifest) error {
	ids, err := e.deviceInventory(ctx, m)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if id == m.DeviceUDID {
			return nil
		}
	}
	m.DeviceUDID = ""
	return e.saveManifest(*m)
}

func (e *Engine) verifyDeviceCreation(ctx context.Context, m *manifest) error {
	if !m.DeviceCreatePending {
		return nil
	}
	ids, err := e.deviceInventory(ctx, m)
	if err != nil {
		return err
	}
	if m.DevicesBefore == nil && len(ids) != 0 {
		return errors.New("interrupted legacy create lacks a protected baseline inventory")
	}
	before := make(map[string]bool, len(m.DevicesBefore))
	for _, id := range m.DevicesBefore {
		before[id] = true
	}
	for _, id := range ids {
		if !before[id] {
			return fmt.Errorf("%w: unrecorded simulator after interrupted creation: %s; worker-reset required", ErrContamination, id)
		}
	}
	m.DeviceCreatePending = false
	m.DevicesBefore = nil
	return e.saveManifest(*m)
}

// Reset can remove only exact job-UID inventory additions to the protected
// pre-create snapshot. Ordinary recovery never adopts these identities.
func (e *Engine) resetDeviceCreation(ctx context.Context, m *manifest) error {
	if !m.DeviceCreatePending {
		return nil
	}
	first, err := e.deviceInventory(ctx, m)
	if err != nil {
		return err
	}
	if m.DevicesBefore == nil && len(first) != 0 {
		return errors.New("interrupted legacy create lacks a protected baseline inventory")
	}
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
	}
	second, err := e.deviceInventory(ctx, m)
	if err != nil {
		return err
	}
	slices.Sort(first)
	slices.Sort(second)
	if !slices.Equal(first, second) {
		return errors.New("simulator inventory changed during reset inspection")
	}
	before := make(map[string]bool, len(m.DevicesBefore))
	for _, id := range m.DevicesBefore {
		if !udidPattern.MatchString(id) {
			return errors.New("invalid protected simulator baseline")
		}
		before[id] = true
	}
	for _, id := range second {
		if before[id] {
			continue
		}
		m.DeviceUDID = id
		if err := e.saveManifest(*m); err != nil {
			return err
		}
		if err := e.stopDevice(ctx, m); err != nil {
			return err
		}
	}
	return e.verifyDeviceCreation(ctx, m)
}

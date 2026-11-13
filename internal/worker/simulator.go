package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/jerryfane/macserve/internal/model"
)

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
	for attempt := 1; ; attempt++ {
		x.result.Observation.SimulatorBootAttempts = attempt
		id, err := x.createDevice(ctx, pin)
		if err != nil {
			return err
		}
		retryable, err := x.bootDevice(ctx, id)
		if err == nil || !retryable || attempt == simulatorBootAttempts {
			return err
		}
		// The one infrastructure retry: discard the device that failed to
		// boot through the teardown path (shutdown and delete the recorded
		// UDID, prove it absent, quiesce the job UID) and create a fresh one.
		// Tests are never retried.
		if stopErr := x.engine.stopWriters(ctx, &x.manifest, x.job.ID); stopErr != nil {
			return errors.Join(err, stopErr)
		}
		x.result.Observation.DeviceUDID = ""
		if _, logErr := fmt.Fprintf(x.stderr, "macserve: simulator boot failed (%v); retrying once on a new device\n", err); logErr != nil {
			return logErr
		}
	}
}

// simulatorBootAttempts bounds how many fresh devices a job may create when
// `simctl boot` or `bootstatus` fails: one retry, for infrastructure flakes.
const simulatorBootAttempts = 2

// createDevice creates the job's own device and records its UDID. The
// inventory is recorded before creation: an interrupted create must never
// infer ownership from a device name or delete an unrecorded UDID.
func (x *execution) createDevice(ctx context.Context, pin *model.Simulator) (string, error) {
	// One creation at a time across lanes: a sibling's device is then
	// either in this snapshot or recorded in its own manifest before this
	// creation starts (see verifyDeviceCreation).
	x.engine.deviceMu.Lock()
	defer x.engine.deviceMu.Unlock()
	before, err := x.engine.deviceInventory(ctx, &x.manifest)
	if err != nil {
		return "", err
	}
	x.manifest.DevicesBefore = before
	x.manifest.DeviceCreatePending = true
	if err := x.engine.saveManifest(x.manifest); err != nil {
		return "", err
	}
	output, err := x.capture(ctx, "/usr/bin/xcrun", "simctl", "create", "macserve-"+x.job.ID, pin.DeviceType, pin.Runtime)
	id := strings.TrimSpace(string(output))
	if !udidPattern.MatchString(id) {
		return "", errors.Join(err, errors.New("simulator creation did not return a valid owned UDID"))
	}
	x.manifest.DeviceUDID = id
	x.manifest.DeviceCreatePending = false
	x.manifest.DevicesBefore = nil
	x.result.Observation.DeviceUDID = id
	if lanes := x.engine.laneRunner(); lanes != nil && x.engine.laneMode() {
		// Before boot: the device's launchd_sim is the job's from its start.
		lanes.AttachDevice(x.job.ID, id)
	}
	if saveErr := x.engine.saveManifest(x.manifest); saveErr != nil {
		return "", errors.Join(err, saveErr)
	}
	return id, err
}

// bootDevice boots the owned device and waits for it. retryable reports a
// plain boot failure: simctl failed with its processes cleaned up, nothing was
// contaminated and the job itself is still live.
func (x *execution) bootDevice(ctx context.Context, id string) (retryable bool, err error) {
	for _, args := range [][]string{{"simctl", "boot", id}, {"simctl", "bootstatus", id, "-b"}} {
		result, err := x.invoke(ctx, x.command("/usr/bin/xcrun", args), x.stdout, x.stderr)
		if err != nil {
			return result.CleanupOK && ctx.Err() == nil && !errors.Is(err, ErrContamination) && !errors.Is(err, ErrRecovery), err
		}
	}
	return false, nil
}

// environment is the whole environment of every job command. HOME, TMPDIR and
// the caches point into the job workspace. USER and LOGNAME name the job
// account (Options.JobUser, resolved from the configured job UID, never from
// the caller's environment): tools such as XcodeGen refuse to run without USER
// ("Couldn't find current username"). Deliberately absent: SHELL (tools fall
// back to the account's login shell or /bin/sh, and Xcode script phases name
// their own shell), __CF_USER_TEXT_ENCODING (CoreFoundation derives the same
// default without it), SSH_AUTH_SOCK and every other launchd session variable,
// which would hand the job the GUI session's agents.
func environment(workspace, developer, account string) []string {
	return []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "USER=" + account, "LOGNAME=" + account, "DEVELOPER_DIR=" + developer, "HOME=" + filepath.Join(workspace, "home"), "TMPDIR=" + filepath.Join(workspace, "tmp"), "TMP=" + filepath.Join(workspace, "tmp"), "TEMP=" + filepath.Join(workspace, "tmp"), "CFFIXED_USER_HOME=" + filepath.Join(workspace, "home"), "XDG_CACHE_HOME=" + filepath.Join(workspace, "caches"), "CLANG_MODULE_CACHE_PATH=" + filepath.Join(workspace, "caches", "clang"), "SWIFT_MODULECACHE_PATH=" + filepath.Join(workspace, "caches", "swift"), "LANG=en_US.UTF-8", "LC_ALL=en_US.UTF-8"}
}

// stopWriters stops m's simulators (its own and those its script created)
// and then the job processes jobID's cleanup may stop (accountQuiesce);
// jobID "" is recovery, which stops every job process. A concurrent script
// job's recorded start (beginScriptDevices) is released only after a
// second adoption, once those processes are stopped, has deleted any device
// one of them created after the first: until then it stays in the manifest
// for recovery.
func (e *Engine) stopWriters(ctx context.Context, m *manifest, jobID string) error {
	ctx, cancel := context.WithTimeout(ctx, e.options.CleanupTimeout)
	defer cancel()
	var simulatorErr error
	if err := e.verifyDeviceCreation(ctx, m); err != nil {
		return err
	}
	if err := e.adoptScriptDevices(ctx, m); err != nil {
		return err
	}
	if m.DeviceUDID != "" {
		if err := e.reconcileDevice(ctx, m); err != nil {
			return err
		}
		simulatorErr = e.stopDevice(ctx, m)
	}
	simulatorErr = errors.Join(simulatorErr, e.stopScriptDevices(ctx, m))
	quietErr := e.accountQuiesce(ctx, jobID)
	if quietErr != nil {
		return errors.Join(ErrRecovery, simulatorErr, quietErr)
	}
	if simulatorErr != nil || !m.ScriptDevicesPending {
		return simulatorErr
	}
	if err := e.adoptScriptDevices(ctx, m); err != nil {
		return err
	}
	if err := e.stopScriptDevices(ctx, m); err != nil {
		return err
	}
	m.ScriptDevicesPending, m.ScriptDevicesBefore = false, nil
	return e.saveManifest(*m)
}

func (e *Engine) stopDevice(ctx context.Context, m *manifest) error {
	if m.DeviceUDID != "" {
		if !udidPattern.MatchString(m.DeviceUDID) {
			return ErrRecovery
		}
		if err := e.removeDevice(ctx, m, m.DeviceUDID); err != nil {
			return err
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

// removeDevice shuts down and deletes the simulator udid that m records.
func (e *Engine) removeDevice(ctx context.Context, m *manifest, udid string) error {
	command := Command{Executable: "/usr/bin/xcrun", Dir: "/", Env: environment(filepath.Join(e.options.WorkspaceRoot, m.JobID), m.DeveloperDir, e.options.JobUser), JobID: m.JobID}
	var failures []error
	for _, action := range []string{"shutdown", "delete"} {
		command.Args = []string{"simctl", action, udid}
		output := &boundedBuffer{max: 1 << 20}
		stderr := &boundedBuffer{max: 1 << 20}
		result, err := e.run(ctx, command, output, stderr)
		if !result.CleanupOK {
			return errors.Join(err, ErrRecovery)
		}
		if action == "shutdown" && alreadyShutdown(err, result, output, stderr) {
			// A device that failed to boot may already be shut down; the
			// delete and the absence proof still decide ownership.
			continue
		}
		if err != nil || result.ExitCode != 0 || result.Signal != "" || output.err != nil || stderr.err != nil {
			failures = append(failures, fmt.Errorf("simulator %s failed: %w", action, errors.Join(err, output.err, stderr.err, fmt.Errorf("exit %d signal %s: %s %s", result.ExitCode, result.Signal, output.String(), stderr.String()))))
		}
	}
	return errors.Join(failures...)
}

// beginScriptDevices runs just before a concurrent script job's script
// (model.Profile.Concurrent): it records the simulator inventory the script
// starts from in m, and has the lane attribution give the job the processes
// of simulators no job created through the engine (laneRunner.AdoptDevices).
// The job's cleanup then adopts and deletes the devices its script added
// (adoptScriptDevices, stopScriptDevices). It runs under deviceMu, so no
// engine creation is in flight.
func (e *Engine) beginScriptDevices(ctx context.Context, m *manifest) error {
	e.deviceMu.Lock()
	defer e.deviceMu.Unlock()
	before, err := e.deviceInventory(ctx, m)
	if err != nil {
		return err
	}
	m.ScriptDevicesPending, m.ScriptDevicesBefore = true, before
	if err := e.saveManifest(*m); err != nil {
		return err
	}
	if lanes := e.laneRunner(); lanes != nil && e.laneMode() {
		lanes.AdoptDevices(m.JobID, e.options.Now())
	}
	return nil
}

// adoptScriptDevices adopts from a recorded script start
// (beginScriptDevices): every simulator listed now that was not in the
// inventory the script started from, is not m's own and that no other
// manifest records becomes one of m's ScriptDevices. Only one concurrent
// script job runs at a time (the store claims one, enter admits one), and
// every engine creation is recorded in its manifest before deviceMu, held
// here, is released: such a device is one the script created. The start
// stays recorded (stopWriters releases it). It also applies after a restart
// (Recover).
func (e *Engine) adoptScriptDevices(ctx context.Context, m *manifest) error {
	if !m.ScriptDevicesPending {
		return nil
	}
	e.deviceMu.Lock()
	defer e.deviceMu.Unlock()
	ids, err := e.deviceInventory(ctx, m)
	if err != nil {
		return err
	}
	recorded, err := e.recordedDevices(m.JobID)
	if err != nil {
		return err
	}
	before := make(map[string]bool, len(m.ScriptDevicesBefore))
	for _, id := range m.ScriptDevicesBefore {
		before[strings.ToUpper(id)] = true
	}
	for _, id := range ids {
		key := strings.ToUpper(id)
		if before[key] || recorded[key] || key == strings.ToUpper(m.DeviceUDID) || slices.ContainsFunc(m.ScriptDevices, func(own string) bool { return strings.EqualFold(own, id) }) {
			continue
		}
		m.ScriptDevices = append(m.ScriptDevices, id)
		if lanes := e.laneRunner(); lanes != nil && e.laneMode() {
			lanes.AttachDevice(m.JobID, id)
		}
	}
	return e.saveManifest(*m)
}

// stopScriptDevices shuts down and deletes every simulator m's script
// created that is still listed and proves them all absent; m keeps only
// those that remain, which is contamination.
func (e *Engine) stopScriptDevices(ctx context.Context, m *manifest) error {
	if len(m.ScriptDevices) == 0 {
		return nil
	}
	if slices.ContainsFunc(m.ScriptDevices, func(id string) bool { return !udidPattern.MatchString(id) }) {
		return ErrRecovery
	}
	ids, err := e.deviceInventory(ctx, m)
	if err != nil {
		return err
	}
	var failures []error
	for _, udid := range m.ScriptDevices {
		if slices.Contains(ids, udid) {
			failures = append(failures, e.removeDevice(ctx, m, udid))
		}
	}
	if err := errors.Join(failures...); err != nil {
		return err
	}
	if ids, err = e.deviceInventory(ctx, m); err != nil {
		return err
	}
	m.ScriptDevices = slices.DeleteFunc(m.ScriptDevices, func(id string) bool { return !slices.Contains(ids, id) })
	if len(m.ScriptDevices) == 0 {
		m.ScriptDevices = nil
	}
	if err := e.saveManifest(*m); err != nil {
		return err
	}
	if len(m.ScriptDevices) != 0 {
		return fmt.Errorf("%w: %d script-created simulator(s) remain after deletion", ErrContamination, len(m.ScriptDevices))
	}
	return nil
}

// simctlAlreadyShutdown is CoreSimulator's refusal to shut down a device that
// is already in the Shutdown state.
const simctlAlreadyShutdown = "Unable to shutdown device in current state: Shutdown"

// alreadyShutdown reports whether a completed `simctl shutdown <recorded UDID>`
// failed only because the device was already shut down: a plain non-zero
// exit (the runner's error is exactly that exit status, or none), no signal,
// intact output and CoreSimulator's state refusal. Cancellation, output,
// drain and cleanup failures are joined to the runner's error, so they never
// qualify.
func alreadyShutdown(err error, result ProcessResult, output, stderr *boundedBuffer) bool {
	return (err == nil || onlyExitStatus(err, result.ExitCode)) && result.ExitCode > 0 && result.Signal == "" && result.CleanupOK && output.err == nil && stderr.err == nil && strings.Contains(output.String()+stderr.String(), simctlAlreadyShutdown)
}

func (e *Engine) cleanup(ctx context.Context, m *manifest) error {
	ctx, cancel := context.WithTimeout(ctx, e.options.CleanupTimeout)
	defer cancel()
	if m.DeviceCreatePending || m.DeviceUDID != "" || m.ScriptDevicesPending || len(m.ScriptDevices) != 0 {
		return fmt.Errorf("%w: unresolved simulator ownership", ErrRecovery)
	}
	if err := e.unmountMetalToolchain(ctx, m); err != nil {
		return err
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
	result, err := e.run(ctx, Command{Executable: "/usr/bin/xcrun", Args: []string{"simctl", "list", "devices", "--json"}, Dir: "/", Env: environment(filepath.Join(e.options.WorkspaceRoot, m.JobID), m.DeveloperDir, e.options.JobUser), JobID: m.JobID}, output, stderr)
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

// verifyDeviceCreation resolves an interrupted creation: every device now
// listed must be in the pre-create snapshot, recorded by another job's
// manifest (a sibling's own device, created after this one's creation
// ended) or one a concurrent script job's cleanup adopts (absent from its
// recorded start inventory); anything else is an unrecorded device. It runs
// under deviceMu, so no sibling creation is in flight.
func (e *Engine) verifyDeviceCreation(ctx context.Context, m *manifest) error {
	if !m.DeviceCreatePending {
		return nil
	}
	e.deviceMu.Lock()
	defer e.deviceMu.Unlock()
	ids, err := e.deviceInventory(ctx, m)
	if err != nil {
		return err
	}
	recorded, err := e.recordedDevices(m.JobID)
	if err != nil {
		return err
	}
	scripts, err := e.scriptStarts(m.JobID)
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
		adopted := slices.ContainsFunc(scripts, func(start map[string]bool) bool { return !start[strings.ToUpper(id)] })
		if !before[id] && !recorded[strings.ToUpper(id)] && !adopted {
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
	recorded, err := e.recordedDevices(m.JobID)
	if err != nil {
		return err
	}
	for _, id := range second {
		if before[id] || recorded[strings.ToUpper(id)] {
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

// recordedDevices is the set of device UDIDs (upper case) other jobs'
// manifests record as theirs: their own devices and their scripts' devices.
func (e *Engine) recordedDevices(except string) (map[string]bool, error) {
	others, err := e.otherManifests(except)
	if err != nil {
		return nil, err
	}
	recorded := map[string]bool{}
	for _, other := range others {
		if other.DeviceUDID != "" {
			recorded[strings.ToUpper(other.DeviceUDID)] = true
		}
		for _, id := range other.ScriptDevices {
			recorded[strings.ToUpper(id)] = true
		}
	}
	return recorded, nil
}

// scriptStarts is the start inventory (UDIDs, upper case) of every other
// job's recorded script start that its cleanup has not yet adopted from
// (beginScriptDevices): a device absent from one is that script's to adopt.
func (e *Engine) scriptStarts(except string) ([]map[string]bool, error) {
	others, err := e.otherManifests(except)
	if err != nil {
		return nil, err
	}
	var starts []map[string]bool
	for _, other := range others {
		if !other.ScriptDevicesPending {
			continue
		}
		start := make(map[string]bool, len(other.ScriptDevicesBefore))
		for _, id := range other.ScriptDevicesBefore {
			start[strings.ToUpper(id)] = true
		}
		starts = append(starts, start)
	}
	return starts, nil
}

// otherManifests reads every resource manifest but except's.
func (e *Engine) otherManifests(except string) ([]manifest, error) {
	names, err := e.registryNames()
	if err != nil {
		return nil, err
	}
	var others []manifest
	for _, name := range names {
		if name == except+".json" || !strings.HasSuffix(name, ".json") {
			continue
		}
		var other manifest
		if err := readJSON(e.root, "manifests/"+name, &other); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		others = append(others, other)
	}
	return others, nil
}

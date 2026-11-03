package worker

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"time"

	"github.com/jerryfane/macserve/internal/model"
)

// This file is class C in BOUNDARY.json. It receives only the profile's
// toolchain pins (values) and two job-command capabilities, and returns
// what it observed; (*execution).observe in execute.go (class B) runs the
// commands, decides which failures are fatal and writes the result.

// metalProbeTimeout bounds the Metal toolchain probe.
const metalProbeTimeout = 30 * time.Second

// toolchainPins are the profile values the toolchain observation checks.
type toolchainPins struct {
	Xcode            model.Xcode
	Simulator        bool
	SimulatorRuntime string
}

// toolchainObservation is what observeToolchain measured, including the part
// observed before a failure.
type toolchainObservation struct {
	MetalToolchain *MetalToolchain
	Xcode          model.Xcode
	SDKVersion     string
	SDKBuild       string
	SwiftVersion   string
	OSVersion      string
	OSBuild        string
	Architecture   string
}

// observeMetalToolchain runs the fixed `xcodebuild -showComponent
// MetalToolchain` as the job, with the job environment, before any other job
// command. Since Xcode 26, xcrun and xcodebuild find the downloaded Metal
// toolchain only through ~/Library/Developer/Xcode/
// XcodeToMetalToolchainIndexMapping.plist (Apple FB20389216), and the job's
// HOME is a fresh empty directory; this command writes that mapping into it.
// A failed or not-installed probe is recorded, never fatal, so projects
// without Metal sources keep building. probeJob returns the failure text of a
// recorded failure; contamination, unconfirmed process cleanup and
// cancellation of the job itself are its error and still fail the job.
func observeMetalToolchain(ctx context.Context, probeJob func(context.Context, time.Duration, string, ...string) ([]byte, string, error)) (*MetalToolchain, error) {
	output, failure, err := probeJob(ctx, metalProbeTimeout, "/usr/bin/xcodebuild", "-showComponent", "MetalToolchain")
	if err != nil {
		return nil, err
	}
	observed := parseMetalToolchain(output)
	if failure != "" {
		observed.Error = clip(failure, 1024)
	}
	return &observed, nil
}

func parseMetalToolchain(output []byte) MetalToolchain {
	var observed MetalToolchain
	for _, line := range strings.Split(string(output), "\n") {
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		switch strings.TrimSpace(key) {
		case "Status":
			observed.Status = strings.TrimSpace(value)
		case "Build Version":
			observed.BuildVersion = strings.TrimSpace(value)
		}
	}
	return observed
}

// observeToolchain probes the Metal toolchain, then requires the installed
// Xcode to match the pins and records the SDK, Swift and OS versions. capture
// runs one fixed command as the job and returns its bounded output.
func observeToolchain(ctx context.Context, pins toolchainPins, probeJob func(context.Context, time.Duration, string, ...string) ([]byte, string, error), capture func(context.Context, string, ...string) ([]byte, error)) (toolchainObservation, error) {
	var observed toolchainObservation
	metal, err := observeMetalToolchain(ctx, probeJob)
	if err != nil {
		return observed, err
	}
	observed.MetalToolchain = metal
	version, err := capture(ctx, "/usr/bin/xcodebuild", "-version")
	if err != nil {
		return observed, err
	}
	lines := strings.Split(strings.TrimSpace(string(version)), "\n")
	if len(lines) != 2 || strings.TrimSpace(lines[0]) != "Xcode "+pins.Xcode.Version || strings.TrimSpace(lines[1]) != "Build version "+pins.Xcode.Build {
		return observed, errors.New("installed Xcode does not match exact profile pins")
	}
	observed.Xcode = pins.Xcode
	sdk := "macosx"
	if pins.Simulator {
		sdk = "iphonesimulator"
		if strings.Contains(pins.SimulatorRuntime, "tvOS-") {
			sdk = "appletvsimulator"
		}
		if strings.Contains(pins.SimulatorRuntime, "watchOS-") {
			sdk = "watchsimulator"
		}
		if strings.Contains(pins.SimulatorRuntime, "xrOS-") {
			sdk = "xrsimulator"
		}
	}
	probes := []struct {
		executable string
		args       []string
		target     *string
	}{
		{"/usr/bin/xcrun", []string{"--sdk", sdk, "--show-sdk-version"}, &observed.SDKVersion},
		{"/usr/bin/xcrun", []string{"--sdk", sdk, "--show-sdk-build-version"}, &observed.SDKBuild},
		{"/usr/bin/xcrun", []string{"swift", "--version"}, &observed.SwiftVersion},
		{"/usr/bin/sw_vers", []string{"-productVersion"}, &observed.OSVersion},
		{"/usr/bin/sw_vers", []string{"-buildVersion"}, &observed.OSBuild},
	}
	for _, probe := range probes {
		output, err := capture(ctx, probe.executable, probe.args...)
		if err != nil {
			return observed, err
		}
		*probe.target = strings.TrimSpace(string(output))
		if *probe.target == "" {
			return observed, errors.New("toolchain observation is empty")
		}
	}
	observed.Architecture = runtime.GOARCH
	return observed, nil
}

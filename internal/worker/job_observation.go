package worker

import (
	"context"
	"errors"
	"io"
	"runtime"
	"strings"
	"time"

	"github.com/jerryfane/macserve/internal/evidence"
)

// This file is class C in BOUNDARY.json: it runs job commands only through
// the reviewed execution seams (invoke, command, capture) and declares no
// methods on boundary types.

// metalProbeTimeout bounds the Metal toolchain probe.
const metalProbeTimeout = 30 * time.Second

// observeMetalToolchain runs the fixed `xcodebuild -showComponent
// MetalToolchain` as the job, with the job environment, before any other job
// command. Since Xcode 26, xcrun and xcodebuild find the downloaded Metal
// toolchain only through ~/Library/Developer/Xcode/
// XcodeToMetalToolchainIndexMapping.plist (Apple FB20389216), and the job's
// HOME is a fresh empty directory; this command writes that mapping into it.
// A failed or not-installed probe is recorded, never fatal, so projects
// without Metal sources keep building. Contamination, unconfirmed process
// cleanup and cancellation of the job itself still fail the job.
func observeMetalToolchain(ctx context.Context, x *execution) error {
	probe, cancel := context.WithTimeout(ctx, metalProbeTimeout)
	defer cancel()
	output := &boundedBuffer{max: evidence.MaxTestsBytes}
	result, err := x.invoke(probe, x.command("/usr/bin/xcodebuild", []string{"-showComponent", "MetalToolchain"}), io.MultiWriter(output, x.stdout), x.stderr)
	err = errors.Join(err, output.err)
	if err != nil && (!result.CleanupOK || errors.Is(err, ErrContamination) || errors.Is(err, ErrRecovery) || ctx.Err() != nil) {
		return err
	}
	observed := parseMetalToolchain(output.Bytes())
	if err != nil {
		observed.Error = clip(err.Error(), 1024)
	}
	x.result.Observation.MetalToolchain = &observed
	return nil
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

func observe(ctx context.Context, x *execution) error {
	if err := observeMetalToolchain(ctx, x); err != nil {
		return err
	}
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

package worker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/model"
)

func isMetalProbe(c Command) bool {
	return c.Executable == "/usr/bin/xcodebuild" && slices.Equal(c.Args, []string{"-showComponent", "MetalToolchain"})
}

// v0.1.27 field failure (herdrup, SwiftTerm Shaders.metal): the empty per-job
// HOME lacks XcodeToMetalToolchainIndexMapping.plist, so xcrun resolves the
// Metal shim. The fixed probe writes it, as the job with the job environment,
// before every other observation and recipe command, for every job kind.
func TestMetalToolchainProbeRunsFirstWithTheJobEnvironment(t *testing.T) {
	for _, kind := range []model.Kind{model.Build, model.UnitTest} {
		t.Run(string(kind), func(t *testing.T) {
			runner := &fakeRunner{}
			runner.hook = func(_ context.Context, c Command, out, _ io.Writer) (bool, ProcessResult, error) {
				if !isMetalProbe(c) {
					return false, ProcessResult{}, nil
				}
				_, err := io.WriteString(out, "Asset Path: /System/Library/AssetsV2/x\nBuild Version: 27A266a\nStatus: installed\nToolchain Identifier: com.apple.dt.toolchain.Metal.32023\n")
				return true, ProcessResult{CleanupOK: true}, err
			}
			engine := engineFixture(t, runner)
			job := fixtureJob(t, kind)
			source, data := sourceFixture(t)
			result, err := engine.Execute(context.Background(), job, source, bytes.NewReader(data), nil)
			if err != nil || result.State != model.Succeeded {
				t.Fatalf("%+v %v", result, err)
			}
			probe := slices.IndexFunc(runner.commands, isMetalProbe)
			version := slices.IndexFunc(runner.commands, func(c Command) bool {
				return c.Executable == "/usr/bin/xcodebuild" && slices.Equal(c.Args, []string{"-version"})
			})
			if probe < 0 || version != probe+1 {
				t.Fatalf("probe %d does not immediately precede xcodebuild -version %d: %+v", probe, version, runner.commands)
			}
			command := runner.commands[probe]
			for _, earlier := range runner.commands[:probe] {
				if earlier.Executable == job.Profile.Run.Executable || strings.Contains(earlier.Executable, "xcrun") {
					t.Fatalf("job command %v ran before the probe", earlier)
				}
			}
			workspace := command.Dir
			want := environment(workspace, job.Profile.DeveloperDir, engine.options.JobUser)
			if !slices.Equal(command.Env, want) || !slices.Contains(command.Env, "HOME="+filepath.Join(workspace, "home")) || !slices.Contains(command.Env, "DEVELOPER_DIR="+job.Profile.DeveloperDir) {
				t.Fatalf("probe env %v, want %v", command.Env, want)
			}
			got := result.Observation.MetalToolchain
			if got == nil || *got != (MetalToolchain{Status: "installed", BuildVersion: "27A266a"}) {
				t.Fatalf("observation = %+v", got)
			}
		})
	}
}

// Projects without Metal sources must keep building when the component is
// absent or the probe fails.
func TestMetalToolchainProbeFailureDoesNotFailTheJob(t *testing.T) {
	for name, outcome := range map[string]struct {
		result ProcessResult
		err    error
		output string
	}{
		"exit":          {ProcessResult{ExitCode: 70, CleanupOK: true}, nil, "xcodebuild: error: unknown component\n"},
		"runner error":  {ProcessResult{ExitCode: -1, CleanupOK: true}, errors.New("spawn failed"), ""},
		"not installed": {ProcessResult{CleanupOK: true}, nil, "Build Version: 27A266a\nStatus: uninstalled\n"},
	} {
		t.Run(name, func(t *testing.T) {
			runner := &fakeRunner{}
			runner.hook = func(_ context.Context, c Command, out, _ io.Writer) (bool, ProcessResult, error) {
				if !isMetalProbe(c) {
					return false, ProcessResult{}, nil
				}
				_, _ = io.WriteString(out, outcome.output)
				return true, outcome.result, outcome.err
			}
			engine := engineFixture(t, runner)
			source, data := sourceFixture(t)
			result, err := engine.Execute(context.Background(), fixtureJob(t, model.Build), source, bytes.NewReader(data), nil)
			if err != nil || result.State != model.Succeeded {
				t.Fatalf("%+v %v", result, err)
			}
			got := result.Observation.MetalToolchain
			if got == nil {
				t.Fatal("probe outcome not recorded")
			}
			failed := outcome.err != nil || outcome.result.ExitCode != 0
			if failed != (got.Error != "") {
				t.Fatalf("error recorded = %q", got.Error)
			}
			if name == "not installed" && got.Status != "uninstalled" {
				t.Fatalf("status = %q", got.Status)
			}
		})
	}
}

// Unconfirmed cleanup of the probe's processes is never tolerated.
func TestMetalToolchainProbeUnconfirmedCleanupFailsTheJob(t *testing.T) {
	runner := &fakeRunner{}
	runner.hook = func(_ context.Context, c Command, _, _ io.Writer) (bool, ProcessResult, error) {
		return isMetalProbe(c), ProcessResult{}, nil
	}
	engine := engineFixture(t, runner)
	source, data := sourceFixture(t)
	if result, err := engine.Execute(context.Background(), fixtureJob(t, model.Build), source, bytes.NewReader(data), nil); err == nil && result.State == model.Succeeded {
		t.Fatalf("job succeeded after unconfirmed probe cleanup: %+v", result)
	}
}

func TestParseMetalToolchain(t *testing.T) {
	for output, want := range map[string]MetalToolchain{
		"Asset Path: /x\nBuild Version: 27A266a\nStatus: installed\nToolchain Search Path: /var/run/x\n": {Status: "installed", BuildVersion: "27A266a"},
		"  Status:   uninstalled  \r\n":      {Status: "uninstalled"},
		"":                                   {},
		"xcodebuild: error: no such thing\n": {},
	} {
		if got := parseMetalToolchain([]byte(output)); got != want {
			t.Fatalf("%q => %+v, want %+v", output, got, want)
		}
	}
}

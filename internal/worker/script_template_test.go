package worker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/model"
)

const scriptConfig = `{"version":1,"work_dir":".","project":"Herdr.xcodeproj","scheme":"Herdr","script":{"shards":{"duo":{"run":"Tools/ci/duo-screenshots.sh"}}}}`

// scriptHook plays the shard's script: it writes files below
// MACSERVE_OUTPUT and records the script command.
func scriptHook(t *testing.T, files map[string]string, script *Command) func(context.Context, Command, io.Writer, io.Writer) (bool, ProcessResult, error) {
	return func(_ context.Context, c Command, _, _ io.Writer) (bool, ProcessResult, error) {
		if c.Executable != "/bin/bash" {
			return false, ProcessResult{}, nil
		}
		*script = c
		var output string
		for _, entry := range c.Env {
			if value, ok := strings.CutPrefix(entry, "MACSERVE_OUTPUT="); ok {
				output = value
			}
		}
		if output == "" {
			t.Error("script ran without MACSERVE_OUTPUT")
			return true, ProcessResult{ExitCode: 1, CleanupOK: true}, nil
		}
		for name, content := range files {
			name = filepath.Join(output, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
				return true, ProcessResult{}, err
			}
			if err := os.WriteFile(name, []byte(content), 0600); err != nil {
				return true, ProcessResult{}, err
			}
		}
		return true, ProcessResult{CleanupOK: true}, nil
	}
}

// A script template job builds the scheme for its own booted simulator in
// prepare, runs the shard's script with /bin/bash in work_dir with the four
// MACSERVE_ variables, and exports every regular file the script left under
// output/ (nested, symlinks skipped) with no test evidence.
func TestTemplateScriptJobExportsOutputTree(t *testing.T) {
	files := map[string]string{
		"summary.md":                "# Duo\n",
		"duo/portrait.png":          "\x89PNG portrait",
		"duo/landscape/folded.json": `{"posture":"folded"}`,
		"1/2/3/4/5/6/7/deepest.txt": "eight levels",
	}
	var script Command
	runner := &fakeRunner{}
	runner.hook = scriptHook(t, files, &script)
	engine := engineFixture(t, runner)
	source, data := checkoutFixture(t, map[string]string{".macserve.json": scriptConfig, "Tools/ci/duo-screenshots.sh": "#!/bin/bash\n"})
	job := testTemplateJob(t, model.SimulatorScript, "duo")
	result, err := engine.Execute(context.Background(), job, source, bytes.NewReader(data), nil)
	if err != nil || result.State != model.Succeeded || !result.CleanupOK {
		t.Fatalf("script job failed: %+v %v", result, err)
	}
	assertExactCleanup(t, runner, true)
	commands := checkoutCommands(runner)
	if len(commands) != 2 {
		t.Fatalf("recipe commands: %+v", commands)
	}
	build := commands[0]
	workspace := filepath.Dir(build.Dir)
	wantBuild := []string{"xcodebuild", "-project", "Herdr.xcodeproj", "-scheme", "Herdr", "-configuration", "Debug", "-sdk", "iphonesimulator", "-destination", "id=" + ownedUDID, "-derivedDataPath", filepath.Join(workspace, "derived-data"), "build", "-jobs", "4", "CODE_SIGNING_ALLOWED=NO"}
	if build.Executable != "/usr/bin/xcrun" || !slices.Equal(build.Args, wantBuild) {
		t.Fatalf("prepare build %s %q, want %q", build.Executable, build.Args, wantBuild)
	}
	if commands[1].Executable != "/bin/bash" || !slices.Equal(commands[1].Args, []string{filepath.Join(workspace, "checkout", "Tools", "ci", "duo-screenshots.sh")}) || commands[1].Dir != filepath.Join(workspace, "checkout") {
		t.Fatalf("script command: %+v", commands[1])
	}
	want := append(slices.Clone(build.Env),
		"MACSERVE_APP_DIR="+filepath.Join(workspace, "derived-data", "Build", "Products", "Debug-iphonesimulator"),
		"MACSERVE_SIMULATOR_ID="+ownedUDID,
		"MACSERVE_OUTPUT="+filepath.Join(workspace, "output"),
		"MACSERVE_JOB_ID="+job.ID,
	)
	if !slices.Equal(script.Env, want) {
		t.Fatalf("script environment\n%q\nwant\n%q", script.Env, want)
	}
	for _, c := range runner.commands {
		if c.Executable != "/bin/bash" && slices.ContainsFunc(c.Env, func(entry string) bool { return strings.HasPrefix(entry, "MACSERVE_") }) {
			t.Fatalf("%s got a script variable: %q", c.Executable, c.Env)
		}
		if filepath.Base(c.Executable) == "xcresulttool" {
			t.Fatal("script job extracted test results")
		}
	}
	if result.Summary != nil {
		t.Fatalf("script job has test evidence: %+v", result.Summary)
	}
	if recipe := result.Observation.Recipe; recipe == nil || recipe.Shard != "duo" || len(recipe.RequiredTests) != 0 || recipe.Run.Executable != "/bin/bash" {
		t.Fatalf("recipe evidence: %+v", recipe)
	}
	exported := map[string]string{}
	for _, artifact := range result.Artifacts {
		exported[artifact.Name] = artifact.SHA256
	}
	for name, content := range files {
		sum := sha256.Sum256([]byte(content))
		if exported["output/"+name] != hex.EncodeToString(sum[:]) {
			t.Fatalf("output/%s not exported intact: %v", name, exported)
		}
	}
	if len(exported) != len(files)+2 || exported["evidence/stdout.log"] == "" || exported["evidence/stderr.log"] == "" {
		t.Fatalf("exports: %v", exported)
	}
}

// Script outputs follow the artifact rules: a symlink is skipped, never
// followed; a file nested more than eight levels below output/ fails the job.
func TestTemplateScriptJobOutputLimits(t *testing.T) {
	for _, tc := range []struct {
		name    string
		files   map[string]string
		link    string
		succeed bool
	}{
		{name: "symlink skipped", files: map[string]string{"shot.png": "png"}, link: "leak.json", succeed: true},
		{name: "too deep", files: map[string]string{"1/2/3/4/5/6/7/8/deep.txt": "nine levels"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var script Command
			runner := &fakeRunner{}
			play := scriptHook(t, tc.files, &script)
			runner.hook = func(ctx context.Context, c Command, out, stderr io.Writer) (bool, ProcessResult, error) {
				handled, result, err := play(ctx, c, out, stderr)
				if handled && tc.link != "" {
					output := filepath.Join(filepath.Dir(c.Dir), "output")
					err = os.Symlink(filepath.Join(c.Dir, ".macserve.json"), filepath.Join(output, tc.link))
				}
				return handled, result, err
			}
			engine := engineFixture(t, runner)
			source, data := checkoutFixture(t, map[string]string{".macserve.json": scriptConfig, "Tools/ci/duo-screenshots.sh": "#!/bin/bash\n"})
			result, err := engine.Execute(context.Background(), testTemplateJob(t, model.SimulatorScript, "duo"), source, bytes.NewReader(data), nil)
			if tc.succeed != (err == nil && result.State == model.Succeeded) || !result.CleanupOK {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			for _, artifact := range result.Artifacts {
				if strings.HasPrefix(artifact.Name, "output/") && !tc.succeed || artifact.Name == "output/"+tc.link {
					t.Fatalf("unexpected export %s", artifact.Name)
				}
			}
			if tc.succeed && !slices.ContainsFunc(result.Artifacts, func(a evidence.Artifact) bool { return a.Name == "output/shot.png" }) {
				t.Fatalf("output/shot.png not exported: %+v", result.Artifacts)
			}
		})
	}
}

// Other kinds create no output directory and add no script variables.
func TestNonScriptJobsHaveNoOutputDirectory(t *testing.T) {
	runner := &fakeRunner{}
	var workspace string
	runner.hook = func(_ context.Context, c Command, _, _ io.Writer) (bool, ProcessResult, error) {
		if strings.HasSuffix(c.Dir, string(filepath.Separator)+"checkout") {
			workspace = filepath.Dir(c.Dir)
			if _, err := os.Lstat(filepath.Join(workspace, "output")); !os.IsNotExist(err) {
				t.Errorf("build job has an output directory: %v", err)
			}
		}
		return false, ProcessResult{}, nil
	}
	engine := engineFixture(t, runner)
	source, data := sourceFixture(t)
	result, err := engine.Execute(context.Background(), fixtureJob(t, model.Build), source, bytes.NewReader(data), nil)
	if err != nil || result.State != model.Succeeded || workspace == "" {
		t.Fatalf("build job: %+v %v", result, err)
	}
	for _, c := range runner.commands {
		if slices.ContainsFunc(c.Env, func(entry string) bool { return strings.HasPrefix(entry, "MACSERVE_") }) {
			t.Fatalf("build job command got a script variable: %q", c.Env)
		}
	}
}

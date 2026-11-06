package worker

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/model"
)

const (
	scriptShard  = "duo-screenshots"
	scriptConfig = `{"version":1,"work_dir":".","project":"Herdr.xcodeproj","scheme":"Herdr","script":{"shards":{"duo-screenshots":{"run":"Tools/ci/duo-screenshots.sh"}}}}`
)

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

func runScriptJob(t *testing.T, runner *fakeRunner, checkout map[string]string) (*Engine, model.Job, Result, error) {
	t.Helper()
	engine := engineFixture(t, runner)
	source, data := checkoutFixture(t, checkout)
	job := testTemplateJob(t, model.SimulatorScript, scriptShard)
	result, err := engine.Execute(context.Background(), job, source, bytes.NewReader(data), nil)
	return engine, job, result, err
}

var scriptCheckout = map[string]string{".macserve.json": scriptConfig, "Tools/ci/duo-screenshots.sh": "#!/bin/bash\n"}

// A script template job builds the scheme for its own booted simulator in
// prepare, runs the shard's script with /bin/bash in work_dir with exactly the
// four MACSERVE_ variables added, and exports the output directory, nested
// files included, as the required output.tar.gz with no test evidence.
func TestTemplateScriptJobExportsOutputArchive(t *testing.T) {
	files := map[string]string{
		"summary.md":                "# Duo\n",
		"duo/portrait.png":          "\x89PNG portrait",
		"duo/landscape/folded.json": `{"posture":"folded"}`,
	}
	var script Command
	runner := &fakeRunner{}
	runner.hook = scriptHook(t, files, &script)
	engine, job, result, err := runScriptJob(t, runner, scriptCheckout)
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
	if recipe := result.Observation.Recipe; recipe == nil || recipe.Shard != scriptShard || len(recipe.RequiredTests) != 0 || recipe.Run.Executable != "/bin/bash" {
		t.Fatalf("recipe evidence: %+v", recipe)
	}
	names := []string{}
	archived := map[string]string{}
	for _, artifact := range result.Artifacts {
		names = append(names, artifact.Name)
		if artifact.Name != "output.tar.gz" {
			continue
		}
		path, err := engine.ArtifactPath(job.ID, artifact.ID)
		if err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		gz, err := gzip.NewReader(f)
		if err != nil {
			t.Fatal(err)
		}
		archive := tar.NewReader(gz)
		for {
			header, err := archive.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			if header.Typeflag == tar.TypeReg {
				content, err := io.ReadAll(archive)
				if err != nil {
					t.Fatal(err)
				}
				archived[header.Name] = string(content)
			}
		}
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"evidence/stderr.log", "evidence/stdout.log", "output.tar.gz"}) {
		t.Fatalf("exports: %q", names)
	}
	for name, content := range files {
		if archived["output/"+name] != content {
			t.Fatalf("output/%s not archived intact: %q", name, archived)
		}
	}
	if len(archived) != len(files) {
		t.Fatalf("archive entries: %q", archived)
	}
}

// The script must be a regular checkout file reached without a symlink; the
// job fails before the script launches otherwise. A symlink the script leaves
// in output/ is never followed: the export, and so the job, fails.
func TestTemplateScriptJobRefusesUnsafeScriptsAndOutputs(t *testing.T) {
	for _, tc := range []struct {
		name     string
		checkout map[string]string
		link     string // made before the script runs, relative to checkout
		target   string
		output   bool // symlink in output/ after the script ran
		launches bool
	}{
		{name: "missing script", checkout: map[string]string{".macserve.json": scriptConfig}},
		{name: "script is a directory", checkout: map[string]string{".macserve.json": scriptConfig, "Tools/ci/duo-screenshots.sh/": ""}},
		{name: "script is a symlink", checkout: map[string]string{".macserve.json": scriptConfig, "Tools/ci/real.sh": "#!/bin/bash\n"}, link: "Tools/ci/duo-screenshots.sh", target: "real.sh"},
		{name: "script directory is a symlink", checkout: map[string]string{".macserve.json": scriptConfig, "Other/duo-screenshots.sh": "#!/bin/bash\n"}, link: "Tools/ci", target: "../Other"},
		{name: "symlink in output", checkout: scriptCheckout, output: true, launches: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var script Command
			runner := &fakeRunner{}
			play := scriptHook(t, map[string]string{"shot.png": "png"}, &script)
			runner.hook = func(ctx context.Context, c Command, out, stderr io.Writer) (bool, ProcessResult, error) {
				if tc.link != "" && filepath.Base(c.Executable) == "xcrun" && slices.Contains(c.Args, "build") {
					link := filepath.Join(c.Dir, filepath.FromSlash(tc.link))
					if err := os.MkdirAll(filepath.Dir(link), 0700); err != nil {
						return true, ProcessResult{}, err
					}
					if err := os.Symlink(tc.target, link); err != nil {
						return true, ProcessResult{}, err
					}
				}
				handled, result, err := play(ctx, c, out, stderr)
				if handled && tc.output {
					err = os.Symlink(filepath.Join(c.Dir, ".macserve.json"), filepath.Join(filepath.Dir(c.Dir), "output", "leak.json"))
				}
				return handled, result, err
			}
			_, _, result, err := runScriptJob(t, runner, tc.checkout)
			if err == nil || result.State == model.Succeeded || !result.CleanupOK {
				t.Fatalf("unsafe script job succeeded: %+v %v", result, err)
			}
			if (script.Executable != "") != tc.launches {
				t.Fatalf("script launched=%v, want %v (%v)", script.Executable != "", tc.launches, err)
			}
			// An output symlink refuses the whole archive.
			for _, artifact := range result.Artifacts {
				if tc.output && artifact.Name == "output.tar.gz" {
					t.Fatal("output with a symlink was exported")
				}
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

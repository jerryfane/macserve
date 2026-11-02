package worker

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
)

func templateJob(t *testing.T) model.Job {
	t.Helper()
	template := model.Template{ID: "org-build-v1", Version: 1, Kind: model.Build, Owners: []string{"example-org"}, Xcode: model.Xcode{Version: "16.0", Build: "16A242d"}, DeveloperDir: "/Applications/Xcode.app/Contents/Developer"}
	registry, err := profiles.New(nil, []model.Template{template})
	if err != nil {
		t.Fatal(err)
	}
	admission, err := registry.Resolve(model.Request{Repo: "example-org/new-app", SHA: strings.Repeat("a", 40), Kind: model.Build, Profile: template.ID, Xcode: template.Xcode})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(admission.Request)
	digest := sha256.Sum256(data)
	return model.Job{ID: "job-1", LeaseToken: "lease-1", WorkerEpoch: "epoch-1", State: model.Preparing, Request: admission.Request, Profile: admission.Profile, ProfileDigest: admission.ProfileDigest, RequestDigest: hex.EncodeToString(digest[:])}
}

// checkoutFixture is a git-archive-shaped tar of files (and directories, for
// names ending in "/") with its Git tree identity.
func checkoutFixture(t *testing.T, files map[string]string) (Source, []byte) {
	t.Helper()
	var stream bytes.Buffer
	writer := tar.NewWriter(&stream)
	tree := &treeEntry{mode: "40000", children: make(map[string]*treeEntry)}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		directory := strings.HasSuffix(name, "/")
		parts := strings.Split(strings.TrimSuffix(name, "/"), "/")
		node := tree
		for _, part := range parts[:len(parts)-1] {
			if node.children[part] == nil {
				node.children[part] = &treeEntry{mode: "40000", children: make(map[string]*treeEntry)}
			}
			node = node.children[part]
		}
		leaf := parts[len(parts)-1]
		if directory {
			if err := writer.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeDir, Mode: 0755}); err != nil {
				t.Fatal(err)
			}
			node.children[leaf] = &treeEntry{mode: "40000", children: map[string]*treeEntry{"keep": {mode: "100644", digest: gitHash("blob", nil)}}}
			if err := writer.WriteHeader(&tar.Header{Name: name + "keep", Typeflag: tar.TypeReg, Mode: 0644}); err != nil {
				t.Fatal(err)
			}
			continue
		}
		content := []byte(files[name])
		if err := writer.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0644, Size: int64(len(content))}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(content); err != nil {
			t.Fatal(err)
		}
		node.children[leaf] = &treeEntry{mode: "100644", digest: gitHash("blob", content)}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(stream.Bytes())
	return Source{Commit: strings.Repeat("a", 40), Tree: hex.EncodeToString(treeDigest(tree)), SHA256: hex.EncodeToString(digest[:]), SizeBytes: int64(stream.Len())}, stream.Bytes()
}

func checkoutCommands(runner *fakeRunner) []Command {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	var recipe []Command
	for _, c := range runner.commands {
		if strings.Contains(c.Dir, string(filepath.Separator)+"checkout") {
			recipe = append(recipe, c)
		}
	}
	return recipe
}

func TestTemplateJobRunsTheDerivedRecipe(t *testing.T) {
	build := []string{"-configuration", "Debug", "-sdk", "iphonesimulator", "-destination", "generic/platform=iOS Simulator", "-derivedDataPath"}
	cases := []struct {
		name, config, workDir string
		want                  [][]string
	}{
		{"project with both steps", `{"version":1,"work_dir":"ios","project":"App.xcodeproj","scheme":"App","xcodegen":true,"resolve_packages":true}`, "ios", [][]string{
			{"/Library/macserve/tools/xcodegen", "generate", "--spec", "project.yml"},
			{"/usr/bin/xcrun", "xcodebuild", "-project", "App.xcodeproj", "-scheme", "App", "-resolvePackageDependencies", "-jobs", "4", "CODE_SIGNING_ALLOWED=NO"},
			append(append([]string{"/usr/bin/xcrun", "xcodebuild", "-project", "App.xcodeproj", "-scheme", "App"}, build...), "DERIVED", "build", "-jobs", "4", "CODE_SIGNING_ALLOWED=NO"),
		}},
		{"workspace without steps", `{"version":1,"work_dir":".","workspace":"App.xcworkspace","scheme":"App Dev"}`, ".", [][]string{
			append(append([]string{"/usr/bin/xcrun", "xcodebuild", "-workspace", "App.xcworkspace", "-scheme", "App Dev"}, build...), "DERIVED", "build", "-jobs", "4", "CODE_SIGNING_ALLOWED=NO"),
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := &fakeRunner{}
			engine := engineFixture(t, runner)
			job := templateJob(t)
			snapshot := job.Profile
			source, data := checkoutFixture(t, map[string]string{".macserve.json": tc.config, "ios/project.yml": "name: App\n"})
			result, err := engine.Execute(context.Background(), job, source, bytes.NewReader(data), nil)
			if err != nil || result.State != model.Succeeded {
				t.Fatalf("template job failed: %+v %v", result, err)
			}
			commands := checkoutCommands(runner)
			if len(commands) != len(tc.want) {
				t.Fatalf("ran %d recipe commands, want %d: %+v", len(commands), len(tc.want), commands)
			}
			for i, c := range commands {
				got := append([]string{c.Executable}, c.Args...)
				for j, arg := range got {
					if strings.HasSuffix(arg, filepath.Join("job-1", "derived-data")) {
						got[j] = "DERIVED"
					}
				}
				if !slices.Equal(got, tc.want[i]) {
					t.Fatalf("command %d:\n got %q\nwant %q", i, got, tc.want[i])
				}
				if !strings.HasSuffix(c.Dir, filepath.Join("job-1", filepath.FromSlash(filepath.Join("checkout", tc.workDir)))) {
					t.Fatalf("command %d ran in %s", i, c.Dir)
				}
				if !slices.Contains(c.Env, "DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer") || !slices.Contains(c.Env, "PATH=/usr/bin:/bin:/usr/sbin:/sbin") {
					t.Fatalf("command %d environment is not the fixed job environment: %q", i, c.Env)
				}
			}
			recipe := result.Observation.Recipe
			sum := sha256.Sum256([]byte(tc.config))
			config, err := profiles.ParseRepoConfig([]byte(tc.config))
			if err != nil {
				t.Fatal(err)
			}
			derived, err := profiles.Derive(snapshot, config)
			if err != nil {
				t.Fatal(err)
			}
			want := &model.RepoRecipe{ConfigSHA256: hex.EncodeToString(sum[:]), Config: config, WorkDir: tc.workDir, Prepare: derived.Prepare, Run: derived.Run}
			if !reflect.DeepEqual(recipe, want) {
				t.Fatalf("observation recipe %+v, want %+v", recipe, want)
			}
		})
	}
}

func TestTemplateJobRefusesRepoConfigBeforeAnyCommand(t *testing.T) {
	valid := `{"version":1,"work_dir":".","project":"App.xcodeproj","scheme":"App"}`
	cases := map[string]map[string]string{
		"missing":           {"README.md": "no configuration\n"},
		"nested only":       {"ios/.macserve.json": valid},
		"unknown field":     {".macserve.json": strings.Replace(valid, `"scheme"`, `"run":"/bin/sh","scheme"`, 1)},
		"project and space": {".macserve.json": strings.Replace(valid, `"scheme"`, `"workspace":"App.xcworkspace","scheme"`, 1)},
		"neither":           {".macserve.json": `{"version":1,"work_dir":".","scheme":"App"}`},
		"path escape":       {".macserve.json": strings.Replace(valid, `App.xcodeproj`, `../App.xcodeproj`, 1)},
		"trailing data":     {".macserve.json": valid + "\n{}"},
		"oversized":         {".macserve.json": valid + strings.Repeat(" ", profiles.MaxRepoConfigBytes)},
		"directory":         {".macserve.json/": ""},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			runner := &fakeRunner{}
			engine := engineFixture(t, runner)
			source, data := checkoutFixture(t, files)
			result, err := engine.Execute(context.Background(), templateJob(t), source, bytes.NewReader(data), nil)
			if err == nil || result.State != model.Failed || !strings.Contains(err.Error(), "repository has no valid .macserve.json") || !strings.Contains(result.Reason, "repository has no valid .macserve.json") {
				t.Fatalf("invalid repository configuration accepted: %+v %v", result, err)
			}
			runner.mu.Lock()
			ran := len(runner.commands)
			runner.mu.Unlock()
			if ran != 0 || result.Observation.Recipe != nil || result.ExitCode != nil {
				t.Fatalf("commands ran before the configuration was validated: %d %+v", ran, result)
			}
		})
	}
}

func TestRepoConfigMustBeARegularFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere.json")
	if err := os.WriteFile(target, []byte(`{"version":1,"work_dir":".","project":"App.xcodeproj","scheme":"App"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, ".macserve.json")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := readRepoConfig(root); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlinked configuration accepted: %v", err)
	}
}

func TestTemplateSnapshotCannotCarryCommands(t *testing.T) {
	for name, mutate := range map[string]func(*model.Job){
		"run":       func(j *model.Job) { j.Profile.Run = model.Command{Executable: "/bin/sh", Args: []string{"-c", "id"}} },
		"prepare":   func(j *model.Job) { j.Profile.Prepare = []model.Command{{Executable: "/bin/sh"}} },
		"work dir":  func(j *model.Job) { j.Profile.WorkDir = "ios" },
		"generated": func(j *model.Job) { j.Profile.GeneratedFiles = []model.GeneratedFile{{Path: "a", Content: "b"}} },
		"owner":     func(j *model.Job) { j.Profile.Template.Owners = []string{"someone-else"} },
	} {
		t.Run(name, func(t *testing.T) {
			runner := &fakeRunner{}
			engine := engineFixture(t, runner)
			job := templateJob(t)
			mutate(&job)
			source, data := checkoutFixture(t, map[string]string{".macserve.json": `{"version":1,"work_dir":".","project":"App.xcodeproj","scheme":"App"}`})
			if result, err := engine.Execute(context.Background(), job, source, bytes.NewReader(data), nil); err == nil || result.State == model.Succeeded {
				t.Fatalf("tampered template snapshot executed: %+v", result)
			}
			if len(checkoutCommands(runner)) != 0 {
				t.Fatal("tampered template snapshot ran a recipe command")
			}
		})
	}
}

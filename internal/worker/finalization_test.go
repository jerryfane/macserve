package worker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/jerryfane/macserve/internal/model"
)

func TestSimulatorAndJobWritersStopBeforeEvidenceExtraction(t *testing.T) {
	quiet, shutdown, deleted, extracted := 0, false, false, false
	runner := &fakeRunner{}
	runner.quiesce = func(context.Context) error {
		quiet++
		if quiet == 2 && (!shutdown || !deleted) {
			t.Fatal("UID barrier ran before owned simulator shutdown/delete")
		}
		return nil
	}
	runner.hook = func(_ context.Context, c Command, _, _ io.Writer) (bool, ProcessResult, error) {
		args := strings.Join(c.Args, " ")
		if args == "simctl shutdown "+ownedUDID {
			shutdown = true
		}
		if args == "simctl delete "+ownedUDID {
			deleted = true
		}
		if filepath.Base(c.Executable) == "xcresulttool" {
			if !shutdown || !deleted || quiet < 2 {
				t.Fatal("evidence tool ran with active writers")
			}
			if c.Executable != "/Applications/Xcode.app/Contents/Developer/usr/bin/xcresulttool" {
				t.Fatalf("unpinned evidence extractor: %s", c.Executable)
			}
			extracted = true
		}
		return false, ProcessResult{}, nil
	}
	engine := engineFixture(t, runner)
	source, data := sourceFixture(t)
	result, err := engine.Execute(context.Background(), fixtureJob(t, model.UnitTest), source, bytes.NewReader(data), nil)
	if err != nil || result.State != model.Succeeded || !result.CleanupOK || !extracted || quiet < 4 {
		t.Fatalf("missing finalization barriers: quiet=%d result=%+v err=%v", quiet, result, err)
	}
	if result.Summary == nil || result.Summary.Passed != 1 || result.Summary.XCResultSHA256 == "" {
		t.Fatalf("evidence was not sealed after quiet: %+v", result.Summary)
	}
}

func TestResidualWritersForbidParsingSealingAndNextLease(t *testing.T) {
	for _, failAt := range []int{1, 2, 3} {
		t.Run(string(rune('0'+failAt)), func(t *testing.T) {
			quiet, extracted := 0, false
			runner := &fakeRunner{}
			runner.quiesce = func(context.Context) error {
				quiet++
				if quiet >= failAt {
					return errors.Join(ErrContamination, errors.New("escaped job-UID writer remains"))
				}
				return nil
			}
			runner.hook = func(_ context.Context, c Command, _, _ io.Writer) (bool, ProcessResult, error) {
				if filepath.Base(c.Executable) == "xcresulttool" {
					extracted = true
				}
				return false, ProcessResult{}, nil
			}
			engine := engineFixture(t, runner)
			source, data := sourceFixture(t)
			job := fixtureJob(t, model.UnitTest)
			result, err := engine.Execute(context.Background(), job, source, bytes.NewReader(data), nil)
			if err == nil || result.State == model.Succeeded || result.CleanupOK || result.Summary != nil || len(result.Artifacts) != 0 {
				t.Fatalf("uncertain evidence escaped: %+v %v", result, err)
			}
			if (failAt == 3) != extracted {
				t.Fatalf("extractor ordering violated: stage=%d extracted=%v", failAt, extracted)
			}
			if _, err := engine.exports.Lstat(job.ID); !os.IsNotExist(err) {
				t.Fatalf("sealed export created despite writers: %v", err)
			}
			if _, err := engine.root.Stat(quarantineRecord); err != nil {
				t.Fatalf("lost positive contamination quarantine: %v", err)
			}
			job.ID = "job-2"
			if _, err := engine.Execute(context.Background(), job, source, bytes.NewReader(data), nil); !errors.Is(err, ErrRecovery) {
				t.Fatalf("new lease admitted: %v", err)
			}
			// A later empty snapshot does not silently clear durable uncertainty.
			runner.quiesce = nil
			if err := engine.Recover(context.Background()); !errors.Is(err, ErrRecovery) {
				t.Fatalf("uncertainty auto-cleared: %v", err)
			}
		})
	}
}

func TestReadOnlyWorkspaceCleanupDoesNotFollowSymlinks(t *testing.T) {
	outside := t.TempDir()
	outsideFile := filepath.Join(outside, "owner-file")
	if err := os.WriteFile(outsideFile, []byte("preserve owner bytes"), 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(outside, 0555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(outside, 0700) })
	runner := &fakeRunner{hook: func(_ context.Context, c Command, _, _ io.Writer) (bool, ProcessResult, error) {
		if len(c.Args) == 0 || c.Args[0] != "build" {
			return false, ProcessResult{}, nil
		}
		nested := filepath.Join(c.Dir, "readonly", "nested")
		if err := os.MkdirAll(nested, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(nested, "file"), []byte("job data"), 0400); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(nested, "outside")); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(nested, 0555); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Dir(nested), 0555); err != nil {
			t.Fatal(err)
		}
		return false, ProcessResult{}, nil
	}}
	engine := engineFixture(t, runner)
	source, data := sourceFixture(t)
	job := fixtureJob(t, model.Build)
	result, err := engine.Execute(context.Background(), job, source, bytes.NewReader(data), nil)
	if err != nil || result.State != model.Succeeded || !result.CleanupOK {
		t.Fatalf("readonly cleanup wedged: %+v %v", result, err)
	}
	if _, err := engine.workspaces.Lstat(job.ID); !os.IsNotExist(err) {
		t.Fatalf("workspace remains: %v", err)
	}
	content, err := os.ReadFile(outsideFile)
	if err != nil || string(content) != "preserve owner bytes" {
		t.Fatalf("outside bytes changed: %q %v", content, err)
	}
	info, err := os.Stat(outside)
	if err != nil || info.Mode().Perm() != 0555 {
		t.Fatalf("outside permissions repaired: %v %v", info, err)
	}
	job.ID = "job-2"
	if result, err := engine.Execute(context.Background(), job, source, bytes.NewReader(data), nil); err != nil || !result.CleanupOK {
		t.Fatalf("readonly input blocked next job: %+v %v", result, err)
	}
}

func TestPrivilegedCollectionRejectsHardlinkedWorkspaceFiles(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "private")
	if err := os.WriteFile(outside, []byte("not a job artifact"), 0600); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{hook: func(_ context.Context, c Command, _, _ io.Writer) (bool, ProcessResult, error) {
		if len(c.Args) > 0 && c.Args[0] == "build" {
			if err := os.Link(outside, filepath.Join(c.Dir, "leak")); err != nil {
				t.Fatal(err)
			}
		}
		return false, ProcessResult{}, nil
	}}
	engine := engineFixture(t, runner)
	source, data := sourceFixture(t)
	job := fixtureJob(t, model.Build)
	job.Profile.Artifacts = []model.ArtifactRule{{Path: "checkout/leak", Required: true}}
	resignJob(t, &job)
	result, err := engine.Execute(context.Background(), job, source, bytes.NewReader(data), nil)
	if err == nil || result.State == model.Succeeded || !result.CleanupOK || len(result.Artifacts) != 0 {
		t.Fatalf("unsafe collection or false cleanup quarantine: %+v %v", result, err)
	}
	if content, err := os.ReadFile(outside); err != nil || string(content) != "not a job artifact" {
		t.Fatalf("outside hardlink target changed: %q %v", content, err)
	}
	if _, err := engine.workspaces.Lstat(job.ID); !os.IsNotExist(err) {
		t.Fatalf("rejected hardlink wedged workspace cleanup: %v", err)
	}
}

func TestControlAndExportsCannotOverlapJobWritableStorage(t *testing.T) {
	for _, placement := range []string{"control-in-workspaces", "workspaces-in-control", "export-in-workspaces", "workspaces-in-export", "control-equals-export"} {
		t.Run(placement, func(t *testing.T) {
			base := t.TempDir()
			options := Options{Root: filepath.Join(base, "control"), ExportRoot: filepath.Join(base, "exports"), WorkspaceRoot: filepath.Join(base, "workspaces"), Runner: &fakeRunner{}}
			switch placement {
			case "control-in-workspaces":
				options.Root = filepath.Join(options.WorkspaceRoot, "control")
			case "workspaces-in-control":
				options.WorkspaceRoot = filepath.Join(options.Root, "workspaces")
			case "export-in-workspaces":
				options.ExportRoot = filepath.Join(options.WorkspaceRoot, "exports")
			case "workspaces-in-export":
				options.WorkspaceRoot = filepath.Join(options.ExportRoot, "workspaces")
			case "control-equals-export":
				options.ExportRoot = options.Root
			}
			if engine, err := New(options); err == nil {
				engine.Close()
				t.Fatal("job storage overlaps broker protected state")
			}
		})
	}
}

func TestJobCannotReplaceProtectedRawLogsWithWorkspaceEvidence(t *testing.T) {
	runner := &fakeRunner{hook: func(_ context.Context, c Command, _, _ io.Writer) (bool, ProcessResult, error) {
		if len(c.Args) > 0 && c.Args[0] == "build" {
			forged := filepath.Join(filepath.Dir(c.Dir), "evidence")
			if err := os.Mkdir(forged, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(forged, "stdout.log"), []byte("forged log"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		return false, ProcessResult{}, nil
	}}
	engine := engineFixture(t, runner)
	source, data := sourceFixture(t)
	job := fixtureJob(t, model.Build)
	result, err := engine.Execute(context.Background(), job, source, bytes.NewReader(data), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, artifact := range result.Artifacts {
		if artifact.Name != "evidence/stdout.log" {
			continue
		}
		path, err := engine.ArtifactPath(job.ID, artifact.ID)
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil || bytes.Contains(data, []byte("forged log")) || !bytes.Contains(data, []byte("recipe output")) {
			t.Fatalf("job replaced protected log: %q %v", data, err)
		}
		return
	}
	t.Fatal("protected stdout artifact absent")
}

func TestRepairOnlyCleanupUnlinksHardlinksUnreadableFilesAndFIFOs(t *testing.T) {
	engine := engineFixture(t, &fakeRunner{})
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("outside content"), 0000); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(outside)
	if err != nil {
		t.Fatal(err)
	}
	job := "cleanup-job"
	nested := filepath.Join(engine.options.WorkspaceRoot, job, "readonly")
	if err := os.MkdirAll(nested, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(nested, "hardlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "unreadable"), []byte("job content"), 0000); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(nested, "fifo"), 0000); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(nested, 0555); err != nil {
		t.Fatal(err)
	}
	if err := engine.saveManifest(manifest{JobID: job, DeveloperDir: "/Applications/Xcode.app/Contents/Developer"}); err != nil {
		t.Fatal(err)
	}
	if err := engine.Recover(context.Background()); err != nil {
		t.Fatalf("safe unlink cleanup quarantined: %v", err)
	}
	if _, err := engine.workspaces.Lstat(job); !os.IsNotExist(err) {
		t.Fatalf("workspace retained: %v", err)
	}
	after, err := os.Stat(outside)
	if err != nil || !os.SameFile(before, after) || after.Mode().Perm() != 0000 {
		t.Fatalf("outside target modified: %v %v", after, err)
	}
	if err := os.Chmod(outside, 0400); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(outside)
	if err != nil || string(data) != "outside content" {
		t.Fatalf("hardlink target changed: %q %v", data, err)
	}
	names, err := engine.registryNames()
	if err != nil || len(names) != 0 {
		t.Fatalf("successful cleanup retained quarantine: %v %v", names, err)
	}
}

package worker

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
)

const ownedUDID = "12345678-1234-1234-1234-123456789ABC"
const passedTests = `{"testPlanConfigurations":[],"devices":[],"testNodes":[{"nodeType":"Test Case","name":"testExample()","nodeIdentifier":"ExampleTests/testExample()","result":"Passed","durationInSeconds":0.25}]}`

type fakeRunner struct {
	mu           sync.Mutex
	commands     []Command
	hook         func(context.Context, Command, io.Writer, io.Writer) (bool, ProcessResult, error)
	xcode        string
	runtimeBuild string
	tests        string
}

func (f *fakeRunner) Run(ctx context.Context, c Command, out, stderr io.Writer) (ProcessResult, error) {
	f.mu.Lock()
	f.commands = append(f.commands, c)
	f.mu.Unlock()
	if f.hook != nil {
		handled, result, err := f.hook(ctx, c, out, stderr)
		if handled {
			return result, err
		}
	}
	result := ProcessResult{CleanupOK: true, PeakMemoryMiB: 123}
	if err := ctx.Err(); err != nil {
		result.ExitCode = -1
		return result, err
	}
	args := strings.Join(c.Args, " ")
	var text string
	switch {
	case c.Executable == "/usr/bin/xcodebuild" && args == "-version":
		text = f.xcode
		if text == "" {
			text = "Xcode 16.0\nBuild version 16A242d\n"
		}
	case args == "--sdk iphonesimulator --show-sdk-version" || args == "--sdk macosx --show-sdk-version":
		text = "18.0\n"
	case strings.Contains(args, "--show-sdk-build-version"):
		text = "22A3362\n"
	case args == "swift --version":
		text = "Apple Swift version 6.0\nTarget: arm64-apple-macosx\n"
	case c.Executable == "/usr/bin/sw_vers" && args == "-productVersion":
		text = "15.0\n"
	case c.Executable == "/usr/bin/sw_vers":
		text = "24A335\n"
	case args == "simctl list runtimes --json":
		build := f.runtimeBuild
		if build == "" {
			build = "22A3351"
		}
		text = fmt.Sprintf(`{"runtimes":[{"identifier":"com.apple.CoreSimulator.SimRuntime.iOS-18-0","version":"18.0","buildversion":%q,"isAvailable":true,"supportedDeviceTypes":[{"identifier":"com.apple.CoreSimulator.SimDeviceType.iPhone-16"}]}]}`, build)
	case args == "simctl list devices --json":
		text = `{"devices":{"com.apple.CoreSimulator.SimRuntime.iOS-18-0":[{"udid":"` + ownedUDID + `","state":"Shutdown"}]}}`
	case strings.HasPrefix(args, "simctl create "):
		text = ownedUDID + "\n"
	case strings.HasPrefix(args, "simctl "):
	case strings.HasPrefix(args, "xcresulttool "):
		text = f.tests
		if text == "" {
			text = passedTests
		}
	default:
		for _, arg := range c.Args {
			if strings.HasSuffix(arg, "results.xcresult") {
				if err := os.MkdirAll(arg, 0700); err != nil {
					return result, err
				}
				if err := os.WriteFile(filepath.Join(arg, "Info.plist"), []byte("fixture result bundle"), 0600); err != nil {
					return result, err
				}
			}
		}
		text = "recipe output\n"
	}
	_, err := io.WriteString(out, text)
	return result, err
}

func fixtureJob(t *testing.T, kind model.Kind) model.Job {
	t.Helper()
	profile := model.Profile{ID: "example", Version: 1, Repo: "example-org/example-app", Kind: kind, Xcode: model.Xcode{Version: "16.0", Build: "16A242d"}, DeveloperDir: "/Applications/Xcode.app/Contents/Developer", WorkDir: ".", Run: model.Command{Executable: "/usr/bin/xcodebuild", Args: []string{"build", "-derivedDataPath", "${DERIVED_DATA}"}}}
	if kind != model.Build {
		profile.Simulator = &model.Simulator{Runtime: "com.apple.CoreSimulator.SimRuntime.iOS-18-0", RuntimeBuild: "22A3351", DeviceType: "com.apple.CoreSimulator.SimDeviceType.iPhone-16"}
		profile.RequiredTests = []string{"ExampleTests/testExample()"}
		profile.Run.Args = []string{"test", "-resultBundlePath", "${RESULT_BUNDLE}"}
	}
	registry, err := profiles.New([]model.Profile{profile})
	if err != nil {
		t.Fatal(err)
	}
	admission, err := registry.Resolve(model.Request{Repo: profile.Repo, SHA: strings.Repeat("a", 40), Kind: kind, Profile: profile.ID, Xcode: profile.Xcode, Simulator: profile.Simulator})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(admission.Request)
	digest := sha256.Sum256(data)
	return model.Job{ID: "job-1", LeaseToken: "lease-1", WorkerEpoch: "epoch-1", State: model.Preparing, Request: admission.Request, Profile: admission.Profile, ProfileDigest: admission.ProfileDigest, RequestDigest: hex.EncodeToString(digest[:])}
}

func resignJob(t *testing.T, job *model.Job) {
	t.Helper()
	registry, err := profiles.New([]model.Profile{job.Profile})
	if err != nil {
		t.Fatal(err)
	}
	admission, err := registry.Resolve(job.Request)
	if err != nil {
		t.Fatal(err)
	}
	job.Profile = admission.Profile
	job.ProfileDigest = admission.ProfileDigest
}

func sourceFixture(t *testing.T) (Source, []byte) {
	t.Helper()
	content := []byte("hello\n")
	var stream bytes.Buffer
	writer := tar.NewWriter(&stream)
	if err := writer.WriteHeader(&tar.Header{Name: "README.txt", Typeflag: tar.TypeReg, Mode: 0644, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	blob := sha1.Sum(append([]byte("blob 6\x00"), content...))
	treeBody := append([]byte("100644 README.txt\x00"), blob[:]...)
	tree := sha1.Sum(append([]byte(fmt.Sprintf("tree %d\x00", len(treeBody))), treeBody...))
	digest := sha256.Sum256(stream.Bytes())
	return Source{Commit: strings.Repeat("a", 40), Tree: hex.EncodeToString(tree[:]), SHA256: hex.EncodeToString(digest[:]), SizeBytes: int64(stream.Len())}, stream.Bytes()
}

func engineFixture(t *testing.T, runner Runner) *Engine {
	t.Helper()
	base := t.TempDir()
	engine, err := New(Options{Root: filepath.Join(base, "worker"), ExportRoot: filepath.Join(base, "exports"), Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := engine.Close(); err != nil {
			t.Error(err)
		}
	})
	return engine
}

func TestBuildExportsSurviveCleanupUntilAcknowledged(t *testing.T) {
	runner := &fakeRunner{}
	engine := engineFixture(t, runner)
	job := fixtureJob(t, model.Build)
	source, data := sourceFixture(t)
	t.Setenv("CONTROLLER_TOKEN", "must-not-leak")
	result, err := engine.Execute(context.Background(), job, source, bytes.NewReader(data), nil)
	if err != nil || result.State != model.Succeeded || !result.CleanupOK || result.Summary != nil || result.ExitCode == nil || *result.ExitCode != 0 || result.PeakMemoryMiB != 123 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if _, err := os.Stat(filepath.Join(engine.options.Root, "jobs", job.ID)); !os.IsNotExist(err) {
		t.Fatalf("workspace remains: %v", err)
	}
	var logID string
	for _, artifact := range result.Artifacts {
		if artifact.Name == "evidence/stdout.log" {
			logID = artifact.ID
		}
	}
	if logID == "" {
		t.Fatal("stdout evidence missing")
	}
	filename, err := engine.ArtifactPath(job.ID, logID)
	if err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contents), "recipe output") {
		t.Fatal("raw recipe output was not retained")
	}
	for _, command := range runner.commands {
		for _, variable := range command.Env {
			if strings.Contains(variable, "CONTROLLER_TOKEN") {
				t.Fatal("inherited secret")
			}
		}
	}
	if err := engine.RemoveExport(job.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.ArtifactPath(job.ID, logID); !os.IsNotExist(err) {
		t.Fatalf("acknowledged export readable: %v", err)
	}
}

func TestTestJobSealsEvidenceAndDeletesOnlyOwnedDevice(t *testing.T) {
	runner := &fakeRunner{}
	engine := engineFixture(t, runner)
	job := fixtureJob(t, model.UnitTest)
	source, data := sourceFixture(t)
	result, err := engine.Execute(context.Background(), job, source, bytes.NewReader(data), nil)
	if err != nil || result.State != model.Succeeded || result.Summary == nil || result.Summary.Passed != 1 || result.Summary.XCResultSHA256 == "" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	names := map[string]bool{}
	for _, artifact := range result.Artifacts {
		names[artifact.Name] = true
		if artifact.Name == "results.xcresult.tar.gz" && artifact.SHA256 != result.Summary.XCResultSHA256 {
			t.Fatal("xcresult digest not linked")
		}
	}
	for _, name := range []string{"results.xcresult.tar.gz", "evidence/tests.json", "evidence/summary.json", "evidence/junit.xml", "evidence/stdout.log", "evidence/stderr.log"} {
		if !names[name] {
			t.Errorf("missing %s", name)
		}
	}
	assertExactCleanup(t, runner, true)
}

func assertExactCleanup(t *testing.T, runner *fakeRunner, want bool) {
	t.Helper()
	shutdown, deleted := false, false
	for _, command := range runner.commands {
		if len(command.Args) < 2 || command.Args[0] != "simctl" {
			continue
		}
		if command.Args[1] == "shutdown" || command.Args[1] == "delete" {
			if len(command.Args) != 3 || command.Args[2] != ownedUDID {
				t.Fatalf("unowned device cleanup: %v", command.Args)
			}
			shutdown = shutdown || command.Args[1] == "shutdown"
			deleted = deleted || command.Args[1] == "delete"
		}
	}
	if shutdown != want || deleted != want {
		t.Fatalf("shutdown=%v delete=%v expected %v", shutdown, deleted, want)
	}
}

func TestPinnedObservationsRejectMismatchesBeforeCreatingDevice(t *testing.T) {
	for _, scenario := range []struct{ name, xcode, build string }{{name: "xcode", xcode: "Xcode 16.1\nBuild version 16B40\n"}, {name: "runtime", build: "22B100"}} {
		t.Run(scenario.name, func(t *testing.T) {
			runner := &fakeRunner{xcode: scenario.xcode, runtimeBuild: scenario.build}
			engine := engineFixture(t, runner)
			source, data := sourceFixture(t)
			result, err := engine.Execute(context.Background(), fixtureJob(t, model.UnitTest), source, bytes.NewReader(data), nil)
			if err == nil || result.State != model.Failed || !result.CleanupOK {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			for _, command := range runner.commands {
				if len(command.Args) > 1 && command.Args[0] == "simctl" && command.Args[1] == "create" {
					t.Fatal("device created despite pin mismatch")
				}
			}
			assertExactCleanup(t, runner, false)
		})
	}
}

func TestRecipeFailuresAlwaysCleanOwnedSimulator(t *testing.T) {
	for _, stage := range []string{"generate", "prepare", "run", "boot"} {
		t.Run(stage, func(t *testing.T) {
			runner := &fakeRunner{}
			job := fixtureJob(t, model.UnitTest)
			if stage == "generate" {
				job.Profile.GeneratedFiles = []model.GeneratedFile{{Path: "README.txt", Content: "overwrite"}}
			}
			if stage == "prepare" {
				job.Profile.Prepare = []model.Command{{Executable: "/usr/bin/false"}}
			}
			resignJob(t, &job)
			runner.hook = func(_ context.Context, c Command, _, _ io.Writer) (bool, ProcessResult, error) {
				fail := stage == "prepare" && c.Executable == "/usr/bin/false" || stage == "run" && len(c.Args) > 0 && c.Args[0] == "test" || stage == "boot" && len(c.Args) > 1 && c.Args[1] == "boot"
				if fail {
					return true, ProcessResult{ExitCode: 7, CleanupOK: true}, nil
				}
				return false, ProcessResult{}, nil
			}
			engine := engineFixture(t, runner)
			source, data := sourceFixture(t)
			result, err := engine.Execute(context.Background(), job, source, bytes.NewReader(data), nil)
			if err == nil || result.State != model.Failed || !result.CleanupOK {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			assertExactCleanup(t, runner, true)
		})
	}
}

func TestIncompleteTestEvidenceCannotSucceed(t *testing.T) {
	reports := map[string]string{"zero": `{"testPlanConfigurations":[],"devices":[],"testNodes":[]}`, "missing-required": strings.ReplaceAll(passedTests, "ExampleTests/testExample()", "OtherTests/testOther()"), "unparseable": "{", "failed": strings.ReplaceAll(passedTests, "Passed", "Failed")}
	for name, report := range reports {
		t.Run(name, func(t *testing.T) {
			runner := &fakeRunner{tests: report}
			engine := engineFixture(t, runner)
			source, data := sourceFixture(t)
			result, err := engine.Execute(context.Background(), fixtureJob(t, model.UnitTest), source, bytes.NewReader(data), nil)
			if err == nil || result.State != model.Failed || !result.CleanupOK {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			assertExactCleanup(t, runner, true)
		})
	}
}

func TestCleanupFailureRetainsOwnershipAndBlocksNextJob(t *testing.T) {
	runner := &fakeRunner{hook: func(_ context.Context, c Command, _, _ io.Writer) (bool, ProcessResult, error) {
		if len(c.Args) > 1 && c.Args[1] == "delete" {
			return true, ProcessResult{ExitCode: 1, CleanupOK: true}, errors.New("device busy")
		}
		return false, ProcessResult{}, nil
	}}
	engine := engineFixture(t, runner)
	source, data := sourceFixture(t)
	job := fixtureJob(t, model.UnitTest)
	result, err := engine.Execute(context.Background(), job, source, bytes.NewReader(data), nil)
	if err == nil || result.State != model.Failed || result.CleanupOK {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	var m manifest
	if err := readJSON(engine.root, "manifests/"+job.ID+".json", &m); err != nil {
		t.Fatal(err)
	}
	if m.DeviceUDID != ownedUDID {
		t.Fatal("owned UDID was lost")
	}
	if _, err := os.Stat(filepath.Join(engine.options.Root, "jobs", job.ID)); err != nil {
		t.Fatal("uncertain workspace removed", err)
	}
	job.ID = "job-2"
	if _, err := engine.Execute(context.Background(), job, source, bytes.NewReader(data), nil); !errors.Is(err, ErrRecovery) {
		t.Fatalf("next job admitted: %v", err)
	}
	runner.hook = nil
	if err := engine.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(engine.options.Root, "jobs", "job-1")); !os.IsNotExist(err) {
		t.Fatal("recovered workspace remains")
	}
}

func TestCancellationDeadlineAndConcurrentRefusal(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(fmt.Sprintf("deadline-%v", deadline), func(t *testing.T) {
			entered := make(chan struct{})
			runner := &fakeRunner{hook: func(ctx context.Context, c Command, _, _ io.Writer) (bool, ProcessResult, error) {
				if len(c.Args) > 0 && c.Args[0] == "test" {
					close(entered)
					<-ctx.Done()
					return true, ProcessResult{ExitCode: -1, Signal: "terminated", CleanupOK: true}, ctx.Err()
				}
				return false, ProcessResult{}, nil
			}}
			engine := engineFixture(t, runner)
			job := fixtureJob(t, model.UnitTest)
			source, data := sourceFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if deadline {
				end := time.Now().Add(500 * time.Millisecond)
				job.Deadline = &end
			}
			done := make(chan Result, 1)
			go func() { result, _ := engine.Execute(ctx, job, source, bytes.NewReader(data), nil); done <- result }()
			<-entered
			if _, err := engine.Execute(context.Background(), job, source, bytes.NewReader(data), nil); !errors.Is(err, ErrBusy) {
				t.Fatalf("concurrent Execute: %v", err)
			}
			if !deadline {
				cancel()
			}
			result := <-done
			want := model.Cancelled
			if deadline {
				want = model.TimedOut
			}
			if result.State != want || !result.CleanupOK || result.Signal != "terminated" {
				t.Fatalf("result=%+v", result)
			}
			assertExactCleanup(t, runner, true)
		})
	}
}

func TestWorkerLockAndUnresolvedRecovery(t *testing.T) {
	runner := &fakeRunner{}
	engine := engineFixture(t, runner)
	if other, err := New(engine.options); err == nil {
		other.Close()
		t.Fatal("second worker acquired root")
	}
	if err := engine.saveManifest(manifest{JobID: "old-job", DeveloperDir: "/Applications/Xcode.app/Contents/Developer", Active: true, DeviceUDID: ownedUDID}); err != nil {
		t.Fatal(err)
	}
	if err := engine.Recover(context.Background()); !errors.Is(err, ErrRecovery) {
		t.Fatalf("recovery accepted live uncertainty: %v", err)
	}
	if len(runner.commands) != 0 {
		t.Fatal("recovery touched unproven live work")
	}
}

func TestImmutableJobSnapshotRejected(t *testing.T) {
	for _, change := range []func(*model.Job){func(j *model.Job) { j.ID = "../escape" }, func(j *model.Job) { j.LeaseToken = "bad/token" }, func(j *model.Job) { j.Profile.Xcode.Build = "16B40" }, func(j *model.Job) { j.Request.TimeoutSeconds++ }, func(j *model.Job) { j.Profile.Run.Args = append(j.Profile.Run.Args, "unexpected") }} {
		runner := &fakeRunner{}
		engine := engineFixture(t, runner)
		job := fixtureJob(t, model.Build)
		change(&job)
		source, data := sourceFixture(t)
		if _, err := engine.Execute(context.Background(), job, source, bytes.NewReader(data), nil); err == nil {
			t.Fatal("mutated job admitted")
		}
		if len(runner.commands) != 0 {
			t.Fatal("invalid job executed commands")
		}
	}
}

type failingSink struct {
	stage model.State
	log   bool
}

func (s failingSink) Log(_, _ string) error {
	if s.log {
		return errors.New("controller log upload failed")
	}
	return nil
}
func (s failingSink) Stage(stage model.State) error {
	if stage == s.stage {
		return errors.New("controller stage upload failed")
	}
	return nil
}

func TestSinkFailureCannotReportSuccess(t *testing.T) {
	for _, sink := range []failingSink{{stage: model.Running}, {stage: model.Finalizing}, {log: true}} {
		runner := &fakeRunner{}
		engine := engineFixture(t, runner)
		source, data := sourceFixture(t)
		result, err := engine.Execute(context.Background(), fixtureJob(t, model.UnitTest), source, bytes.NewReader(data), sink)
		if err == nil || result.State != model.Failed || !result.CleanupOK {
			t.Fatalf("result=%+v err=%v", result, err)
		}
		assertExactCleanup(t, runner, !sink.log)
	}
}

func TestGeneratedDigestsAndTrackedLockfileMutation(t *testing.T) {
	for _, mutate := range []bool{false, true} {
		t.Run(fmt.Sprint(mutate), func(t *testing.T) {
			runner := &fakeRunner{}
			job := fixtureJob(t, model.Build)
			job.Profile.GeneratedFiles = []model.GeneratedFile{{Path: "generated.conf", Content: "safe configuration\n"}}
			resignJob(t, &job)
			source, data := sourceFixture(t)
			// Rename the fixture source file to a tracked lockfile, preserving blob data.
			var buf bytes.Buffer
			tw := tar.NewWriter(&buf)
			if err := tw.WriteHeader(&tar.Header{Name: "Package.resolved", Typeflag: tar.TypeReg, Mode: 0644, Size: 6}); err != nil {
				t.Fatal(err)
			}
			if _, err := tw.Write([]byte("hello\n")); err != nil {
				t.Fatal(err)
			}
			if err := tw.Close(); err != nil {
				t.Fatal(err)
			}
			data = buf.Bytes()
			digest := sha256.Sum256(data)
			source.SHA256 = hex.EncodeToString(digest[:])
			source.SizeBytes = int64(len(data))
			blob := sha1.Sum([]byte("blob 6\x00hello\n"))
			body := append([]byte("100644 Package.resolved\x00"), blob[:]...)
			tree := sha1.Sum(append([]byte(fmt.Sprintf("tree %d\x00", len(body))), body...))
			source.Tree = hex.EncodeToString(tree[:])
			if mutate {
				runner.hook = func(_ context.Context, c Command, _, _ io.Writer) (bool, ProcessResult, error) {
					if len(c.Args) > 0 && c.Args[0] == "build" {
						err := os.WriteFile(filepath.Join(c.Dir, "Package.resolved"), []byte("changed"), 0600)
						return true, ProcessResult{CleanupOK: true}, err
					}
					return false, ProcessResult{}, nil
				}
			}
			engine := engineFixture(t, runner)
			result, err := engine.Execute(context.Background(), job, source, bytes.NewReader(data), nil)
			generated := sha256.Sum256([]byte("safe configuration\n"))
			original := sha256.Sum256([]byte("hello\n"))
			if result.Observation.GeneratedDigests["generated.conf"] != hex.EncodeToString(generated[:]) || result.Observation.LockfileDigests["Package.resolved"] != hex.EncodeToString(original[:]) {
				t.Fatalf("missing provenance: %+v", result.Observation)
			}
			if mutate {
				if err == nil || result.State != model.Failed || !strings.Contains(err.Error(), "lockfile mutated") {
					t.Fatalf("mutation accepted: %+v %v", result, err)
				}
			} else if err != nil || result.State != model.Succeeded {
				t.Fatalf("valid generation failed: %+v %v", result, err)
			}
		})
	}
}

func TestWorkspaceBudgetAndBadArchivePreventSuccess(t *testing.T) {
	runner := &fakeRunner{}
	engine := engineFixture(t, runner)
	source, data := sourceFixture(t)
	source.SHA256 = strings.Repeat("0", 64)
	result, err := engine.Execute(context.Background(), fixtureJob(t, model.Build), source, bytes.NewReader(data), nil)
	if err == nil || result.State != model.Failed || !result.CleanupOK || len(runner.commands) != 0 {
		t.Fatalf("unverified source executed: %+v %v", result, err)
	}
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.WriteFile("oversize", []byte("12345"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := workspaceBudget(root, 4); err == nil {
		t.Fatal("workspace oversize not detected")
	}
	if err := workspaceBudget(root, 5); err != nil {
		t.Fatal(err)
	}
}

func TestLostProcessCleanupIsQuarantined(t *testing.T) {
	runner := &fakeRunner{hook: func(_ context.Context, c Command, _, _ io.Writer) (bool, ProcessResult, error) {
		if len(c.Args) > 0 && c.Args[0] == "build" {
			return true, ProcessResult{ExitCode: -1, CleanupOK: false}, errors.New("process remains live")
		}
		return false, ProcessResult{}, nil
	}}
	engine := engineFixture(t, runner)
	source, data := sourceFixture(t)
	result, err := engine.Execute(context.Background(), fixtureJob(t, model.Build), source, bytes.NewReader(data), nil)
	if err == nil || result.CleanupOK || result.State != model.Failed {
		t.Fatalf("uncertain process succeeded: %+v %v", result, err)
	}
	if err := engine.Recover(context.Background()); !errors.Is(err, ErrRecovery) {
		t.Fatalf("uncertain process recovered unsafely: %v", err)
	}
}

func TestRawLogBoundaryCancelsWithoutWritingBeyondLimit(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "log")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	state := &logState{size: maxLogBytes - 1}
	writer := &logWriter{state: state, file: file, cancel: cancel}
	if n, err := writer.Write([]byte("ab")); n != 0 || err == nil {
		t.Fatalf("unbounded log write n=%d err=%v", n, err)
	}
	if ctx.Err() != context.Canceled || !state.truncated {
		t.Fatal("log truncation did not cancel the job")
	}
	info, err := file.Stat()
	if err != nil || info.Size() != 0 {
		t.Fatalf("oversized bytes reached log file: %v %v", info, err)
	}
}

func TestUnregisteredWorkspaceIsNeverDeleted(t *testing.T) {
	engine := engineFixture(t, &fakeRunner{})
	job := fixtureJob(t, model.Build)
	if err := engine.root.MkdirAll("jobs/"+job.ID, 0700); err != nil {
		t.Fatal(err)
	}
	if err := engine.root.WriteFile("jobs/"+job.ID+"/owner-data", []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	source, data := sourceFixture(t)
	if _, err := engine.Execute(context.Background(), job, source, bytes.NewReader(data), nil); err == nil {
		t.Fatal("existing workspace claimed")
	}
	if err := engine.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	contents, err := engine.root.ReadFile("jobs/" + job.ID + "/owner-data")
	if err != nil || string(contents) != "preserve" {
		t.Fatalf("unregistered data changed: %q %v", contents, err)
	}
	if err := engine.RemoveExport("missing-job"); err != nil {
		t.Fatalf("absent export acknowledgement: %v", err)
	}
}

package worker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
)

// fixtureSimulator is the pin fakeRunner's runtime listing satisfies.
var fixtureSimulator = model.Simulator{Runtime: "com.apple.CoreSimulator.SimRuntime.iOS-18-0", RuntimeBuild: "22A3351", DeviceType: "com.apple.CoreSimulator.SimDeviceType.iPhone-16"}

// testTemplateJob admits a job of a test template of kind for shard,
// leaving the simulator to the template's first pin.
func testTemplateJob(t *testing.T, kind model.Kind, shard string) model.Job {
	t.Helper()
	return admitTemplateJob(t, model.Template{ID: "org-test-v1", Version: 1, Kind: kind, Owners: []string{"example-org"}, Xcode: model.Xcode{Version: "16.0", Build: "16A242d"}, DeveloperDir: "/Applications/Xcode.app/Contents/Developer", Simulators: []model.Simulator{fixtureSimulator}}, shard)
}

// admitTemplateJob admits a job of template for shard as job-1.
func admitTemplateJob(t *testing.T, template model.Template, shard string) model.Job {
	t.Helper()
	registry, err := profiles.New(nil, []model.Template{template})
	if err != nil {
		t.Fatal(err)
	}
	admission, err := registry.Resolve(model.Request{Repo: "example-org/new-app", SHA: strings.Repeat("a", 40), Kind: template.Kind, Profile: template.ID, Xcode: template.Xcode, Shard: shard})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(admission.Request)
	digest := sha256.Sum256(data)
	return model.Job{ID: "job-1", LeaseToken: "lease-1", WorkerEpoch: "epoch-1", State: model.Preparing, Request: admission.Request, Profile: admission.Profile, ProfileDigest: admission.ProfileDigest, RequestDigest: hex.EncodeToString(digest[:])}
}

func simctl(runner *fakeRunner, verb string) []Command {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	var matched []Command
	for _, c := range runner.commands {
		if len(c.Args) > 1 && c.Args[0] == "simctl" && c.Args[1] == verb {
			matched = append(matched, c)
		}
	}
	return matched
}

func argValue(args []string, flag string) string {
	if i := slices.Index(args, flag); i >= 0 && i+1 < len(args) {
		return args[i+1]
	}
	return ""
}

// bootAttempts reads the observation's simulator_boot_attempts through its
// JSON form, the job report the controller receives.
func bootAttempts(t *testing.T, result Result) int {
	t.Helper()
	data, err := json.Marshal(result.Observation)
	if err != nil {
		t.Fatal(err)
	}
	var observed struct {
		Attempts int `json:"simulator_boot_attempts"`
	}
	if err := json.Unmarshal(data, &observed); err != nil {
		t.Fatal(err)
	}
	return observed.Attempts
}

// A template test job runs end to end on the job's own simulator: create,
// boot and bootstatus, build-for-testing in prepare, then test-without-building
// on the same device and DerivedData, then the xcresult extraction. The
// shard's selectors are the job's required tests and are proved to have run.
func TestTemplateUITestRunsBuildForTestingThenTestWithoutBuilding(t *testing.T) {
	report, err := os.ReadFile(filepath.Join("..", "evidence", "testdata", "herdrup-uitests.json"))
	if err != nil {
		t.Fatal(err)
	}
	selectors := []string{"HerdrUITests/TerminalControlTests", "HerdrUITests/TerminalSearchTests"}
	config := `{"version":1,"work_dir":".","project":"Herdr.xcodeproj","scheme":"Herdr","ui_test":{"shards":{"iphone-terminal":["HerdrUITests/TerminalControlTests","HerdrUITests/TerminalSearchTests"],"iphone-chrome":["HerdrUITests/TerminalResizeTests"]}},"unit_test":{"shards":{"core":["HerdrTests/CoreTests"]}}}`
	for _, tc := range []struct {
		kind  model.Kind
		shard string
		want  []string
	}{
		{model.SimulatorUITest, "iphone-terminal", selectors},
		{model.UnitTest, "core", []string{"HerdrTests/CoreTests"}},
	} {
		t.Run(string(tc.kind), func(t *testing.T) {
			runner := &fakeRunner{tests: string(report)}
			if tc.kind == model.UnitTest {
				runner.tests = strings.ReplaceAll(strings.ReplaceAll(string(report), `"HerdrUITests"`, `"HerdrTests"`), "TerminalControlTests", "CoreTests")
			}
			engine := engineFixture(t, runner)
			source, data := checkoutFixture(t, map[string]string{".macserve.json": config})
			result, err := engine.Execute(context.Background(), testTemplateJob(t, tc.kind, tc.shard), source, bytes.NewReader(data), nil)
			if err != nil || result.State != model.Succeeded || !result.CleanupOK {
				t.Fatalf("template test job failed: %+v %v", result, err)
			}
			if creates := simctl(runner, "create"); len(creates) != 1 || !slices.Equal(creates[0].Args[3:], []string{fixtureSimulator.DeviceType, fixtureSimulator.Runtime}) {
				t.Fatalf("simulator creation: %+v", creates)
			}
			for _, verb := range []string{"boot", "bootstatus"} {
				if got := simctl(runner, verb); len(got) != 1 || got[0].Args[2] != ownedUDID {
					t.Fatalf("simctl %s: %+v", verb, got)
				}
			}
			assertExactCleanup(t, runner, true)
			commands := checkoutCommands(runner)
			if len(commands) != 2 {
				t.Fatalf("recipe commands: %+v", commands)
			}
			build, test := commands[0].Args, commands[1].Args
			workspace := filepath.Dir(commands[0].Dir)
			if !slices.Contains(build, "build-for-testing") || slices.Contains(build, "test-without-building") || !slices.Contains(test, "test-without-building") || slices.Contains(test, "build-for-testing") {
				t.Fatalf("build then test:\n%q\n%q", build, test)
			}
			for _, args := range [][]string{build, test} {
				if argValue(args, "-destination") != "id="+ownedUDID || argValue(args, "-derivedDataPath") != filepath.Join(workspace, "derived-data") {
					t.Fatalf("not on the owned device and job DerivedData: %q", args)
				}
				var only []string
				for _, arg := range args {
					if selector, ok := strings.CutPrefix(arg, "-only-testing:"); ok {
						only = append(only, selector)
					}
				}
				if !slices.Equal(only, tc.want) {
					t.Fatalf("selection %q, want %q", only, tc.want)
				}
				if argValue(args, "-parallel-testing-enabled") != "NO" || argValue(args, "-maximum-concurrent-test-simulator-destinations") != "1" || argValue(args, "-jobs") != "4" {
					t.Fatalf("forced flags missing: %q", args)
				}
			}
			if argValue(test, "-resultBundlePath") != filepath.Join(workspace, "results.xcresult") || slices.Contains(build, "-resultBundlePath") {
				t.Fatalf("result bundle: %q %q", build, test)
			}
			var extracted bool
			for _, c := range runner.commands {
				if filepath.Base(c.Executable) == "xcresulttool" {
					extracted = slices.Contains(c.Args, filepath.Join(workspace, "results.xcresult"))
				}
			}
			if !extracted {
				t.Fatal("xcresult was not extracted")
			}
			summary := result.Summary
			if summary == nil || summary.Failed != 0 || summary.Passed == 0 || !slices.Equal(summary.RequiredTests, tc.want) || summary.XCResultSHA256 == "" {
				t.Fatalf("summary: %+v", summary)
			}
			if recipe := result.Observation.Recipe; recipe == nil || recipe.Shard != tc.shard || !slices.Equal(recipe.RequiredTests, tc.want) {
				t.Fatalf("recipe evidence: %+v", recipe)
			}
			if result.Observation.DeviceUDID != ownedUDID || bootAttempts(t, result) != 1 {
				t.Fatalf("simulator observation: %+v", result.Observation)
			}
			names := make([]string, 0, len(result.Artifacts))
			for _, artifact := range result.Artifacts {
				names = append(names, artifact.Name)
			}
			for _, name := range []string{"results.xcresult.tar.gz", "evidence/tests.json", "evidence/summary.json", "evidence/junit.xml"} {
				if !slices.Contains(names, name) {
					t.Fatalf("artifact %s missing from %q", name, names)
				}
			}
		})
	}
}

// A shard selector with no non-skipped case fails the template job: the
// -only-testing selection must be proved to have run.
func TestTemplateUITestRequiresEveryShardSelector(t *testing.T) {
	config := `{"version":1,"work_dir":".","project":"App.xcodeproj","scheme":"App","ui_test":{"shards":{"smoke":["ExampleTests/MissingTests"]}}}`
	runner := &fakeRunner{}
	engine := engineFixture(t, runner)
	source, data := checkoutFixture(t, map[string]string{".macserve.json": config})
	result, err := engine.Execute(context.Background(), testTemplateJob(t, model.SimulatorUITest, "smoke"), source, bytes.NewReader(data), nil)
	if err == nil || result.State != model.Failed || !result.CleanupOK {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if !errors.Is(err, evidence.ErrRequiredTests) || result.Summary == nil {
		t.Fatalf("want a required-tests failure with its summary: %v %+v", err, result.Summary)
	}
	assertExactCleanup(t, runner, true)
}

// When `simctl boot` or `bootstatus` fails, the job discards that device
// through the ownership teardown and creates and boots exactly one more; a
// second failure fails the job. Unconfirmed process cleanup is not retried.
func TestSimulatorBootRetriedOnceThenFails(t *testing.T) {
	for _, tc := range []struct {
		name     string
		failVerb string
		failures int
		cleanup  bool
		creates  int
		succeed  bool
		// shutdown, when set, is the stderr of a failed first
		// `simctl shutdown` of the device that failed to boot.
		shutdown string
	}{
		{name: "boot-recovers", failVerb: "boot", failures: 1, cleanup: true, creates: 2, succeed: true},
		{name: "bootstatus-recovers", failVerb: "bootstatus", failures: 1, cleanup: true, creates: 2, succeed: true},
		{name: "fails-twice", failVerb: "boot", failures: 2, cleanup: true, creates: 2},
		{name: "unconfirmed-cleanup", failVerb: "boot", failures: 1, creates: 1},
		{name: "already-shut-down-recovers", failVerb: "boot", failures: 1, cleanup: true, creates: 2, succeed: true, shutdown: "An error was encountered processing the command (domain=com.apple.CoreSimulator.SimError, code=405):\nUnable to shutdown device in current state: Shutdown\n"},
		{name: "shutdown-error-not-retried", failVerb: "boot", failures: 1, cleanup: true, creates: 1, shutdown: "An error was encountered processing the command (domain=NSPOSIXErrorDomain, code=60):\nOperation timed out\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &fakeRunner{}
			var mu sync.Mutex
			failed, shutdowns := 0, 0
			runner.hook = func(_ context.Context, c Command, _, stderr io.Writer) (bool, ProcessResult, error) {
				mu.Lock()
				defer mu.Unlock()
				if len(c.Args) > 1 && c.Args[0] == "simctl" && c.Args[1] == tc.failVerb && failed < tc.failures {
					failed++
					return true, ProcessResult{ExitCode: 164, CleanupOK: tc.cleanup}, nil
				}
				if tc.shutdown != "" && len(c.Args) > 1 && c.Args[0] == "simctl" && c.Args[1] == "shutdown" {
					if shutdowns++; shutdowns == 1 {
						io.WriteString(stderr, tc.shutdown)
						return true, ProcessResult{ExitCode: 149, CleanupOK: true}, nil
					}
				}
				return false, ProcessResult{}, nil
			}
			engine := engineFixture(t, runner)
			source, data := sourceFixture(t)
			result, err := engine.Execute(context.Background(), fixtureJob(t, model.SimulatorUITest), source, bytes.NewReader(data), nil)
			if tc.succeed != (err == nil && result.State == model.Succeeded) || !tc.succeed && result.State != model.Failed {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			if got, attempts := len(simctl(runner, "create")), bootAttempts(t, result); got != tc.creates || attempts != tc.creates {
				t.Fatalf("created %d devices, %d attempts recorded; want %d", got, attempts, tc.creates)
			}
			if !tc.cleanup {
				return
			}
			if !result.CleanupOK {
				t.Fatalf("cleanup not confirmed: %+v", result)
			}
			assertExactCleanup(t, runner, true)
			// Every created device is deleted before the next one is created.
			created := 0
			for _, c := range runner.commands {
				if len(c.Args) > 1 && c.Args[0] == "simctl" {
					switch c.Args[1] {
					case "create":
						created++
					case "delete":
						created--
					}
					if created > 1 {
						t.Fatal("second device created before the first was deleted")
					}
				}
			}
			if created != 0 || len(simctl(runner, "delete")) != tc.creates {
				t.Fatalf("devices left behind: %d", created)
			}
			if ran := len(checkoutCommands(runner)) > 0; ran != tc.succeed {
				t.Fatalf("recipe ran=%v after boot outcome", ran)
			}
		})
	}
}

// The prepare budget covers extraction, the simulator and prepare commands:
// 10 minutes for builds, 30 minutes for test kinds (a template's
// build-for-testing runs in prepare), always within the job deadline.
func TestTestKindPrepareBudget(t *testing.T) {
	for _, tc := range []struct {
		kind     model.Kind
		deadline time.Duration
		min, max time.Duration
	}{
		{kind: model.Build, min: 9 * time.Minute, max: 10 * time.Minute},
		{kind: model.UnitTest, min: 29 * time.Minute, max: 30 * time.Minute},
		{kind: model.SimulatorUITest, min: 29 * time.Minute, max: 30 * time.Minute},
		{kind: model.SimulatorUITest, deadline: 15 * time.Minute, min: 14 * time.Minute, max: 15 * time.Minute},
	} {
		t.Run(string(tc.kind)+map[bool]string{true: "-job-deadline"}[tc.deadline > 0], func(t *testing.T) {
			runner := &fakeRunner{}
			var remaining time.Duration
			runner.hook = func(ctx context.Context, c Command, _, _ io.Writer) (bool, ProcessResult, error) {
				if c.Executable == "/usr/bin/true" {
					deadline, ok := ctx.Deadline()
					if !ok {
						t.Error("prepare command has no deadline")
					}
					remaining = time.Until(deadline)
					return true, ProcessResult{CleanupOK: true}, nil
				}
				return false, ProcessResult{}, nil
			}
			job := fixtureJob(t, tc.kind)
			job.Profile.Prepare = []model.Command{{Executable: "/usr/bin/true"}}
			resignJob(t, &job)
			if tc.deadline > 0 {
				deadline := time.Now().Add(tc.deadline)
				job.Deadline = &deadline
			}
			engine := engineFixture(t, runner)
			source, data := sourceFixture(t)
			result, err := engine.Execute(context.Background(), job, source, bytes.NewReader(data), nil)
			if err != nil || result.State != model.Succeeded {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			if remaining < tc.min || remaining > tc.max {
				t.Fatalf("prepare budget left %v, want between %v and %v", remaining, tc.min, tc.max)
			}
		})
	}
}

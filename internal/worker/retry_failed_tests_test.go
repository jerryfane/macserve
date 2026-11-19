package worker

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/model"
)

func retryReport(t *testing.T, name string) string {
	t.Helper()
	report, err := os.ReadFile(filepath.Join("..", "evidence", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(report)
}

// A UI-test template that opts in to retries runs its test command with
// -retry-tests-on-failure -test-iterations 2, beside the parallel-testing
// options and the shard's -only-testing selectors, each once; its
// build-for-testing command, and every command of a job without the opt-in,
// has none. A case that failed and then passed on retry leaves the job
// succeeded.
func TestRetryFailedTestsArguments(t *testing.T) {
	for _, tc := range []struct {
		name, members string
		retry         bool
		parallel      string
	}{
		{"without the opt-in", "", false, "NO"},
		{"retries", `"retry_failed_tests":{"iterations":2}`, true, "NO"},
		{"retries and parallel testing", `"retry_failed_tests":{"iterations":2},"parallel_testing":{"workers":2}`, true, "YES"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set := &testingSet{devices: map[string]string{}}
			report := retryReport(t, "herdrup-uitests.json")
			if tc.retry {
				report = retryReport(t, "herdrup-uitests-retry-passed.json")
			}
			runner := &fakeRunner{tests: report, hook: set.hook}
			engine := engineFixture(t, runner)
			source, data := checkoutFixture(t, map[string]string{".macserve.json": parallelConfig})
			result, err := engine.Execute(context.Background(), parallelUITestJob(t, tc.members), source, bytes.NewReader(data), nil, nil)
			if err != nil || result.State != model.Succeeded || !result.CleanupOK {
				t.Fatalf("job: %+v %v", result, err)
			}
			commands := checkoutCommands(runner)
			if len(commands) != 2 || !slices.Contains(commands[0].Args, "build-for-testing") || !slices.Contains(commands[1].Args, "test-without-building") {
				t.Fatalf("recipe commands: %+v", commands)
			}
			build, test := commands[0].Args, commands[1].Args
			if slices.Contains(build, "-retry-tests-on-failure") || slices.Contains(build, "-test-iterations") {
				t.Fatalf("build-for-testing retries: %q", build)
			}
			if got := slices.Contains(test, "-retry-tests-on-failure"); got != tc.retry {
				t.Fatalf("test run retries %v, want %v: %q", got, tc.retry, test)
			}
			want := ""
			if tc.retry {
				want = "2"
			}
			if argValue(test, "-test-iterations") != want || argValue(test, "-parallel-testing-enabled") != tc.parallel {
				t.Fatalf("test run options: %q", test)
			}
			for _, flag := range []string{"-retry-tests-on-failure", "-test-iterations", "-parallel-testing-enabled", "-only-testing:HerdrUITests/TerminalControlTests", "-only-testing:HerdrUITests/TerminalSearchTests"} {
				want := 1
				if !tc.retry && (flag == "-retry-tests-on-failure" || flag == "-test-iterations") {
					want = 0
				}
				if n := strings.Count(" "+strings.Join(test, " ")+" ", " "+flag+" "); n != want {
					t.Fatalf("%s given %d times: %q", flag, n, test)
				}
			}
			if tc.retry && (result.Summary == nil || result.Summary.Retried != 1 || result.Summary.Failed != 0) {
				t.Fatalf("retry summary: %+v", result.Summary)
			}
		})
	}
}

// A retry job still fails on a test that failed on every attempt, and on a
// test command that exited non-zero, even when every case's last attempt
// passed: xcodebuild exits 0 when each test passes on some attempt, so a
// non-zero exit is a failure the parsed cases do not override (a build
// failure, a runner crash, a timeout). Without the opt-in, a pass on retry
// is a failure.
func TestRetryFailedTestsFailures(t *testing.T) {
	const retry = `"retry_failed_tests":{"iterations":2}`
	for _, tc := range []struct {
		name, members, report string
		exit                  int
	}{
		{"failed on every attempt", retry, "herdrup-uitests-retry-mixed.json", 0},
		{"non-zero exit", retry, "herdrup-uitests-retry-passed.json", 65},
		{"retry pass without the opt-in", "", "herdrup-uitests-retry-passed.json", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &fakeRunner{tests: retryReport(t, tc.report)}
			runner.hook = func(ctx context.Context, c Command, out, stderr io.Writer) (bool, ProcessResult, error) {
				if tc.exit == 0 || !slices.Contains(c.Args, "test-without-building") {
					return false, ProcessResult{}, nil
				}
				for _, arg := range c.Args {
					if strings.HasSuffix(arg, "results.xcresult") {
						if err := os.MkdirAll(arg, 0700); err != nil {
							return true, ProcessResult{}, err
						}
						if err := os.WriteFile(filepath.Join(arg, "Info.plist"), []byte("fixture result bundle"), 0600); err != nil {
							return true, ProcessResult{}, err
						}
					}
				}
				return true, ProcessResult{ExitCode: tc.exit, CleanupOK: true, PeakMemoryMiB: 123}, nil
			}
			engine := engineFixture(t, runner)
			source, data := checkoutFixture(t, map[string]string{".macserve.json": parallelConfig})
			result, _ := engine.Execute(context.Background(), parallelUITestJob(t, tc.members), source, bytes.NewReader(data), nil, nil)
			if result.State != model.Failed {
				t.Fatalf("job %s, want failed: %+v", result.State, result)
			}
		})
	}
}

// An action is a bare word that is not an option's value.
func TestRunsTestAction(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want bool
	}{
		{[]string{"test-without-building", "-xctestrun", "x"}, true},
		{[]string{"-scheme", "App", "CODE_SIGNING_ALLOWED=NO", "test"}, true},
		{[]string{"-scheme", "test", "build-for-testing"}, false},
		{[]string{"-scheme", "test", "-resolvePackageDependencies"}, false},
		{[]string{"-scheme", "test", "test"}, true},
		{[]string{"-only-testing:A/B", "test"}, true},
		{[]string{"build", "-destination", "test-without-building"}, false},
	} {
		if got := runsTestAction(tc.args); got != tc.want {
			t.Fatalf("%q: %v, want %v", tc.args, got, tc.want)
		}
	}
}

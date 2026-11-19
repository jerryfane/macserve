package worker

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/model"
)

// Retry options follow the xcodebuild action, not a scheme name: with a
// scheme named like an action, the build-for-testing command still gets
// none and the test run gets them once.
func TestRetryFailedTestsIgnoresActionNamedSchemes(t *testing.T) {
	for _, scheme := range []string{"test", "test-without-building"} {
		t.Run(scheme, func(t *testing.T) {
			config := strings.Replace(parallelConfig, `"scheme":"Herdr"`, `"scheme":"`+scheme+`"`, 1)
			runner := &fakeRunner{tests: retryReport(t, "herdrup-uitests-retry-passed.json")}
			engine := engineFixture(t, runner)
			source, data := checkoutFixture(t, map[string]string{".macserve.json": config})
			result, err := engine.Execute(context.Background(), parallelUITestJob(t, `"retry_failed_tests":{"iterations":2}`), source, bytes.NewReader(data), nil, nil)
			if err != nil || result.State != model.Succeeded {
				t.Fatalf("job: %+v %v", result, err)
			}
			commands := checkoutCommands(runner)
			if len(commands) != 2 || !slices.Contains(commands[0].Args, "build-for-testing") || argValue(commands[0].Args, "-scheme") != scheme {
				t.Fatalf("recipe commands: %+v", commands)
			}
			for i, want := range []int{0, 1} {
				args := commands[i].Args
				if n := strings.Count(" "+strings.Join(args, " ")+" ", " -retry-tests-on-failure "); n != want {
					t.Fatalf("command %d has -retry-tests-on-failure %d times, want %d: %q", i, n, want, args)
				}
			}
		})
	}
}

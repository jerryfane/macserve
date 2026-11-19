package evidence

import "testing"

// A test case's own failure (outside its attempts) keeps it failed in a
// retry job, whether its retry passed or was an expected failure and even
// when its failed first attempt has no message of its own; without one, a
// retry pass or an expected failure on retry is not a failure.
func TestParseTestsRetryKeepsCaseDiagnostics(t *testing.T) {
	const teardown = `{"nodeType":"Failure Message","name":"teardown failed"}`
	const silentFirstRun = `{"nodeType":"Repetition","name":"First Run","result":"Failed","durationInSeconds":1}`
	const expectedRetry = `{"nodeType":"Repetition","name":"Retry 1","result":"Expected Failure","durationInSeconds":1,"children":[{"nodeType":"Expected Failure","name":"known issue","children":[{"nodeType":"Failure Message","name":"tracked failure"}]}]}`
	// expectedTeardown is an expected failure on retry whose issue has the
	// teardown's text: an expected issue never explains away a failure.
	const expectedTeardown = `{"nodeType":"Repetition","name":"Retry 1","result":"Expected Failure","durationInSeconds":1,"children":[{"nodeType":"Expected Failure","name":"known issue","children":[{"nodeType":"Failure Message","name":"teardown failed"}]}]}`
	for _, tc := range []struct {
		name, nodes             string
		failed, retried, expect int
	}{
		{"teardown, silent first run", retryCase(silentFirstRun + `,` + retryPassed + `,` + teardown), 2, 0, 0},
		{"teardown, retry passed", retryCase(firstRunFailed + `,` + retryPassed + `,` + teardown), 2, 0, 0},
		{"teardown, expected failure on retry", retryCase(firstRunFailed + `,` + expectedRetry + `,` + teardown), 2, 0, 0},
		{"teardown, expected issue of the same text on retry", retryCase(firstRunFailed + `,` + expectedTeardown + `,` + teardown), 2, 0, 0},
		{"expected issue of the teardown's text, no teardown", retryCase(firstRunFailed + `,` + expectedTeardown), 0, 1, 1},
		{"clean retry pass", retryCase(firstRunFailed + `,` + retryPassed), 0, 1, 0},
		{"clean expected failure on retry", retryCase(firstRunFailed + `,` + expectedRetry), 0, 1, 1},
		{"silent first run, retry passed", retryCase(silentFirstRun + `,` + retryPassed), 0, 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			summary, err := ParseTests(simpleReport(tc.nodes), nil, 2)
			if err != nil {
				t.Fatal(err)
			}
			if summary.Failed != tc.failed || summary.Retried != tc.retried || summary.ExpectedFailures != tc.expect {
				t.Fatalf("failed %d retried %d expected %d, want %d, %d, %d: %+v", summary.Failed, summary.Retried, summary.ExpectedFailures, tc.failed, tc.retried, tc.expect, summary.Cases)
			}
		})
	}
	for _, fixture := range []string{"herdrup-uitests-retry-teardown.json", "herdrup-uitests-retry-teardown-expected.json", "herdrup-uitests-retry-teardown-same-text.json"} {
		summary, err := ParseTests(retryFixture(t, fixture), nil, 2)
		if err != nil || summary.Failed == 0 || summary.Retried != 0 {
			t.Fatalf("%s: failed %d retried %d %v", fixture, summary.Failed, summary.Retried, err)
		}
	}
}

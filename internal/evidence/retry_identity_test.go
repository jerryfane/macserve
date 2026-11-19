package evidence

import "testing"

// retryCase is a Test Case node of suite S whose children are given.
func retryCase(children string) string {
	return `{"nodeType":"Test Case","name":"c()","nodeIdentifier":"S/c()","result":"Failed","children":[` + children + `]}`
}

const (
	firstRunFailed = `{"nodeType":"Repetition","name":"First Run","result":"Failed","durationInSeconds":1,"children":[{"nodeType":"Failure Message","name":"flaky"}]}`
	firstRunPassed = `{"nodeType":"Repetition","name":"First Run","result":"Passed","durationInSeconds":1}`
	retryPassed    = `{"nodeType":"Repetition","name":"Retry 1","result":"Passed","durationInSeconds":1}`
)

// Attempts are one test's only by xcodebuild's retry provenance under one
// parent with an unambiguous identity. A failure on one device and a pass on
// another that shares its display name (no device identifier), attempts
// under a device without an identifier, two Test Case nodes of one identity,
// and repetitions without retry labels are not a pass on retry: the failure
// stays. A labelled retry under an identified device is one.
func TestParseTestsRetryNeedsUnambiguousIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, nodes     string
		failed, retried int
	}{
		{"two devices, one display name", retryCase(`{"nodeType":"Device","name":"iPhone 16","children":[` + firstRunFailed + `]},{"nodeType":"Device","name":"iPhone 16","children":[` + firstRunPassed + `]}`), 1, 0},
		{"device without an identifier", retryCase(`{"nodeType":"Device","name":"iPhone 16","children":[` + firstRunFailed + `,` + retryPassed + `]}`), 1, 0},
		{"duplicate test case nodes", `{"nodeType":"Test Suite","name":"S","children":[` + retryCase(firstRunFailed) + `,` + `{"nodeType":"Test Case","name":"c()","nodeIdentifier":"S/c()","result":"Passed","children":[` + firstRunPassed + `]}` + `]}`, 1, 0},
		{"repetitions without retry labels", retryCase(`{"nodeType":"Repetition","name":"Repetition 1","result":"Failed","children":[{"nodeType":"Failure Message","name":"flaky"}]},{"nodeType":"Repetition","name":"Repetition 2","result":"Passed"}`), 1, 0},
		{"identified device", retryCase(`{"nodeType":"Device","name":"iPhone 16","nodeIdentifier":"device-1","children":[` + firstRunFailed + `,` + retryPassed + `]}`), 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			summary, err := ParseTests(simpleReport(tc.nodes), nil, 2)
			if err != nil {
				t.Fatal(err)
			}
			if summary.Failed != tc.failed || summary.Retried != tc.retried {
				t.Fatalf("failed %d retried %d, want %d and %d: %+v", summary.Failed, summary.Retried, tc.failed, tc.retried, summary.Cases)
			}
		})
	}
	// The captured suite with the retried case's attempts split over two
	// same-named devices.
	summary, err := ParseTests(retryFixture(t, "herdrup-uitests-retry-devices.json"), nil, 2)
	if err != nil || summary.Failed != 1 || summary.Retried != 0 {
		t.Fatalf("captured suite, colliding devices: failed %d retried %d %v", summary.Failed, summary.Retried, err)
	}
}

// A pass on retry supersedes only the failure of the retried attempt. A
// suite's own failure (a teardown, say) and a test case's message no
// attempt records stay failures; a suite failure that only rolls up the
// retried attempt does not.
func TestParseTestsRetryKeepsIndependentFailures(t *testing.T) {
	suite := func(result, children string) string {
		return `{"nodeType":"Test Suite","name":"S","result":"` + result + `","children":[` + children + `]}`
	}
	for _, tc := range []struct {
		name, nodes     string
		failed, retried int
	}{
		{"suite teardown failure", suite("Failed", retryCase(firstRunFailed+`,`+retryPassed)+`,{"nodeType":"Failure Message","name":"teardown failed"}`), 1, 1},
		{"test case message outside its attempts", suite("Passed", retryCase(firstRunFailed+`,`+retryPassed+`,{"nodeType":"Failure Message","name":"case teardown failed"}`)), 2, 0},
		{"suite roll-up of the retried attempt", suite("Failed", retryCase(firstRunFailed+`,`+retryPassed)), 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			summary, err := ParseTests(simpleReport(tc.nodes), nil, 2)
			if err != nil {
				t.Fatal(err)
			}
			if summary.Failed != tc.failed || summary.Retried != tc.retried {
				t.Fatalf("failed %d retried %d, want %d and %d: %+v", summary.Failed, summary.Retried, tc.failed, tc.retried, summary.Cases)
			}
		})
	}
}

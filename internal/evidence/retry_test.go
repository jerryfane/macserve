package evidence

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func retryFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func casesOf(s Summary, id string) []TestCase {
	var found []TestCase
	for _, c := range s.Cases {
		if c.ID == id {
			found = append(found, c)
		}
	}
	return found
}

const (
	retriedCase = "TerminalControlTests/testACopiedDocumentBeatsItsFinderIcon()"
	brokenCase  = "TerminalSelectionTests/testATapThatStopsAScrollDoesNotRaiseTheKeyboard()"
	plainCase   = "TerminalControlTests/testACopiedFileURLAttachesTheFileRatherThanItsPath()"
)

// The herdrup suite with xcodebuild's retry attempts (First Run, Retry 1)
// on two cases: one failed then passed, one failed on both attempts; the
// rest passed first time. With the job's retry opt-in every attempt keeps
// its record, the fail-then-pass case passes on retry (its last attempt
// passed, marked retried with one failed attempt, the failed attempt
// superseded), the fail-then-fail case still fails and a pass stays a
// plain pass.
func TestParseTestsRetryVerdict(t *testing.T) {
	required := []string{"HerdrUITests/TerminalControlTests", "HerdrUITests/TerminalSelectionTests"}
	summary, err := ParseTests(retryFixture(t, "herdrup-uitests-retry-mixed.json"), required, 2)
	if err != nil {
		t.Fatal(err)
	}
	retried := casesOf(summary, retriedCase)
	if len(retried) != 2 || retried[0].Attempt != 1 || retried[0].Outcome != "failed" || !retried[0].Superseded || retried[0].Retried || len(retried[0].Failures) != 1 ||
		retried[1].Attempt != 2 || retried[1].Outcome != "passed" || !retried[1].Retried || retried[1].FailedAttempts != 1 || retried[1].Superseded {
		t.Fatalf("fail then pass: %+v", retried)
	}
	broken := casesOf(summary, brokenCase)
	if len(broken) != 2 || broken[0].Outcome != "failed" || broken[1].Outcome != "failed" || broken[0].Superseded || broken[1].Superseded || broken[1].Retried {
		t.Fatalf("fail then fail: %+v", broken)
	}
	plain := casesOf(summary, plainCase)
	if len(plain) != 1 || plain[0].Outcome != "passed" || plain[0].Retried || plain[0].Superseded {
		t.Fatalf("pass: %+v", plain)
	}
	if summary.Failed != 2 || summary.Retried != 1 || summary.Superseded != 1 || summary.Tests != summary.Passed+summary.Failed+summary.Skipped+summary.ExpectedFailures+summary.Superseded {
		t.Fatalf("summary counts: tests %d passed %d failed %d skipped %d retried %d superseded %d", summary.Tests, summary.Passed, summary.Failed, summary.Skipped, summary.Retried, summary.Superseded)
	}

	passed, err := ParseTests(retryFixture(t, "herdrup-uitests-retry-passed.json"), required, 2)
	if err != nil || passed.Failed != 0 || passed.Retried != 1 || passed.Superseded != 1 || passed.ParseStatus != "parsed" {
		t.Fatalf("every case passed, one on retry: %+v %v", passed, err)
	}
}

// Without the opt-in (iterations 0) the same attempts are a failure: a
// retry pass exists only in a retry job.
func TestParseTestsRetryNeedsOptIn(t *testing.T) {
	summary, err := ParseTests(retryFixture(t, "herdrup-uitests-retry-passed.json"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Failed != 1 || summary.Retried != 0 || summary.Superseded != 0 {
		t.Fatalf("retry pass outside a retry job: failed %d retried %d superseded %d", summary.Failed, summary.Retried, summary.Superseded)
	}
	for _, c := range summary.Cases {
		if c.Retried || c.Superseded || c.FailedAttempts != 0 {
			t.Fatalf("retry marks outside a retry job: %+v", c)
		}
	}
}

// A required test that passed on retry is executed, and the job's
// evidence has no failure.
func TestParseTestsRetryPassSatisfiesRequired(t *testing.T) {
	summary, err := ParseTests(retryFixture(t, "herdrup-uitests-retry-passed.json"), []string{"HerdrUITests/TerminalControlTests/testACopiedDocumentBeatsItsFinderIcon"}, 2)
	if err != nil || summary.ParseStatus != "parsed" || summary.Failed != 0 {
		t.Fatalf("required retry pass: %+v %v", summary, err)
	}
}

// An expected failure (XCTExpectFailure) after a failed attempt passes on
// retry and counts as an expected failure; xcodebuild retries only a
// failure, so an attempt after a pass, a skip or an expected failure, or more
// attempts than the iterations, is invalid evidence.
func TestMarkRetriesShapes(t *testing.T) {
	attempt := func(outcome string, n int) TestCase {
		return TestCase{ID: "S/c", Suite: "S", Name: "c", Outcome: outcome, Attempt: n}
	}
	cases := []TestCase{attempt("failed", 1), attempt("expected-failure", 2)}
	if err := MarkRetries(cases, 2); err != nil || !cases[0].Superseded || !cases[1].Retried || cases[1].FailedAttempts != 1 {
		t.Fatalf("expected failure on retry: %+v %v", cases, err)
	}
	for name, cases := range map[string][]TestCase{
		"after a pass":              {attempt("passed", 1), attempt("passed", 2)},
		"after a skip":              {attempt("skipped", 1), attempt("passed", 2)},
		"after an expected failure": {attempt("expected-failure", 1), attempt("passed", 2)},
		"more than the iterations":  {attempt("failed", 1), attempt("failed", 2), attempt("passed", 3)},
	} {
		t.Run(name, func(t *testing.T) {
			if err := MarkRetries(cases, 2); !errors.Is(err, ErrInvalidTests) {
				t.Fatalf("%+v: %v", cases, err)
			}
		})
	}
	// Separate suites (devices, configurations, arguments) are separate
	// cases: one attempt each is no retry.
	separate := []TestCase{{ID: "S/c", Suite: "S/A", Name: "c", Outcome: "failed", Attempt: 1}, {ID: "S/c", Suite: "S/B", Name: "c", Outcome: "passed", Attempt: 2}}
	if err := MarkRetries(separate, 2); err != nil || separate[0].Superseded || separate[1].Retried {
		t.Fatalf("separate suites: %+v %v", separate, err)
	}
}

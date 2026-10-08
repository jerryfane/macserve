package evidence

import (
	"bytes"
	"testing"
)

func TestPassedCaseCannotHideFailureDiagnostic(t *testing.T) {
	for _, children := range []string{
		`{"nodeType":"Failure Message","name":"assertion failed"}`,
		`{"nodeType":"Test Case Run","name":"run","result":"Passed"},{"nodeType":"Failure Message","name":"assertion failed"}`,
		`{"nodeType":"Test Case Run","name":"run","result":"Passed","children":[{"nodeType":"Failure Message","name":"assertion failed"}]}`,
	} {
		report := simpleReport(`{"nodeType":"Test Case","name":"testFails","nodeIdentifier":"Suite/testFails","result":"Passed","children":[` + children + `]}`)
		summary, err := ParseTests(report, []string{"Suite/testFails"})
		if err != nil {
			t.Fatal(err)
		}
		if summary.Tests != 1 || summary.Passed != 0 || summary.Failed != 1 || summary.Cases[0].Outcome != "failed" || len(summary.Cases[0].Failures) != 1 || summary.Cases[0].Failures[0] != "assertion failed" {
			t.Fatalf("failure diagnostic became passing evidence: %+v", summary)
		}
		junit, err := JUnit(summary)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(junit, []byte("<failure")) || !bytes.Contains(junit, []byte("assertion failed")) {
			t.Fatalf("JUnit lost case failure: %s", junit)
		}
	}
}

package evidence

import (
	"errors"
	"testing"
)

func TestRequiredSelectionCannotUseDisplayNameFromAnotherSuite(t *testing.T) {
	report := simpleReport(`{"nodeType":"Test Suite","name":"OtherSuite","children":[{"nodeType":"Test Case","name":"testSharedName","nodeIdentifier":"OtherSuite/testSharedName","result":"Passed"}]}`)
	for _, required := range []string{"testSharedName", "ExpectedSuite/testSharedName"} {
		summary, err := ParseTests(report, []string{required})
		if !errors.Is(err, ErrRequiredTests) || summary.Tests != 1 || summary.Passed != 1 {
			t.Fatalf("unexecuted selection %q accepted or evidence lost: %+v %v", required, summary, err)
		}
	}
	for _, required := range []string{"OtherSuite/testSharedName", "OtherSuite"} {
		summary, err := ParseTests(report, []string{required})
		if err != nil || summary.Passed != 1 {
			t.Fatalf("canonical case/suite selection %q rejected: %+v %v", required, summary, err)
		}
	}
}

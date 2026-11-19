package githubpull

import (
	"fmt"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/receipt"
)

// A verified receipt's check summary names its tests that passed on retry,
// at most the receipt's bounded list, with the rest as a count; a receipt
// without retries adds nothing.
func TestRetriedSummaryNamesBoundedTests(t *testing.T) {
	if got := retriedSummary(receipt.TestEvidence{}); got != "" {
		t.Fatalf("summary without retries: %q", got)
	}
	got := retriedSummary(receipt.TestEvidence{Retried: 2, RetriedTests: []string{"Suite/testA()", "Suite/test`B`()"}})
	if !strings.Contains(got, "2 test(s) failed and then passed on retry") || !strings.Contains(got, "- `Suite/testA()`") || !strings.Contains(got, "- `Suite/test'B'()`") || strings.Contains(got, "more") {
		t.Fatalf("two retried tests: %q", got)
	}
	names := make([]string, receipt.PublishedRetried)
	for i := range names {
		names[i] = fmt.Sprintf("Suite/test%d()", i)
	}
	got = retriedSummary(receipt.TestEvidence{Retried: 30, RetriedTests: names})
	if strings.Count(got, "\n- `") != receipt.PublishedRetried || !strings.Contains(got, "and 22 more") {
		t.Fatalf("thirty retried tests: %q", got)
	}
}

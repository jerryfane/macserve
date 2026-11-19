package receipt

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/model"
)

// A retry job's captured suite in which a test fails and then passes or
// expectedly fails on retry, but the test case node also has a failure of
// its own outside its attempts (a teardown), has a failed test: the signer
// refuses to seal its success, so neither a compact nor a full receipt
// exists. The first shape's failed First Run has no message of its own, so
// the parser's aggregate fallback copies the teardown onto it. The same
// suite without the teardown seals and validates as a pass on retry.
func TestRetryReceiptKeepsCaseDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		fixture string
		sealed  bool
	}{
		{"herdrup-uitests-retry-teardown.json", false},
		{"herdrup-uitests-retry-teardown-expected.json", false},
		{"herdrup-uitests-retry-passed.json", true},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			options, job, result, expected := testTemplateFixtureWith(t, model.SimulatorUITest, retryTemplate)
			report, err := os.ReadFile(filepath.Join("..", "evidence", "testdata", tc.fixture))
			if err != nil {
				t.Fatal(err)
			}
			summary, err := evidence.ParseTests(report, result.Summary.RequiredTests, job.Profile.RetryIterations())
			if err != nil {
				t.Fatal(err)
			}
			summary.XCResultSHA256 = result.Summary.XCResultSHA256
			result.Summary = &summary
			if !tc.sealed {
				signer, err := NewSigner(options)
				if err != nil {
					t.Fatal(err)
				}
				defer signer.Close()
				if _, err := signer.Seal(context.Background(), job, result); !errors.Is(err, ErrInvalid) {
					t.Fatalf("success with a case teardown failure sealed: %v (failed %d, retried %d)", err, summary.Failed, summary.Retried)
				}
				return
			}
			expected.RetryIterations = 2
			signer, _, p := sealFixture(t, options, job, result)
			for form, payload := range map[string]Payload{"compact": p, "full": fullPayload(t, signer, p)} {
				if err := ValidateSuccess(payload, expected); err != nil || payload.Tests.Retried != 1 {
					t.Fatalf("%s clean retry pass: retried %d, %v", form, payload.Tests.Retried, err)
				}
			}
		})
	}
}

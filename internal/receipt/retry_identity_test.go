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

// A retry job whose captured suite records a test's failed attempt on one
// device and its pass on another device of the same display name has a
// failed test, not a pass on retry: the signer refuses to seal its success.
func TestRetryReceiptRefusesCollidingDevices(t *testing.T) {
	options, job, result, _ := testTemplateFixtureWith(t, model.SimulatorUITest, retryTemplate)
	report, err := os.ReadFile(filepath.Join("..", "evidence", "testdata", "herdrup-uitests-retry-devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	summary, err := evidence.ParseTests(report, result.Summary.RequiredTests, job.Profile.RetryIterations())
	if err != nil {
		t.Fatal(err)
	}
	summary.XCResultSHA256 = result.Summary.XCResultSHA256
	result.Summary = &summary
	signer, err := NewSigner(options)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()
	if _, err := signer.Seal(context.Background(), job, result); !errors.Is(err, ErrInvalid) {
		t.Fatalf("success with a failure on one of two same-named devices sealed: %v (failed %d, retried %d)", err, summary.Failed, summary.Retried)
	}
}

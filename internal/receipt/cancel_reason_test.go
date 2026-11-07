package receipt

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
)

// A cancel reason is job-record metadata only: a cancelled job seals to the
// same receipt bytes with or without one.
func TestCancelReasonDoesNotChangeReceipt(t *testing.T) {
	options, job, result, _ := fixture(t, model.Build)
	result.State, result.Reason = model.Cancelled, "cancellation requested"
	job.CancelRequested = true
	_, plain, _ := sealFixture(t, options, job, result)
	options.Root = filepath.Join(t.TempDir(), "receipts")
	job.CancelReason = &model.CancelReason{Source: model.CancelHostReadiness, Blockers: []string{"isolation_unavailable", "host_memory_pressure"}, At: job.CreatedAt.Add(time.Second), Detail: "free_bytes=1 used_bytes=-1"}
	_, reasoned, _ := sealFixture(t, options, job, result)
	if !bytes.Equal(plain, reasoned) {
		t.Fatalf("cancel reason changed the receipt:\n%s\n%s", plain, reasoned)
	}
}

package receipt

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/worker"
)

// v0131Result is worker.Result as released in v0.1.31. Deployed v0.1.31
// verifiers (`macserve wait`, receipt checks) decode receipt details strictly,
// so a field this release adds to worker.Result makes them reject its receipts.
type v0131Result struct {
	State         model.State              `json:"state"`
	Reason        string                   `json:"reason,omitempty"`
	ExitCode      *int                     `json:"exit_code,omitempty"`
	Signal        string                   `json:"signal,omitempty"`
	CleanupOK     bool                     `json:"cleanup_ok"`
	StartedAt     time.Time                `json:"started_at"`
	FinishedAt    time.Time                `json:"finished_at"`
	Source        worker.Source            `json:"source"`
	Observation   worker.Observation       `json:"observation"`
	Summary       *evidence.Summary        `json:"summary,omitempty"`
	Artifacts     []evidence.Artifact      `json:"artifacts"`
	LogsTruncated bool                     `json:"logs_truncated"`
	Commands      []worker.ExecutedCommand `json:"commands"`
	PeakMemoryMiB int64                    `json:"peak_memory_mib"`
}

func TestManifestDetailsDecodeWithV0131Result(t *testing.T) {
	options, job, result, _ := fixture(t, model.UnitTest)
	result.PeakMemoryMiB = 2048
	signer, _, core := sealFixture(t, options, job, result)
	if core.Manifest == nil {
		t.Fatal("fixture receipt has no private manifest")
	}
	manifest, err := signer.Manifest(context.Background(), job.ID, core.Manifest.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Details json.RawMessage `json:"details"`
	}
	if err := json.Unmarshal(manifest, &payload); err != nil {
		t.Fatal(err)
	}
	var details struct {
		Profile model.Profile `json:"profile"`
		Result  v0131Result   `json:"result"`
	}
	if err := strictDecode(payload.Details, &details); err != nil {
		t.Fatalf("a v0.1.31 verifier rejects this release's receipt details: %v", err)
	}
	if details.Result.PeakMemoryMiB != 2048 {
		t.Fatalf("peak memory changed meaning on the wire: %+v", details.Result)
	}
}

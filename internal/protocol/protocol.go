// Package protocol defines the private, peer-UID-authenticated worker transport.
package protocol

import (
	"time"

	"github.com/jerryfane/macserve/internal/buildseal"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/worker"
)

const (
	Prefix         = "/worker/v1"
	EpochHeader    = "X-Macserve-Epoch"
	LeaseHeader    = "X-Macserve-Lease"
	ArtifactHeader = "X-Macserve-Artifact"
)

// Registration announces a worker epoch. Lanes is how many jobs the worker
// runs at once (its max_concurrent_jobs); 0 means 1, the pre-lane worker.
type Registration struct {
	Epoch     string `json:"epoch"`
	Quiescent bool   `json:"quiescent"`
	Lanes     int    `json:"lanes,omitempty"`
}

// NextRequest is the body of POST /next. Running lists the job IDs the
// worker is executing in any phase; the controller never offers one of
// them again, so a free lane asks only for a job no lane holds.
type NextRequest struct {
	Running []string `json:"running,omitempty"`
}

type Lease struct {
	Job    model.Job     `json:"job"`
	Token  string        `json:"token"`
	Source worker.Source `json:"source"`
}

type Heartbeat struct {
	Cancel   bool      `json:"cancel"`
	Deadline time.Time `json:"deadline"`
}

// Stage reports a lease's stage. Held (with Finalizing) reports that the
// job's completion waits for the worker's next idle check: the worker could
// not verify the account (worker.IdleDeferred with cleanup_ok).
type Stage struct {
	State model.State `json:"state"`
	Held  bool        `json:"held,omitempty"`
}

type Log struct {
	Stream string `json:"stream"`
	Data   []byte `json:"data"`
}

// Completion is the worker's final report: its result and the root
// worker's signed build seal over that result, which the controller passes
// to the keyholder unchanged. AdmissionRefused is set only when the worker
// refused the job before it ran for a cause of its own (a failed result
// with cleanup_ok); the controller then ends the job cancelled by the
// service (model.CancelWorkerAdmission). A controller from before this field
// refuses a completion carrying it (unknown fields are refused), so the
// worker and controller of one release ship together.
type Completion struct {
	Result           worker.Result      `json:"result"`
	Seal             buildseal.Envelope `json:"seal"`
	AdmissionRefused AdmissionRefusal   `json:"admission_refused,omitempty"`
}

// AdmissionRefusal is why the worker refused a job's admission before it
// ran, when the service caused the refusal; empty for any other completion.
type AdmissionRefusal string

// AdmissionACLCensusUnavailable is an admission whose registered tree ACL
// census its deadline cut short, on a loaded host, also after its retries
// (worker.ErrACLCensusUnavailable): it observed nothing about the job.
const AdmissionACLCensusUnavailable AdmissionRefusal = "acl_census_unavailable"

// Valid reports whether r is empty or a known refusal.
func (r AdmissionRefusal) Valid() bool {
	return r == "" || r == AdmissionACLCensusUnavailable
}

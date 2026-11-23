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

// Log is a chunk of a job's output. Seq numbers a lease's chunks from 1,
// consecutively, so a resent chunk (its first request's answer was lost) is
// recorded once: the controller acknowledges a seq it already recorded for
// the lease without appending it again, and refuses a gap (409: output was
// lost). A Log without Seq (0) is appended unconditionally, as before Seq.
type Log struct {
	Stream string `json:"stream"`
	Data   []byte `json:"data"`
	Seq    int64  `json:"seq,omitempty"`
}

// HeartbeatTimeout is how long a delivered lease that is not finalizing
// lives without a heartbeat: the controller's default lease window, and how
// long the worker retries a failed heartbeat, log or stage request before it
// ends the job.
const HeartbeatTimeout = 30 * time.Second

// Completion is the worker's final report: its result and the root
// worker's signed build seal over that result, which the controller passes
// to the keyholder unchanged. AdmissionRefused is set only when the worker
// refused the job before it ran for a cause of its own (a failed result
// with cleanup_ok); the controller then ends the job cancelled by the
// service (model.CancelWorkerAdmission), except AdmissionWorkerDraining,
// which returns the job to the queue untouched. A controller from before this field
// refuses a completion carrying it (unknown fields are refused), so the
// worker and controller of one release ship together. Stalled is set only
// when the worker ended the job itself because its run command's output
// stopped for its stall limit (worker.ErrStalled); the controller then
// records the job cancelled by the service (model.CancelStalled), which
// pull mode reruns once. It ships the same way.
type Completion struct {
	Result           worker.Result      `json:"result"`
	Seal             buildseal.Envelope `json:"seal"`
	AdmissionRefused AdmissionRefusal   `json:"admission_refused,omitempty"`
	Stalled          bool               `json:"stalled,omitempty"`
}

// CompletionReply is the controller's answer (200) to a completion whose
// handling retired the worker's epoch: a drain refusal
// (AdmissionWorkerDraining) whose job it returned to the queue, fencing the
// lease's epoch in the same transaction (#214). Every other accepted
// completion is answered 204 with no body, and the epoch stays valid unless
// the worker's own cleanup was unverified. The worker registers a new epoch
// after its idle check only on what the controller committed, never on the
// refusal it sent.
type CompletionReply struct {
	EpochRetired bool `json:"epoch_retired"`
}

// AdmissionRefusal is why the worker refused a job's admission before it
// ran, when the service caused the refusal; empty for any other completion.
type AdmissionRefusal string

// AdmissionACLCensusUnavailable is an admission one of whose inspections its
// deadline cut short on a loaded host, also after its retries: the
// registered tree ACL census, the protected-input ACL inspection, or any
// other (worker.ErrACLCensusUnavailable; the name predates #150). It
// observed nothing about the job.
const AdmissionACLCensusUnavailable AdmissionRefusal = "acl_census_unavailable"

// AdmissionRelaunchUnverified is a lane admission beside running jobs that
// found an audited GUI process exited beside an unattributed process it could
// not verify as its launchd relaunch (worker.ErrRelaunchRefusal):
// inconclusive, never contamination. The worker drains until its idle check;
// the job is returned to the queue rather than failed (#206).
const AdmissionRelaunchUnverified AdmissionRefusal = "relaunch_unverified"

// AdmissionWorkerDraining is a job refused before it started because the
// worker drains (another job's cleanup is unverified) until its idle check
// (worker.ErrDrainRefusal): nothing of the job ran. The controller returns
// it to the queue untouched (same job, attempt and check run), never
// cancelled (#214).
const AdmissionWorkerDraining AdmissionRefusal = "worker_draining"

// DeliveryTimeout bounds the worker's delivery of a completion after its
// finalization (worker.FinalizationTimeout), and the controller's handling
// of one. The controller's finalizing lease budget covers both, plus its
// heartbeat grace.
const DeliveryTimeout = 2 * time.Minute

// Valid reports whether r is empty or a known refusal.
func (r AdmissionRefusal) Valid() bool {
	return r == "" || r == AdmissionACLCensusUnavailable || r == AdmissionRelaunchUnverified || r == AdmissionWorkerDraining
}

package worker

import (
	"encoding/json"
	"errors"
	"os"
	"time"
)

// admissionInconclusiveRecord is the broker's durable record of admissions
// refused because a child of a tolerated launch outlived the wait
// (errToleratedChildPersists) or because refused processes kept vanishing
// before verification (errAdmissionUnsettled, v0.1.15). Admission only observes and never terminates
// such a child; only a job's quiesce or worker-reset does, and no job starts
// while admission refuses. Without this record the worker would refuse work
// for as long as the child runs while quarantine-based alerting saw nothing.
// Maintenance publishes the record's reason in health
// (`admission_inconclusive`), which the controller's gate reports as the
// `worker_admission_inconclusive` blocker.
//
// The record is not quarantine: checkQuarantine ignores it and every
// admission runs again. Engine.admission removes it when it passes (Recover
// once the child has exited, and a job's own admission, so no job runs while
// it exists), and worker-reset removes it after its cleanup terminated the
// child and its admission passed. A job's post-quiesce admission can only
// write it.
const admissionInconclusiveRecord = "admission-inconclusive.json"

// AdmissionInconclusive is admissionInconclusiveRecord: the refusal reason,
// the first refusal since the last admission that passed, and the latest.
type AdmissionInconclusive struct {
	Reason    string    `json:"reason"`
	Since     time.Time `json:"since"`
	CheckedAt time.Time `json:"checked_at"`
}

func (e *Engine) recordInconclusive(reason error) error {
	now := e.options.Now().UTC()
	record := AdmissionInconclusive{Reason: reason.Error(), Since: now, CheckedAt: now}
	var previous AdmissionInconclusive
	if readJSON(e.root, admissionInconclusiveRecord, &previous) == nil && !previous.Since.IsZero() && !previous.Since.After(now) {
		record.Since = previous.Since
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return durableFile(e.root, admissionInconclusiveRecord, data)
}

func (e *Engine) clearInconclusive() error {
	if err := e.root.Remove(admissionInconclusiveRecord); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	dir, err := e.root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// ReadAdmissionInconclusive returns the record in the broker root, or nil
// when the last admission was not refused for a persisting tolerated child.
func ReadAdmissionInconclusive(brokerRoot string) (*AdmissionInconclusive, error) {
	root, err := os.OpenRoot(brokerRoot)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	var record AdmissionInconclusive
	if err := readJSON(root, admissionInconclusiveRecord, &record); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if record.Reason == "" || record.Since.IsZero() || record.CheckedAt.Before(record.Since) {
		return nil, errors.New("invalid admission inconclusive record")
	}
	return &record, nil
}

package worker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// QuiescentReport is the read-only residual census worker-quiescent prints.
type QuiescentReport struct {
	Quiescent         bool              `json:"quiescent"`
	JobUID            uint32            `json:"job_uid"`
	BaselineBoot      string            `json:"baseline_boot,omitempty"`
	BaselineProcesses int               `json:"baseline_processes"`
	BaselineExited    []ProcessIdentity `json:"baseline_exited"`
	Error             string            `json:"error,omitempty"`
}

// WorkerQuiescent is the census a release carry runs with the services booted
// out, before the binary swap keeps the job GUI session alive. Unlike
// ObserveGUIBaseline, which tolerates active-job processes, it fails on any
// job-UID process outside the audited baseline once verified relaunches and
// tolerated launches are filtered: the broker's admission census
// (observeQuiet), including its wait for children of tolerated launches. A
// quarantined or admission-inconclusive worker also fails. It never signals,
// adopts, quarantines or writes state.
func WorkerQuiescent(ctx context.Context, options Options) (QuiescentReport, error) {
	scope := &processScope{uid: int(options.JobUID), sample: identityProcesses, agents: nativeAgents{}, interval: 50 * time.Millisecond, childWait: toleratedChildWait}
	return workerQuiescent(ctx, options, scope)
}

func workerQuiescent(parent context.Context, options Options, scope *processScope) (QuiescentReport, error) {
	report := QuiescentReport{JobUID: options.JobUID}
	err := func() error {
		// A durable quarantine is contamination evidence and an inconclusive
		// admission is an unsettled worker; neither is quiescent.
		if _, err := os.Lstat(filepath.Join(options.Root, quarantineRecord)); err == nil {
			return fmt.Errorf("%w: worker quarantined; administrator reset required", ErrRecovery)
		} else if !os.IsNotExist(err) {
			return err
		}
		if inconclusive, err := ReadAdmissionInconclusive(options.Root); err != nil {
			return err
		} else if inconclusive != nil {
			return fmt.Errorf("worker admission inconclusive since %s: %s", inconclusive.Since.Format(time.RFC3339), inconclusive.Reason)
		}
		baseline, err := loadBaseline(options.BaselinePath, options.JobUID)
		if err != nil {
			return err
		}
		digest, err := PersistenceDigest(options.PersistencePath, options.JobUID)
		if err != nil {
			return err
		}
		if baseline.PersistenceSHA256 != digest {
			return errors.New("reviewed persistence changed; baseline reset and requalification required")
		}
		report.BaselineBoot, report.BaselineProcesses = baseline.Boot, len(baseline.Processes)
		scope.baseline = baseline
		ctx, cancel := context.WithTimeout(parent, scope.childWait+persistenceAdmissionTimeout)
		defer cancel()
		if err := scope.observeQuiet(ctx); err != nil {
			return err
		}
		samples, err := scope.sample(ctx)
		if err != nil {
			return err
		}
		report.BaselineExited = baselineExited(baseline, samples)
		return ctx.Err()
	}()
	report.Quiescent = err == nil
	if err != nil {
		report.Error = err.Error()
	}
	return report, err
}

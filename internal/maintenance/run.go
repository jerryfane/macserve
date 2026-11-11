package maintenance

import (
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/jerryfane/macserve/internal/controllerconfig"
	"github.com/jerryfane/macserve/internal/health"
	"github.com/jerryfane/macserve/internal/hostguard"
	"github.com/jerryfane/macserve/internal/worker"
)

// Run requires the protected fixed deployment topology. Every cycle reloads all
// approval inputs. A finding publishes invalid health, as do startup and
// shutdown; no failure path extends the lifetime of a successful observation.
// A probe that failed without evidence (keepLastValid) is not a finding
// (#53): the last valid health is republished unchanged with the count of
// such probes in a row, which blocks admission and, from
// health.ProbeFailureLimit, cancels active work, until that health expires.
// The facts a probe may take from an earlier observation are the byte census
// and the GUI-baseline check, which run in the background and may be up to
// censusMaxAge and guiBaselineMaxAge old (tracker); every other fact is
// observed by the probe itself.
func Run(ctx context.Context, c Config) error {
	if runtime.GOOS != "darwin" || os.Getuid() != 0 || os.Geteuid() != 0 {
		return errors.New("maintenance requires macOS root")
	}
	if c.path == "" {
		return errors.New("maintenance config must be loaded from a protected file")
	}
	const healthPath = "/Library/macserve/health/current.json"
	if err := hostguard.RootDirectory(filepath.Dir(healthPath)); err != nil {
		return err
	}
	var probes probeRecord
	var report healthReport
	invalid := func(cause string) error {
		o := Observation{}
		if opts, err := persistenceOptions(c); err == nil {
			o.Persistence, err = worker.PersistenceAttestationStatus(opts)
			if err != nil {
				o.Persistence.Valid = false
			}
		}
		h, _ := Evaluate(time.Now(), Qualification{}, BoundaryEvidence{}, o)
		if err := publish(healthPath, h); err != nil {
			return err
		}
		report.failed(h, probes.lastValid, cause)
		return nil
	}
	if err := invalid("maintenance starting"); err != nil {
		return err
	}
	defer func() { _ = invalid("maintenance stopping") }()
	monitorCtx, stopMonitor := context.WithCancel(ctx)
	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		monitorPersistence(monitorCtx, c.path)
	}()
	defer func() {
		stopMonitor()
		<-monitorDone
	}()
	bg := newBackground(ctx)
	for {
		started := time.Now()
		current, err := LoadConfig(c.path)
		interval := 10 * time.Second
		var h health.Health
		if err == nil {
			interval = time.Duration(current.IntervalSeconds) * time.Second
			// The log names the blockers the controller derives, whose disk
			// budget depends on its max_concurrent_jobs.
			if cc, ccErr := controllerconfig.LoadConfig(current.ControllerConfig); ccErr == nil {
				report.lanes = health.EffectiveLanes(cc.Lanes())
			}
			probeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
			h, err = observe(probeCtx, current, bg)
			cancel()
		}
		if err != nil {
			// The published health carries no reason; keep it diagnosable.
			log.Printf("macserve maintenance: probe failed: %v\n", err)
			if h.CheckedAt.IsZero() {
				h, _ = Evaluate(time.Now(), Qualification{}, BoundaryEvidence{}, Observation{})
			}
		}
		lastValid := probes.lastValid
		h = probes.publication(h, err, time.Now())
		if pubErr := publish(healthPath, h); pubErr != nil {
			return pubErr
		}
		if err != nil {
			report.failed(h, lastValid, err.Error())
		} else {
			report.valid(h)
		}
		// Anchor cadence to probe start; probe duration must not extend the interval.
		if !sleepUntil(ctx, started.Add(interval)) {
			return ctx.Err()
		}
	}
}

// probeRecord is the run loop's last valid health and the number of
// consecutive probes since that failed without evidence.
type probeRecord struct {
	lastValid health.Health
	failures  int
}

// publication returns the health to publish for one probe that returned h and
// err at now. A valid probe publishes h and restarts the count. A probe that
// failed without evidence after valid health counts one more failure and
// republishes that health, still valid but with the count (the gate blocks
// admission, and cancels from health.ProbeFailureLimit), or once it has
// expired publishes invalid h with the count. Any other failure is a finding:
// it publishes invalid h and forgets the last valid health, so the next
// failure of any kind cannot keep it either.
func (r *probeRecord) publication(h health.Health, err error, now time.Time) health.Health {
	switch {
	case err == nil:
		*r = probeRecord{lastValid: h}
		return h
	case !withoutEvidence(err) || !r.lastValid.BoundaryValidated:
		*r = probeRecord{}
		return h
	}
	r.failures++
	if keepLastValid(err, r.lastValid, now) {
		h = r.lastValid
	}
	h.ProbeFailures = r.failures
	return h
}

// withoutEvidence reports whether a probe failed without evidence, as opposed
// to a finding (#53). It is a closed list; every other error, including any
// whose cause is unclear, is a finding:
//   - the probe's own deadline, or a deadline inside it (context.DeadlineExceeded:
//     a census or GUI-baseline check with no usable earlier result, the
//     persistence-status read, a protected-input ACL inspection killed at its
//     deadline, a coexisting service read). Under launchd ProcessType=Background
//     a census of a job home that a build is writing into measured up to 8 s,
//     1-2 s typical, and probes ran out of time for over 40 s while simulators
//     booted (#108);
//   - the accepted CoreDevice devicefs changed mid-census (errAcceptedMountChanged:
//     Xcode does this as a build finishes);
//   - a configured coexisting service between two launchd runs
//     (errCoexistingServiceRestarting: a KeepAlive relaunch or its own redeploy).
//
// Only the daemon's own shutdown cancels a probe otherwise (context.Canceled),
// which is a finding.
func withoutEvidence(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, errAcceptedMountChanged) || errors.Is(err, errCoexistingServiceRestarting)
}

// keepLastValid reports whether a probe that failed without evidence
// (withoutEvidence) republishes the last valid health with its failure count:
// only while that health has not yet expired. A finding, and any failure once
// the last valid health has expired, publishes invalid health.
func keepLastValid(err error, last health.Health, now time.Time) bool {
	return withoutEvidence(err) && last.BoundaryValidated && last.ExpiresAt.After(now)
}

func sleepUntil(ctx context.Context, at time.Time) bool {
	timer := time.NewTimer(max(0, time.Until(at)))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

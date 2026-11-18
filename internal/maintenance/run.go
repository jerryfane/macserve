package maintenance

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
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
// shutdown. A probe that failed without evidence (keepLastValid) is not a
// finding (#53): for up to the configured probe outage bound after the last
// valid health (ProbeOutageSeconds, DefaultProbeOutage) the probe publishes
// that health's facts with the count of such probes in a row, which blocks
// admission only (#194); a finding, the end of that bound or a daemon that
// stops publishing (every record's own lifetime) cancels active work.
// The facts a probe may take from an earlier observation are the byte census
// and the GUI-baseline check, which run in the background and may be up to
// censusMaxAge and guiBaselineMaxAge old (tracker); every other fact is
// observed by the probe itself. scanLog receives each periodic full
// persistence scan's stage-timing line (worker.Options.ScanLog).
func Run(ctx context.Context, c Config, scanLog io.Writer) error {
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
		monitorPersistence(monitorCtx, c.path, scanLog)
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
			probes.outage = time.Duration(current.ProbeOutageSeconds) * time.Second
			report.outage = probes.outage
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
		failure := err
		if err != nil && ctx.Err() != nil {
			// The daemon is stopping: whatever the probe returned is not a
			// failure without evidence, so it never republishes valid health.
			failure = fmt.Errorf("maintenance stopping: %v", err)
		}
		h = probes.publication(h, failure, time.Now())
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

// probeRecord is the run loop's last valid health, the number of consecutive
// probes since that failed without evidence, and the probe outage bound.
type probeRecord struct {
	lastValid health.Health
	failures  int
	// outage is Config.ProbeOutageSeconds; zero means DefaultProbeOutage.
	outage time.Duration
}

// outageBound is a configured probe outage bound, DefaultProbeOutage when
// unset.
func outageBound(configured time.Duration) time.Duration {
	if configured <= 0 {
		return DefaultProbeOutage
	}
	return configured
}

// publication returns the health to publish for one probe that returned h and
// err at now. A valid probe publishes h and restarts the count. A probe that
// failed without evidence after valid health counts one more failure and,
// within the outage bound, publishes that health's facts with the count
// (carried: the gate blocks admission only), or once the bound has passed
// publishes invalid h with the count. Any other failure is a finding: it
// publishes invalid h and forgets the last valid health, so the next
// failure of any kind cannot carry it either.
func (r *probeRecord) publication(h health.Health, err error, now time.Time) health.Health {
	switch {
	case err == nil:
		r.lastValid, r.failures = h, 0
		return h
	case !withoutEvidence(err) || !r.lastValid.BoundaryValidated:
		r.lastValid, r.failures = health.Health{}, 0
		return h
	}
	r.failures++
	if bound := outageBound(r.outage); keepLastValid(err, r.lastValid, now) && now.Before(r.lastValid.CheckedAt.Add(bound)) {
		h = carried(r.lastValid, now, bound)
	}
	h.ProbeFailures = r.failures
	return h
}

// carried is the record a probe that failed without evidence at now publishes
// within the outage bound: the facts of last, the last valid health, with
// LastValidAt its check, checked at now and expiring after healthLifetime,
// or at the end of the bound if that is sooner. Its own timestamps prove the
// daemon still publishes; the facts are never refreshed, and admission stays
// blocked while it is in force (maintenance_probe_failed).
func carried(last health.Health, now time.Time, outage time.Duration) health.Health {
	h := last
	h.LastValidAt = last.CheckedAt
	h.CheckedAt = now
	h.ExpiresAt = now.Add(healthLifetime)
	if end := last.CheckedAt.Add(outage); end.Before(h.ExpiresAt) {
		h.ExpiresAt = end
	}
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
//     (errCoexistingServiceRestarting: a KeepAlive relaunch or its own redeploy);
//   - an inspection subprocess that exited but whose output pipes did not
//     close within its WaitDelay (exec.ErrWaitDelay: a timing failure of the
//     read, not its result; Studio 2026-11-13, `launchctl print` of a
//     coexisting service, the next probe clean).
//
// Only the daemon's own shutdown cancels a probe otherwise (context.Canceled),
// which is a finding.
func withoutEvidence(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, errAcceptedMountChanged) || errors.Is(err, errCoexistingServiceRestarting) || errors.Is(err, exec.ErrWaitDelay)
}

// keepLastValid reports whether a probe that failed with err at now may carry
// the facts of last, the last valid health: a failure without evidence
// (withoutEvidence) after valid health checked no later than now. A finding
// publishes invalid health; publication carries the facts only within the
// probe outage bound after last was checked.
func keepLastValid(err error, last health.Health, now time.Time) bool {
	return withoutEvidence(err) && last.BoundaryValidated && last.ExpiresAt.After(last.CheckedAt) && !last.CheckedAt.After(now)
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

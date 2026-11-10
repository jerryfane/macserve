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
// approval inputs. Failure publishes invalid health, including shutdown; no
// failure path extends the lifetime of a successful observation. A probe that
// only ran out of time is inconclusive, not a finding: the last valid health
// then stays in place until its own expiry instead of being replaced at once.
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
	var lastValid health.Health
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
		report.invalid(h, lastValid, cause)
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
				report.lanes = cc.Lanes()
			}
			probeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
			h, err = observe(probeCtx, current, bg)
			cancel()
			// Inspect bounds itself (8 s) inside the probe, so a deadline error
			// can come from either context; only the daemon's own shutdown is not
			// a timeout.
			if err != nil && ctx.Err() == nil && keepLastValid(err, lastValid, time.Now()) {
				log.Printf("macserve maintenance: probe inconclusive; keeping last valid health until %s: %v\n",
					lastValid.ExpiresAt.Format(time.RFC3339), err)
				if !sleepUntil(ctx, started.Add(interval)) {
					return ctx.Err()
				}
				continue
			}
		}
		if err != nil {
			// The published health carries no reason; keep it diagnosable.
			log.Printf("macserve maintenance: probe failed: %v\n", err)
			if h.CheckedAt.IsZero() {
				h, _ = Evaluate(time.Now(), Qualification{}, BoundaryEvidence{}, Observation{})
			}
		}
		if pubErr := publish(healthPath, h); pubErr != nil {
			return pubErr
		}
		if err != nil {
			report.invalid(h, lastValid, err.Error())
		} else {
			report.valid(h)
		}
		lastValid = health.Health{}
		if err == nil && h.BoundaryValidated {
			lastValid = h
		}
		// Anchor cadence to probe start; probe duration must not extend the interval.
		if !sleepUntil(ctx, started.Add(interval)) {
			return ctx.Err()
		}
	}
}

// keepLastValid reports whether a failed probe may leave the last valid health
// in place: only when the probe was inconclusive, never a finding, and that
// health has not yet expired. Inconclusive means it ran out of time (under
// launchd ProcessType=Background a census of a job home that a build is
// writing into measured up to 8 s, 1-2 s typical) or the accepted CoreDevice
// devicefs changed mid-census (Xcode does this as a build finishes), or a
// configured coexisting service was between two launchd runs (a KeepAlive
// relaunch or its own redeploy). Every
// other error, and any inconclusive probe once the last valid health has
// expired, publishes invalid health.
func keepLastValid(err error, last health.Health, now time.Time) bool {
	inconclusive := errors.Is(err, context.DeadlineExceeded) || errors.Is(err, errCoreDeviceMountChanged) || errors.Is(err, errCoexistingServiceRestarting)
	return inconclusive && last.BoundaryValidated && last.ExpiresAt.After(now)
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

package maintenance

import (
	"log"
	"strings"
	"time"

	"github.com/jerryfane/macserve/internal/health"
)

// timeLayout is RFC 3339 in UTC with milliseconds, as the daemons' log prefix.
const timeLayout = "2006-01-02T15:04:05.000Z07:00"

// healthReport logs published health in terms of the controller readiness
// blockers it implies, so a job the controller cancels can be tied to the
// maintenance failure behind it: every invalid record, with its cause and the
// last valid health it replaced; every republished last valid health, with the
// probe failure that kept it and their count; and every valid record whose
// blockers differ from the previously published record's.
type healthReport struct {
	blockers string
	// lanes is the controller's max_concurrent_jobs, which sizes the
	// service disk budget the controller applies (health.ServiceBudget).
	lanes int
}

// failed logs h, published for a failed probe or the daemon's start or stop
// with lastValid the last valid health before it: invalid health, or that
// health republished with a probe failure count.
func (r *healthReport) failed(h, lastValid health.Health, cause string) {
	blockers, cancel := healthBlockers(h, r.lanes)
	r.blockers = blockers
	if h.BoundaryValidated {
		log.Printf("macserve maintenance: republished last valid health checked_at=%s expires_at=%s probe_failures=%d blockers=%s cancels_active_job=%t: %s", stamp(h.CheckedAt), stamp(h.ExpiresAt), h.ProbeFailures, blockers, cancel, cause)
		return
	}
	until := "none"
	if lastValid.BoundaryValidated {
		until = stamp(lastValid.ExpiresAt)
	}
	log.Printf("macserve maintenance: published invalid health checked_at=%s last_valid_until=%s probe_failures=%d blockers=%s cancels_active_job=%t: %s", stamp(h.CheckedAt), until, h.ProbeFailures, blockers, cancel, cause)
}

func (r *healthReport) valid(h health.Health) {
	blockers, cancel := healthBlockers(h, r.lanes)
	if blockers == r.blockers {
		return
	}
	r.blockers = blockers
	log.Printf("macserve maintenance: published health checked_at=%s accounted_bytes=%d memory_pressure=%t blockers=%s cancels_active_job=%t", stamp(h.CheckedAt), h.AccountedBytes, h.MemoryPressure, blockers, cancel)
}

// healthBlockers lists the blockers a controller reports for h when it reads
// it fresh. Toolchain qualification is the controller's own comparison against
// its profiles and is not listed.
func healthBlockers(h health.Health, lanes int) (string, bool) {
	found := health.HealthBlockers(h, h.CheckedAt, h.JobUID, nil, lanes)
	if len(found) == 0 {
		return "none", false
	}
	names := make([]string, len(found))
	cancel := false
	for i, b := range found {
		names[i] = b.Name
		cancel = cancel || b.Cancel
	}
	return strings.Join(names, ","), cancel
}

func stamp(t time.Time) string { return t.UTC().Format(timeLayout) }

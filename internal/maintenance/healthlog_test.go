package maintenance

import (
	"bytes"
	"context"
	"log"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/health"
)

// Every invalid publication is logged with the controller blockers it
// implies, its cause, the end of the probe outage bound of the last valid
// health it replaced and the probes that failed without evidence in a row; a
// record carrying the last valid health's facts with its failure count; a
// valid publication only when its blockers change. Invalid health names no
// disk or memory blocker: it measured neither.
func TestHealthReportLogsInvalidHealthAndBlockerChanges(t *testing.T) {
	var logs bytes.Buffer
	previous, flags := log.Writer(), log.Flags()
	log.SetOutput(&logs)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(previous); log.SetFlags(flags) })

	now, q, e, o := approvedFixture()
	valid, err := Evaluate(now, q, e, o)
	if err != nil {
		t.Fatal(err)
	}
	var r healthReport
	startup, _ := Evaluate(now.Add(-time.Second), Qualification{}, BoundaryEvidence{}, Observation{})
	r.failed(startup, health.Health{}, "maintenance starting")
	r.valid(valid)
	r.valid(valid)
	pressured := valid
	pressured.MemoryPressure = true
	r.valid(pressured)
	probes := probeRecord{lastValid: pressured}
	kept := probes.publication(health.Health{}, context.DeadlineExceeded, now.Add(10*time.Second))
	r.failed(kept, pressured, "cannot inspect protected input ACL: signal: killed: context deadline exceeded")
	failed, _ := Evaluate(now.Add(11*time.Minute), Qualification{}, BoundaryEvidence{}, Observation{})
	failed.ProbeFailures = 66
	r.failed(failed, pressured, "mutable census /Users/macservejob: context deadline exceeded")

	want := []string{
		"macserve maintenance: published invalid health checked_at=2026-01-02T03:04:04.000Z last_valid_until=none probe_failures=0 blockers=isolation_unavailable,persistence_attestation_unavailable cancels_active_job=true: maintenance starting",
		"macserve maintenance: published health checked_at=2026-01-02T03:04:05.000Z accounted_bytes=1234 memory_pressure=false blockers=none cancels_active_job=false",
		"macserve maintenance: published health checked_at=2026-01-02T03:04:05.000Z accounted_bytes=1234 memory_pressure=true blockers=host_memory_pressure cancels_active_job=false",
		"macserve maintenance: republished last valid health checked_at=2026-01-02T03:04:15.000Z last_valid_at=2026-01-02T03:04:05.000Z expires_at=2026-01-02T03:04:55.000Z probe_failures=1 blockers=maintenance_probe_failed,host_memory_pressure cancels_active_job=false: cannot inspect protected input ACL: signal: killed: context deadline exceeded",
		"macserve maintenance: published invalid health checked_at=2026-01-02T03:15:05.000Z last_valid_until=2026-01-02T03:14:05.000Z probe_failures=66 blockers=isolation_unavailable,maintenance_probe_failed,persistence_attestation_unavailable cancels_active_job=true: mutable census /Users/macservejob: context deadline exceeded",
	}
	if got := strings.Split(strings.TrimSpace(logs.String()), "\n"); !reflect.DeepEqual(got, want) {
		t.Fatalf("maintenance log:\n%s\nwant:\n%s", logs.String(), strings.Join(want, "\n"))
	}
}

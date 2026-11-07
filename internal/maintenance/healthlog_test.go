package maintenance

import (
	"bytes"
	"log"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/controller"
)

// Every invalid publication is logged with the controller blockers it
// implies, its cause and the last valid health it replaced; a valid
// publication is logged only when its blockers change.
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
	r.invalid(startup, controller.Health{}, "maintenance starting")
	r.valid(valid)
	r.valid(valid)
	pressured := valid
	pressured.MemoryPressure = true
	r.valid(pressured)
	failed, _ := Evaluate(now.Add(time.Minute), Qualification{}, BoundaryEvidence{}, Observation{})
	r.invalid(failed, pressured, "mutable census /Users/macservejob: context deadline exceeded")

	want := []string{
		"macserve maintenance: published invalid health checked_at=2026-01-02T03:04:04.000Z last_valid_until=none blockers=isolation_unavailable,persistence_attestation_unavailable,service_disk_budget_exceeded,host_memory_pressure cancels_active_job=true: maintenance starting",
		"macserve maintenance: published health checked_at=2026-01-02T03:04:05.000Z accounted_bytes=1234 memory_pressure=false blockers=none cancels_active_job=false",
		"macserve maintenance: published health checked_at=2026-01-02T03:04:05.000Z accounted_bytes=1234 memory_pressure=true blockers=host_memory_pressure cancels_active_job=false",
		"macserve maintenance: published invalid health checked_at=2026-01-02T03:05:05.000Z last_valid_until=" + stamp(valid.ExpiresAt) + " blockers=isolation_unavailable,persistence_attestation_unavailable,service_disk_budget_exceeded,host_memory_pressure cancels_active_job=true: mutable census /Users/macservejob: context deadline exceeded",
	}
	if got := strings.Split(strings.TrimSpace(logs.String()), "\n"); !reflect.DeepEqual(got, want) {
		t.Fatalf("maintenance log:\n%s\nwant:\n%s", logs.String(), strings.Join(want, "\n"))
	}
}

package maintenance

import (
	"fmt"
	"testing"
	"time"
)

// probe_outage_seconds is range-checked as an integer, 40..3600 (#195 review
// F4): 2^55+600 seconds overflows to exactly 600 s as a time.Duration, which
// a check on the product accepted.
func TestProbeOutageSecondsRange(t *testing.T) {
	config := func(outage string) []byte {
		return fmt.Appendf(nil, `{"controller_config":"/Library/macserve/config/controller.json","worker_config":"/Library/macserve/config/worker.json","qualification_file":"/Library/macserve/config/qualification.json","boundary_evidence_file":"/Library/macserve/config/boundary-evidence.json","interval_seconds":10%s}`, outage)
	}
	for outage, want := range map[string]time.Duration{"": DefaultProbeOutage, `,"probe_outage_seconds":40`: 40 * time.Second, `,"probe_outage_seconds":3600`: time.Hour} {
		c, err := parseConfig(config(outage), "/Library/macserve/config/maintenance.json")
		if err != nil || time.Duration(c.ProbeOutageSeconds)*time.Second != want {
			t.Fatalf("%q: %+v %v, want %v", outage, c, err, want)
		}
	}
	for _, seconds := range []int64{-1, 39, 3601, 1<<55 + 600} {
		if c, err := parseConfig(config(fmt.Sprintf(`,"probe_outage_seconds":%d`, seconds)), "/Library/macserve/config/maintenance.json"); err == nil {
			t.Fatalf("probe_outage_seconds %d accepted as %v", seconds, time.Duration(c.ProbeOutageSeconds)*time.Second)
		}
	}
}

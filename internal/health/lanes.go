package health

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/jerryfane/macserve/internal/hostguard"
	"github.com/jerryfane/macserve/internal/model"
)

// LanesOverrideFile lowers max_concurrent_jobs without editing the anchored
// controller.json or worker.json: root-owned, not group- or other-writable,
// {"max_concurrent_jobs": N}. The activation anchor does not hash it, so an
// administrator can lower concurrency (rollback to 1) without a sitting.
// The controller, worker and maintenance read it at start.
const LanesOverrideFile = "/Library/macserve/config/lanes.json"

// EffectiveLanes is configured (already >= 1) lowered by the override file.
func EffectiveLanes(configured int) int {
	_, err := os.Lstat(LanesOverrideFile)
	lanes, note := LaneOverride(configured, !errors.Is(err, os.ErrNotExist), func() error { return hostguard.RootConfig(LanesOverrideFile) }, func() ([]byte, error) { return os.ReadFile(LanesOverrideFile) })
	if note != "" {
		log.Printf("macserve lanes: %s", note)
	}
	return lanes
}

// LaneOverride is the override rule, given whether the file is present,
// its protection check and its reader, so that doctor applies the runtime
// rule through its own read-only probe. An absent file leaves configured; a
// value above configured is ignored (an override never raises); a file that
// is unsafe, unreadable or malformed fails closed to one lane.
func LaneOverride(configured int, present bool, check func() error, read func() ([]byte, error)) (int, string) {
	configured = max(configured, 1)
	if !present {
		return configured, ""
	}
	fail := func(err error) (int, string) {
		return 1, fmt.Sprintf("%s refused (%v); running one lane", LanesOverrideFile, err)
	}
	if err := check(); err != nil {
		return fail(err)
	}
	data, err := read()
	if err != nil {
		return fail(err)
	}
	// Exactly one member; json.Unmarshal refuses trailing data.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return fail(err)
	}
	raw, ok := fields["max_concurrent_jobs"]
	var n int
	if !ok || len(fields) != 1 || json.Unmarshal(raw, &n) != nil || n < 1 || n > model.MaxConcurrentJobs {
		return fail(errors.New(`must be exactly {"max_concurrent_jobs": 1..3}`))
	}
	if n > configured {
		return configured, fmt.Sprintf("%s max_concurrent_jobs %d above the configured %d ignored", LanesOverrideFile, n, configured)
	}
	return n, fmt.Sprintf("%s lowers max_concurrent_jobs to %d (configured %d)", LanesOverrideFile, n, configured)
}

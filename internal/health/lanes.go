package health

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	lanes, note := laneOverride(LanesOverrideFile, configured, hostguard.RootConfig, os.ReadFile)
	if note != "" {
		log.Printf("macserve lanes: %s", note)
	}
	return lanes
}

// laneOverride is EffectiveLanes for path. An absent file leaves configured;
// a value above configured is ignored (an override never raises); a file that
// is unsafe, unreadable or malformed fails closed to one lane.
func laneOverride(path string, configured int, check func(string) error, read func(string) ([]byte, error)) (int, string) {
	configured = max(configured, 1)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return configured, ""
	}
	fail := func(err error) (int, string) {
		return 1, fmt.Sprintf("%s refused (%v); running one lane", path, err)
	}
	if err := check(path); err != nil {
		return fail(err)
	}
	data, err := read(path)
	if err != nil {
		return fail(err)
	}
	var override struct {
		MaxConcurrentJobs *int `json:"max_concurrent_jobs"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&override); err != nil {
		return fail(err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fail(errors.New("trailing data"))
	}
	if override.MaxConcurrentJobs == nil || *override.MaxConcurrentJobs < 1 || *override.MaxConcurrentJobs > model.MaxConcurrentJobs {
		return fail(errors.New("max_concurrent_jobs must be 1..3"))
	}
	n := *override.MaxConcurrentJobs
	if n > configured {
		return configured, fmt.Sprintf("%s max_concurrent_jobs %d above the configured %d ignored", path, n, configured)
	}
	return n, fmt.Sprintf("%s lowers max_concurrent_jobs to %d (configured %d)", path, n, configured)
}

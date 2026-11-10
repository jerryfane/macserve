package qualification

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/jerryfane/macserve/internal/health"
)

// The lowering-only lanes override is not configuration identity: editing it
// must not change the anchored bindings, so rollback to one lane needs no
// sitting. It must also live in the anchored config directory the bindings
// walk skips it in, not elsewhere.
func TestAnchorIgnoresLanesOverride(t *testing.T) {
	if filepath.Dir(health.LanesOverrideFile) != configDir {
		t.Fatalf("override %s is outside the config directory %s", health.LanesOverrideFile, configDir)
	}
	if !slices.Contains(mutableConfig, filepath.Base(health.LanesOverrideFile)) {
		t.Fatal("anchor hashes the lanes override")
	}
	for _, identity := range []string{"controller.json", "worker.json"} {
		if slices.Contains(mutableConfig, identity) {
			t.Fatalf("%s left configuration identity", identity)
		}
	}
}

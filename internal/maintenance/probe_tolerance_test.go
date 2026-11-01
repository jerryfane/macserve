package maintenance

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/controller"
)

// A probe that only ran out of time while a build loads the host is
// inconclusive. It must not replace still-valid health (which made the
// controller cancel every real build on the Studio), but it must never extend
// that health past its own expiry, and genuine findings must still publish
// invalid health at once.
func TestKeepLastValidOnlyForTimeoutsWithinLifetime(t *testing.T) {
	now := time.Date(2026, 11, 1, 21, 9, 0, 0, time.UTC)
	valid := controller.Health{BoundaryValidated: true, CheckedAt: now.Add(-12 * time.Second), ExpiresAt: now.Add(18 * time.Second)}
	// Exactly the error the Studio produced: Inspect's own 8 s deadline,
	// wrapped by the census, while the outer probe context was still live.
	inner := fmt.Errorf("mutable census /Users/macservejob: %w", context.DeadlineExceeded)
	for _, tc := range []struct {
		name string
		err  error
		last controller.Health
		at   time.Time
		want bool
	}{
		{"inner Inspect deadline within lifetime", inner, valid, now, true},
		{"timeout after expiry", inner, valid, valid.ExpiresAt, false},
		{"timeout without prior valid health", inner, controller.Health{}, now, false},
		{"prior health invalid", inner, controller.Health{ExpiresAt: now.Add(time.Minute)}, now, false},
		{"real finding", errors.New("GUI baseline process changed; worker-reset required"), valid, now, false},
		{"permission failure", errors.New(`mutable census /Library/macserve/var: "controller/Library/Mail": operation not permitted`), valid, now, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := keepLastValid(tc.err, tc.last, tc.at); got != tc.want {
				t.Fatalf("keepLastValid = %v, want %v", got, tc.want)
			}
		})
	}
}

// Measured on the Studio (real binary, ProcessType=Background, real macserve
// build): probe seconds per 10 s cycle, one inner-deadline failure at 8 s.
// With the 30 s health lifetime, isolated misses never let health lapse.
func TestStudioLoadedProbeSequenceNeverInvalidates(t *testing.T) {
	durations := []int{2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 4, 4, 4, 8, 4, 7, 7, 2, 2, 2, 2, 2, 6, 2}
	start := time.Date(2026, 11, 1, 16, 6, 0, 0, time.UTC)
	var last controller.Health
	for i, d := range durations {
		at := start.Add(time.Duration(i) * 10 * time.Second)
		done := at.Add(time.Duration(d) * time.Second)
		if d >= 8 {
			err := fmt.Errorf("mutable census /Users/macservejob: %w", context.DeadlineExceeded)
			if !keepLastValid(err, last, done) {
				t.Fatalf("cycle %d (%ds) would publish invalid health and cancel the build", i, d)
			}
			continue
		}
		last = controller.Health{BoundaryValidated: true, CheckedAt: at, ExpiresAt: at.Add(30 * time.Second)}
	}
}

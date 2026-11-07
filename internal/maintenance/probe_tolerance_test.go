package maintenance

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/health"
)

// A probe that only ran out of time while a build loads the host is
// inconclusive. It must not replace still-valid health (which made the
// controller cancel every real build on the Studio), but it must never extend
// that health past its own expiry, and genuine findings must still publish
// invalid health at once.
func TestKeepLastValidOnlyForTimeoutsWithinLifetime(t *testing.T) {
	now := time.Date(2026, 11, 1, 21, 9, 0, 0, time.UTC)
	valid := health.Health{BoundaryValidated: true, CheckedAt: now.Add(-12 * time.Second), ExpiresAt: now.Add(18 * time.Second)}
	// Exactly the error the Studio produced: Inspect's own 8 s deadline,
	// wrapped by the census, while the outer probe context was still live.
	inner := fmt.Errorf("mutable census /Users/macservejob: %w", context.DeadlineExceeded)
	for _, tc := range []struct {
		name string
		err  error
		last health.Health
		at   time.Time
		want bool
	}{
		{"inner Inspect deadline within lifetime", inner, valid, now, true},
		{"timeout after expiry", inner, valid, valid.ExpiresAt, false},
		{"timeout without prior valid health", inner, health.Health{}, now, false},
		{"prior health invalid", inner, health.Health{ExpiresAt: now.Add(time.Minute)}, now, false},
		{"real finding", errors.New("GUI baseline process changed; worker-reset required"), valid, now, false},
		{"permission failure", errors.New(`mutable census /Library/macserve/var: "controller/Library/Mail": operation not permitted`), valid, now, false},
		// Studio, 2026-11-02, as a real build finished: the accepted
		// CoreDevice devicefs changed during the census.
		{"CoreDevice mount changed within lifetime", fmt.Errorf("mutable census /Users/macservejob: %q: %w", coreDeviceMountPoint, errCoreDeviceMountChanged), valid, now, true},
		{"CoreDevice mount changed after expiry", fmt.Errorf("mutable census /Users/macservejob: %q: %w", coreDeviceMountPoint, errCoreDeviceMountChanged), valid, valid.ExpiresAt, false},
		{"same text, not the race", errors.New(`mutable census /Users/macservejob: "Library/Developer/CoreDevice/DeviceFS": mutable mount table changed during census`), valid, now, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := keepLastValid(tc.err, tc.last, tc.at); got != tc.want {
				t.Fatalf("keepLastValid = %v, want %v", got, tc.want)
			}
		})
	}
}

// gateAccepts mirrors the controller's freshness rule for published health
// (internal/controller/guards.go): checked no more than 45 s ago, not expired,
// and a lifetime of at most 45 s.
func gateAccepts(h health.Health, now time.Time) bool {
	return h.BoundaryValidated && now.Sub(h.CheckedAt) <= 45*time.Second && h.ExpiresAt.After(now) &&
		h.ExpiresAt.Sub(h.CheckedAt) <= 45*time.Second
}

// replayProbes runs the maintenance loop's publish/keep decisions over probe
// durations (seconds, 10 s cadence; >= 8 s is an inconclusive deadline miss)
// and reports the first second at which the controller would see no valid
// health, which cancels the running build.
func replayProbes(t *testing.T, durations []int, lifetime time.Duration) (lapse time.Duration, lapsed bool) {
	t.Helper()
	start := time.Date(2026, 11, 2, 14, 56, 0, 0, time.UTC)
	var published, last health.Health
	publishAt := map[time.Duration]health.Health{}
	for i, d := range durations {
		at := start.Add(time.Duration(i) * 10 * time.Second)
		done := at.Add(time.Duration(d) * time.Second)
		if d >= 8 {
			err := fmt.Errorf("mutable census /Users/macservejob: %w", context.DeadlineExceeded)
			if keepLastValid(err, last, done) {
				continue
			}
			publishAt[done.Sub(start)] = health.Health{}
			last = health.Health{}
			continue
		}
		h := health.Health{BoundaryValidated: true, CheckedAt: at, ExpiresAt: at.Add(lifetime)}
		publishAt[done.Sub(start)] = h
		last = h
	}
	end := time.Duration(len(durations)) * 10 * time.Second
	for s := time.Duration(0); s < end; s += time.Second {
		if h, ok := publishAt[s]; ok {
			published = h
		}
		if s >= 10*time.Second && !gateAccepts(published, start.Add(s)) {
			return s, true
		}
	}
	return 0, false
}

// Measured on the Studio under real builds: isolated 8 s misses (v0.1.22
// launchd diagnostic) and two consecutive misses (v0.1.24 maintenance log,
// "keeping last valid health until 14:59:13" twice, then the build was
// cancelled at 14:59:18 with no failed probe logged).
func TestStudioLoadedProbeSequencesKeepGateValid(t *testing.T) {
	for name, durations := range map[string][]int{
		"isolated misses":     {2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 4, 4, 4, 8, 4, 7, 7, 2, 2, 2, 2, 2, 6, 2},
		"two misses in a row": {2, 2, 8, 8, 2, 2, 2, 8, 2, 2},
	} {
		t.Run(name, func(t *testing.T) {
			if at, lapsed := replayProbes(t, durations, healthLifetime); lapsed {
				t.Fatalf("controller sees no valid health %v into the run; the build would be cancelled", at)
			}
		})
	}
	// The 30 s lifetime of v0.1.24 lapses on two misses in a row, as on the Studio.
	if _, lapsed := replayProbes(t, []int{2, 2, 8, 8, 2, 2}, 30*time.Second); !lapsed {
		t.Fatal("replay does not reproduce the Studio lapse with the old 30 s lifetime")
	}
	if healthLifetime > 45*time.Second {
		t.Fatalf("healthLifetime %v exceeds the controller's 45 s acceptance", healthLifetime)
	}
}

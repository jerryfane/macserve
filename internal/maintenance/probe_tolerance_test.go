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
	timeout := fmt.Errorf("mutable census /Users/macservejob: %w", context.DeadlineExceeded)
	for _, tc := range []struct {
		name     string
		err      error
		timedOut bool
		last     controller.Health
		at       time.Time
		want     bool
	}{
		{"timeout within lifetime", timeout, true, valid, now, true},
		{"timeout after expiry", timeout, true, valid, valid.ExpiresAt, false},
		{"timeout without prior valid health", timeout, true, controller.Health{}, now, false},
		{"prior health invalid", timeout, true, controller.Health{ExpiresAt: now.Add(time.Minute)}, now, false},
		{"finding while deadline also passed", errors.New("GUI baseline process changed; worker-reset required"), true, valid, now, false},
		{"deadline error but probe did not time out", timeout, false, valid, now, false},
		{"other failure", errors.New("persistence attestation changed during qualification"), false, valid, now, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := keepLastValid(tc.err, tc.timedOut, tc.last, tc.at); got != tc.want {
				t.Fatalf("keepLastValid = %v, want %v", got, tc.want)
			}
		})
	}
}

// The deadline must leave room to publish inside the 30 s health lifetime, and
// exceed the slowest observed loaded probe (8 s) with margin.
func TestProbeTimeoutFitsHealthLifetime(t *testing.T) {
	if probeTimeout <= 8*time.Second || probeTimeout >= 30*time.Second {
		t.Fatalf("probeTimeout %v outside (8s, 30s)", probeTimeout)
	}
}

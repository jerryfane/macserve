package controller

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func readyGuard(t *testing.T) (*Guard, *Health, *int64) {
	t.Helper()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	digest := strings.Repeat("a", 64)
	g, err := NewGuard(GuardOptions{Root: "/service/data", HealthFile: "/service/config/health.json", PolicySHA256: digest, JobUID: 502, OwnerUID: 501, Profiles: map[string]string{"unit": digest}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	h := &Health{Schema: 1, JobUID: 502, PolicySHA256: digest, InterfacesSHA256: digest, BoundaryReceiptSHA256: digest, BoundaryValidated: true, CheckedAt: now, ExpiresAt: now.Add(30 * time.Second), AccountedBytes: 10 << 30, QualifiedProfiles: map[string]string{"unit": digest}}
	free := int64(200 << 30)
	g.readHealth = func(string) (Health, error) { return *h, nil }
	g.freeBytes = func(string) (int64, error) { return free, nil }
	g.interfaces = func() (string, error) { return digest, nil }
	return g, h, &free
}
func TestReadinessRequiresCurrentQualifiedBoundary(t *testing.T) {
	for _, scenario := range []string{"stale", "future", "expiry", "unsigned qualification", "policy changed", "wrong worker", "interface changed", "profile changed", "unreadable"} {
		t.Run(scenario, func(t *testing.T) {
			g, h, _ := readyGuard(t)
			switch scenario {
			case "stale":
				h.CheckedAt = h.CheckedAt.Add(-time.Minute)
			case "future":
				h.CheckedAt = h.CheckedAt.Add(time.Minute)
			case "expiry":
				h.ExpiresAt = h.CheckedAt
			case "unsigned qualification":
				h.BoundaryValidated = false
			case "policy changed":
				h.PolicySHA256 = strings.Repeat("b", 64)
			case "wrong worker":
				h.JobUID = 503
			case "interface changed":
				h.InterfacesSHA256 = strings.Repeat("b", 64)
			case "profile changed":
				h.QualifiedProfiles["unit"] = strings.Repeat("b", 64)
			case "unreadable":
				g.readHealth = func(string) (Health, error) { return Health{}, errors.New("denied") }
			}
			state, err := g.Check(context.Background())
			if err != nil || state.Ready || !state.CancelActive {
				t.Fatalf("unsafe boundary admitted: %+v %v", state, err)
			}
		})
	}
}
func TestDiskReservationAndEmergencyHaveDifferentCancellationSemantics(t *testing.T) {
	g, h, free := readyGuard(t)
	for _, tc := range []struct {
		free, used    int64
		ready, cancel bool
	}{{150 << 30, 50 << 30, true, false}, {(150 << 30) - 1, 50 << 30, false, false}, {100 << 30, 50 << 30, false, false}, {(100 << 30) - 1, 50 << 30, false, true}, {200 << 30, 51 << 30, false, false}, {200 << 30, 81 << 30, false, true}} {
		*free = tc.free
		h.AccountedBytes = tc.used
		state, err := g.Check(context.Background())
		if err != nil || state.Ready != tc.ready || state.CancelActive != tc.cancel {
			t.Fatalf("free=%d used=%d: %+v %v", tc.free, tc.used, state, err)
		}
	}
}
func TestOwnerPauseDoesNotCancelDrainingWork(t *testing.T) {
	g, h, _ := readyGuard(t)
	g.options.PauseFile = "/service/control/pause"
	g.pause = func(string, uint32) (bool, error) { return true, nil }
	state, err := g.Check(context.Background())
	if err != nil || state.Ready || state.CancelActive {
		t.Fatalf("pause did not drain: %+v %v", state, err)
	}
	g.options.PauseFile = ""
	h.MemoryPressure = true
	state, err = g.Check(context.Background())
	if err != nil || state.Ready || state.CancelActive {
		t.Fatalf("memory pressure did not stop admission: %+v %v", state, err)
	}
}
func TestPrivateListenerPolicyRejectsPublicWildcardAndMappedAddresses(t *testing.T) {
	base := Config{Root: "/service/data", Socket: "/service/run/worker.sock", JobUID: 502, OwnerUID: 501, ProfilesFile: "/service/config/profiles.json", TLSCertificate: "/service/config/tls.crt", TLSKey: "/service/secrets/tls.key", HealthFile: "/service/config/health.json", PolicySHA256: strings.Repeat("a", 64)}
	for _, address := range []string{"0.0.0.0:9443", "[::]:9443", "127.0.0.1:9443", "localhost:9443", "8.8.8.8:9443", "[::ffff:100.64.0.1]:9443", "100.64.0.1:0", "192.168.1.1:9443"} {
		c := base
		c.Listen = address
		if err := c.validate(); err == nil {
			t.Fatalf("accepted listener %q", address)
		}
	}
	for _, address := range []string{"100.64.0.1:9443", "[fd7a:115c:a1e0::1]:9443"} {
		c := base
		c.Listen = address
		if err := c.validate(); err != nil {
			t.Fatalf("private listener %q: %v", address, err)
		}
	}
	c := base
	c.Listen = "8.8.8.8:9443"
	c.AllowedNetworks = []string{"0.0.0.0/0"}
	if err := c.validate(); err == nil {
		t.Fatal("public CIDR expanded listener policy")
	}
}

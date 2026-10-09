package controller

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
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
	base.Receipt = ReceiptConfig{KeyID: "test", PrivateKeyFile: "/service/secrets/receipt.key", ServiceID: "test", HostID: "test", Repositories: map[string]int64{"example-org/example-app": 123}}
	for _, address := range []string{"0.0.0.0:9443", "[::]:9443", "127.0.0.1:9443", "localhost:9443", "8.8.8.8:9443", "[::ffff:100.64.0.1]:9443", "100.64.0.1:0", "192.168.1.1:9443", "[fe80::1]:9443", "[fe80::1%en0]:9443", "169.254.1.1:9443", "[fd7a:115c:a1e0::1%en0]:9443"} {
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

type inventoryAddress string

func (a inventoryAddress) Network() string { return "ip" }
func (a inventoryAddress) String() string  { return string(a) }

func fixtureInventory(interfaces []net.Interface, addresses map[string][]string, includeAddresses bool) (string, []netip.Addr, error) {
	return interfaceInventory(interfaces, func(iface *net.Interface) ([]net.Addr, error) {
		var result []net.Addr
		for _, text := range addresses[iface.Name] {
			result = append(result, inventoryAddress(text))
		}
		return result, nil
	}, includeAddresses)
}

func TestInterfaceInventoryIgnoresOnlyCoveredLinkLocalChurn(t *testing.T) {
	interfaces := []net.Interface{{Name: "lo0", Flags: net.FlagUp | net.FlagLoopback}, {Name: "en0", Flags: net.FlagUp}}
	addresses := map[string][]string{
		"lo0": {"127.0.0.1/8", "::1/128"},
		"en0": {"192.0.2.10/24", "2001:db8::1/64", "fd00::1/64", "100.64.0.10/32"},
	}
	digest, hosts, err := fixtureInventory(interfaces, addresses, true)
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1"), netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("fd00::1"), netip.MustParseAddr("100.64.0.10")}
	if !slices.Equal(hosts, want) {
		t.Fatalf("lost relevant hosts: %v", hosts)
	}
	for _, linkLocal := range [][]string{
		{"fe80::1/64", "169.254.1.2/16"},
		{"febf:ffff::2/10", "169.254.255.255/32"},
		nil,
	} {
		churn := map[string][]string{
			"lo0": addresses["lo0"],
			"en0": append(slices.Clone(addresses["en0"]), linkLocal...),
			"ll0": linkLocal,
		}
		withExtra := append(slices.Clone(interfaces), net.Interface{Name: "ll0", Flags: net.FlagUp}, net.Interface{Name: "empty0"})
		got, gotHosts, err := fixtureInventory(withExtra, churn, true)
		if err != nil || got != digest || !slices.Equal(gotHosts, hosts) {
			t.Fatalf("link-local churn changed qualification: %s %v %v", got, gotHosts, err)
		}
		digestOnly, _, err := fixtureInventory(withExtra, churn, false)
		if err != nil || digestOnly != digest {
			t.Fatalf("digest-only observer diverged: %s %v", digestOnly, err)
		}
	}
	for name, replacement := range map[string]string{
		"ipv4": "192.0.2.11/24", "prefix": "192.0.2.10/25",
		"global": "2001:db8::2/64", "ula": "fd00::2/64", "tailnet": "100.64.0.11/32",
		"loopback": "127.0.0.2/8", "name": "", "flags": "", "new interface": "",
	} {
		t.Run(name, func(t *testing.T) {
			changedInterfaces := slices.Clone(interfaces)
			changed := map[string][]string{"lo0": slices.Clone(addresses["lo0"]), "en0": slices.Clone(addresses["en0"])}
			switch name {
			case "name":
				changedInterfaces[1].Name = "en1"
				changed["en1"] = changed["en0"]
			case "flags":
				changedInterfaces[1].Flags |= net.FlagMulticast
			case "new interface":
				changedInterfaces = append(changedInterfaces, net.Interface{Name: "bridge0", Flags: net.FlagUp})
				changed["bridge0"] = []string{"198.51.100.1/24"}
			case "loopback":
				changed["lo0"][0] = replacement
			default:
				index := map[string]int{"ipv4": 0, "prefix": 0, "global": 1, "ula": 2, "tailnet": 3}[name]
				changed["en0"][index] = replacement
			}
			got, _, err := fixtureInventory(changedInterfaces, changed, true)
			if err != nil {
				t.Fatal(err)
			}
			g, health, _ := readyGuard(t)
			health.InterfacesSHA256 = digest
			g.interfaces = func() (string, error) { return got, nil }
			state, err := g.Check(context.Background())
			if err != nil || state.Ready || !state.CancelActive {
				t.Fatalf("relevant inventory drift admitted: %+v %v", state, err)
			}
		})
	}
}

func TestInterfaceInventoryFailsClosed(t *testing.T) {
	interfaces := []net.Interface{{Name: "en0", Flags: net.FlagUp}}
	for _, includeHosts := range []bool{false, true} {
		for _, text := range []string{"not-an-address", "fe80::1/129", "169.254.1.1/no-prefix", "fe80::1%en0/64"} {
			digest, hosts, err := fixtureInventory(interfaces, map[string][]string{"en0": {text}}, includeHosts)
			if err == nil || digest != "" || hosts != nil {
				t.Fatalf("accepted malformed interface address %q: %s %v %v", text, digest, hosts, err)
			}
		}
		digest, hosts, err := interfaceInventory(interfaces, func(*net.Interface) ([]net.Addr, error) {
			return nil, errors.New("address query failed")
		}, includeHosts)
		if err == nil || digest != "" || hosts != nil {
			t.Fatalf("accepted unreadable interface: %s %v %v", digest, hosts, err)
		}
	}
}

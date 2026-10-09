package maintenance

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func guestTranslationPolicy() Config {
	return Config{
		PFAnchor:                    DefaultPFAnchor,
		ToleratedTranslationAnchors: []string{"com.apple/guest-b", "com.apple/guest-a"},
		ApprovedGuestSubnets:        []string{"fd42:1234::/64", "172.20.40.0/24"},
	}
}

func TestPFConfigExactGuestPolicy(t *testing.T) {
	var defaults Config
	if err := validatePFConfig(&defaults); err != nil || defaults.PFAnchor != DefaultPFAnchor {
		t.Fatalf("default anchor: %q, %v", defaults.PFAnchor, err)
	}
	c := guestTranslationPolicy()
	c.PFAnchor = "com.apple/custom-service"
	if err := validatePFConfig(&c); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.ToleratedTranslationAnchors, []string{"com.apple/guest-a", "com.apple/guest-b"}) || !slices.Equal(c.ApprovedGuestSubnets, []string{"172.20.40.0/24", "fd42:1234::/64"}) {
		t.Fatal("equivalent policy order does not canonicalize for hashing")
	}
	prefixes, err := approvedGuestPrefixes(c)
	if err != nil || !slices.Equal(prefixes, []netip.Prefix{netip.MustParsePrefix("172.20.40.0/24"), netip.MustParsePrefix("fd42:1234::/64")}) {
		t.Fatalf("approved policy parsed incorrectly: %v, %v", prefixes, err)
	}

	cases := map[string]func(*Config){
		"wildcard service":     func(c *Config) { c.PFAnchor = "com.apple/*" },
		"relative traversal":   func(c *Config) { c.PFAnchor = "com.apple/../service" },
		"empty component":      func(c *Config) { c.PFAnchor = "com.apple//service" },
		"absolute path":        func(c *Config) { c.PFAnchor = "/com.apple/service" },
		"service too deep":     func(c *Config) { c.PFAnchor = strings.Repeat("a/", 8) + "b" },
		"wildcard tolerated":   func(c *Config) { c.ToleratedTranslationAnchors[0] = "com.apple/*" },
		"empty tolerated":      func(c *Config) { c.ToleratedTranslationAnchors[0] = "" },
		"own anchor tolerated": func(c *Config) { c.ToleratedTranslationAnchors[0] = c.PFAnchor },
		"duplicate tolerated":  func(c *Config) { c.ToleratedTranslationAnchors[0] = c.ToleratedTranslationAnchors[1] },
		"unpaired anchors":     func(c *Config) { c.ApprovedGuestSubnets = nil },
		"unpaired subnets":     func(c *Config) { c.ToleratedTranslationAnchors = nil },
		"duplicate subnet":     func(c *Config) { c.ApprovedGuestSubnets[0] = c.ApprovedGuestSubnets[1] },
		"noncanonical network": func(c *Config) { c.ApprovedGuestSubnets[0] = "172.20.40.1/24" },
		"noncanonical ipv6":    func(c *Config) { c.ApprovedGuestSubnets[0] = "FD42:1234::/64" },
		"noncanonical mask":    func(c *Config) { c.ApprovedGuestSubnets[0] = "172.20.40.0/024" },
		"bare guest host":      func(c *Config) { c.ApprovedGuestSubnets[0] = "172.20.40.4" },
		"guest wildcard":       func(c *Config) { c.ApprovedGuestSubnets[0] = "0.0.0.0/0" },
		"guest mapped alias":   func(c *Config) { c.ApprovedGuestSubnets[0] = "::ffff:172.20.40.0/120" },
		"too many anchors": func(c *Config) {
			c.ToleratedTranslationAnchors = nil
			for i := range 65 {
				c.ToleratedTranslationAnchors = append(c.ToleratedTranslationAnchors, fmt.Sprintf("com.apple/guest%d", i))
			}
		},
		"too many prefixes": func(c *Config) {
			c.ApprovedGuestSubnets = nil
			for i := range 65 {
				c.ApprovedGuestSubnets = append(c.ApprovedGuestSubnets, fmt.Sprintf("10.42.%d.0/24", i))
			}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			c := guestTranslationPolicy()
			change(&c)
			if err := validatePFConfig(&c); err == nil {
				t.Fatal("unsafe or ambiguous guest policy accepted")
			}
		})
	}
}

func TestGuestTranslationMappings(t *testing.T) {
	approved := []netip.Prefix{netip.MustParsePrefix("172.20.40.0/24"), netip.MustParsePrefix("fd42:1234::/64")}
	hosts := []netip.Addr{netip.MustParseAddr("192.0.2.20"), netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1"), netip.MustParseAddr("fd42:5678::1")}
	accepted := []string{
		"nat on en0 inet from 172.20.40.0/24 to any -> (en0)",
		"nat on en0 inet from 172.20.40.0/24 to any -> (en0:0)",
		"nat on en0 inet from 172.20.40.0/25 to any -> (en0) port 1024:65535 round-robin",
		"nat inet from 172.20.40.128/25 to any -> 192.0.2.20 static-port",
		"nat inet proto udp from 172.20.40.4 port = 500 to any -> (en0) port 500",
		"nat from 172.20.40.4/32 to 198.51.100.0/24 -> (en0) round-robin static-port",
		"nat inet6 from fd42:1234::/64 to any -> (en0)",
		"nat inet6 proto ipv6-icmp from fd42:1234::4 to any -> 2001:db8::20",
		"rdr on bridge0 inet proto tcp from 172.20.40.4 to 198.51.100.20 port = 80 -> 172.20.40.8 port 8080",
		"rdr inet proto udp from 172.20.40.0/24 port 1024:65535 to any port 8000:8099 -> 172.20.40.8 port 9000:*",
		"rdr inet6 proto tcp from fd42:1234::4/128 to any port = 443 -> fd42:1234::8 port 8443 round-robin",
		"rdr from 172.20.40.4 to any -> 172.20.40.8/32",
		"rdr inet proto tcp from 172.20.40.4 port >= 1024 to any port 80 : 90 -> 172.20.40.8 port 8080:8090",
	}
	for _, rule := range accepted {
		t.Run(rule, func(t *testing.T) {
			if err := validateGuestTranslations(rule+"\n", approved, hosts); err != nil {
				t.Fatal(err)
			}
		})
	}
	if err := validateGuestTranslations(strings.Join(accepted, "\n")+"\n", approved, hosts); err != nil {
		t.Fatal(err)
	}
	if err := validateGuestTranslations("", approved, hosts); err != nil {
		t.Fatalf("safe policy preflight: %v", err)
	}

	unsafe := []string{
		"nat on en0 inet from any to any -> (en0)",
		"nat on en0 inet from ! 172.20.40.0/24 to any -> (en0)",
		"nat inet from !172.20.40.0/24 to any -> (en0)",
		"nat inet from { 172.20.40.0/24, 192.0.2.20 } to any -> (en0)",
		"nat inet from 172.20.40.0/23 to any -> (en0)",
		"nat inet from 172.20.41.0/24 to any -> (en0)",
		"nat inet from 172.20.40.1/24 to any -> (en0)",
		"nat inet from (bridge0) to any -> (en0)",
		"nat inet from <guests> to any -> (en0)",
		"nat inet from $guests to any -> (en0)",
		"nat inet from self to any -> (en0)",
		"nat inet from 172.20.40.4 to (en0) -> (en0)",
		"nat inet from 172.20.40.4 to <targets> -> (en0)",
		"nat inet from 172.20.40.4 to any -> (en0:network)",
		"nat inet from 172.20.40.4 to any -> (en0:0:network)",
		"rdr inet from 172.20.40.4 to any -> (en0:0)",
		"nat pass inet from 172.20.40.4 to any -> (en0)",
		"rdr pass inet from 172.20.40.4 to any -> 172.20.40.8",
		"nat quick inet from 172.20.40.4 to any -> (en0)",
		"no nat inet from 172.20.40.4 to any",
		"binat inet from 172.20.40.4 to any -> 172.20.40.8",
		"nat-anchor \"com.apple/guest\" all",
		"rdr-anchor \"com.apple/guest\" all",
		"rdr inet from 172.20.40.4 to any -> (en0)",
		"rdr inet from 172.20.40.4 to any -> 127.0.0.2",
		"rdr inet from 172.20.40.4 to any -> 192.0.2.20",
		"rdr inet from 172.20.40.4 to any -> 0.0.0.0",
		"rdr inet from 172.20.40.4 to any -> 169.254.1.1",
		"rdr inet from 172.20.40.4 to any -> 224.0.0.1",
		"rdr inet from 172.20.40.4 to any -> 255.255.255.255",
		"rdr inet from 172.20.40.4 to any -> 172.20.40.0/24",
		"rdr inet6 from fd42:1234::4 to any -> ::1",
		"rdr inet6 from fd42:1234::4 to any -> fd42:5678::1",
		"rdr inet6 from fd42:1234::4 to any -> ::ffff:192.0.2.20",
		"rdr inet6 from fd42:1234::4 to any -> ::192.0.2.20",
		"rdr inet6 from fd42:1234::4 to any -> 64:ff9b::c000:214",
		"rdr inet6 from fd42:1234::4 to any -> fe80::4%en0",
		"rdr inet6 from fd42:1234::4 to any -> ff02::1",
		"rdr inet6 from fd42:1234::4 to any -> ::",
		"nat inet6 from 172.20.40.4 to any -> (en0)",
		"nat inet from fd42:1234::4 to any -> (en0)",
		"nat inet6 from ::ffff:172.20.40.4 to any -> (en0)",
		"nat inet6 from FD42:1234::4 to any -> (en0)",
		"nat inet6 from fd42:1234::4%en0 to any -> (en0)",
		"nat inet from 172.20.040.4 to any -> (en0)",
		"nat inet from 172.20.40.4 to fd42:1234::4 -> (en0)",
		"nat inet from 172.20.40.4 to any -> fd42:1234::4",
		"nat inet proto ipv6-icmp from 172.20.40.4 to any -> (en0)",
		"nat inet6 proto icmp from fd42:1234::4 to any -> (en0)",
		"nat inet proto unknown from 172.20.40.4 to any -> (en0)",
		"nat inet from 172.20.40.4 port = 80 to any -> (en0)",
		"nat inet from 172.20.40.4 to any -> (en0) port 65536",
		"nat inet from 172.20.40.4 to any -> (en0) port 65535:1024",
		"nat inet from 172.20.40.4 to any -> (en0) port 80:*",
		"nat inet from 172.20.40.4 to any -> (en0) port http",
		"nat inet from 172.20.40.4 to any -> (en0) port 1024:65535 static-port",
		"rdr inet from 172.20.40.4 to any -> 172.20.40.8 static-port",
		"nat inet from 172.20.40.4 to any -> (en0) round-robin round-robin",
		"nat inet from 172.20.40.4 to any -> (en0) tag bypass",
		"nat inet from 172.20.40.4 to any -> (en0) pass",
		"nat inet from 172.20.40.4 to any -> (en0) # ignored",
		"nat inet from 172.20.40.4 to any -> (en0); pass all",
		"nat inet from 172.20.40.4 to any ->",
		"nat inet from 172.20.40.4 to any",
		"nat inet from 172.20.40.4",
		"nat inet",
		"nat",
		"nat\r inet from 172.20.40.4 to any -> (en0)",
		"nat\u00a0inet from 172.20.40.4 to any -> (en0)",
	}
	for _, rule := range unsafe {
		t.Run(rule, func(t *testing.T) {
			if err := validateGuestTranslations(rule+"\n", approved, hosts); err == nil {
				t.Fatal("unsafe translation accepted")
			}
		})
	}
	for name, text := range map[string]string{
		"unterminated rule":       accepted[0],
		"unterminated later rule": accepted[0] + "\n" + accepted[1],
		"unsafe later rule":       accepted[0] + "\n" + unsafe[0] + "\n",
		"oversized line":          strings.Repeat(" ", 4097) + "\n",
		"excessive rules":         strings.Repeat(accepted[0]+"\n", 1025),
		"excessive output":        strings.Repeat("\n", (1<<20)+1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateGuestTranslations(text, approved, hosts); err == nil {
				t.Fatal("incomplete or unbounded output accepted")
			}
		})
	}
}

func TestGuestTranslationLiveHostOverlapAndBoundaries(t *testing.T) {
	for _, host := range []string{"172.20.40.0", "172.20.40.1", "172.20.40.255", "::ffff:172.20.40.1"} {
		t.Run(host, func(t *testing.T) {
			approved := []netip.Prefix{netip.MustParsePrefix("172.20.40.0/24")}
			hosts := []netip.Addr{netip.MustParseAddr(host)}
			for _, text := range []string{"", "nat inet from 172.20.40.128/25 to any -> (en0)\n"} {
				if err := validateGuestTranslations(text, approved, hosts); err == nil {
					t.Fatal("bridge/host overlap tolerated, including a narrower current rule or empty anchor")
				}
			}
		})
	}
	for _, host := range []string{"fd42:1234::", "fd42:1234::1", "fd42:1234::ffff:ffff:ffff:ffff", "fd42:1234::1%en0"} {
		if err := validateGuestTranslations("", []netip.Prefix{netip.MustParsePrefix("fd42:1234::/64")}, []netip.Addr{netip.MustParseAddr(host)}); err == nil {
			t.Fatalf("IPv6 host overlap accepted: %s", host)
		}
	}
	for _, subnet := range []string{"0.0.0.0/0", "0.0.0.0/8", "126.0.0.0/7", "127.0.0.0/8", "169.254.0.0/16", "192.0.0.0/24", "192.88.99.0/24", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4", "::/0", "::/96", "::ffff:0.0.0.0/96", "64:ff9b::/96", "2001::/32", "2002::/16", "fe80::/10", "ff00::/8"} {
		t.Run(subnet, func(t *testing.T) {
			c := guestTranslationPolicy()
			c.ApprovedGuestSubnets = []string{subnet}
			if err := validatePFConfig(&c); err == nil {
				t.Fatal("special or non-unicast guest space accepted")
			}
		})
	}
	approved := []netip.Prefix{netip.MustParsePrefix("172.20.40.4/32"), netip.MustParsePrefix("fd42:1234::4/128")}
	hosts := []netip.Addr{netip.MustParseAddr("172.20.40.3"), netip.MustParseAddr("172.20.40.5"), netip.MustParseAddr("fd42:1234::3"), netip.MustParseAddr("fd42:1234::5")}
	if err := validateGuestTranslations("nat from 172.20.40.4 to any -> (en0)\nnat from fd42:1234::4 to any -> (en0)\n", approved, hosts); err != nil {
		t.Fatalf("adjacent host addresses incorrectly overlap guest-only host prefixes: %v", err)
	}
	for _, inventory := range [][]netip.Addr{nil, {{}}, make([]netip.Addr, 4097)} {
		if err := validateGuestTranslations("", approved, inventory); err == nil {
			t.Fatal("missing or invalid inventory accepted")
		}
	}
	if err := validateGuestTranslations("rdr from 172.20.40.4 to any -> 192.0.2.20\n", approved, []netip.Addr{netip.MustParseAddr("::ffff:192.0.2.20")}); err == nil {
		t.Fatal("mapped host alias bypassed RDR target exclusion")
	}
}

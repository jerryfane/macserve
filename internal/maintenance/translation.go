package maintenance

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/jerryfane/macserve/internal/pfctl"
)

const maxGuestPolicyEntries = 64

func validatePFConfig(c *Config) error {
	if c.PFAnchor == "" {
		c.PFAnchor = DefaultPFAnchor
	}
	if err := pfctl.ValidateOwnedAnchor(c.PFAnchor, c.CoexistingAnchors, c.ToleratedTranslationAnchors); err != nil {
		return err
	}
	if len(c.ToleratedTranslationAnchors) > maxGuestPolicyEntries || len(c.ApprovedGuestSubnets) > maxGuestPolicyEntries {
		return errors.New("guest translation policy exceeds entry limit")
	}
	if (len(c.ToleratedTranslationAnchors) == 0) != (len(c.ApprovedGuestSubnets) == 0) {
		return errors.New("tolerated translation anchors and approved guest subnets must be configured together")
	}
	if len(c.ToleratedTranslationAnchors) == 0 {
		c.ToleratedTranslationAnchors, c.ApprovedGuestSubnets = nil, nil
		return nil
	}
	for i, path := range c.ToleratedTranslationAnchors {
		if !pfctl.AnchorPath(path) || path == c.PFAnchor {
			return errors.New("tolerated translation anchor must be an exact path distinct from the service anchor")
		}
		for _, previous := range c.ToleratedTranslationAnchors[:i] {
			if previous == path {
				return errors.New("duplicate tolerated translation anchor")
			}
		}
	}
	if _, err := approvedGuestPrefixes(*c); err != nil {
		return err
	}
	sort.Strings(c.ToleratedTranslationAnchors)
	sort.Strings(c.ApprovedGuestSubnets)
	return nil
}

func approvedGuestPrefixes(c Config) ([]netip.Prefix, error) {
	if len(c.ApprovedGuestSubnets) > maxGuestPolicyEntries {
		return nil, errors.New("approved guest subnets exceed entry limit")
	}
	prefixes := make([]netip.Prefix, len(c.ApprovedGuestSubnets))
	for i, text := range c.ApprovedGuestSubnets {
		p, err := netip.ParsePrefix(text)
		if err != nil || p.String() != text || p != p.Masked() || !guestUnicastPrefix(p) {
			return nil, errors.New("approved guest subnet must be a canonical unicast CIDR")
		}
		for _, previous := range prefixes[:i] {
			if previous == p {
				return nil, errors.New("duplicate approved guest subnet")
			}
		}
		prefixes[i] = p
	}
	return prefixes, nil
}

// Exclude non-unicast, scoped and address-translation aliases. IPv6 is limited
// to ordinary global unicast and ULA; IPv4-compatible/mapped, NAT64, 6to4 and
// protocol-assignment ranges cannot disguise a host address as a guest address.
// Documentation ranges remain usable for isolated deployments and fixtures.
var guestExcludedPrefixes = [...]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("224.0.0.0/3"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2002::/16"),
}

var guestIPv6Global = netip.MustParsePrefix("2000::/3")
var guestIPv6Private = netip.MustParsePrefix("fc00::/7")

func guestUnicastPrefix(p netip.Prefix) bool {
	if !p.IsValid() || p.Addr().Is4In6() || p != p.Masked() {
		return false
	}
	if p.Addr().Is6() && !prefixWithin(p, guestIPv6Global) && !prefixWithin(p, guestIPv6Private) {
		return false
	}
	for _, excluded := range guestExcludedPrefixes {
		if p.Overlaps(excluded) {
			return false
		}
	}
	return true
}

func prefixWithin(p, outer netip.Prefix) bool {
	return p.IsValid() && outer.IsValid() && p.Addr().BitLen() == outer.Addr().BitLen() && p.Bits() >= outer.Bits() && outer.Contains(p.Addr())
}

func translationLiteral(text string) (netip.Prefix, bool) {
	if strings.Contains(text, "/") {
		p, err := netip.ParsePrefix(text)
		return p, err == nil && p == p.Masked() && p.String() == text && !p.Addr().Is4In6()
	}
	a, err := netip.ParseAddr(text)
	if err != nil || a.Zone() != "" || a.Is4In6() || a.String() != text {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(a, a.BitLen()), true
}

func prefixContainsHost(p netip.Prefix, hosts []netip.Addr) bool {
	for _, host := range hosts {
		if p.Contains(host.WithZone("").Unmap()) {
			return true
		}
	}
	return false
}

// validateGuestTranslations recognizes a deliberately small subset of macOS
// pf.conf(5)'s nat-rule/rdr-rule grammar, not arbitrary pf.conf input. The
// mandatory final newline detects incomplete pfctl output. Interface scope is
// never evidence of guest isolation: every source is bounded by guest-only
// prefixes and checked against the complete live host-address inventory.
func validateGuestTranslations(text string, approved []netip.Prefix, hosts []netip.Addr) error {
	if len(text) > 1<<20 || len(approved) == 0 || len(approved) > maxGuestPolicyEntries || len(hosts) == 0 || len(hosts) > 4096 {
		return errors.New("guest translation input or address inventory outside bounds")
	}
	for _, host := range hosts {
		if !host.IsValid() {
			return errors.New("invalid host address in guest translation inventory")
		}
	}
	for _, p := range approved {
		if !guestUnicastPrefix(p) || prefixContainsHost(p, hosts) {
			return errors.New("approved guest subnet is unsafe or overlaps a current host address")
		}
	}
	for lineNumber := 1; text != ""; lineNumber++ {
		line, rest, complete := strings.Cut(text, "\n")
		if !complete || len(line) > 4096 || lineNumber > 1024 {
			return errors.New("incomplete or excessive guest translation output")
		}
		text = rest
		var tokens translationTokens
		if !tokens.scan(line) {
			return fmt.Errorf("unsupported guest translation syntax on line %d", lineNumber)
		}
		if tokens.n == 0 {
			continue
		}
		if !tokens.rule(approved, hosts) {
			return fmt.Errorf("unsafe or unsupported guest translation on line %d", lineNumber)
		}
	}
	return nil
}

// Fixed storage bounds both tokenization work and allocations per rule.
type translationTokens struct {
	words [40]string
	n     int
	i     int
}

func (t *translationTokens) scan(line string) bool {
	for _, c := range line {
		if c != '\t' && (c < ' ' || c > '~') {
			return false
		}
	}
	for line != "" {
		line = strings.TrimLeft(line, " \t")
		if line == "" {
			break
		}
		if t.n == len(t.words) {
			return false
		}
		end := strings.IndexAny(line, " \t")
		if end < 0 {
			end = len(line)
		}
		t.words[t.n] = line[:end]
		t.n++
		line = line[end:]
	}
	return true
}

func (t *translationTokens) take() string {
	if t.i == t.n {
		return ""
	}
	word := t.words[t.i]
	t.i++
	return word
}

func (t *translationTokens) accept(word string) bool {
	if t.i < t.n && t.words[t.i] == word {
		t.i++
		return true
	}
	return false
}

func translationInterface(name string) bool {
	if len(name) == 0 || len(name) >= 16 || name[0] < 'a' || name[0] > 'z' {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

func (t *translationTokens) rule(approved []netip.Prefix, hosts []netip.Addr) bool {
	kind := t.take()
	if kind != "nat" && kind != "rdr" {
		return false
	}
	if t.accept("on") && !translationInterface(t.take()) {
		return false
	}
	family := 0
	if t.accept("inet") {
		family = 32
	} else if t.accept("inet6") {
		family = 128
	}
	proto := ""
	if t.accept("proto") {
		proto = t.take()
		if proto != "tcp" && proto != "udp" && proto != "icmp" && proto != "ipv6-icmp" {
			return false
		}
	}
	if !t.accept("from") {
		return false
	}
	source, ok := translationLiteral(t.take())
	if !ok || !guestUnicastPrefix(source) || prefixContainsHost(source, hosts) {
		return false
	}
	bits := source.Addr().BitLen()
	if family != 0 && family != bits || proto == "icmp" && bits != 32 || proto == "ipv6-icmp" && bits != 128 {
		return false
	}
	allowed := false
	for _, p := range approved {
		if prefixWithin(source, p) {
			allowed = true
			break
		}
	}
	if !allowed || !t.matchPort(proto) || !t.accept("to") {
		return false
	}
	if !t.accept("any") {
		destination, ok := translationLiteral(t.take())
		if !ok || destination.Addr().BitLen() != bits {
			return false
		}
	}
	if !t.matchPort(proto) || !t.accept("->") {
		return false
	}
	target := t.take()
	if strings.HasPrefix(target, "(") && strings.HasSuffix(target, ")") {
		iface, modifier, modified := strings.Cut(target[1:len(target)-1], ":")
		if kind != "nat" || !translationInterface(iface) || modified && modifier != "0" {
			return false
		}
	} else {
		p, ok := translationLiteral(target)
		if !ok || p.Bits() != bits || p.Addr().BitLen() != bits || !guestUnicastPrefix(p) || kind == "rdr" && prefixContainsHost(p, hosts) {
			return false
		}
	}
	translatedPort := t.accept("port")
	if translatedPort && (!translationPortRange(t.take(), kind == "rdr") || kind == "rdr" && proto != "tcp" && proto != "udp") {
		return false
	}
	t.accept("round-robin")
	if t.accept("static-port") && (kind != "nat" || translatedPort) {
		return false
	}
	return t.i == t.n
}

func translationPort(text string) (int, bool) {
	if len(text) == 0 || len(text) > 5 || len(text) > 1 && text[0] == '0' {
		return 0, false
	}
	n := 0
	for _, c := range text {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, n <= 65535
}

func translationPortRange(text string, allowStar bool) bool {
	low, high, ranged := strings.Cut(text, ":")
	a, ok := translationPort(low)
	if !ok {
		return false
	}
	if !ranged {
		return true
	}
	if high == "*" {
		return allowStar
	}
	b, ok := translationPort(high)
	return ok && b >= a
}

func (t *translationTokens) matchPort(proto string) bool {
	if !t.accept("port") {
		return true
	}
	if proto != "tcp" && proto != "udp" {
		return false
	}
	word := t.take()
	switch word {
	case "=", "!=", "<", "<=", ">", ">=":
		_, ok := translationPort(t.take())
		return ok
	default:
		if !translationPortRange(word, false) {
			return false
		}
		if t.accept(":") || t.accept("<>") || t.accept("><") {
			a, ok := translationPort(word)
			b, valid := translationPort(t.take())
			return ok && valid && b >= a
		}
		return true
	}
}

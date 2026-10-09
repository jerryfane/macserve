package pfctl

import (
	"errors"
	"net/netip"
	"strings"
)

var mandatoryDestinations = [...]netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fe80::/10"),
}

// Each destination requires both TCP and UDP coverage before any pass.
type mandatoryDeny uint8

// add receives a rule whose exact outbound job scope has already been checked.
func (d *mandatoryDeny) add(tokens []string, macros map[string]string) error {
	if tokens[0] == "pass" {
		return d.complete()
	}
	*d |= mandatoryBlock(tokens, macros)
	return nil
}

func (d mandatoryDeny) complete() error {
	if d != 255 {
		return errors.New("PF policy must quick-deny job TCP and UDP to loopback and link-local ranges before any pass")
	}
	return nil
}

// ValidateMandatoryDeny proves the fixed job boundary in normalized, direct
// pfctl -sr output. It is also used after loading a policy. This is a coverage
// proof, not a replacement for the caller's filter syntax/order validation.
// Lists in source and individual family/protocol rules in native output use
// the same token parser and coverage accumulator.
func ValidateMandatoryDeny(text string, uid uint32) error {
	if len(text) == 0 || len(text) > maxPolicyBytes || !strings.HasSuffix(text, "\n") {
		return errors.New("mandatory PF boundary output is empty, excessive, or incomplete")
	}
	var deny mandatoryDeny
	for n, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		if n >= 4096 || len(line) > 8192 {
			return errors.New("mandatory PF boundary rule limit exceeded")
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		tokens, ok := filterTokens(line)
		if !ok || !jobScope(tokens, nil, uid) {
			return errors.New("mandatory PF boundary requires exact outbound job scope")
		}
		if err := deny.add(tokens, nil); err != nil {
			return err
		}
	}
	return deny.complete()
}

// Only unconditional quick blocks establish coverage. Unknown predicates,
// including interface/source/port restrictions, contribute no coverage.
func mandatoryBlock(tokens []string, macros map[string]string) mandatoryDeny {
	i := 1
	if i < len(tokens) && (tokens[i] == "drop" || tokens[i] == "return" || tokens[i] == "return-rst" || tokens[i] == "return-icmp" || tokens[i] == "return-icmp6") {
		i++
	}
	seen := make(map[string]bool)
	protocols, family := uint8(3), 0
	var destinations []string
	next := func() string {
		if i == len(tokens) {
			return ""
		}
		value := tokens[i]
		i++
		return value
	}
	for i < len(tokens) {
		key := next()
		if seen[key] {
			return 0
		}
		seen[key] = true
		switch key {
		case "out", "log", "quick":
		case "inet", "inet6":
			if family != 0 {
				return 0
			}
			family = 4
			if key == "inet6" {
				family = 6
			}
		case "proto":
			protocols = 0
			for _, protocol := range boundaryValues(tokens, &i, macros) {
				switch protocol {
				case "tcp":
					protocols |= 1
				case "udp":
					protocols |= 2
				default:
					return 0
				}
			}
		case "all":
			if seen["from"] {
				return 0
			}
			destinations = []string{"any"}
		case "from":
			if seen["all"] || next() != "any" || next() != "to" {
				return 0
			}
			destinations = boundaryValues(tokens, &i, macros)
		case "user":
			if next() == "=" {
				next()
			}
		case "label":
			value := next()
			if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
				return 0
			}
		default:
			return 0
		}
	}
	if !seen["quick"] {
		return 0
	}
	var covered mandatoryDeny
	for _, destination := range destinations {
		var prefix netip.Prefix
		if destination != "any" {
			var err error
			prefix, err = netip.ParsePrefix(destination)
			if err != nil {
				address, err := netip.ParseAddr(destination)
				if err != nil || address.Zone() != "" {
					return 0
				}
				prefix = netip.PrefixFrom(address, address.BitLen())
			}
		}
		for n, required := range mandatoryDestinations {
			if family == 4 && !required.Addr().Is4() || family == 6 && required.Addr().Is4() {
				continue
			}
			if destination == "any" || prefix.Bits() <= required.Bits() && prefix.Contains(required.Addr()) {
				covered |= mandatoryDeny(protocols << (2 * n))
			}
		}
	}
	return covered
}

func boundaryValues(tokens []string, i *int, macros map[string]string) []string {
	if *i >= len(tokens) {
		return nil
	}
	value := tokens[*i]
	*i++
	if strings.HasPrefix(value, "$") {
		expanded, ok := filterTokens(macros[value[1:]])
		if !ok || len(expanded) == 0 {
			return nil
		}
		j := 0
		return boundaryValues(expanded, &j, nil)
	}
	if value != "{" {
		return []string{value}
	}
	start := *i
	for *i < len(tokens) && tokens[*i] != "}" {
		*i++
	}
	if *i == len(tokens) {
		return nil
	}
	values := make([]string, 0, *i-start)
	for _, token := range tokens[start:*i] {
		if token != "," {
			values = append(values, token)
		}
	}
	*i++
	return values
}

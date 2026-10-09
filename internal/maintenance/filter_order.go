package maintenance

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/jerryfane/macserve/internal/pfctl"
)

// The four bits cover outbound job-owned IPv4/IPv6 TCP/UDP socket traffic.
// A partial predicate may match its entire domain for bypass detection, but
// cannot prove an override. Interface restrictions never prove disjointness.
type filterEffect struct {
	domain uint8
	all    bool
	pass   bool
	quick  bool
}

type orderedFilterRule struct {
	targets []string
	effect  filterEffect
}

// Apple's pf_step_into_anchor/pf_step_out_of_anchor use RB_MIN then RB_NEXT
// over immediate children; pf_anchor_compare compares full paths by strbufcmp.
// Sorted ASCII paths therefore reproduce kernel order, not enumeration order.
// pf_test_rule retains the last matching rule and a quick match breaks the
// entire evaluation, including the anchor stack:
// https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/pf.c#L3119-L3200
// https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/pf.c#L5355-L5375
// https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/pf_ruleset.c#L148-L154
func proveFilterOrder(selected string, uid uint32, snapshot []pfTranslation) error {
	paths := make([]string, len(snapshot))
	for i, rules := range snapshot {
		paths[i] = rules.Path
	}
	slices.Sort(paths)
	graph := make(map[string][]orderedFilterRule, len(snapshot))
	remaining := 65536
	for _, rules := range snapshot {
		if rules.Path == selected {
			if err := pfctl.ValidateMandatoryDeny(rules.Rules, uid); err != nil {
				return fmt.Errorf("PF mandatory job boundary: %w", err)
			}
		}
		graph[rules.Path] = nil
		text := rules.Rules
		for text != "" {
			line, rest, complete := strings.Cut(text, "\n")
			if !complete {
				return errors.New("truncated PF direct filter rules")
			}
			text = rest
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			remaining--
			if remaining < 0 || !directFilterRuleLine(line) {
				return errors.New("unsupported or excessive PF filter rule output")
			}
			kind, _, _ := strings.Cut(line, " ")
			switch kind {
			case "anchor", "scrub-anchor", "dummynet-anchor", "nat-anchor", "rdr-anchor", "binat-anchor":
				target, wildcard, err := filterAnchorTarget(rules.Path, line)
				if err != nil {
					return err
				}
				if kind != "anchor" {
					continue // Separate kernel rulesets, not filter edges.
				}
				if !slices.Contains(paths, target) {
					return errors.New("PF filter anchor target missing from topology")
				}
				targets := []string{target}
				if wildcard {
					targets = nil
					prefix := target
					if prefix != "" {
						prefix += "/"
					}
					for _, child := range paths {
						if child != target && strings.HasPrefix(child, prefix) && !strings.Contains(strings.TrimPrefix(child, prefix), "/") {
							targets = append(targets, child)
						}
					}
				}
				graph[rules.Path] = append(graph[rules.Path], orderedFilterRule{targets: targets})
			case "pass", "block":
				effect, err := parseFilterEffect(line, uid, rules.Path == selected)
				if err != nil {
					return fmt.Errorf("PF filter anchor %q: %w", rules.Path, err)
				}
				graph[rules.Path] = append(graph[rules.Path], orderedFilterRule{effect: effect})
			default:
				return errors.New("unsupported PF filter rule kind")
			}
		}
	}
	active, pending := uint8(15), uint8(0)
	reached := false
	stack := make(map[string]bool)
	visits, steps := 0, 0
	var visit func(string, int) error
	visit = func(path string, depth int) error {
		visits++
		if depth > 8 || visits > 4096 || stack[path] {
			return errors.New("PF filter evaluation depth, cycle or visit limit exceeded")
		}
		stack[path] = true
		defer delete(stack, path)
		if path == selected {
			reached = true
		}
		for _, rule := range graph[path] {
			steps++
			if steps > 65536 {
				return errors.New("PF filter evaluation rule limit exceeded")
			}
			for _, child := range rule.targets {
				if err := visit(child, depth+1); err != nil {
					return err
				}
			}
			e := rule.effect
			matches := active & e.domain
			if e.pass && path != selected && matches != 0 {
				if e.quick {
					return fmt.Errorf("PF quick pass in %q can bypass job filter", path)
				}
				pending |= matches
			} else if e.all {
				// Every remaining packet in this domain gets a known later
				// decision. A quick decision also protects against later passes.
				pending &^= matches
				if e.quick {
					active &^= matches
				}
			}
		}
		return nil
	}
	if err := visit("", 0); err != nil {
		return err
	}
	if !reached {
		return errors.New("selected PF filter anchor is not unconditionally reachable from root")
	}
	if pending != 0 {
		return errors.New("PF nonquick pass can survive job filter evaluation")
	}
	return nil
}

var filterTokens = regexp.MustCompile(`"[^"\\]*"|[^ ]+`)

// Accept a deliberately small normalized pfctl subset. All tokens are consumed
// even for a rule proved disjoint, so unknown matching semantics fail closed.
func parseFilterEffect(line string, uid uint32, owned bool) (filterEffect, error) {
	bad := errors.New("unsupported PF filter match syntax")
	t := filterTokens.FindAllString(line, -1)
	e := filterEffect{domain: 15, all: true, pass: t[0] == "pass"}
	i := 1
	if i < len(t) && (t[i] == "drop" || t[i] == "return") && !e.pass {
		i++
	}
	seen := make(map[string]bool)
	direction, user := "", false
	match := false
	for i < len(t) {
		key := t[i]
		i++
		if seen[key] {
			return e, bad
		}
		seen[key] = true
		next := func() string {
			if i == len(t) {
				return ""
			}
			s := t[i]
			i++
			return s
		}
		switch key {
		case "in", "out":
			if direction != "" {
				return e, bad
			}
			direction = key
			if key == "in" {
				e.domain = 0
			}
		case "log":
		case "quick":
			e.quick = true
		case "on":
			iface := next()
			if iface == "!" {
				iface = next()
			}
			if iface == "" || strings.ContainsAny(iface, "\"()<>!{}") {
				return e, bad
			}
			e.all = false
		case "inet", "inet6":
			if seen["inet"] && seen["inet6"] {
				return e, bad
			}
			if key == "inet" {
				e.domain &= 3
			} else {
				e.domain &= 12
			}
		case "proto":
			switch next() {
			case "tcp":
				e.domain &= 5
			case "udp":
				e.domain &= 10
			case "icmp", "icmp6", "ipv6-icmp":
				e.domain = 0
			default:
				return e, bad
			}
		case "all":
			if match {
				return e, bad
			}
			match = true
		case "from":
			if match {
				return e, bad
			}
			match = true
			for side := range 2 {
				addr := next()
				if addr != "any" {
					if _, err := netip.ParseAddr(addr); err != nil {
						if _, err := netip.ParsePrefix(addr); err != nil {
							return e, bad
						}
					}
					e.all = false
				}
				if i < len(t) && t[i] == "port" {
					i++
					if next() != "=" {
						return e, bad
					}
					if _, err := strconv.ParseUint(next(), 10, 16); err != nil {
						return e, bad
					}
					e.all = false
				}
				if side == 0 && next() != "to" {
					return e, bad
				}
			}
		case "user":
			value := next()
			if value == "=" {
				value = next()
			}
			n, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return e, bad
			}
			user = n == uint64(uid)
			if !user {
				e.domain = 0
			}
		case "flags":
			flags := next()
			if flags == "" || strings.Trim(flags, "FSRPAUEW/") != "" {
				return e, bad
			}
			e.all = false
		case "keep", "no":
			if next() != "state" || seen["keep"] && seen["no"] {
				return e, bad
			}
		case "label":
			label := next()
			if len(label) < 2 || label[0] != '"' || label[len(label)-1] != '"' {
				return e, bad
			}
		default:
			return e, bad
		}
	}
	if !match || owned && (direction != "out" || !user) {
		return e, bad
	}
	return e, nil
}

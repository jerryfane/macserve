package maintenance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"github.com/jerryfane/macserve/internal/pfctl"
)

// pfctl(8) documents recursive '*' -sr and -v -s Interfaces. The BSD
// print_iface format prints ' (skip)' only with -v; -vv adds counters.
// Unknown output is refused rather than treated as filtering enabled.
func loopbackFiltered(text string) bool { return text == "lo0\n" }
func pfEnabled(text string) bool {
	lines := strings.Split(text, "\n")
	if len(lines) == 0 {
		return false
	}
	return strings.HasPrefix(lines[0], "Status: Enabled for ") && strings.Contains(lines[0], "Debug:")
}
func observePF(ctx context.Context, c Config, hosts []netip.Addr, o *Observation) error {
	if err := validatePFConfig(&c); err != nil {
		return err
	}
	client, err := pfctl.New(c.PFAnchor)
	if err != nil {
		return err
	}
	return observePFWithCommand(ctx, c, hosts, o, func(ctx context.Context, args ...string) (string, error) {
		out, err := client.Read(ctx, args...)
		return out.Stdout, err
	})
}

func observePFWithCommand(ctx context.Context, c Config, hosts []netip.Addr, o *Observation, command func(context.Context, ...string) (string, error)) error {
	o.PFAnchor, o.RootRulesSHA256, o.AnchorRulesSHA256 = "", "", ""
	if err := validatePFConfig(&c); err != nil {
		return err
	}
	if err := validateCoexistenceConfig(&c); err != nil {
		return err
	}
	approved, err := approvedGuestPrefixes(c)
	if err != nil {
		return err
	}
	if len(c.ToleratedTranslationAnchors) != 0 {
		if err := validateGuestTranslations("", approved, hosts); err != nil {
			return err
		}
	}
	remaining := 4 << 20
	query := func(ctx context.Context, args ...string) (string, error) {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		text, err := command(ctx, args...)
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		remaining -= len(text)
		if len(text) > 1<<20 || remaining < 0 {
			return "", errors.New("PF observation output limit exceeded")
		}
		return text, err
	}
	status, err := query(ctx, "-s", "info")
	if err != nil {
		return err
	}
	o.PFEnabled = pfEnabled(status)
	if !o.PFEnabled {
		return errors.New("PF not verifiably enabled")
	}
	interfaces, err := query(ctx, "-i", "lo0", "-v", "-s", "Interfaces")
	if err != nil {
		return err
	}
	o.LoopbackFiltered = loopbackFiltered(interfaces)
	if !o.LoopbackFiltered {
		return errors.New("loopback filtering not verifiable")
	}
	root, err := query(ctx, "-a", "*", "-sr")
	if err != nil {
		return err
	}
	if err := filterAnchorReachable(ctx, c.PFAnchor, query); err != nil {
		return err
	}
	anchor, err := query(ctx, "-a", c.PFAnchor, "-sr")
	if err != nil {
		return err
	}
	// Dynamic tables/interfaces can change effective policy without changing rule
	// text. This initial observer supports only literal static addresses.
	if strings.TrimSpace(root) == "" || strings.TrimSpace(anchor) == "" || strings.ContainsAny(root, "<(") || strings.ContainsAny(anchor, "<(") {
		return errors.New("missing anchor or unsupported dynamic PF rules")
	}
	translations, err := observePFTranslations(ctx, c, approved, hosts, query)
	if err != nil {
		return err
	}
	rootAfter, err := query(ctx, "-a", "*", "-sr")
	if err != nil {
		return err
	}
	anchorAfter, err := query(ctx, "-a", c.PFAnchor, "-sr")
	if err != nil {
		return err
	}
	if rootAfter != root || anchorAfter != anchor {
		return errors.New("PF filter rules changed during observation")
	}
	// Bind the selected path and reviewed exceptions as well as every observed
	// ruleset. Changing tolerance policy requires new qualification even when
	// the current translation text happens to remain unchanged.
	framed, err := json.Marshal(struct {
		PFAnchor                    string
		ToleratedTranslationAnchors []string
		ApprovedGuestSubnets        []string
		CoexistingAnchors           []string
		CoexistingServices          []string
		Filter                      string
		Translations                []pfTranslation
	}{c.PFAnchor, c.ToleratedTranslationAnchors, c.ApprovedGuestSubnets, c.CoexistingAnchors, c.CoexistingServices, root, translations})
	if err != nil {
		return err
	}
	o.PFAnchor = c.PFAnchor
	o.RootRulesSHA256 = digest(framed)
	o.AnchorRulesSHA256 = digest([]byte(anchor))
	return nil
}

type pfTranslation struct {
	Path  string
	Rules string
}

// pfctl(8), -s Anchors: -v recursively lists all children, including unnamed
// anchors. The BSD pfctl_show_anchors printer nevertheless hides "_pf"; probe
// that reserved child explicitly at every level, never infer its absence.
// https://github.com/freebsd/freebsd-src/blob/stable/10/sbin/pfctl/pfctl.c
// Apple defines the same reserved name in xnu/bsd/net/pfvar.h.
func pfAnchorTopology(ctx context.Context, query func(context.Context, ...string) (string, error)) ([]string, error) {
	paths := []string{""}
	seen := map[string]bool{"": true}
	add := func(path string) error {
		if !pfctl.AnchorPath(path) || seen[path] || len(paths) >= 65 {
			return errors.New("unsupported PF anchor topology")
		}
		seen[path] = true
		paths = append(paths, path)
		return nil
	}
	parse := func(text, parent string) error {
		for text != "" {
			line, rest, ok := strings.Cut(text, "\n")
			if !ok || !strings.HasPrefix(line, "  ") {
				return errors.New("malformed PF anchor listing")
			}
			path := strings.TrimPrefix(line, "  ")
			if parent != "" && !strings.HasPrefix(path, parent+"/") {
				return errors.New("PF anchor escaped parent")
			}
			if err := add(path); err != nil {
				return err
			}
			text = rest
		}
		return nil
	}
	text, err := query(ctx, "-v", "-s", "Anchors")
	if err != nil {
		return nil, err
	}
	if err := parse(text, ""); err != nil {
		return nil, err
	}
	// Re-evaluate len: discovering reserved anchors appends more parents.
	for i := 0; i < len(paths); i++ {
		reserved := strings.TrimPrefix(paths[i]+"/_pf", "/")
		if seen[reserved] {
			continue
		}
		text, err := query(ctx, "-a", reserved, "-v", "-s", "Anchors")
		if errors.Is(err, pfctl.ErrAnchorAbsent) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if err := add(reserved); err != nil {
			return nil, err
		}
		if err := parse(text, reserved); err != nil {
			return nil, err
		}
	}
	for _, path := range paths[1:] {
		if i := strings.LastIndexByte(path, '/'); i >= 0 && !seen[path[:i]] {
			return nil, errors.New("incomplete PF anchor topology")
		}
	}
	sort.Strings(paths)
	return paths, nil
}

func observePFTranslations(ctx context.Context, c Config, approved []netip.Prefix, hosts []netip.Addr, query func(context.Context, ...string) (string, error)) ([]pfTranslation, error) {
	paths, err := pfAnchorTopology(ctx, query)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(paths, c.PFAnchor) {
		return nil, errors.New("selected filter anchor missing from PF topology")
	}
	rules := make([]pfTranslation, len(paths))
	for pass := range 2 {
		for i, path := range paths {
			text, err := query(ctx, "-a", path, "-sn")
			if err != nil {
				return nil, err
			}
			if path != "" && text != "" {
				if !slices.Contains(c.ToleratedTranslationAnchors, path) {
					return nil, errors.New("nonempty translation anchor is not explicitly tolerated")
				}
				if err := validateGuestTranslations(text, approved, hosts); err != nil {
					return nil, fmt.Errorf("translation anchor %q: %w", path, err)
				}
			}
			if path == "" && !rootPFTranslationCalls(text, paths) {
				return nil, errors.New("unsupported or unobserved PF translation rules")
			}
			if pass == 0 {
				rules[i] = pfTranslation{path, text}
			} else if rules[i].Rules != text {
				return nil, errors.New("PF translation rules changed during observation")
			}
		}
		after, err := pfAnchorTopology(ctx, query)
		if err != nil {
			return nil, err
		}
		if !slices.Equal(paths, after) {
			return nil, errors.New("PF anchors changed during observation")
		}
	}
	return rules, nil
}

// Only unconditional root translation calls are supported. Every descendant is
// independently checked; nested calls and unreviewed mappings fail closed.
func rootPFTranslationCalls(text string, paths []string) bool {
	for text != "" {
		line, rest, ok := strings.Cut(text, "\n")
		if !ok {
			return false
		}
		kind, target, ok := strings.Cut(line, " \"")
		if !ok || kind != "nat-anchor" && kind != "rdr-anchor" && kind != "binat-anchor" {
			return false
		}
		target = strings.TrimSuffix(target, " all")
		if !strings.HasSuffix(target, "\"") {
			return false
		}
		target = strings.TrimSuffix(strings.TrimSuffix(target, "\""), "/*")
		if !pfctl.AnchorPath(target) {
			return false
		}
		i := sort.SearchStrings(paths, target)
		if i == len(paths) || paths[i] != target {
			return false
		}
		text = rest
	}
	return true
}

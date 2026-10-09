package maintenance

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/jerryfane/macserve/internal/pfctl"
)

// observeFilterOrder binds a stable, bounded direct-rules snapshot to the order
// proof. Recursive -sr output alone cannot establish which wildcard siblings ran.
func observeFilterOrder(ctx context.Context, path string, uid uint32, query func(context.Context, ...string) (string, error)) ([]pfTranslation, error) {
	if !pfctl.AnchorPath(path) || uid < 501 {
		return nil, errors.New("invalid selected PF filter anchor or job UID")
	}
	remaining := 4 << 20
	bounded := func(ctx context.Context, args ...string) (string, error) {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		text, err := query(ctx, args...)
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		remaining -= len(text)
		if len(text) > 1<<20 || remaining < 0 {
			return "", errors.New("PF filter anchor output limit exceeded")
		}
		return text, err
	}
	paths, err := pfAnchorTopology(ctx, bounded)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(paths, path) {
		return nil, errors.New("selected PF filter anchor missing from topology")
	}
	rules := make([]pfTranslation, len(paths))
	for pass := range 2 {
		for i, current := range paths {
			var text string
			if current == "" {
				text, err = bounded(ctx, "-sr")
			} else {
				text, err = bounded(ctx, "-a", current, "-sr")
			}
			if err != nil {
				return nil, err
			}
			if pass == 0 {
				rules[i] = pfTranslation{current, text}
			} else if text != rules[i].Rules {
				return nil, errors.New("PF direct filter rules changed during observation")
			}
		}
		after, err := pfAnchorTopology(ctx, bounded)
		if err != nil {
			return nil, err
		}
		if !slices.Equal(paths, after) {
			return nil, errors.New("PF filter topology changed during observation")
		}
	}
	if err := proveFilterOrder(path, uid, rules); err != nil {
		return nil, err
	}
	return rules, nil
}

// Reject multi-line quoted labels and recursive/inline output before parsing.
func directFilterRuleLine(line string) bool {
	quoted := false
	for _, c := range line {
		switch {
		case c == '\\', c < ' ', c == 127:
			return false
		case c == '"':
			quoted = !quoted
		case !quoted && (c == '{' || c == '}'):
			return false
		}
	}
	if quoted {
		return false
	}
	kind, _, _ := strings.Cut(line, " ")
	switch kind {
	case "anchor", "pass", "block", "scrub", "no", "scrub-anchor", "dummynet-anchor", "nat-anchor", "rdr-anchor", "binat-anchor", "nat", "rdr", "binat":
		return true
	default:
		return false
	}
}

// Exact printed calls only: conditional and quick anchor calls are unsupported.
func filterAnchorTarget(current, line string) (string, bool, error) {
	kind, name, ok := strings.Cut(line, " \"")
	if !ok {
		return "", false, errors.New("unsupported PF anchor call")
	}
	switch kind {
	case "anchor", "scrub-anchor", "dummynet-anchor", "nat-anchor", "rdr-anchor", "binat-anchor":
	default:
		return "", false, errors.New("unsupported PF anchor call")
	}
	name, suffix, ok := strings.Cut(name, "\"")
	if !ok || (suffix != " all" && (kind != "scrub-anchor" || suffix != " all fragment reassemble")) {
		return "", false, errors.New("unsupported PF anchor call")
	}
	absolute := strings.HasPrefix(name, "/")
	if absolute {
		name = strings.TrimPrefix(name, "/")
	}
	if name == "" || strings.HasPrefix(name, "/") {
		return "", false, errors.New("unsupported PF anchor reference")
	}
	wildcard := name == "*" || strings.HasSuffix(name, "/*")
	if name == "*" {
		name = ""
	} else if wildcard {
		name = strings.TrimSuffix(name, "/*")
	}
	if name == "" && !wildcard || name != "" && !pfctl.AnchorPath(name) {
		return "", false, errors.New("unsupported PF anchor reference")
	}
	base := name
	if !absolute && current != "" {
		base = current
		if name != "" {
			base += "/" + name
		}
	}
	if base != "" && !pfctl.AnchorPath(base) {
		return "", false, errors.New("unsupported PF anchor depth")
	}
	return base, wildcard, nil
}

package maintenance

import (
	"context"
	"errors"
	"strings"

	"github.com/jerryfane/macserve/internal/pfctl"
)

// filterAnchorReachable proves a call path, not that earlier quick rules cannot
// bypass it. The observer separately checks the selected rules and whole policy.
// Only direct, newline-terminated pfctl -sr output is accepted. Proof edges have
// exactly the printed form anchor "name" all; conditional calls are not edges.
// Names may be relative, absolute (one leading slash), or end in /*. Dot/parent
// components, escaped names, inline/recursive braces and other call modifiers
// are unsupported. Absolute paths follow Apple's pf_anchor_copyout:
// https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/pf_ruleset.c
//
// pf.conf(5), ANCHORS specifies that wildcards visit immediate children only.
// Without an anchor-list query, we can prove only the wildcard child on the
// selected path, not an unrelated wildcard child that might call back into it.
// The caller supplies its aggregate query budget; local bounds also cap direct
// output, graph nodes and path depth even for a query without such a budget.
func filterAnchorReachable(ctx context.Context, path string, query func(context.Context, ...string) (string, error)) error {
	if !pfctl.AnchorPath(path) {
		return errors.New("invalid selected PF filter anchor")
	}
	pending := []string{""}
	visited := map[string]bool{"": true}
	remaining := 4 << 20
	for i := 0; i < len(pending); i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		current := pending[i]
		var text string
		var err error
		if current == "" {
			text, err = query(ctx, "-sr")
		} else {
			text, err = query(ctx, "-a", current, "-sr")
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			return err
		}
		remaining -= len(text)
		if len(text) > 1<<20 || remaining < 0 {
			return errors.New("PF filter anchor output limit exceeded")
		}
		if current == path {
			return nil
		}
		for text != "" {
			line, rest, complete := strings.Cut(text, "\n")
			if !complete {
				return errors.New("truncated PF filter rules")
			}
			text = rest
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if !directFilterRuleLine(line) {
				return errors.New("unsupported direct PF filter rule output")
			}
			if !strings.HasPrefix(line, "anchor ") {
				continue
			}
			name, suffix, quoted := strings.Cut(strings.TrimPrefix(line, "anchor \""), "\"")
			if !strings.HasPrefix(line, "anchor \"") || !quoted {
				return errors.New("unsupported PF filter anchor call")
			}
			if suffix != " all" {
				continue
			}
			next, err := filterAnchorTarget(current, name, path)
			if err != nil {
				return err
			}
			if next == "" || visited[next] {
				continue
			}
			if len(pending) >= 65 {
				return errors.New("PF filter anchor traversal limit exceeded")
			}
			visited[next] = true
			pending = append(pending, next)
		}
	}
	return errors.New("selected PF filter anchor is not unconditionally reachable from root")
}

// Reject multi-line quoted labels and recursive/inline output before looking
// for anchor lines, so a label or nested block cannot manufacture a root edge.
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
	case "anchor", "pass", "block", "scrub", "no", "nat-anchor", "rdr-anchor", "binat-anchor", "nat", "rdr", "binat":
		return true
	default:
		return false
	}
}

func filterAnchorTarget(current, name, selected string) (string, error) {
	absolute := strings.HasPrefix(name, "/")
	if absolute {
		name = strings.TrimPrefix(name, "/")
	}
	if name == "" || strings.HasPrefix(name, "/") {
		return "", errors.New("unsupported PF filter anchor reference")
	}
	wildcard := name == "*" || strings.HasSuffix(name, "/*")
	if name == "*" {
		name = ""
	} else if wildcard {
		name = strings.TrimSuffix(name, "/*")
	}
	// Empty names are only meaningful for "*" (or its absolute form "/*").
	if name == "" && !wildcard || name != "" && !pfctl.AnchorPath(name) {
		return "", errors.New("unsupported PF filter anchor reference")
	}
	base := name
	if !absolute && current != "" {
		base = current
		if name != "" {
			base += "/" + name
		}
	}
	if base != "" && !pfctl.AnchorPath(base) {
		return "", errors.New("unsupported PF filter anchor depth")
	}
	if !wildcard {
		return base, nil
	}
	prefix := base
	if prefix != "" {
		prefix += "/"
	}
	if !strings.HasPrefix(selected, prefix) {
		return "", nil
	}
	rest := strings.TrimPrefix(selected, prefix)
	child, _, _ := strings.Cut(rest, "/")
	if child == "" {
		return "", nil
	}
	return prefix + child, nil
}

package maintenance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"slices"
	"sort"
	"strings"
	"time"
)

type boundedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		return 0, errors.New("probe output limit exceeded")
	}
	return b.Buffer.Write(p)
}

var errPFAnchorAbsent = errors.New("PF anchor absent")

func pfCommand(ctx context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/sbin/pfctl", args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}
	cmd.Dir = "/"
	cmd.WaitDelay = 100 * time.Millisecond
	out := boundedBuffer{limit: 1 << 20}
	diagnostic := boundedBuffer{limit: 8192}
	cmd.Stdout = &out
	cmd.Stderr = &diagnostic
	err := cmd.Run()
	text := strings.TrimSpace(diagnostic.String())
	const altq = "No ALTQ support in kernel\nALTQ related functions disabled"
	if text == altq {
		text = ""
	} else {
		text = strings.TrimPrefix(text, altq+"\n")
	}
	// The BSD anchor enumerator hides _pf. Explicit existence probes below must
	// distinguish this exact diagnostic from permission errors or partial reads.
	var exitErr *exec.ExitError
	normalExit := err == nil || errors.As(err, &exitErr) && exitErr.ExitCode() == 1
	if normalExit && ctx.Err() == nil && out.Len() == 0 && len(args) == 5 &&
		args[0] == "-a" && args[2] == "-v" && args[3] == "-s" && args[4] == "Anchors" &&
		(args[1] == "_pf" || strings.HasSuffix(args[1], "/_pf")) &&
		text == "Anchor '"+args[1]+"' not found." {
		return "", errPFAnchorAbsent
	}
	if err != nil {
		return "", err
	}
	if text != "" {
		return "", errors.New("unrecognized PF diagnostic")
	}
	return out.String(), ctx.Err()
}

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
func observePF(ctx context.Context, o *Observation) error {
	return observePFWithCommand(ctx, o, pfCommand)
}

func observePFWithCommand(ctx context.Context, o *Observation, command func(context.Context, ...string) (string, error)) error {
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
	anchor, err := query(ctx, "-a", "org.macserve", "-sr")
	if err != nil {
		return err
	}
	// Dynamic tables/interfaces can change effective policy without changing rule
	// text. This initial observer supports only literal static addresses.
	if strings.TrimSpace(anchor) == "" || !strings.Contains(root, "anchor \"org.macserve\"") || strings.ContainsAny(root, "<(") || strings.ContainsAny(anchor, "<(") {
		return errors.New("missing anchor or unsupported dynamic PF rules")
	}
	translations, err := observePFTranslations(ctx, query)
	if err != nil {
		return err
	}
	// JSON string/array framing binds rule text and every observed path without
	// delimiter ambiguity. A topology change invalidates prior qualification.
	framed, err := json.Marshal(struct {
		Filter       string
		Translations []pfTranslation
	}{root, translations})
	if err != nil {
		return err
	}
	o.RootRulesSHA256 = digest(framed)
	o.AnchorRulesSHA256 = digest([]byte(anchor))
	return nil
}

type pfTranslation struct {
	Path  string
	Rules string
}

func pfAnchorPath(path string) bool {
	if path == "" || len(path) >= 1024 || strings.Count(path, "/") >= 8 {
		return false
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." || len(part) >= 64 {
			return false
		}
		for _, c := range part {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
				return false
			}
		}
	}
	return true
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
		if !pfAnchorPath(path) || seen[path] || len(paths) >= 65 {
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
		if errors.Is(err, errPFAnchorAbsent) {
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

func observePFTranslations(ctx context.Context, query func(context.Context, ...string) (string, error)) ([]pfTranslation, error) {
	paths, err := pfAnchorTopology(ctx, query)
	if err != nil {
		return nil, err
	}
	rules := make([]pfTranslation, len(paths))
	for pass := range 2 {
		for i, path := range paths {
			text, err := query(ctx, "-a", path, "-sn")
			if err != nil {
				return nil, err
			}
			if path != "" && text != "" {
				return nil, errors.New("nonempty translation anchor requires unsupported qualification")
			}
			if path == "" && !emptyPFTranslationCalls(text, paths) {
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

// Only unconditional root calls into proven-empty anchors are supported.
// Descendant calls, mappings, tables, interfaces and other syntax fail closed.
func emptyPFTranslationCalls(text string, paths []string) bool {
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
		if !pfAnchorPath(target) {
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

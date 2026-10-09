package pfctl

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const maxPolicyBytes = 1 << 20

func policyFile(path string, jobUID uint32) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("PF policy must have a clean absolute path")
	}
	var info os.FileInfo
	for current := path; ; current = filepath.Dir(current) {
		st, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if st.Mode()&os.ModeSymlink != 0 || current != path && !st.IsDir() {
			return errors.New("PF policy and ancestors must not be symlinks")
		}
		if current == path {
			info = st
			if !st.Mode().IsRegular() || st.Size() <= 0 || st.Size() > maxPolicyBytes {
				return errors.New("PF policy must be a nonempty bounded regular file")
			}
		}
		if current == string(filepath.Separator) {
			break
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(info, st) || !st.Mode().IsRegular() {
		return errors.New("PF policy changed during preflight")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxPolicyBytes+1))
	if err != nil {
		return err
	}
	return validatePolicy(string(data), jobUID)
}

// This is a scope guard, not a substitute for reviewing PF semantics. Only
// literal numeric/address macros and a deliberately small filter-only dialect
// are supported. In particular, macros can never expand into PF keywords.
func validatePolicy(text string, jobUID uint32) error {
	if len(text) == 0 || len(text) > maxPolicyBytes || strings.ContainsAny(text, "\\\r") {
		return errors.New("unsupported PF policy size or line continuation")
	}
	if jobUID == 0 {
		return errors.New("PF policy requires an explicit non-root job UID")
	}
	macros := make(map[string]string)
	rules, marked := 0, false
	var deny mandatoryDeny
	for n, line := range strings.Split(text, "\n") {
		if n >= 4096 || len(line) > 8192 {
			return errors.New("PF policy line limit exceeded")
		}
		for _, c := range line {
			if c != '\t' && (c < ' ' || c > '~') {
				return errors.New("PF policy contains unsupported characters")
			}
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.ContainsRune(line, ';') {
			return errors.New("unsupported PF statement separator")
		}
		if name, value, ok := strings.Cut(line, "="); ok && macroName(strings.TrimSpace(name)) {
			name, value = strings.TrimSpace(name), strings.TrimSpace(value)
			if strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"") && len(value) >= 2 {
				value = value[1 : len(value)-1]
			}
			if len(macros) >= 128 || macros[name] != "" || !literalValue(value) {
				return fmt.Errorf("unsupported PF literal macro on line %d", n+1)
			}
			macros[name] = value
			continue
		}
		tokens, ok := filterTokens(line)
		if !ok || !filterLine(tokens, macros, jobUID) {
			return fmt.Errorf("unsupported PF filter-only source on line %d", n+1)
		}
		if err := deny.add(tokens, macros); err != nil {
			return fmt.Errorf("PF policy line %d: %w", n+1, err)
		}
		if strings.HasPrefix(line, "block") && strings.Contains(line, `"macserve-default-deny"`) {
			marked = true
		}
		rules++
	}
	if rules == 0 || !marked {
		return errors.New("PF policy requires filter rules and the macserve default-deny marker")
	}
	return deny.complete()
}

func macroName(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for i, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || i > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func literal(s string) bool {
	if s == "" {
		return false
	}
	if _, err := strconv.ParseUint(s, 10, 32); err == nil && s[0] >= '0' && s[0] <= '9' {
		return true
	}
	if a, err := netip.ParseAddr(s); err == nil && a.Zone() == "" {
		return true
	}
	_, err := netip.ParsePrefix(s)
	return err == nil
}

func literalValue(s string) bool {
	if !strings.HasPrefix(s, "{") {
		return literal(s)
	}
	if !strings.HasSuffix(s, "}") {
		return false
	}
	for _, item := range strings.Split(s[1:len(s)-1], ",") {
		if !literal(strings.TrimSpace(item)) {
			return false
		}
	}
	return true
}

func filterLine(tokens []string, macros map[string]string, jobUID uint32) bool {
	if !jobScope(tokens, macros, jobUID) {
		return false
	}
	depth := 0
	for i, token := range tokens[1:] {
		switch token {
		case "{":
			if depth != 0 {
				return false
			}
			depth++
		case "}":
			if depth != 1 {
				return false
			}
			depth--
		case ",":
			if depth != 1 {
				return false
			}
		case "=", "drop", "return", "return-rst", "return-icmp", "return-icmp6", "out", "log", "quick", "inet", "inet6", "proto", "tcp", "udp", "icmp", "icmp6", "from", "to", "any", "all", "port", "user", "label", "keep", "no", "modulate", "synproxy", "state":
		default:
			if strings.HasPrefix(token, "\"") {
				if tokens[i] != "label" || len(token) < 3 || len(token)-2 > 63 || !labelLiteral(token[1:len(token)-1]) {
					return false
				}
			} else if strings.HasPrefix(token, "$") {
				if macros[token[1:]] == "" {
					return false
				}
			} else if !literal(token) {
				return false
			}
		}
	}
	return depth == 0
}

func filterTokens(line string) ([]string, bool) {
	// Tokenize braces/commas even when adjacent; quotes are confined to labels.
	var tokens []string
	for rest := line; rest != ""; {
		rest = strings.TrimLeft(rest, " \t")
		if rest == "" {
			break
		}
		i := 0
		switch rest[0] {
		case '{', '}', ',', '=':
			i = 1
		case '"':
			end := strings.IndexByte(rest[1:], '"')
			if end < 0 {
				return nil, false
			}
			i = end + 2
		default:
			i = strings.IndexAny(rest, " \t{},=\"")
			if i < 0 {
				i = len(rest)
			}
		}
		tokens = append(tokens, rest[:i])
		rest = rest[i:]
	}
	return tokens, true
}

// A scalar numeric UID (or scalar literal macro) is the only accepted user
// predicate. Operators, lists, groups, repeated directions and repeated users
// cannot weaken the boundary. PF itself subsequently checks grammar/order.
func jobScope(tokens []string, macros map[string]string, jobUID uint32) bool {
	if jobUID == 0 || len(tokens) < 4 || tokens[0] != "block" && tokens[0] != "pass" {
		return false
	}
	out, user, depth := false, false, 0
	for i := 1; i < len(tokens); i++ {
		token := tokens[i]
		switch token {
		case "{":
			depth++
		case "}":
			depth--
		case "in", "group":
			return false
		case "out":
			if out || depth != 0 {
				return false
			}
			out = true
		case "user":
			if user || depth != 0 {
				return false
			}
			user = true
			i++
			if i < len(tokens) && tokens[i] == "=" {
				i++
			}
			if i >= len(tokens) {
				return false
			}
			value := tokens[i]
			if strings.HasPrefix(value, "$") {
				value = macros[value[1:]]
			}
			if value != strconv.FormatUint(uint64(jobUID), 10) {
				return false
			}
			if i+1 < len(tokens) && (literal(tokens[i+1]) || strings.HasPrefix(tokens[i+1], "$") || strings.ContainsAny(tokens[i+1], "{},=<>!")) {
				return false
			}
		}
		if depth < 0 {
			return false
		}
	}
	return out && user && depth == 0
}

func labelLiteral(s string) bool {
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

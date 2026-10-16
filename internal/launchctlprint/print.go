// Package launchctlprint reads bounded, balanced launchctl service snapshots.
// It does not infer service health from nested dictionaries or command success.
package launchctlprint

import (
	"errors"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxOutput = 1 << 20
	maxDepth  = 16
)

var errInvalid = errors.New("invalid launchctl running service snapshot")

// Snapshot contains only service-root authority. Callers must bind Target to
// the exact service they requested; nested state and pid fields are never used.
// Path and Type are the root service path and type when launchctl printed them.
// Program and Arguments are the root `program` and `arguments` launchd execs
// (Arguments is nil when not printed, as for an inferred program). Environment
// is the service's own root `environment` dictionary (its plist
// EnvironmentVariables plus launchd's per-service entries such as
// XPC_SERVICE_NAME); it is nil when not printed or when an entry is not a
// plain `KEY => value` line. It never includes the `inherited environment`
// that `launchctl setenv` changes.
type Snapshot struct {
	Target      string
	State       string
	PID         int
	Path        string
	Type        string
	Program     string
	Arguments   []string
	Environment map[string]string
}

// Parse accepts a complete newline-terminated service dictionary with exactly
// one unquoted state = running and one canonical positive 32-bit pid = N.
// Root path, type, program, arguments and environment are optional but
// unique; a value that injects a second root line (a filename, or a
// `launchctl setenv` value printed in the inherited environment, which comes
// before the root environment) therefore invalidates the snapshot instead of
// shadowing the first. Collected entries never bypass the structural checks.
// Other fields may contain dictionaries, arrays, quoted keys, and => entries.
// Quotes are line-local; controls, malformed nesting and trailing output fail.
func Parse(text string) (Snapshot, error) {
	if len(text) == 0 || len(text) > maxOutput || !utf8.ValidString(text) {
		return Snapshot{}, errInvalid
	}
	for _, c := range text {
		if unicode.IsControl(c) && c != '\n' && c != '\t' {
			return Snapshot{}, errInvalid
		}
	}
	first, text, complete := strings.Cut(text, "\n")
	target, ok := strings.CutSuffix(first, " = {")
	if !complete || !ok || target == "" || strings.ContainsAny(target, " \t\"{}[]\\=") {
		return Snapshot{}, errInvalid
	}
	result := Snapshot{Target: target}
	var stack [maxDepth]byte
	stack[0] = '{'
	depth := 1
	stateSeen, pidSeen, pathSeen, typeSeen, programSeen := false, false, false, false, false
	// section names the root dictionary ("arguments" or "environment") whose
	// depth-2 entries are collected; envUsable is cleared by any environment
	// entry that is not a plain unique `KEY => value`.
	section, envUsable := "", true
	for text != "" {
		line, rest, complete := strings.Cut(text, "\n")
		if !complete {
			return Snapshot{}, errInvalid
		}
		text = rest
		trimmed := strings.Trim(line, " \t")
		if trimmed == "" {
			continue
		}
		if trimmed == "}" || trimmed == "]" {
			if !matches(stack[depth-1], trimmed[0]) {
				return Snapshot{}, errInvalid
			}
			depth--
			if depth == 1 {
				section = ""
			}
			if depth == 0 {
				if text != "" || !stateSeen || !pidSeen {
					return Snapshot{}, errInvalid
				}
				if !envUsable {
					result.Environment = nil
				}
				return result, nil
			}
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			return Snapshot{}, errInvalid
		}
		// Retain trailing whitespace here: it must not canonicalize a PID or
		// state into an authoritative value that launchctl did not emit.
		body := strings.TrimLeft(line, " \t")
		key, value, arrow, property, valid := entry(body)
		if !valid || depth == 1 && !property {
			return Snapshot{}, errInvalid
		}
		if depth == 2 && section == "arguments" {
			result.Arguments = append(result.Arguments, body)
		}
		if depth == 2 && section == "environment" {
			if _, seen := result.Environment[key]; seen || !arrow || !property || strings.HasPrefix(key, "\"") || strings.ContainsAny(value, "\"{}[]") {
				envUsable = false
			} else {
				result.Environment[key] = value
			}
		}
		if depth == 1 {
			if strings.HasPrefix(key, "\"") {
				return Snapshot{}, errInvalid
			}
			switch key {
			case "state":
				if stateSeen || arrow || value != "running" {
					return Snapshot{}, errInvalid
				}
				result.State, stateSeen = value, true
			case "pid":
				if pidSeen || arrow || !decimal(value, false) {
					return Snapshot{}, errInvalid
				}
				pid, err := strconv.ParseInt(value, 10, 32)
				if err != nil {
					return Snapshot{}, errInvalid
				}
				result.PID, pidSeen = int(pid), true
			case "path":
				if pathSeen || arrow {
					return Snapshot{}, errInvalid
				}
				result.Path, pathSeen = value, true
			case "type":
				if typeSeen || arrow {
					return Snapshot{}, errInvalid
				}
				result.Type, typeSeen = value, true
			case "program":
				if programSeen || arrow {
					return Snapshot{}, errInvalid
				}
				result.Program, programSeen = value, true
			case "arguments", "environment":
				open := strings.Trim(value, " \t")
				empty := open == "{}"
				if key == "arguments" && result.Arguments != nil || key == "environment" && result.Environment != nil || arrow || open != "{" && !empty {
					return Snapshot{}, errInvalid
				}
				if key == "arguments" {
					result.Arguments = []string{}
				} else {
					result.Environment = map[string]string{}
				}
				if !empty {
					section = key
				}
			}
		}
		if stack[depth-1] == '[' && property && (arrow || !decimal(key, true)) {
			return Snapshot{}, errInvalid
		}
		value = strings.Trim(value, " \t")
		if bracketedScalar(value) {
			continue
		}
		bracket, valid := structural(value)
		if !valid {
			return Snapshot{}, errInvalid
		}
		if bracket < 0 {
			continue
		}
		c := value[bracket]
		switch c {
		case '{', '[':
			// Containers occupy the value, never a suffix of an unquoted
			// scalar. Empty inline containers are also emitted by launchctl.
			if bracket != 0 || !property && stack[depth-1] != '[' || depth == maxDepth {
				return Snapshot{}, errInvalid
			}
			remainder := strings.Trim(value[1:], " \t")
			if remainder != "" {
				if len(remainder) != 1 || !matches(c, remainder[0]) {
					return Snapshot{}, errInvalid
				}
				continue
			}
			stack[depth], depth = c, depth+1
		case ']':
			// LWCR's empty indexed value is printed as `0 = <tabs>]`.
			// The close belongs to its array, not the enclosing service.
			prefix := strings.Trim(value[:bracket], " \t")
			if prefix != "" {
				return Snapshot{}, errInvalid
			}
			if stack[depth-1] != '[' || strings.Trim(value[bracket+1:], " \t") != "" {
				return Snapshot{}, errInvalid
			}
			depth--
		default:
			return Snapshot{}, errInvalid
		}
	}
	return Snapshot{}, errInvalid
}

func matches(open, close byte) bool {
	return open == '{' && close == '}' || open == '[' && close == ']'
}

func decimal(value string, zero bool) bool {
	if value == "" || value[0] == '0' && (!zero || len(value) != 1) {
		return false
	}
	for i := range value {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

// entry finds only unquoted assignment separators. Nested dictionary bodies
// may also contain bare scalar entries (notably the arguments dictionary).
func entry(line string) (key, value string, arrow, property, valid bool) {
	quoted, escaped := false, false
	for i := range len(line) {
		c := line[i]
		if escaped {
			escaped = false
			continue
		}
		if quoted && c == '\\' {
			escaped = true
			continue
		}
		if c == '"' {
			quoted = !quoted
			continue
		}
		if !quoted && c == ' ' {
			width := 0
			if strings.HasPrefix(line[i:], " => ") {
				width, arrow = 4, true
			} else if strings.HasPrefix(line[i:], " = ") {
				width = 3
			}
			if width != 0 {
				key, value = line[:i], line[i+width:]
				return key, value, arrow, true, validKey(key)
			}
		}
	}
	return "", line, false, false, !quoted && !escaped
}

func validKey(key string) bool {
	if key == "" || key != strings.Trim(key, " \t") {
		return false
	}
	if key[0] != '"' {
		return !strings.ContainsAny(key, "\"{}[]\\\t=><")
	}
	// A quoted key is one complete string, not adjacent quoted fragments.
	escaped := false
	for i := 1; i < len(key); i++ {
		if escaped {
			escaped = false
		} else if key[i] == '\\' {
			escaped = true
		} else if key[i] == '"' {
			return i == len(key)-1
		}
	}
	return false
}

// structural validates line-local quoting and finds the first unquoted
// container delimiter. Delimiters within quoted scalar text have no authority.
func structural(value string) (int, bool) {
	quoted, escaped := false, false
	bracket := -1
	for i := range len(value) {
		c := value[i]
		if escaped {
			escaped = false
		} else if quoted && c == '\\' {
			escaped = true
		} else if c == '"' {
			quoted = !quoted
		} else if !quoted && strings.ContainsRune("{}[]", rune(c)) && bracket < 0 {
			bracket = i
		}
	}
	return bracket, !quoted && !escaped
}

// bracketedScalar accepts launchctl's same-line annotation suffix, as in
// `domain = gui/501 [100002]` or `domain = pid/359 [Finder]`. The bracket pair
// closes on the same line around plain text, so it cannot open, close or
// reparent a container. Everything else keeps the structural checks.
func bracketedScalar(value string) bool {
	head, note, ok := strings.Cut(value, " [")
	inner, closed := strings.CutSuffix(note, "]")
	return ok && closed && head != "" && inner != "" && !strings.ContainsAny(head, "\"\\{}[]") && !strings.ContainsAny(inner, "\"\\{}[]")
}

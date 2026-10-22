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
// Original is the root `original` label launchd prints for an instance of a
// MultipleInstances service (com.apple.mdworker.shared.<instance>).
// Program and Arguments are the root `program` and `arguments` launchd execs
// (Arguments is nil when not printed, as for an inferred program). Environment
// is the service's own root `environment` dictionary (its plist
// EnvironmentVariables plus launchd's per-service entries such as
// XPC_SERVICE_NAME); it is nil when not printed or when an entry is not a
// plain `KEY => value` line. Inherited is the root `inherited environment`
// dictionary, the domain environment launchd lists for the service, where a
// `launchctl setenv` value appears; it is nil when not printed, and an entry
// that is not a plain `KEY => value` line invalidates the snapshot, because
// callers compare it as authority.
type Snapshot struct {
	Target      string
	State       string
	PID         int
	Path        string
	Type        string
	Original    string
	Program     string
	Arguments   []string
	Environment map[string]string
	Inherited   map[string]string
}

// Domain is the root authority of `launchctl print <domain>` (gui/UID,
// user/UID or pid/PID). Environment is the domain's own root `environment`
// dictionary, what `launchctl setenv` changes for every later launch there;
// it is nil when not printed, and an entry that is not a plain `KEY => value`
// line invalidates the print. Services maps each running PID in the root
// `services` table to its label. It is only a hint for finding the exact
// service record: rows that are not `PID STATUS LABEL`, PID 0 (not running)
// and PIDs listed more than once are left out. Disabled is the root `disabled
// services` table, the per-user `launchctl enable`/`disable` overrides, as
// label => "enabled" or "disabled". DisabledComplete is false when an entry
// there is not a plain `"label" => enabled|disabled` line; Disabled is then
// partial and must not be read as proof that a label has no override.
type Domain struct {
	Target           string
	Environment      map[string]string
	Services         map[int]string
	Disabled         map[string]string
	DisabledComplete bool
}

// Parse accepts a complete newline-terminated service dictionary with exactly
// one unquoted state = running and one canonical positive 32-bit pid = N.
// Root path, type, original, program, arguments, environment and inherited environment
// are optional but unique; a value that injects a second root line (a
// filename, or a `launchctl setenv` value printed in the inherited
// environment, which comes before the root environment) therefore invalidates
// the snapshot instead of shadowing the first. Collected entries never bypass
// the structural checks. Other fields may contain dictionaries, arrays, quoted
// keys, and => entries. Quotes are line-local; controls, malformed nesting and
// trailing output fail.
func Parse(text string) (Snapshot, error) {
	var result Snapshot
	stateSeen, pidSeen, pathSeen, typeSeen, programSeen, originalSeen := false, false, false, false, false, false
	// envUsable is cleared by any root environment entry that is not a plain
	// unique `KEY => value`.
	envUsable := true
	root := func(key, value string, arrow bool) (string, error) {
		switch key {
		case "state":
			if stateSeen || arrow || value != "running" {
				return "", errInvalid
			}
			result.State, stateSeen = value, true
		case "pid":
			if pidSeen || arrow || !decimal(value, false) {
				return "", errInvalid
			}
			pid, err := strconv.ParseInt(value, 10, 32)
			if err != nil {
				return "", errInvalid
			}
			result.PID, pidSeen = int(pid), true
		case "path":
			if pathSeen || arrow {
				return "", errInvalid
			}
			result.Path, pathSeen = value, true
		case "type":
			if typeSeen || arrow {
				return "", errInvalid
			}
			result.Type, typeSeen = value, true
		case "original":
			if originalSeen || arrow {
				return "", errInvalid
			}
			result.Original, originalSeen = value, true
		case "program":
			if programSeen || arrow {
				return "", errInvalid
			}
			result.Program, programSeen = value, true
		case "arguments":
			if result.Arguments != nil {
				return "", errInvalid
			}
			result.Arguments = []string{}
			return opened(key, value, arrow)
		case "environment":
			if result.Environment != nil {
				return "", errInvalid
			}
			result.Environment = map[string]string{}
			return opened(key, value, arrow)
		case "inherited environment":
			if result.Inherited != nil {
				return "", errInvalid
			}
			result.Inherited = map[string]string{}
			return opened(key, value, arrow)
		}
		return "", nil
	}
	item := func(section, body, key, value string, arrow, property bool) error {
		switch section {
		case "arguments":
			result.Arguments = append(result.Arguments, body)
		case "environment":
			if !plainEntry(result.Environment, key, value, arrow, property) {
				envUsable = false
			} else {
				result.Environment[key] = value
			}
		case "inherited environment":
			if !plainEntry(result.Inherited, key, value, arrow, property) {
				return errInvalid
			}
			result.Inherited[key] = value
		}
		return nil
	}
	target, err := walk(text, root, item)
	if err != nil || !stateSeen || !pidSeen {
		return Snapshot{}, errInvalid
	}
	result.Target = target
	if !envUsable {
		result.Environment = nil
	}
	return result, nil
}

// ParseDomain accepts a complete newline-terminated `launchctl print` of a
// domain with the structure Parse requires of a service. Root environment and
// services are optional but unique.
func ParseDomain(text string) (Domain, error) {
	result := Domain{DisabledComplete: true}
	servicesSeen := false
	listed := make(map[int]int)
	root := func(key, value string, arrow bool) (string, error) {
		switch key {
		case "disabled services":
			if result.Disabled != nil {
				return "", errInvalid
			}
			result.Disabled = map[string]string{}
			return opened(key, value, arrow)
		case "environment":
			if result.Environment != nil {
				return "", errInvalid
			}
			result.Environment = map[string]string{}
			return opened(key, value, arrow)
		case "services":
			if servicesSeen {
				return "", errInvalid
			}
			servicesSeen = true
			return opened(key, value, arrow)
		}
		return "", nil
	}
	item := func(section, body, key, value string, arrow, property bool) error {
		switch section {
		case "environment":
			if !plainEntry(result.Environment, key, value, arrow, property) {
				return errInvalid
			}
			result.Environment[key] = value
		case "disabled services":
			label, quoted := strings.CutPrefix(key, "\"")
			label, closed := strings.CutSuffix(label, "\"")
			_, seen := result.Disabled[label]
			if !quoted || !closed || seen || !arrow || !property || label == "" || strings.ContainsAny(label, "\"\\") || value != "enabled" && value != "disabled" {
				result.DisabledComplete = false
				return nil
			}
			result.Disabled[label] = value
		case "services":
			fields := strings.Fields(body)
			if property || len(fields) != 3 || !decimal(fields[0], true) {
				return nil
			}
			if pid, err := strconv.ParseInt(fields[0], 10, 32); err == nil && pid > 0 {
				listed[int(pid)]++
				if result.Services == nil {
					result.Services = make(map[int]string)
				}
				result.Services[int(pid)] = fields[2]
			}
		}
		return nil
	}
	target, err := walk(text, root, item)
	if err != nil {
		return Domain{}, errInvalid
	}
	result.Target = target
	for pid, n := range listed {
		if n != 1 {
			delete(result.Services, pid)
		}
	}
	return result, nil
}

// opened returns the root dictionary key opens for collection: the value
// must open a dictionary, and an empty inline one collects nothing.
func opened(key, value string, arrow bool) (string, error) {
	open := strings.Trim(value, " \t")
	if arrow || open != "{" && open != "{}" {
		return "", errInvalid
	}
	if open == "{}" {
		return "", nil
	}
	return key, nil
}

// plainEntry reports whether a collected dictionary line is a plain unique
// unquoted `KEY => value` with a scalar value.
func plainEntry(m map[string]string, key, value string, arrow, property bool) bool {
	_, seen := m[key]
	return !seen && arrow && property && !strings.HasPrefix(key, "\"") && !strings.ContainsAny(value, "\"{}[]")
}

// walk validates one complete newline-terminated launchctl print and returns
// its root target. It calls root for every root-level property, in order;
// root may name the root dictionary it opens as a section, and item is then
// called for each line directly inside that section.
func walk(text string, root func(key, value string, arrow bool) (string, error), item func(section, body, key, value string, arrow, property bool) error) (string, error) {
	if len(text) == 0 || len(text) > maxOutput || !utf8.ValidString(text) {
		return "", errInvalid
	}
	for _, c := range text {
		if unicode.IsControl(c) && c != '\n' && c != '\t' {
			return "", errInvalid
		}
	}
	first, text, complete := strings.Cut(text, "\n")
	target, ok := strings.CutSuffix(first, " = {")
	if !complete || !ok || target == "" || strings.ContainsAny(target, " \t\"{}[]\\=") {
		return "", errInvalid
	}
	var stack [maxDepth]byte
	stack[0] = '{'
	depth := 1
	section := ""
	for text != "" {
		line, rest, complete := strings.Cut(text, "\n")
		if !complete {
			return "", errInvalid
		}
		text = rest
		trimmed := strings.Trim(line, " \t")
		if trimmed == "" {
			continue
		}
		if trimmed == "}" || trimmed == "]" {
			if !matches(stack[depth-1], trimmed[0]) {
				return "", errInvalid
			}
			depth--
			if depth == 1 {
				section = ""
			}
			if depth == 0 {
				if text != "" {
					return "", errInvalid
				}
				return target, nil
			}
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			return "", errInvalid
		}
		// Retain trailing whitespace here: it must not canonicalize a PID or
		// state into an authoritative value that launchctl did not emit.
		body := strings.TrimLeft(line, " \t")
		key, value, arrow, property, valid := entry(body)
		if !valid || depth == 1 && !property {
			return "", errInvalid
		}
		if depth == 2 && section != "" {
			if err := item(section, body, key, value, arrow, property); err != nil {
				return "", err
			}
		}
		if depth == 1 {
			if strings.HasPrefix(key, "\"") {
				return "", errInvalid
			}
			opens, err := root(key, value, arrow)
			if err != nil {
				return "", err
			}
			section = opens
		}
		if stack[depth-1] == '[' && property && (arrow || !decimal(key, true)) {
			return "", errInvalid
		}
		value = strings.Trim(value, " \t")
		if bracketedScalar(value) {
			continue
		}
		bracket, valid := structural(value)
		if !valid {
			return "", errInvalid
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
				return "", errInvalid
			}
			remainder := strings.Trim(value[1:], " \t")
			if remainder != "" {
				if len(remainder) != 1 || !matches(c, remainder[0]) {
					return "", errInvalid
				}
				continue
			}
			stack[depth], depth = c, depth+1
		case ']':
			// LWCR's empty indexed value is printed as `0 = <tabs>]`.
			// The close belongs to its array, not the enclosing service.
			prefix := strings.Trim(value[:bracket], " \t")
			if prefix != "" {
				return "", errInvalid
			}
			if stack[depth-1] != '[' || strings.Trim(value[bracket+1:], " \t") != "" {
				return "", errInvalid
			}
			depth--
		default:
			return "", errInvalid
		}
	}
	return "", errInvalid
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

// bracketedScalar accepts launchctl's same-line bracket annotations, as in
// `domain = gui/501 [100002]`, `domain = pid/359 [Finder]` or a domain's
// `creator = loginwindow[15160]`. Each bracket pair closes on the same line
// around plain text and the value has no braces, so it cannot open, close or
// reparent a container. Everything else keeps the structural checks.
func bracketedScalar(value string) bool {
	if value == "" || value[0] == '[' || strings.ContainsAny(value, "\"\\{}") {
		return false
	}
	open, closed, inner := false, false, 0
	for i := range len(value) {
		switch value[i] {
		case '[':
			if open {
				return false
			}
			open, inner = true, 0
		case ']':
			if !open || inner == 0 {
				return false
			}
			open, closed = false, true
		default:
			if open {
				inner++
			}
		}
	}
	return closed && !open
}

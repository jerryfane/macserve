package maintenance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jerryfane/macserve/internal/pfctl"
)

const coexistenceListLimit = 64

type coexistenceBuffer struct {
	buffer bytes.Buffer
	limit  int
}

func (b *coexistenceBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.buffer.Len() {
		return 0, errors.New("coexistence command output limit exceeded")
	}
	return b.buffer.Write(p)
}

func (b *coexistenceBuffer) String() string { return b.buffer.String() }

// AnchorRulesDigest measures only an exact anchor's direct rules, never its
// descendants, table contents, counters, or other changing PF runtime state.
type AnchorRulesDigest struct {
	Path              string `json:"path"`
	Status            string `json:"status"`
	FilterSHA256      string `json:"filter_sha256,omitempty"`
	TranslationSHA256 string `json:"translation_sha256,omitempty"`
}

type ServicePID struct {
	Label string `json:"label"`
	PID   int    `json:"pid"`
}

type CoexistenceState struct {
	RecordedAt      time.Time           `json:"recorded_at"`
	MainRulesStatus string              `json:"main_rules_status"`
	MainRulesSHA256 string              `json:"main_rules_sha256,omitempty"`
	Anchors         []AnchorRulesDigest `json:"anchors"`
	Services        []ServicePID        `json:"services"`
}

type CoexistenceEvidence struct {
	Before CoexistenceState `json:"before"`
	After  CoexistenceState `json:"after"`
}

// Labels are literal system-domain service names, not launchctl targets. The
// conservative ASCII subset excludes slashes, domain selectors and wildcards.
func coexistenceServiceLabel(label string) bool {
	if label == "" || len(label) > 255 || label == "." || label == ".." {
		return false
	}
	for i, c := range label {
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if !alnum && (i == 0 || c != '.' && c != '_' && c != '-') {
			return false
		}
	}
	return true
}

// ValidateCoexistenceConfig validates and canonicalizes the configured peers.
func ValidateCoexistenceConfig(c *Config) error {
	if len(c.CoexistingAnchors) > coexistenceListLimit || len(c.CoexistingServices) > coexistenceListLimit {
		return errors.New("coexistence configuration list limit exceeded")
	}
	anchors := slices.Clone(c.CoexistingAnchors)
	services := slices.Clone(c.CoexistingServices)
	slices.Sort(anchors)
	slices.Sort(services)
	for i, path := range anchors {
		if !pfctl.AnchorPath(path) || i > 0 && anchors[i-1] == path {
			return errors.New("invalid or duplicate coexisting PF anchor")
		}
	}
	for i, label := range services {
		if !coexistenceServiceLabel(label) || i > 0 && services[i-1] == label {
			return errors.New("invalid or duplicate coexisting system service label")
		}
	}
	if len(anchors) == 0 {
		anchors = nil
	}
	if len(services) == 0 {
		services = nil
	}
	c.CoexistingAnchors, c.CoexistingServices = anchors, services
	return nil
}

type coexistenceCommand func(context.Context, ...string) (pfctl.Output, error)

// ObserveCoexistence makes read-only native observations. Successful service
// entries come only from unambiguous running state and PID fields in launchctl
// output; there is no caller-supplied health flag or inferred empty-anchor read.
func ObserveCoexistence(ctx context.Context, c Config) (CoexistenceState, error) {
	if runtime.GOOS != "darwin" || os.Getuid() != 0 || os.Geteuid() != 0 {
		return CoexistenceState{}, errors.New("coexistence observation requires macOS root")
	}
	if err := ValidateCoexistenceConfig(&c); err != nil {
		return CoexistenceState{}, err
	}
	return observeCoexistenceWithCommands(ctx, c, pfctl.Read, coexistenceLaunchctl)
}

func coexistenceLaunchctl(ctx context.Context, args ...string) (pfctl.Output, error) {
	// Keep the native seam read-only even if a future internal caller is added.
	if len(args) != 2 || args[0] != "print" || !strings.HasPrefix(args[1], "system/") || !coexistenceServiceLabel(strings.TrimPrefix(args[1], "system/")) {
		return pfctl.Output{}, errors.New("unsupported coexistence launchctl command")
	}
	cmd := exec.CommandContext(ctx, "/bin/launchctl", args...)
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}
	cmd.WaitDelay = 100 * time.Millisecond
	out := coexistenceBuffer{limit: 1 << 20}
	diagnostic := coexistenceBuffer{limit: 8192}
	cmd.Stdout, cmd.Stderr = &out, &diagnostic
	err := cmd.Run()
	return pfctl.Output{Stdout: out.String(), Stderr: diagnostic.String()}, err
}

// The command seams are private: fixtures cannot replace production host/root
// checks. Every returned byte, including diagnostics, consumes the shared budget.
func observeCoexistenceWithCommands(ctx context.Context, c Config, pf, launchctl coexistenceCommand) (CoexistenceState, error) {
	if err := ValidateCoexistenceConfig(&c); err != nil {
		return CoexistenceState{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	pfRemaining, serviceRemaining := 4<<20, 4<<20
	pfCtx, pfCancel := context.WithTimeout(ctx, 2*time.Second)
	defer pfCancel()
	query := func(command coexistenceCommand, isPF bool, args ...string) (string, error) {
		commandParent := ctx
		if isPF {
			commandParent = pfCtx
		}
		if err := commandParent.Err(); err != nil {
			return "", err
		}
		commandCtx, commandCancel := context.WithTimeout(commandParent, 2*time.Second)
		defer commandCancel()
		out, err := command(commandCtx, args...)
		if commandCtx.Err() != nil {
			return "", commandCtx.Err()
		}
		remaining := &serviceRemaining
		if isPF {
			remaining = &pfRemaining
		}
		*remaining -= len(out.Stdout) + len(out.Stderr)
		if len(out.Stdout) > 1<<20 || len(out.Stderr) > 8192 || *remaining < 0 {
			return "", errors.New("coexistence observation output limit exceeded")
		}
		if err != nil {
			return "", err
		}
		diagnostic := strings.TrimSpace(out.Stderr)
		const altq = "No ALTQ support in kernel\nALTQ related functions disabled"
		if diagnostic != "" && (!isPF || diagnostic != altq) {
			return "", errors.New("unsupported coexistence command diagnostic")
		}
		return out.Stdout, nil
	}
	// PF bytes are opaque. A failed read does not imply an empty or absent anchor.
	state := CoexistenceState{
		MainRulesStatus: "unavailable",
		Anchors:         make([]AnchorRulesDigest, 0, len(c.CoexistingAnchors)),
		Services:        make([]ServicePID, 0, len(c.CoexistingServices)),
	}
	// Required service observations have their own budget and run first so PF
	// unavailability cannot consume their bounded observation window.
	for _, label := range c.CoexistingServices {
		text, err := query(launchctl, false, "print", "system/"+label)
		if err != nil {
			return CoexistenceState{}, fmt.Errorf("coexisting system service %q: %w", label, err)
		}
		pid, err := coexistenceServicePID(label, text)
		if err != nil {
			return CoexistenceState{}, fmt.Errorf("coexisting system service %q: %w", label, err)
		}
		state.Services = append(state.Services, ServicePID{label, pid})
	}
	mainFilter, filterErr := query(pf, true, "-sr")
	mainTranslation, translationErr := query(pf, true, "-sn")
	if filterErr == nil && translationErr == nil {
		state.MainRulesStatus = "available"
		state.MainRulesSHA256 = coexistenceMainDigest(mainFilter, mainTranslation)
	}
	for _, path := range c.CoexistingAnchors {
		anchor := AnchorRulesDigest{Path: path, Status: "unavailable"}
		filter, filterErr := query(pf, true, "-a", path, "-sr")
		translation, translationErr := query(pf, true, "-a", path, "-sn")
		if filterErr == nil && translationErr == nil {
			anchor.Status = "available"
			anchor.FilterSHA256 = digest([]byte(filter))
			anchor.TranslationSHA256 = digest([]byte(translation))
		}
		state.Anchors = append(state.Anchors, anchor)
	}
	state.RecordedAt = time.Now().UTC()
	return state, nil
}

func coexistenceMainDigest(filter, translation string) string {
	h := sha256.New()
	var length [8]byte
	for _, text := range [...]string{filter, translation} {
		binary.BigEndian.PutUint64(length[:], uint64(len(text)))
		h.Write(length[:])
		io.WriteString(h, text)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Accept the newline-terminated `launchctl print system/LABEL` dictionary, with
// one unquoted depth-one `state = running` and one canonical positive `pid = N`.
// Nested dictionaries and quoted values may contain health-looking text, but
// never provide the service's state/PID. Unsupported or truncated syntax fails.
func coexistenceServicePID(label, text string) (int, error) {
	bad := errors.New("service is not verifiably running with one canonical PID")
	if !coexistenceServiceLabel(label) || len(text) > 1<<20 {
		return 0, bad
	}
	first, text, complete := strings.Cut(text, "\n")
	if !complete || first != "system/"+label+" = {" {
		return 0, bad
	}
	depth, pid := 1, 0
	stateSeen, pidSeen := false, false
	for text != "" {
		line, rest, complete := strings.Cut(text, "\n")
		if !complete {
			return 0, bad
		}
		text = rest
		trimmed := strings.TrimSpace(line)
		braces, ok := coexistenceLineSyntax(line)
		if !ok {
			return 0, bad
		}
		if trimmed == "" {
			continue
		}
		if trimmed == "}" {
			depth--
			if depth == 0 {
				if text != "" || !stateSeen || !pidSeen {
					return 0, bad
				}
				return pid, nil
			}
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			return 0, bad
		}
		key, value, property := strings.Cut(strings.TrimLeft(line, " \t"), " = ")
		if depth == 1 {
			if !property || key == "" || key != strings.TrimSpace(key) || strings.ContainsAny(key, "\"{}\\\t") {
				return 0, bad
			}
			switch key {
			case "state":
				if stateSeen || value != "running" {
					return 0, bad
				}
				stateSeen = true
			case "pid":
				parsed, err := strconv.ParseInt(value, 10, 32)
				if pidSeen || err != nil || parsed <= 0 || strconv.FormatInt(parsed, 10) != value {
					return 0, bad
				}
				pid, pidSeen = int(parsed), true
			}
		}
		if braces != 0 {
			if braces != 1 || !property || !strings.HasSuffix(trimmed, " = {") || depth >= 16 {
				return 0, bad
			}
			depth++
		}
	}
	return 0, bad
}

// Quotes are line-local. Braces inside quoted strings are data, not dictionaries;
// unquoted closing braces are accepted only as a standalone dictionary close.
func coexistenceLineSyntax(line string) (int, bool) {
	quoted, escaped := false, false
	braces := 0
	for _, c := range line {
		if c < ' ' && c != '\t' || c == 127 {
			return 0, false
		}
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' && quoted {
			escaped = true
			continue
		}
		if c == '"' {
			quoted = !quoted
		} else if !quoted && c == '{' {
			braces++
		} else if !quoted && c == '}' && strings.TrimSpace(line) != "}" {
			return 0, false
		}
	}
	return braces, !quoted && !escaped
}

func validCoexistenceState(state CoexistenceState) error {
	if state.RecordedAt.IsZero() || !validMeasurement(state.MainRulesStatus, state.MainRulesSHA256) || len(state.Anchors) > coexistenceListLimit || len(state.Services) > coexistenceListLimit {
		return errors.New("incomplete coexistence state")
	}
	for i, anchor := range state.Anchors {
		if !pfctl.AnchorPath(anchor.Path) || !validMeasurement(anchor.Status, anchor.FilterSHA256, anchor.TranslationSHA256) || i > 0 && state.Anchors[i-1].Path >= anchor.Path {
			return errors.New("invalid or noncanonical coexistence anchor state")
		}
	}
	for i, service := range state.Services {
		if !coexistenceServiceLabel(service.Label) || service.PID <= 0 || int64(service.PID) > 1<<31-1 || i > 0 && state.Services[i-1].Label >= service.Label {
			return errors.New("invalid or noncanonical coexistence service state")
		}
	}
	return nil
}

func validMeasurement(status string, digests ...string) bool {
	if status != "available" && status != "unavailable" {
		return false
	}
	for _, d := range digests {
		if status == "available" && !validDigest(d) || status == "unavailable" && d != "" {
			return false
		}
	}
	return true
}

// SameCoexistingServices validates canonical observations and unchanged running
// service PIDs. Current PF bytes and availability do not gate health.
func SameCoexistingServices(before, after CoexistenceState) error {
	if err := validCoexistenceState(before); err != nil {
		return err
	}
	if err := validCoexistenceState(after); err != nil {
		return err
	}
	if after.RecordedAt.Before(before.RecordedAt) || !slices.Equal(before.Services, after.Services) {
		return errors.New("coexisting running service PIDs changed, or observation time regressed")
	}
	return nil
}

// SameCoexistence compares the configured sets, services and any mutually
// available opaque rule measurements across one observation window.
func SameCoexistence(before, after CoexistenceState) error {
	if err := SameCoexistingServices(before, after); err != nil {
		return err
	}
	if len(before.Anchors) != len(after.Anchors) {
		return errors.New("coexisting anchor set changed")
	}
	if before.MainRulesStatus == "available" && after.MainRulesStatus == "available" && before.MainRulesSHA256 != after.MainRulesSHA256 {
		return errors.New("main PF rules changed")
	}
	for i, old := range before.Anchors {
		current := after.Anchors[i]
		if old.Path != current.Path {
			return errors.New("coexisting anchor set changed")
		}
		if old.Status == "available" && current.Status == "available" && (old.FilterSHA256 != current.FilterSHA256 || old.TranslationSHA256 != current.TranslationSHA256) {
			return fmt.Errorf("coexisting PF rules changed: %s", old.Path)
		}
	}
	return nil
}

func ValidateCoexistenceEvidence(e CoexistenceEvidence, current CoexistenceState) error {
	if err := SameCoexistence(e.Before, e.After); err != nil {
		return err
	}
	return SameCoexistingServices(e.After, current)
}

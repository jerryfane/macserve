package worker

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"
)

// Contamination refusals name the processes they refuse. Before v0.1.15 the
// error said only "processes outside audited GUI baseline", and a field
// failure (an Apple agent whose plist program has a redundant separator)
// could only be diagnosed from the host's unified log. The full list reaches
// only root: the quarantine record, the broker's log and admission status,
// and the stderr of root-run qualification commands. What leaves the host as
// a job's reason is PublicReason.

const (
	contaminationEntries   = 8
	contaminationPathBytes = 160
	contaminationRuleBytes = 200
)

// contamination is ErrContamination observed for specific job processes.
type contamination struct {
	what    string
	entries []string
	total   int
}

func (c *contamination) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s: %d unexpected process(es)", ErrContamination, c.what, c.total)
	for _, e := range c.entries {
		b.WriteString("\n  ")
		b.WriteString(e)
	}
	if more := c.total - len(c.entries); more > 0 {
		fmt.Fprintf(&b, "\n  +%d more", more)
	}
	return b.String()
}

func (c *contamination) Unwrap() error { return ErrContamination }

// contaminated returns ErrContamination for census c's residual processes:
// by PID, at most contaminationEntries of them, each with its kernel parent
// and executable, the launchd target a tolerance rule found and why each rule
// refused it. Every field is bounded, so the error stays a few KiB.
func (s *processScope) contaminated(what string, c processCensus) error {
	residual := slices.SortedFunc(slices.Values(c.residual), func(a, b processSample) int { return a.pid - b.pid })
	err := &contamination{what: what, total: len(residual)}
	for _, p := range residual[:min(len(residual), contaminationEntries)] {
		entry := fmt.Sprintf("pid=%d start=%s", p.pid, p.start)
		if s.agents != nil {
			if k, kerr := s.agents.kernel(p.pid); kerr == nil && k.start == p.start {
				entry += fmt.Sprintf(" ppid=%d exe=%q", k.ppid, clip(k.executable, contaminationPathBytes))
			} else {
				entry += " exe=unavailable"
			}
		}
		r, ok := c.refused[p.pid]
		if r.target != "" {
			entry += fmt.Sprintf(" target=%q", clip(r.target, contaminationPathBytes))
		}
		entry += ": not audited and not a verified launchd relaunch"
		if ok {
			entry += "; apple: " + clip(errorText(r.apple), contaminationRuleBytes) + "; developer-tool: " + clip(errorText(r.developerTool), contaminationRuleBytes)
		} else if s.adopt != nil {
			entry += "; not adoptable during worker-reset"
		}
		err.entries = append(err.entries, entry)
	}
	return err
}

func errorText(err error) string {
	if err == nil {
		return "not evaluated"
	}
	return strings.ReplaceAll(err.Error(), "\n", "; ")
}

// clip returns at most n bytes of s, cut at a UTF-8 boundary, marked when cut.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// PublicReason is err's text for a reason that leaves the host (a job's
// reason sent to the controller and its API clients): each contamination
// refusal, with its process list, is replaced by its count.
func PublicReason(err error) string {
	if err == nil {
		return ""
	}
	return publicError(err).Error()
}

func publicError(err error) error {
	var c *contamination
	if errors.As(err, &c) && err == error(c) {
		return fmt.Errorf("job-user contamination: %d unexpected process(es); see host diagnostics", c.total)
	}
	switch e := err.(type) {
	case interface{ Unwrap() []error }:
		var parts []error
		for _, part := range e.Unwrap() {
			if part != nil {
				parts = append(parts, publicError(part))
			}
		}
		if hasContamination(err) {
			return errors.Join(parts...)
		}
	case interface{ Unwrap() error }:
		if inner := e.Unwrap(); hasContamination(inner) {
			// A wrapper's own text embeds the detail; keep only the count.
			return publicError(inner)
		}
	}
	return err
}

func hasContamination(err error) bool {
	var c *contamination
	return errors.As(err, &c)
}

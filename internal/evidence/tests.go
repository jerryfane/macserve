package evidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"
)

var (
	ErrInvalidTests  = errors.New("invalid or incomplete test evidence")
	ErrRequiredTests = errors.New("required tests did not execute")
)

// MaxTestsBytes bounds both xcresulttool capture and parser input.
const MaxTestsBytes = 32 << 20
const maxTestDepth = 128

// xcresultNode is the pinned xcresulttool test-results tests schema 0.4.0.
// Presentation-only fields are deliberately ignored, not interpreted as results.
type xcresultNode struct {
	Type       string         `json:"nodeType"`
	Name       string         `json:"name"`
	Identifier string         `json:"nodeIdentifier"`
	Duration   string         `json:"duration"`
	Seconds    testDuration   `json:"durationInSeconds"`
	Result     string         `json:"result"`
	Children   []xcresultNode `json:"children"`
}

type testDuration struct {
	value   float64
	present bool
}

func (d *testDuration) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return fmt.Errorf("%w: null duration", ErrInvalidTests)
	}
	if err := json.Unmarshal(data, &d.value); err != nil {
		return err
	}
	d.present = true
	return nil
}

type xcresultTests struct {
	Configurations []xcresultConfiguration `json:"testPlanConfigurations"`
	Devices        []xcresultDevice        `json:"devices"`
	Nodes          []xcresultNode          `json:"testNodes"`
}

type xcresultConfiguration struct {
	ID   *string `json:"configurationId"`
	Name *string `json:"configurationName"`
}

type xcresultDevice struct {
	ID           *string `json:"deviceId"`
	Name         *string `json:"deviceName"`
	Architecture *string `json:"architecture"`
	Model        *string `json:"modelName"`
	OSVersion    *string `json:"osVersion"`
}

var durationPart = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)?)\s*(days?|hours?|minutes?|seconds?|mins?|secs?|ms|us|µs|ns|d|h|m|s)`)

func nodeDuration(n xcresultNode) (float64, error) {
	if n.Seconds.present {
		if !finiteDuration(n.Seconds.value) {
			return 0, fmt.Errorf("%w: invalid duration for %q", ErrInvalidTests, n.Name)
		}
		return n.Seconds.value, nil
	}
	if n.Duration == "" {
		return 0, nil
	}
	remaining := strings.TrimSpace(n.Duration)
	if remaining == "" {
		return 0, fmt.Errorf("%w: empty duration", ErrInvalidTests)
	}
	total, previous := float64(0), math.Inf(1)
	for remaining != "" {
		part := durationPart.FindStringSubmatch(remaining)
		if part == nil {
			return 0, fmt.Errorf("%w: unsupported duration %q", ErrInvalidTests, n.Duration)
		}
		value, err := strconv.ParseFloat(part[1], 64)
		if err != nil {
			return 0, fmt.Errorf("%w: invalid duration %q", ErrInvalidTests, n.Duration)
		}
		var scale float64
		switch part[2] {
		case "d", "day", "days":
			scale = 86400
		case "h", "hour", "hours":
			scale = 3600
		case "m", "min", "mins", "minute", "minutes":
			scale = 60
		case "s", "sec", "secs", "second", "seconds":
			scale = 1
		case "ms":
			scale = .001
		case "us", "µs":
			scale = .000001
		case "ns":
			scale = .000000001
		}
		if scale >= previous {
			return 0, fmt.Errorf("%w: repeated or unordered duration units", ErrInvalidTests)
		}
		previous = scale
		total += value * scale
		remaining = strings.TrimSpace(remaining[len(part[0]):])
		if strings.HasPrefix(remaining, ",") {
			remaining = strings.TrimSpace(remaining[1:])
			if remaining == "" {
				return 0, fmt.Errorf("%w: trailing duration separator", ErrInvalidTests)
			}
		}
	}
	if !finiteDuration(total) {
		return 0, fmt.Errorf("%w: invalid duration", ErrInvalidTests)
	}
	return total, nil
}

func finiteDuration(v float64) bool { return v >= 0 && !math.IsNaN(v) && !math.IsInf(v, 0) }

func boundedTestJSON(data []byte) error {
	if len(data) > MaxTestsBytes {
		return fmt.Errorf("%w: report exceeds 32 MiB", ErrInvalidTests)
	}
	depth, quoted, escaped := 0, false, false
	for _, c := range data {
		if quoted {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				quoted = false
			}
			continue
		}
		switch c {
		case '"':
			quoted = true
		case '{', '[':
			depth++
			if depth > maxTestDepth {
				return fmt.Errorf("%w: report nesting exceeds limit", ErrInvalidTests)
			}
		case '}', ']':
			depth--
		}
	}
	return nil
}

func outcome(result string) (string, error) {
	switch result {
	case "Passed":
		return "passed", nil
	case "Failed":
		return "failed", nil
	case "Skipped":
		return "skipped", nil
	case "Expected Failure":
		return "expected-failure", nil
	default:
		return "", fmt.Errorf("%w: unknown test outcome %q", ErrInvalidTests, result)
	}
}

func executionNode(kind string) bool {
	return kind == "Test Case" || kind == "Test Case Run" || kind == "Repetition"
}

func containerNode(kind string) bool {
	switch kind {
	case "Test Plan", "Unit test bundle", "UI test bundle", "Test Suite", "Device", "Test Plan Configuration", "Arguments":
		return true
	default:
		return false
	}
}

func validateNode(n xcresultNode) error {
	if n.Name == "" {
		return fmt.Errorf("%w: node has no name", ErrInvalidTests)
	}
	switch n.Type {
	case "Test Plan", "Unit test bundle", "UI test bundle", "Test Suite", "Test Case", "Device", "Test Plan Configuration", "Arguments", "Repetition", "Test Case Run", "Failure Message", "Source Code Reference", "Attachment", "Expression", "Test Value", "Runtime Warning", "Skip Message", "Expected Failure":
	default:
		return fmt.Errorf("%w: unknown node type %q", ErrInvalidTests, n.Type)
	}
	if _, err := nodeDuration(n); err != nil {
		return err
	}
	if (executionNode(n.Type) || containerNode(n.Type)) && n.Result != "" {
		if _, err := outcome(n.Result); err != nil {
			return err
		}
	}
	for _, child := range n.Children {
		if err := validateNode(child); err != nil {
			return err
		}
	}
	return nil
}

func failures(n xcresultNode) []string {
	var messages []string
	if n.Type == "Failure Message" {
		messages = append(messages, n.Name)
	}
	for _, child := range n.Children {
		messages = append(messages, failures(child)...)
	}
	return messages
}

type testParser struct {
	summary  Summary
	attempts map[string]int
	// scope is the suite of the Test Case node being emitted, before
	// per-device, configuration or argument labels extend it.
	scope string
	// retry is the job's retry iterations (0: no retries). In a retry job,
	// repetition is the label of the Repetition node being emitted when it
	// belongs to a proper retry sequence (retrySequence), ambiguous records
	// that the Test Case being emitted has a Device without an identifier,
	// and groups counts the attempt groups (retryGroups) of earlier Test
	// Case nodes by case identity.
	retry      int
	repetition string
	ambiguous  bool
	groups     map[caseKey]int
}

func (p *testParser) emit(n xcresultNode, id, suite, name string) error {
	status, err := outcome(n.Result)
	if err != nil {
		return err
	}
	seconds, err := nodeDuration(n)
	if err != nil {
		return err
	}
	messages := failures(n)
	if status == "passed" && len(messages) != 0 {
		status = "failed"
	}
	p.attempts[id]++
	c := TestCase{ID: id, Suite: suite, Name: name, Outcome: status, DurationSeconds: seconds, Failures: messages, Attempt: p.attempts[id]}
	if p.scope != suite {
		c.Scope = p.scope
	}
	if n.Type == "Repetition" && p.repetition != "" && n.Name == p.repetition {
		c.Repetition = n.Name
	}
	p.summary.Cases = append(p.summary.Cases, c)
	return nil
}

// firstRun is the label xcodebuild -retry-tests-on-failure gives a test's
// first attempt; its retries are "Retry 1", "Retry 2"...
const firstRun = "First Run"

func retryLabel(attempt int) string {
	if attempt == 0 {
		return firstRun
	}
	return "Retry " + strconv.Itoa(attempt)
}

// retrySequence reports whether children are the attempts of one test
// under one parent as xcodebuild records a retry: only Repetition nodes,
// labelled First Run, Retry 1, ... in order.
func retrySequence(children []xcresultNode) bool {
	repetitions := 0
	for _, child := range children {
		if executionNode(child.Type) && (child.Type != "Repetition" || child.Name != retryLabel(repetitions)) {
			return false
		}
		if child.Type == "Repetition" {
			repetitions++
		}
	}
	return repetitions > 0
}

// Executions emits only the deepest run/repetition, retaining every attempt.
// Failure messages on an aggregate case supplement its failing run, but an
// aggregate failure with only successful leaves is incomplete evidence.
func (p *testParser) executions(n xcresultNode, id, suite, name string) (bool, error) {
	start := len(p.summary.Cases)
	found := false
	retries := p.retry > 0 && retrySequence(n.Children)
	for _, child := range n.Children {
		if child.Type == "Test Case" {
			return false, fmt.Errorf("%w: nested test case", ErrInvalidTests)
		}
		childSuite := suite
		if child.Type == "Device" || child.Type == "Test Plan Configuration" || child.Type == "Arguments" {
			childSuite = joinTestPath(suite, nodeLabel(child))
		}
		if child.Type == "Device" && child.Identifier == "" {
			p.ambiguous = true
		}
		outer := p.repetition
		if retries && child.Type == "Repetition" {
			p.repetition = child.Name
		}
		present, err := p.executions(child, id, childSuite, name)
		p.repetition = outer
		if err != nil {
			return false, err
		}
		found = found || present
	}
	if executionNode(n.Type) {
		if !found {
			if err := p.emit(n, id, suite, name); err != nil {
				return false, err
			}
			return true, nil
		}
		if n.Result == "Failed" {
			failed := false
			for i := start; i < len(p.summary.Cases); i++ {
				if p.summary.Cases[i].Outcome == "failed" {
					failed = true
					if len(p.summary.Cases[i].Failures) == 0 {
						p.summary.Cases[i].Failures = failures(n)
					}
				}
			}
			if !failed {
				return false, fmt.Errorf("%w: failed aggregate %q has no failing execution", ErrInvalidTests, name)
			}
		}
		return true, nil
	}
	return found, nil
}

func nodeLabel(n xcresultNode) string {
	if n.Identifier != "" {
		return n.Identifier
	}
	return n.Name
}

func joinTestPath(parent, child string) string {
	if parent == "" || child == parent || strings.HasPrefix(child, parent+"/") {
		return child
	}
	for end := strings.LastIndexByte(child, '/'); end > 0; end = strings.LastIndexByte(child[:end], '/') {
		prefix := child[:end]
		if parent == prefix || strings.HasSuffix(parent, "/"+prefix) {
			return parent + child[end:]
		}
	}
	return parent + "/" + child
}

// A failed container explained by a failed descendant contributes diagnostics,
// not another failure count. Distinct ancestor messages stay on a failed case.
// A superseded attempt (one a retry passed) explains only the container
// failure it rolls up: a container whose only failed descendants are
// superseded and that has messages of its own (a suite teardown failure, for
// example) keeps them on a failed diagnostic record.
func (p *testParser) containerFailure(n xcresultNode, path string, start int) {
	target := -1
	superseded := false
	seen := make(map[string]bool)
	for i := start; i < len(p.summary.Cases); i++ {
		c := &p.summary.Cases[i]
		if c.Outcome == "failed" && c.Superseded {
			superseded = true
		} else if c.Outcome == "failed" {
			target = i
		}
		for _, message := range c.Failures {
			seen[message] = true
		}
	}
	messages := failures(n)
	if target == -1 && superseded {
		var own []string
		for _, message := range messages {
			if !seen[message] {
				own = append(own, message)
			}
		}
		if len(own) == 0 {
			return
		}
	}
	if target == -1 {
		// This record is diagnostic only: it cannot satisfy required selections
		// or the requirement that at least one test actually executed.
		target = len(p.summary.Cases)
		p.summary.Cases = append(p.summary.Cases, TestCase{
			ID: path, Suite: path, Name: n.Name, Outcome: "failed",
			Attempt: 1, Container: true,
		})
		messages = append([]string{n.Type + " " + path + " failed"}, messages...)
	}
	for _, message := range messages {
		if !seen[message] {
			p.summary.Cases[target].Failures = append(p.summary.Cases[target].Failures, message)
			seen[message] = true
		}
	}
}

func (p *testParser) visit(n xcresultNode, parent string) error {
	if n.Type == "Test Case" {
		id := n.Identifier
		if id == "" {
			id = joinTestPath(parent, n.Name)
		}
		suite := parent
		if index := strings.LastIndexByte(id, '/'); index >= 0 {
			identifierSuite := id[:index]
			if suite == "" {
				suite = identifierSuite
			}
		}
		start := len(p.summary.Cases)
		p.scope, p.ambiguous = suite, false
		_, err := p.executions(n, id, suite, n.Name)
		if err != nil {
			return err
		}
		messages := failures(n)
		if len(messages) != 0 {
			seen := make(map[string]bool, len(messages))
			target := start
			for i := start; i < len(p.summary.Cases); i++ {
				c := &p.summary.Cases[i]
				if c.Outcome == "failed" || c.Outcome == "expected-failure" {
					target = i
				}
				for _, message := range c.Failures {
					seen[message] = true
				}
			}
			if p.retry > 0 {
				// A case's own message that no attempt records is not
				// attributable to a retried attempt: it fails the last one.
				target = len(p.summary.Cases) - 1
			}
			for _, message := range messages {
				if !seen[message] {
					p.summary.Cases[target].Failures = append(p.summary.Cases[target].Failures, message)
					if p.summary.Cases[target].Outcome == "passed" {
						p.summary.Cases[target].Outcome = "failed"
					}
					seen[message] = true
				}
			}
		}
		return p.markRetries(start)
	}
	if n.Type == "Test Case Run" || n.Type == "Repetition" {
		return fmt.Errorf("%w: execution without a test case", ErrInvalidTests)
	}
	if containerNode(n.Type) {
		parent = joinTestPath(parent, nodeLabel(n))
	}
	start := len(p.summary.Cases)
	for _, child := range n.Children {
		if err := p.visit(child, parent); err != nil {
			return err
		}
	}
	if containerNode(n.Type) && n.Result == "Failed" {
		p.containerFailure(n, parent, start)
	}
	return nil
}

// RequiredMatch reports whether case c satisfies the required test selector
// by name; the outcome is the caller's to check. It accepts an exact or
// "/"-prefix match of the case ID or suite, or a bundle-relative selector
// Target/Class[/method]. Real Xcode reports class-relative case identifiers
// ("Class/method()") under a suite path that starts with the test plan
// ("Plan/Target/Class"), so the selector also matches when the case's scope
// (its suite before per-device labels) ends in [Target, Class] and, for a
// method selector, the case ID is Class/method or Class/method(). Receipt
// validation applies the same rule to the recorded cases.
func RequiredMatch(c TestCase, required string) bool {
	if c.Container {
		return false
	}
	if c.ID == required || c.Suite == required || strings.HasPrefix(c.ID, required+"/") || strings.HasPrefix(c.Suite, required+"/") {
		return true
	}
	scope := c.Suite
	if c.Scope != "" {
		scope = c.Scope
	}
	selector := strings.Split(required, "/")
	if len(selector) != 2 && len(selector) != 3 {
		return false
	}
	for _, part := range selector {
		if part == "" {
			return false
		}
	}
	path := strings.Split(scope, "/")
	if len(path) < 2 || path[len(path)-2] != selector[0] || path[len(path)-1] != selector[1] {
		return false
	}
	if len(selector) == 2 {
		return true
	}
	method := strings.TrimSuffix(selector[2], "()")
	if strings.ContainsAny(method, "()") {
		return false
	}
	method = selector[1] + "/" + method
	return c.ID == method || c.ID == method+"()"
}

type caseKey struct{ id, suite string }

func keyOf(c TestCase) caseKey { return caseKey{c.ID, c.Suite} }

// retryGroups splits the non-container cases into attempt groups: a run of
// consecutive cases of one ID and suite whose Repetition labels are First
// Run, Retry 1, ... in order is one group (the parser labels only such a
// sequence recorded under one parent node); every other case is a group of
// its own.
func retryGroups(cases []TestCase) [][]int {
	var groups [][]int
	for i := 0; i < len(cases); i++ {
		if cases[i].Container {
			continue
		}
		group := []int{i}
		if cases[i].Repetition == firstRun {
			for j := i + 1; j < len(cases) && !cases[j].Container && keyOf(cases[j]) == keyOf(cases[i]) && cases[j].Repetition == retryLabel(len(group)); j++ {
				group = append(group, j)
			}
		}
		groups = append(groups, group)
		i = group[len(group)-1]
	}
	return groups
}

// MarkRetries applies a retry job's verdict to its parsed cases. Only
// xcodebuild's own retry provenance makes attempts one test's: a group of
// attempts labelled First Run, Retry 1, ... (retryGroups) passes on retry
// when its last attempt passed or was an expected failure. That attempt is
// marked Retried with its FailedAttempts and the failed ones Superseded. A
// group whose last attempt failed stays failed on every attempt, and so does
// a group whose identity (ID and suite) is ambiguous: shared with another
// group or case, as two devices with one display name are. xcodebuild
// retries only a failure, so a group attempt other than the last that did
// not fail, or more attempts than iterations, is invalid evidence. It first
// clears earlier marks. With iterations 0 (no retries) it changes nothing.
// Receipt validation reapplies it to the recorded cases.
func MarkRetries(cases []TestCase, iterations int) error {
	if iterations == 0 {
		return nil
	}
	for i := range cases {
		cases[i].Retried, cases[i].FailedAttempts, cases[i].Superseded = false, 0, false
	}
	groups := retryGroups(cases)
	identities := make(map[caseKey]int, len(groups))
	for _, group := range groups {
		identities[keyOf(cases[group[0]])]++
	}
	for _, group := range groups {
		first := cases[group[0]]
		if len(group) > iterations {
			return fmt.Errorf("%w: %q has %d attempts, more than %d", ErrInvalidTests, first.ID, len(group), iterations)
		}
		earlier, last := group[:len(group)-1], &cases[group[len(group)-1]]
		for _, i := range earlier {
			if cases[i].Outcome != "failed" {
				return fmt.Errorf("%w: %q was retried after a %s attempt", ErrInvalidTests, first.ID, cases[i].Outcome)
			}
		}
		if len(earlier) == 0 || identities[keyOf(first)] > 1 || last.Outcome != "passed" && last.Outcome != "expected-failure" {
			continue
		}
		last.Retried, last.FailedAttempts = true, len(earlier)
		for _, i := range earlier {
			cases[i].Superseded = true
		}
	}
	return nil
}

// markRetries applies MarkRetries to the cases of the Test Case node whose
// first case is start, so that its enclosing containers see which failures
// a retry superseded (containerFailure). A Device without an identifier in
// the node makes its attempts' identity ambiguous: they lose their retry
// labels. An identity an earlier node already recorded is ambiguous too;
// ParseTests' final MarkRetries also unmarks that earlier node's.
func (p *testParser) markRetries(start int) error {
	if p.retry == 0 {
		return nil
	}
	cases := p.summary.Cases[start:]
	if p.ambiguous {
		for i := range cases {
			cases[i].Repetition = ""
		}
	}
	if err := MarkRetries(cases, p.retry); err != nil {
		return err
	}
	for _, group := range retryGroups(cases) {
		key := keyOf(cases[group[0]])
		if p.groups[key] > 0 {
			for _, i := range group {
				cases[i].Retried, cases[i].FailedAttempts, cases[i].Superseded = false, 0, false
			}
		}
		p.groups[key]++
	}
	return nil
}

// ParseTests parses only schema 0.4.0's test tree, not command exit status.
// Failed tests are valid evidence and return a summary with a nil error.
// retryIterations is the job's retry opt-in
// (model.Profile.RetryIterations): nonzero, attempts get their retry labels
// and a case that passes on retry (MarkRetries) does not count as failed.
func ParseTests(data []byte, required []string, retryIterations int) (Summary, error) {
	p := testParser{summary: Summary{SchemaVersion: 1, ParserVersion: "xcresult-tests-0.4.0", ParseStatus: "invalid", Cases: []TestCase{}, RequiredTests: append([]string(nil), required...)}, attempts: make(map[string]int), retry: retryIterations, groups: make(map[caseKey]int)}
	if err := boundedTestJSON(data); err != nil {
		return p.summary, err
	}
	var report xcresultTests
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&report); err != nil {
		return p.summary, fmt.Errorf("%w: %v", ErrInvalidTests, err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return p.summary, fmt.Errorf("%w: trailing report data", ErrInvalidTests)
	}
	if report.Configurations == nil || report.Devices == nil || report.Nodes == nil {
		return p.summary, fmt.Errorf("%w: required report arrays missing", ErrInvalidTests)
	}
	for _, configuration := range report.Configurations {
		if configuration.ID == nil || configuration.Name == nil {
			return p.summary, fmt.Errorf("%w: configuration fields missing", ErrInvalidTests)
		}
	}
	for _, device := range report.Devices {
		if device.ID == nil || device.Name == nil || device.Architecture == nil || device.Model == nil || device.OSVersion == nil {
			return p.summary, fmt.Errorf("%w: device fields missing", ErrInvalidTests)
		}
	}
	for _, n := range report.Nodes {
		if err := validateNode(n); err != nil {
			return p.summary, err
		}
		if err := p.visit(n, ""); err != nil {
			return p.summary, err
		}
	}
	if err := MarkRetries(p.summary.Cases, retryIterations); err != nil {
		return p.summary, err
	}
	executed := 0
	for _, c := range p.summary.Cases {
		if !c.Container && c.Outcome != "skipped" {
			executed++
		}
		p.summary.Tests++
		p.summary.DurationSeconds += c.DurationSeconds
		if c.Retried {
			p.summary.Retried++
		}
		switch {
		case c.Superseded:
			p.summary.Superseded++
		case c.Outcome == "passed":
			p.summary.Passed++
		case c.Outcome == "failed":
			p.summary.Failed++
		case c.Outcome == "skipped":
			p.summary.Skipped++
		case c.Outcome == "expected-failure":
			p.summary.ExpectedFailures++
		}
	}
	if !finiteDuration(p.summary.DurationSeconds) {
		return p.summary, fmt.Errorf("%w: total duration overflow", ErrInvalidTests)
	}
	p.summary.ParseStatus = "incomplete"
	if executed == 0 {
		return p.summary, fmt.Errorf("%w: no executed tests", ErrInvalidTests)
	}
	for _, name := range required {
		executed := false
		for _, c := range p.summary.Cases {
			if name != "" && RequiredMatch(c, name) && c.Outcome != "skipped" {
				executed = true
				break
			}
		}
		if !executed {
			return p.summary, fmt.Errorf("%w: %q", ErrRequiredTests, name)
		}
	}
	p.summary.ParseStatus = "parsed"
	return p.summary, nil
}

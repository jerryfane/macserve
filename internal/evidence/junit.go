package evidence

import (
	"encoding/xml"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type junitReport struct {
	XMLName  xml.Name     `xml:"testsuites"`
	Tests    int          `xml:"tests,attr"`
	Failures int          `xml:"failures,attr"`
	Skipped  int          `xml:"skipped,attr"`
	Time     string       `xml:"time,attr"`
	Suites   []junitSuite `xml:"testsuite"`
}

type junitSuite struct {
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Skipped  int         `xml:"skipped,attr"`
	Time     string      `xml:"time,attr"`
	Cases    []junitCase `xml:"testcase"`
}

type junitCase struct {
	ID      string        `xml:"id,attr"`
	Class   string        `xml:"classname,attr"`
	Name    string        `xml:"name,attr"`
	Time    string        `xml:"time,attr"`
	Attempt int           `xml:"attempt,attr"`
	Failure *junitMessage `xml:"failure,omitempty"`
	Skipped *junitMessage `xml:"skipped,omitempty"`
}

type junitMessage struct {
	Type    string `xml:"type,attr"`
	Message string `xml:"message,attr,omitempty"`
	Text    string `xml:",chardata"`
}

func junitTime(seconds float64) string { return strconv.FormatFloat(seconds, 'f', -1, 64) }

// JUnit preserves failed attempts and renders expected failures as explicit
// skipped cases, never as ordinary successes. Suites are sorted; attempts retain
// the test tree's order within their suite.
func JUnit(summary Summary) ([]byte, error) {
	groups := make(map[string][]TestCase)
	for _, c := range summary.Cases {
		groups[c.Suite] = append(groups[c.Suite], c)
	}
	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	sort.Strings(names)
	report := junitReport{}
	total := float64(0)
	for _, name := range names {
		suite := junitSuite{Name: name}
		seconds := float64(0)
		for _, c := range groups[name] {
			if c.ID == "" || c.Name == "" || c.Attempt < 1 || !finiteDuration(c.DurationSeconds) {
				return nil, fmt.Errorf("%w: invalid normalized test case", ErrInvalidTests)
			}
			item := junitCase{ID: c.ID, Class: c.Suite, Name: c.Name, Time: junitTime(c.DurationSeconds), Attempt: c.Attempt}
			switch c.Outcome {
			case "passed":
			case "failed":
				text := strings.Join(c.Failures, "\n")
				item.Failure = &junitMessage{Type: "failure", Message: text, Text: text}
				suite.Failures++
			case "skipped", "expected-failure":
				item.Skipped = &junitMessage{Type: c.Outcome, Text: strings.Join(c.Failures, "\n")}
				suite.Skipped++
			default:
				return nil, fmt.Errorf("%w: invalid normalized outcome %q", ErrInvalidTests, c.Outcome)
			}
			suite.Tests++
			seconds += c.DurationSeconds
			suite.Cases = append(suite.Cases, item)
		}
		suite.Time = junitTime(seconds)
		report.Tests += suite.Tests
		report.Failures += suite.Failures
		report.Skipped += suite.Skipped
		total += seconds
		report.Suites = append(report.Suites, suite)
	}
	if !finiteDuration(total) {
		return nil, fmt.Errorf("%w: total duration overflow", ErrInvalidTests)
	}
	report.Time = junitTime(total)
	data, err := xml.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), append(data, '\n')...), nil
}

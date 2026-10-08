package evidence

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"math"
	"strings"
	"testing"
)

const nestedTestReport = `{
  "testPlanConfigurations":[{"configurationId":"configuration-1","configurationName":"Debug"}],
  "devices":[{"deviceId":"device-1","deviceName":"Example Phone","architecture":"arm64","modelName":"Example Phone","osVersion":"18.0"}],
  "testNodes":[{"nodeType":"Test Plan","name":"Example Plan","children":[
    {"nodeType":"Unit test bundle","name":"ExampleTests","nodeIdentifier":"ExampleTests","children":[
      {"nodeType":"Test Suite","name":"Flow","nodeIdentifier":"ExampleTests/Flow","children":[
        {"nodeType":"Test Case","name":"testRepeated()","nodeIdentifier":"ExampleTests/Flow/testRepeated()","result":"Failed","durationInSeconds":99,"children":[
          {"nodeType":"Arguments","name":"value: 1","children":[
            {"nodeType":"Repetition","name":"Repetition 1","result":"Failed","durationInSeconds":0.2,"children":[{"nodeType":"Failure Message","name":"expected <ready> & got \"waiting\""}]},
            {"nodeType":"Repetition","name":"Repetition 2","result":"Passed","durationInSeconds":0.3}
          ]},
          {"nodeType":"Arguments","name":"value: 2","children":[{"nodeType":"Test Case Run","name":"Run 1","result":"Passed","durationInSeconds":0.4}]}
        ]},
        {"nodeType":"Test Case","name":"testSkipped()","nodeIdentifier":"ExampleTests/Flow/testSkipped()","result":"Skipped","children":[{"nodeType":"Skip Message","name":"not applicable"}]},
        {"nodeType":"Test Case","name":"testExpected()","nodeIdentifier":"ExampleTests/Flow/testExpected()","result":"Expected Failure","durationInSeconds":0.1,"children":[{"nodeType":"Expected Failure","name":"known issue","children":[{"nodeType":"Failure Message","name":"tracked failure"}]}]},
        {"nodeType":"Test Case","name":"testPassed()","nodeIdentifier":"ExampleTests/Flow/testPassed()","result":"Passed","duration":"1 minute, 2 seconds"}
      ]}
    ]}
  ]}]
}`

func simpleReport(nodes string) []byte {
	return []byte(`{"testPlanConfigurations":[],"devices":[],"testNodes":[` + nodes + `]}`)
}

func TestParseTestsPreservesNestedAttemptsAndOutcomes(t *testing.T) {
	summary, err := ParseTests([]byte(nestedTestReport), []string{"ExampleTests/Flow", "testExpected()", "ExampleTests/Flow/testRepeated()"})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Tests != 6 || summary.Passed != 3 || summary.Failed != 1 || summary.Skipped != 1 || summary.ExpectedFailures != 1 || summary.DurationSeconds != 63 {
		t.Fatalf("incorrect aggregate: %+v", summary)
	}
	for index, expected := range []string{"failed", "passed", "passed"} {
		c := summary.Cases[index]
		if c.ID != "ExampleTests/Flow/testRepeated()" || c.Attempt != index+1 || c.Outcome != expected {
			t.Fatalf("lost repeated execution: %+v", c)
		}
	}
	if got := summary.Cases[0].Failures; len(got) != 1 || got[0] != `expected <ready> & got "waiting"` {
		t.Fatalf("failure detail: %q", got)
	}
	if summary.Cases[0].Suite == summary.Cases[2].Suite {
		t.Fatal("parameter configurations were merged")
	}
	if got := summary.Cases[4].Failures; len(got) != 1 || got[0] != "tracked failure" {
		t.Fatalf("expected failure detail: %q", got)
	}
}

func TestParseTestsKeepsDeviceConfigurationsAndFallbackIdentifiers(t *testing.T) {
	report := simpleReport(`{"nodeType":"Test Suite","name":"Suite","children":[
		{"nodeType":"Device","name":"First","children":[{"nodeType":"Test Case","name":"case","nodeIdentifier":"Suite/case","result":"Failed"}]},
		{"nodeType":"Device","name":"Second","children":[{"nodeType":"Test Case","name":"case","nodeIdentifier":"Suite/case","result":"Passed"}]},
		{"nodeType":"Test Case","name":"fallback","result":"Passed"}
	]}`)
	summary, err := ParseTests(report, []string{"Suite"})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Tests != 3 || summary.Failed != 1 || summary.Cases[0].Suite != "Suite/First" || summary.Cases[1].Suite != "Suite/Second" || summary.Cases[2].ID != "Suite/fallback" {
		t.Fatalf("configuration identity: %+v", summary)
	}
}

func TestParseTestsRequiredScopeBoundaries(t *testing.T) {
	for _, required := range []string{"Flow", "ExampleTests/Flo", "Repeated", "testSkipped()", "ExampleTests/Other", ""} {
		t.Run(required, func(t *testing.T) {
			summary, err := ParseTests([]byte(nestedTestReport), []string{required})
			if !errors.Is(err, ErrRequiredTests) || summary.ParseStatus != "incomplete" {
				t.Fatalf("scope %q: %+v, %v", required, summary, err)
			}
		})
	}
	for _, report := range [][]byte{
		simpleReport(""),
		simpleReport(`{"nodeType":"Test Case","name":"skip","result":"Skipped"}`),
	} {
		if _, err := ParseTests(report, nil); !errors.Is(err, ErrInvalidTests) {
			t.Fatalf("non-executed report accepted: %v", err)
		}
	}
	if summary, err := ParseTests(simpleReport(`{"nodeType":"Test Case","name":"expected","result":"Expected Failure"}`), []string{"expected"}); err != nil || summary.ExpectedFailures != 1 {
		t.Fatalf("expected failure did not execute: %+v %v", summary, err)
	}
}

func TestParseTestsRejectsMalformedAndIncompleteReports(t *testing.T) {
	invalid := map[string][]byte{
		"syntax":                      []byte(`{`),
		"trailing":                    append(simpleReport(`{"nodeType":"Test Case","name":"pass","result":"Passed"}`), []byte(` {}`)...),
		"missing root arrays":         []byte(`{"testNodes":[]}`),
		"null root array":             []byte(`{"testPlanConfigurations":null,"devices":[],"testNodes":[]}`),
		"wrong root array":            []byte(`{"testPlanConfigurations":[],"devices":{},"testNodes":[]}`),
		"missing name":                simpleReport(`{"nodeType":"Test Case","result":"Passed"}`),
		"unknown type":                simpleReport(`{"nodeType":"Mystery","name":"case","result":"Passed"}`),
		"unknown result":              simpleReport(`{"nodeType":"Test Case","name":"case","result":"unknown"}`),
		"missing result":              simpleReport(`{"nodeType":"Test Case","name":"case"}`),
		"negative duration":           simpleReport(`{"nodeType":"Test Case","name":"case","result":"Passed","durationInSeconds":-1}`),
		"overflow duration":           simpleReport(`{"nodeType":"Test Case","name":"case","result":"Passed","durationInSeconds":1e999}`),
		"nan duration":                simpleReport(`{"nodeType":"Test Case","name":"case","result":"Passed","durationInSeconds":NaN}`),
		"string duration":             simpleReport(`{"nodeType":"Test Case","name":"case","result":"Passed","durationInSeconds":"1"}`),
		"null duration":               simpleReport(`{"nodeType":"Test Case","name":"case","result":"Passed","durationInSeconds":null}`),
		"missing configuration field": []byte(strings.Replace(nestedTestReport, `"configurationName":"Debug"`, `"additive":"allowed"`, 1)),
		"missing device field":        []byte(strings.Replace(nestedTestReport, `"architecture":"arm64"`, `"additive":"allowed"`, 1)),
		"unknown duration unit":       simpleReport(`{"nodeType":"Test Case","name":"case","result":"Passed","duration":"1 fortnight"}`),
		"negative human duration":     simpleReport(`{"nodeType":"Test Case","name":"case","result":"Passed","duration":"-1s"}`),
		"empty human duration":        simpleReport(`{"nodeType":"Test Case","name":"case","result":"Passed","duration":" "}`),
		"duration separator":          simpleReport(`{"nodeType":"Test Case","name":"case","result":"Passed","duration":"1s,"}`),
		"orphan run":                  simpleReport(`{"nodeType":"Test Case Run","name":"run","result":"Passed"}`),
		"lost aggregate failure":      simpleReport(`{"nodeType":"Test Case","name":"case","result":"Failed","children":[{"nodeType":"Test Case Run","name":"run","result":"Passed"}]}`),
		"deep":                        []byte(strings.Repeat("[", maxTestDepth+1) + strings.Repeat("]", maxTestDepth+1)),
	}
	for name, data := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseTests(data, nil); !errors.Is(err, ErrInvalidTests) {
				t.Fatalf("accepted invalid evidence: %v", err)
			}
		})
	}
	oversized := bytes.Repeat([]byte(" "), maxTestsBytes+1)
	if _, err := ParseTests(oversized, nil); !errors.Is(err, ErrInvalidTests) {
		t.Fatalf("accepted oversized report: %v", err)
	}
}

func TestParseTestsUsesExplicitDurationAndValidHumanUnits(t *testing.T) {
	for _, tc := range []struct {
		duration string
		seconds  float64
	}{
		{"2d 3h 4m 5s", 183845}, {"12ms", .012}, {"1 hour 0.5 seconds", 3600.5},
	} {
		node, err := json.Marshal(map[string]any{"nodeType": "Test Case", "name": "case", "result": "Passed", "duration": tc.duration})
		if err != nil {
			t.Fatal(err)
		}
		summary, err := ParseTests(simpleReport(string(node)), nil)
		if err != nil || summary.DurationSeconds != tc.seconds {
			t.Fatalf("duration %q: %+v, %v", tc.duration, summary, err)
		}
	}
	summary, err := ParseTests(simpleReport(`{"nodeType":"Test Case","name":"case","result":"Passed","duration":"presentation only","durationInSeconds":0.25}`), nil)
	if err != nil || summary.DurationSeconds != .25 {
		t.Fatalf("explicit numeric duration: %+v %v", summary, err)
	}
}

func TestJUnitEscapesAndPreservesFailureAndRepetitionDetails(t *testing.T) {
	summary, err := ParseTests([]byte(nestedTestReport), nil)
	if err != nil {
		t.Fatal(err)
	}
	summary.Cases[0].Name = `case <one> & "two"`
	data, err := JUnit(summary)
	if err != nil {
		t.Fatal(err)
	}
	second, err := JUnit(summary)
	if err != nil || !bytes.Equal(data, second) {
		t.Fatal("JUnit is not deterministic")
	}
	var report junitReport
	if err := xml.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.Tests != 6 || report.Failures != 1 || report.Skipped != 2 || report.Time != "63" {
		t.Fatalf("JUnit counts: %+v", report)
	}
	foundFailure, foundExpected, attempts := false, false, map[int]bool{}
	for _, suite := range report.Suites {
		for _, c := range suite.Cases {
			if c.ID == "ExampleTests/Flow/testRepeated()" {
				attempts[c.Attempt] = true
			}
			if c.Failure != nil {
				foundFailure = c.Name == summary.Cases[0].Name && c.Failure.Text == `expected <ready> & got "waiting"` && c.Time == "0.2"
			}
			if c.Skipped != nil && c.Skipped.Type == "expected-failure" {
				foundExpected = c.Skipped.Text == "tracked failure"
			}
		}
	}
	if !foundFailure || !foundExpected || !attempts[1] || !attempts[2] || !attempts[3] {
		t.Fatalf("JUnit lost execution details: %s", data)
	}
}

func TestJUnitRejectsInvalidNormalizedCases(t *testing.T) {
	for _, c := range []TestCase{
		{ID: "case", Name: "case", Attempt: 1, Outcome: "unknown"},
		{ID: "case", Name: "case", Attempt: 1, Outcome: "passed", DurationSeconds: math.Inf(1)},
		{ID: "case", Name: "case", Attempt: 1, Outcome: "passed", DurationSeconds: -1},
	} {
		if _, err := JUnit(Summary{Cases: []TestCase{c}}); !errors.Is(err, ErrInvalidTests) {
			t.Fatalf("invalid JUnit case accepted: %v", err)
		}
	}
}

func TestParseTestsKeepsAggregateFailureDetailsWithoutDoubleCounting(t *testing.T) {
	summary, err := ParseTests(simpleReport(`{"nodeType":"Test Case","name":"case","result":"Failed","children":[
		{"nodeType":"Failure Message","name":"aggregate detail"},
		{"nodeType":"Test Case Run","name":"run","result":"Failed","children":[{"nodeType":"Failure Message","name":"run detail"}]}
	]}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Tests != 1 || summary.Failed != 1 || len(summary.Cases[0].Failures) != 2 || summary.Cases[0].Failures[0] != "run detail" || summary.Cases[0].Failures[1] != "aggregate detail" {
		t.Fatalf("aggregate failure evidence lost: %+v", summary)
	}
}

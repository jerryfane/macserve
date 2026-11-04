package evidence

import (
	"errors"
	"os"
	"testing"
)

// testdata/herdrup-uitests.json is the schema 0.4.0 test tree of a real
// herdrup iPhone UI-test result bundle (iPhoneTerminal-first.xcresult: four
// HerdrUITests classes, 52 passed and 2 skipped cases, one Runtime Warning).
// Xcode records class-relative case identifiers ("TerminalControlTests/
// testX()") under the suite path "Herdr/HerdrUITests/TerminalControlTests".
func herdrupUITests(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/herdrup-uitests.json")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestRequiredSelectorMatchesBundleRelative(t *testing.T) {
	fixture := herdrupUITests(t)
	for _, required := range [][]string{
		{"HerdrUITests/TerminalControlTests"},
		{"HerdrUITests/TerminalControlTests", "HerdrUITests/TerminalResizeTests", "HerdrUITests/TerminalSearchTests", "HerdrUITests/TerminalSelectionTests"},
		{"HerdrUITests/TerminalControlTests/testACopiedDocumentBeatsItsFinderIcon()"},
		{"HerdrUITests/TerminalControlTests/testACopiedDocumentBeatsItsFinderIcon"},
	} {
		summary, err := ParseTests(fixture, required)
		if err != nil || summary.ParseStatus != "parsed" {
			t.Fatalf("selectors %q not matched: %v", required, err)
		}
		if summary.Tests != 54 || summary.Passed != 52 || summary.Skipped != 2 || summary.Failed != 0 {
			t.Fatalf("fixture aggregate: %+v", summary)
		}
	}
}

func TestRequiredSelectorRejectsOtherTargetsClassesAndMethods(t *testing.T) {
	fixture := herdrupUITests(t)
	for _, required := range []string{
		"OtherUITests/TerminalControlTests",
		"UITests/TerminalControlTests",
		"Herdr/TerminalControlTests",
		"HerdrUITests/TerminalControl",
		"HerdrUITests/TerminalControlTests/testACopiedDocument",
		"HerdrUITests/TerminalControlTests/testACopiedDocumentBeatsItsFinderIcon()()",
		"HerdrUITests/TerminalResizeTests/testACopiedDocumentBeatsItsFinderIcon",
		"OtherUITests/TerminalControlTests/testACopiedDocumentBeatsItsFinderIcon",
		"HerdrUITests//testACopiedDocumentBeatsItsFinderIcon",
		"HerdrUITests/TerminalControlTests/testACopiedDocumentBeatsItsFinderIcon/extra",
	} {
		summary, err := ParseTests(fixture, []string{required})
		if !errors.Is(err, ErrRequiredTests) || summary.ParseStatus != "incomplete" {
			t.Fatalf("selector %q accepted: %+v %v", required, summary.ParseStatus, err)
		}
	}
}

func TestRequiredSelectorSkippedCasesDoNotSatisfy(t *testing.T) {
	// Real skipped case in the fixture: the iPad-only sidebar receipt.
	for _, required := range []string{
		"HerdrUITests/TerminalResizeTests/testRealSidebarOrientationAndFontPreserveHistory",
		"HerdrUITests/TerminalResizeTests/testRealSidebarOrientationAndFontPreserveHistory()",
	} {
		if _, err := ParseTests(herdrupUITests(t), []string{required}); !errors.Is(err, ErrRequiredTests) {
			t.Fatalf("skipped case satisfied %q: %v", required, err)
		}
	}
	// A class whose every case skips on the device does not satisfy its selector.
	report := simpleReport(`{"nodeType":"Test Plan","name":"Herdr","children":[{"nodeType":"UI test bundle","name":"HerdrUITests","children":[
		{"nodeType":"Test Suite","name":"SelectAgentFieldTests","nodeIdentifier":"SelectAgentFieldTests","children":[
			{"nodeType":"Test Case","name":"testPadOnly()","nodeIdentifier":"SelectAgentFieldTests/testPadOnly()","result":"Skipped","children":[{"nodeType":"Skip Message","name":"iPad only"}]}]},
		{"nodeType":"Test Suite","name":"GramTests","nodeIdentifier":"GramTests","children":[
			{"nodeType":"Test Case","name":"testGram()","nodeIdentifier":"GramTests/testGram()","result":"Passed"}]}]}]}`)
	if _, err := ParseTests(report, []string{"HerdrUITests/SelectAgentFieldTests"}); !errors.Is(err, ErrRequiredTests) {
		t.Fatalf("all-skipped class satisfied its selector: %v", err)
	}
	if _, err := ParseTests(report, []string{"HerdrUITests/GramTests"}); err != nil {
		t.Fatalf("executed class rejected: %v", err)
	}
}

func TestRequiredSelectorMatchesPerDeviceExecutions(t *testing.T) {
	// Device labels below a case extend its suite, not the selector scope.
	report := simpleReport(`{"nodeType":"Test Plan","name":"Herdr","children":[{"nodeType":"UI test bundle","name":"HerdrUITests","children":[
		{"nodeType":"Test Suite","name":"GramTests","nodeIdentifier":"GramTests","children":[
			{"nodeType":"Test Case","name":"testGram()","nodeIdentifier":"GramTests/testGram()","result":"Passed","children":[
				{"nodeType":"Device","name":"iPhone 17 Pro","nodeIdentifier":"device-1","children":[{"nodeType":"Test Case Run","name":"Run 1","result":"Passed"}]}]}]}]}]}`)
	summary, err := ParseTests(report, []string{"HerdrUITests/GramTests", "HerdrUITests/GramTests/testGram"})
	if err != nil || summary.Cases[0].Suite != "Herdr/HerdrUITests/GramTests/device-1" {
		t.Fatalf("per-device execution: %+v %v", summary, err)
	}
}

package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite testdata/macserve.rb.golden")

const (
	goldenSHA      = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	controllerSHA  = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	controllerLine = controllerSHA + "  macserve-controller-darwin-arm64\n"
	tmplPath       = "../../assets/homebrew/macserve.rb.tmpl"
)

func writeSums(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "SHA256SUMS")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestGolden(t *testing.T) {
	sums := writeSums(t, goldenSHA+"  macserve-darwin-arm64\n"+controllerLine)
	var out bytes.Buffer
	if err := run(tmplPath, sums, "v1.2.3", "jerryfane/macserve", &out); err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "macserve.rb.golden")
	if *update {
		if err := os.WriteFile(golden, out.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), want) {
		t.Fatalf("rendered formula differs from %s (rerun with -update after review):\n%s", golden, out.String())
	}
	var again bytes.Buffer
	if err := run(tmplPath, sums, "v1.2.3", "jerryfane/macserve", &again); err != nil || !bytes.Equal(again.Bytes(), want) {
		t.Fatalf("rendering is not deterministic: %v", err)
	}
}

func TestRefusesBadInputs(t *testing.T) {
	for name, tc := range map[string]struct{ sums, tag, repo, want string }{
		"missing entry":         {goldenSHA + "  other\n" + controllerLine, "v1.2.3", "jerryfane/macserve", "no macserve-darwin-arm64"},
		"empty sums":            {"", "v1.2.3", "jerryfane/macserve", "no macserve-darwin-arm64"},
		"duplicate entry":       {goldenSHA + "  macserve-darwin-arm64\n" + goldenSHA + "  macserve-darwin-arm64\n" + controllerLine, "v1.2.3", "jerryfane/macserve", "2 times"},
		"short sha":             {"abc  macserve-darwin-arm64\n" + controllerLine, "v1.2.3", "jerryfane/macserve", "invalid sha256"},
		"uppercase sha":         {strings.ToUpper(goldenSHA) + "  macserve-darwin-arm64\n" + controllerLine, "v1.2.3", "jerryfane/macserve", "invalid sha256"},
		"template inject":       {`"; system "x  macserve-darwin-arm64` + "\n" + controllerLine, "v1.2.3", "jerryfane/macserve", "invalid sha256"},
		"malformed line":        {goldenSHA + "\n", "v1.2.3", "jerryfane/macserve", "malformed"},
		"bad tag":               {goldenSHA + "  macserve-darwin-arm64\n" + controllerLine, "1.2.3", "jerryfane/macserve", "invalid tag"},
		"bad repo":              {goldenSHA + "  macserve-darwin-arm64\n" + controllerLine, "v1.2.3", `x"/y`, "invalid repository"},
		"missing controller":    {goldenSHA + "  macserve-darwin-arm64\n", "v1.2.3", "jerryfane/macserve", "no macserve-controller-darwin-arm64"},
		"duplicate controller":  {goldenSHA + "  macserve-darwin-arm64\n" + controllerLine + controllerLine, "v1.2.3", "jerryfane/macserve", "macserve-controller-darwin-arm64 2 times"},
		"short controller sha":  {goldenSHA + "  macserve-darwin-arm64\nabc  macserve-controller-darwin-arm64\n", "v1.2.3", "jerryfane/macserve", "invalid sha256"},
		"controller sha inject": {goldenSHA + "  macserve-darwin-arm64\n" + `"; system "x  macserve-controller-darwin-arm64` + "\n", "v1.2.3", "jerryfane/macserve", "invalid sha256"},
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			err := run(tmplPath, writeSums(t, tc.sums), tc.tag, tc.repo, &out)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if out.Len() != 0 {
				t.Fatalf("wrote output on error: %q", out.String())
			}
		})
	}
	if err := run(tmplPath, "", "v1.2.3", "jerryfane/macserve", &bytes.Buffer{}); err == nil {
		t.Fatal("missing -sums accepted")
	}
}

// TestRefusesJunkAroundValidValues pins the ^ and $ anchors of the tag, repo
// and sha patterns: a valid value with leading or trailing junk, including a
// newline, must never reach the formula.
func TestRefusesJunkAroundValidValues(t *testing.T) {
	valid := formula{Repo: "jerryfane/macserve", Tag: "v0.1.29", SHA256: goldenSHA, ControllerSHA256: controllerSHA}
	for name, tc := range map[string]struct {
		edit func(*formula)
		want string
	}{
		"sha trailing newline":  {func(f *formula) { f.SHA256 += "\nsystem 'x'" }, "invalid sha256"},
		"sha trailing quote":    {func(f *formula) { f.SHA256 += `"` }, "invalid sha256"},
		"sha leading junk":      {func(f *formula) { f.SHA256 = "\"\n" + f.SHA256 }, "invalid sha256"},
		"controller sha junk":   {func(f *formula) { f.ControllerSHA256 += "\nsystem 'x'" }, "invalid sha256"},
		"controller sha empty":  {func(f *formula) { f.ControllerSHA256 = "" }, "invalid sha256"},
		"tag trailing newline":  {func(f *formula) { f.Tag += "\nfoo" }, "invalid tag"},
		"tag trailing junk":     {func(f *formula) { f.Tag += `"` }, "invalid tag"},
		"tag leading junk":      {func(f *formula) { f.Tag = "x\n" + f.Tag }, "invalid tag"},
		"repo trailing quote":   {func(f *formula) { f.Repo += `"` }, "invalid repository"},
		"repo trailing newline": {func(f *formula) { f.Repo += "\nsystem 'x'" }, "invalid repository"},
		"repo leading junk":     {func(f *formula) { f.Repo = `"` + f.Repo }, "invalid repository"},
	} {
		t.Run(name, func(t *testing.T) {
			f := valid
			tc.edit(&f)
			out, err := render("{{.Repo}} {{.Tag}} {{.SHA256}} {{.ControllerSHA256}}", f)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if out != nil {
				t.Fatalf("rendered on error: %q", out)
			}
		})
	}
	if _, err := render("{{.Repo}}", valid); err != nil {
		t.Fatalf("valid values refused: %v", err)
	}
}

func TestTemplateRefusesUnknownField(t *testing.T) {
	_, err := render("{{.Missing}}", formula{Repo: "a/b", Tag: "v1.0.0", SHA256: goldenSHA, ControllerSHA256: controllerSHA})
	if err == nil {
		t.Fatal("unknown template field accepted")
	}
}

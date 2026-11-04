package doctor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// ModeLive is the word Mode returns for --live, the only doctor mode with
// effects (a transient launchd job and GitHub calls).
const ModeLive = "live"

// Mode returns ModeLive only when an argument is exactly --live or -live,
// and "check" otherwise. runDoctorWith refuses any other spelling that the
// flag package would read as live (--live=true), and a live probe without
// a parsed --live (a "-live" that is another flag's value), so the
// read-only clause never runs live and --live=false is read-only.
func Mode(args []string) string {
	for _, a := range args {
		if a == "--live" || a == "-live" {
			return ModeLive
		}
	}
	return "check"
}

// Render formats the report as text, or as indented JSON.
func Render(r Report, asJSON bool) ([]byte, error) {
	var b bytes.Buffer
	if asJSON {
		data, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			return nil, err
		}
		b.Write(data)
		b.WriteByte('\n')
		return b.Bytes(), nil
	}
	for _, c := range r.Checks {
		fmt.Fprintf(&b, "%-7s %-14s %s\n", c.Status, c.ID, c.Detail)
		if c.Fix != "" && c.Status != Pass {
			fmt.Fprintf(&b, "%-22s fix: %s\n", "", c.Fix)
		}
	}
	fmt.Fprintf(&b, "\n%d pass, %d warn, %d fail, %d unknown\n", r.Summary[Pass], r.Summary[Warn], r.Summary[Fail], r.Summary[Unknown])
	if !r.Root {
		b.WriteString("Without sudo some checks cannot run; sudo macserve doctor runs them all except --live.\n")
	}
	return b.Bytes(), nil
}

// Write renders the report to w.
func Write(w io.Writer, r Report, asJSON bool) error {
	data, err := Render(r, asJSON)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

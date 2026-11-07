package daemonlog

import (
	"bytes"
	"fmt"
	"log"
	"regexp"
	"testing"
	"time"
)

// Every line is prefixed with its RFC 3339 UTC time in milliseconds; a write
// that ends mid-line is continued, not prefixed again.
func TestDaemonStderrPrefixesEveryLine(t *testing.T) {
	var out bytes.Buffer
	at := time.Date(2026, 11, 7, 3, 16, 26, 123456789, time.FixedZone("CET", 3600))
	w := &stampWriter{out: &out, now: func() time.Time { return at }, lineStart: true}
	for _, chunk := range []string{"macserve maintenance: probe failed: census\n", "two\nlines\n", "partial ", "line\n", "unterminated"} {
		n, err := w.Write([]byte(chunk))
		if err != nil || n != len(chunk) {
			t.Fatalf("write %q: %d %v", chunk, n, err)
		}
		at = at.Add(time.Second)
	}
	want := "2026-11-07T02:16:26.123Z macserve maintenance: probe failed: census\n" +
		"2026-11-07T02:16:27.123Z two\n" +
		"2026-11-07T02:16:27.123Z lines\n" +
		"2026-11-07T02:16:28.123Z partial line\n" +
		"2026-11-07T02:16:30.123Z unterminated"
	if out.String() != want {
		t.Fatalf("stamped output:\n%s\nwant:\n%s", out.String(), want)
	}
}

// The daemon stderr is the standard logger's output, which adds no prefix of
// its own; direct writes and log lines carry the same format.
func TestDaemonStderrInstallsStandardLogger(t *testing.T) {
	previous, flags := log.Writer(), log.Flags()
	t.Cleanup(func() { log.SetOutput(previous); log.SetFlags(flags) })
	var out bytes.Buffer
	stderr := Stderr(&out)
	log.Printf("controller readiness: ready=%t", false)
	fmt.Fprintf(stderr, "macserve controller: %v\n", "stopped")
	line := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z `)
	lines := bytes.Split(bytes.TrimSuffix(out.Bytes(), []byte("\n")), []byte("\n"))
	if len(lines) != 2 || !bytes.HasSuffix(lines[0], []byte(" controller readiness: ready=false")) || !bytes.HasSuffix(lines[1], []byte(" macserve controller: stopped")) {
		t.Fatalf("daemon stderr:\n%s", out.String())
	}
	for _, l := range lines {
		if !line.Match(l) {
			t.Fatalf("line lacks RFC 3339 UTC millisecond prefix: %q", l)
		}
		if _, err := time.Parse(time.RFC3339Nano, string(l[:24])); err != nil {
			t.Fatalf("prefix %q: %v", l[:24], err)
		}
	}
}

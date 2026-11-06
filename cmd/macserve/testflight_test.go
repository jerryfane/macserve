package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTestflightUploadCommand(t *testing.T) {
	base := []string{"testflight-upload", "--api", "http://127.0.0.1:1/role/macserve-builds", "--job", "job_1", "--keyring-role", "role"}
	if got := run([]string{"testflight-upload", "--help"}, io.Discard, io.Discard); got != 0 {
		t.Fatalf("help: %d", got)
	}
	if got := run(base, io.Discard, io.Discard); got != 2 {
		t.Fatalf("missing --app-id: %d", got)
	}
	dir := t.TempDir()
	existing := filepath.Join(dir, "existing.json")
	if err := os.WriteFile(existing, []byte("kept"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if got := run(append(base, "--app-id", "123", "--out", existing), &stdout, &stderr); got != 1 || stdout.Len() != 0 {
		t.Fatalf("existing --out: %d %q %q", got, stdout.String(), stderr.String())
	}
	if raw, _ := os.ReadFile(existing); string(raw) != "kept" {
		t.Fatalf("existing --out overwritten: %q", raw)
	}
	// A refused run still writes its evidence and summary.
	out := filepath.Join(dir, "evidence.json")
	stdout.Reset()
	stderr.Reset()
	if got := run(append(base, "--app-id", "com.example.app", "--out", out), &stdout, &stderr); got != 1 || !strings.Contains(stdout.String(), "job_id=job_1\n") || !strings.Contains(stderr.String(), "numeric App Store Connect app ID") {
		t.Fatalf("invalid app ID: %d %q %q", got, stdout.String(), stderr.String())
	}
	var evidence map[string]any
	raw, err := os.ReadFile(out)
	if err != nil || json.Unmarshal(raw, &evidence) != nil || !strings.Contains(evidence["error"].(string), "numeric") {
		t.Fatalf("evidence: %s %v", raw, err)
	}
}

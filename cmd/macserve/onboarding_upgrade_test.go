package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/setup"
	"github.com/jerryfane/macserve/internal/setup/upgrade"
)

type fakeUpgradeSession struct {
	calls []setup.Request
	resp  setup.Response
}

func (s *fakeUpgradeSession) Call(r setup.Request) (setup.Response, error) {
	s.calls = append(s.calls, r)
	if s.resp.Error != "" {
		return s.resp, errors.New(s.resp.Error)
	}
	return s.resp, nil
}
func (s *fakeUpgradeSession) Close() error { return nil }

// newUpgradeRun is the wizard against a fake host: the running binary is a
// file in a temporary directory, the plan's reads are faked, and starting
// the helper is recorded.
func newUpgradeRun(t *testing.T, answer string, binary string) (*upgradeRun, *[]string, *fakeUpgradeSession, string) {
	t.Helper()
	dir := t.TempDir()
	self := filepath.Join(dir, "macserve-darwin-arm64")
	if err := os.WriteFile(self, []byte(binary), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		self: binary, upgrade.Root + "/bin/macserve": "macserve release v0.1.0", setup.LedgerPath: "{}",
		upgrade.Root + "/config/deploy.env": "CONTROLLER_USER=macservectl\nCONTROLLER_UID=6201\nCONTROLLER_GID=6201\nJOB_USER=macservejob\nJOB_UID=6202\nJOB_GID=6202\nOWNER_USER=jdoe\nOWNER_UID=501\nTAILNET_IP=100.64.0.10\nPORT=8443\nPROTECTED_PORTS=8443\nHOST_ADDRESSES=100.64.0.10\nDEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer\nREPOSITORIES=jdoe/myapp:4242\n",
	}
	probe := upgrade.Probe{
		Run: func(context.Context, []string) (string, error) { return "", errors.New("exit status 113") },
		ReadFile: func(path string, _ int64) ([]byte, error) {
			if d, ok := files[path]; ok {
				return []byte(d), nil
			}
			return nil, fs.ErrNotExist
		},
		Exists: func(path string) (bool, error) { _, ok := files[path]; return ok, nil },
		Self:   func() (string, error) { return self, nil },
		Version: func(b []byte) (string, error) {
			if _, v, ok := strings.Cut(string(b), "release "); ok {
				return v, nil
			}
			return "", errors.New("not a release build")
		},
	}
	started := &[]string{}
	session := &fakeUpgradeSession{resp: setup.Response{Done: true, Detail: "installed", Items: []string{setup.EffectRequalify}}}
	u := &upgradeRun{
		probe: probe, in: bufio.NewReader(strings.NewReader(answer)), out: &bytes.Buffer{}, euid: 501, self: self,
		start: func(path, digest string) (setupSession, error) {
			*started = append(*started, path+" "+digest)
			return session, nil
		},
	}
	return u, started, session, dir
}

func TestUpgradeApplyDigestComesFromTheRelease(t *testing.T) {
	binary := "macserve release v0.2.0"
	u, started, session, _ := newUpgradeRun(t, "yes\n", binary)
	var stderr bytes.Buffer
	if got := u.run([]string{"--sha256", strings.Repeat("0", 64)}, &bytes.Buffer{}, &stderr); got != 1 || len(*started) != 0 || !strings.Contains(stderr.String(), "not the release digest") {
		t.Fatalf("mismatched digest: exit %d started %q: %s", got, *started, stderr.String())
	}
	digest := digestOf(binary)
	if got := u.run([]string{"--sha256", digest, "--tag", "v0.2.0"}, &bytes.Buffer{}, &stderr); got != 0 || len(*started) != 1 || !strings.HasSuffix((*started)[0], " "+digest) {
		t.Fatalf("exit %d started %q: %s", got, *started, stderr.String())
	}
	if c := session.calls[0]; c.Verb != setup.VerbUpgrade || c.SHA256 != digest || c.Tag != "v0.2.0" || c.Proof != "" || c.Sums != "" {
		t.Fatalf("request %+v", c)
	}
}

func TestUpgradeApplyRefusals(t *testing.T) {
	binary := "macserve release v0.2.0"
	digest := digestOf(binary)
	for _, tc := range []struct {
		name   string
		args   []string
		euid   int
		answer string
		code   int
	}{
		{"sudo", []string{"--sha256", digest}, 0, "yes\n", 2},
		{"plan flag", []string{"--plan", "--sha256", digest}, 501, "yes\n", 2},
		{"no digest", nil, 501, "yes\n", 2},
		{"both digests", []string{"--sha256", digest, "--sha256sums", "x"}, 501, "yes\n", 2},
		{"proof without sums", []string{"--sha256", digest, "--carry-proof", "x"}, 501, "yes\n", 2},
		{"bad tag", []string{"--sha256", digest, "--tag", "0.2"}, 501, "yes\n", 2},
		{"not confirmed", []string{"--sha256", digest}, 501, "no\n", 0},
	} {
		u, started, _, _ := newUpgradeRun(t, tc.answer, binary)
		u.euid = tc.euid
		if got := u.run(tc.args, &bytes.Buffer{}, &bytes.Buffer{}); got != tc.code || len(*started) != 0 {
			t.Errorf("%s: exit %d started %q", tc.name, got, *started)
		}
	}
}

// TestUpgradeApplySendsReleaseProof: the SHA256SUMS and proof bytes go to
// the helper, which checks the proof against them.
func TestUpgradeApplySendsReleaseProof(t *testing.T) {
	binary := "macserve release v0.2.0"
	u, _, session, dir := newUpgradeRun(t, "yes\n", binary)
	proof := filepath.Join(dir, "carry-proof.json")
	sums := filepath.Join(dir, "SHA256SUMS")
	os.WriteFile(proof, []byte("{}"), 0o644)
	os.WriteFile(sums, []byte(digestOf(binary)+"  macserve-darwin-arm64\n"+digestOf("{}")+"  carry-proof.json\n"), 0o644)
	var stderr bytes.Buffer
	if got := u.run([]string{"--sha256sums", sums, "--carry-proof", proof}, &bytes.Buffer{}, &stderr); got != 0 {
		t.Fatalf("exit %d: %s", got, stderr.String())
	}
	if c := session.calls[0]; c.Proof != "{}" || !strings.Contains(c.Sums, "carry-proof.json") {
		t.Fatalf("request %+v", c)
	}
}

func digestOf(s string) string {
	d := sha256.Sum256([]byte(s))
	return hex.EncodeToString(d[:])
}

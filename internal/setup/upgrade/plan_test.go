package upgrade

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/qualification"
	"github.com/jerryfane/macserve/internal/setup"
)

const (
	self      = "/Users/jdoe/Downloads/macserve-darwin-arm64"
	installed = "macserve release v0.1.0"
	target    = "macserve release v0.2.0"
	env       = "CONTROLLER_USER=macservectl\nCONTROLLER_UID=6201\nCONTROLLER_GID=6201\nJOB_USER=macservejob\nJOB_UID=6202\nJOB_GID=6202\nOWNER_USER=jdoe\nOWNER_UID=501\nTAILNET_IP=100.64.0.10\nPORT=8443\nPROTECTED_PORTS=8443\nHOST_ADDRESSES=100.64.0.10\nDEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer\nREPOSITORIES=jdoe/myapp:4242\n"
)

func sum(s string) string {
	d := sha256.Sum256([]byte(s))
	return hex.EncodeToString(d[:])
}

// host is a fake Mac: files, commands that succeed, and every call made.
type host struct {
	files    map[string]string
	ok       map[string]bool
	commands []string
	reads    []string
}

func newHost() *host {
	return &host{
		files: map[string]string{self: target, Root + "/bin/macserve": installed, Root + "/config/deploy.env": env, setup.LedgerPath: "{}", Root + "/config/activation-anchor.json": "{}"},
		ok:    map[string]bool{},
	}
}

func (h *host) probe() Probe {
	return Probe{
		Run: func(_ context.Context, argv []string) (string, error) {
			c := strings.Join(argv, " ")
			h.commands = append(h.commands, c)
			if h.ok[c] {
				return "", nil
			}
			return "", errors.New("exit status 113")
		},
		ReadFile: func(path string, _ int64) ([]byte, error) {
			h.reads = append(h.reads, path)
			if d, ok := h.files[path]; ok {
				return []byte(d), nil
			}
			return nil, fs.ErrNotExist
		},
		Exists: func(path string) (bool, error) { _, ok := h.files[path]; return ok, nil },
		Self:   func() (string, error) { return self, nil },
		Version: func(b []byte) (string, error) {
			if _, v, ok := strings.Cut(string(b), "release "); ok {
				return v, nil
			}
			return "", errors.New("not a release build")
		},
	}
}

func proof() []byte {
	p := qualification.CarryProof{
		Schema: 1, Kind: "release-carry-proof", ReleaseEffect: "QualificationCarried",
		From:                 qualification.CarryRelease{Tag: "v0.1.0", Commit: "c1", BinarySHA256: sum(installed)},
		To:                   qualification.CarryRelease{Tag: "v0.2.0", Commit: "c2", BinarySHA256: sum(target)},
		BoundaryManifestBlob: "b", ClassesPresent: []string{"T"},
		Changed: []qualification.CarryChange{{Path: "docs/install.md", Class: "T", Old: []string{"100644", "a"}, New: []string{"100644", "b"}}},
	}
	data, _ := json.Marshal(p)
	return data
}

func sums(proof []byte) []byte {
	s := sum(target) + "  " + setup.ReleaseAsset + "\n"
	if proof != nil {
		s += sum(string(proof)) + "  " + setup.CarryProofAsset + "\n"
	}
	return []byte(s)
}

func status(r Result, id string) string {
	for _, c := range r.Checks {
		if c.ID == id {
			return c.Status
		}
	}
	return ""
}

func TestPlanFullRequalification(t *testing.T) {
	h := newHost()
	r := Plan(context.Background(), h.probe(), Options{SHA256Sums: sums(nil)})
	if !r.Ready() || r.From != "v0.1.0" || r.To != "v0.2.0" || r.Carry || status(r, "release.digest") != Pass || status(r, "svc.stopped") != Pass || status(r, "session.job") != Pass {
		t.Fatalf("%+v", r)
	}
	var b bytes.Buffer
	if err := Write(&b, r); err != nil || !strings.Contains(b.String(), "reset the setup ledger to owner-actions") || !strings.Contains(b.String(), "remove the approval") {
		t.Fatalf("%v\n%s", err, b.String())
	}
	// Only doctor's read-only commands, and only reads.
	for _, c := range h.commands {
		if !strings.HasPrefix(c, "/bin/launchctl print ") {
			t.Errorf("command %q", c)
		}
	}
}

func TestPlanRefusals(t *testing.T) {
	for _, tc := range []struct {
		name, id string
		prepare  func(h *host, o *Options)
	}{
		{"digest mismatch", "release.digest", func(h *host, o *Options) { h.files[self] = "tampered" }},
		{"sums lacks binary", "release.digest", func(h *host, o *Options) { o.SHA256Sums = []byte(sum("x") + "  other\n") }},
		{"wrong tag", "release.version", func(h *host, o *Options) { o.Tag = "v0.3.0" }},
		{"same version", "release.version", func(h *host, o *Options) { h.files[Root+"/bin/macserve"] = target; h.files[self] = target }},
		{"downgrade", "release.version", func(h *host, o *Options) { h.files[Root+"/bin/macserve"] = "macserve release v0.3.0" }},
		{"dev build", "release.version", func(h *host, o *Options) {
			h.files[self] = "dev"
			o.SHA256Sums = []byte(sum("dev") + "  " + setup.ReleaseAsset + "\n")
		}},
		{"no ledger", "setup.ledger", func(h *host, o *Options) { delete(h.files, setup.LedgerPath) }},
		{"service loaded", "svc.stopped", func(h *host, o *Options) { h.ok["/bin/launchctl print system/org.macserve.worker"] = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHost()
			o := Options{SHA256Sums: sums(nil)}
			tc.prepare(h, &o)
			r := Plan(context.Background(), h.probe(), o)
			if r.Ready() || status(r, tc.id) != Fail {
				t.Fatalf("%+v", r.Checks)
			}
			var b bytes.Buffer
			if err := Write(&b, r); err != nil || strings.Contains(b.String(), "will:") {
				t.Fatalf("a refused plan lists steps:\n%s", b.String())
			}
		})
	}
}

func TestPlanCarry(t *testing.T) {
	h := newHost()
	h.ok["/bin/launchctl print gui/6202"] = true
	p := proof()
	r := Plan(context.Background(), h.probe(), Options{SHA256Sums: sums(p), CarryProof: p})
	if !r.Ready() || !r.Carry || status(r, "release.carry") != Pass {
		t.Fatalf("%+v", r.Checks)
	}
	for _, tc := range []struct {
		name    string
		options func() Options
	}{
		{"not in sums", func() Options { return Options{SHA256Sums: sums(nil), CarryProof: p} }},
		{"no sums", func() Options { return Options{SHA256: sum(target), CarryProof: p} }},
		{"other bytes", func() Options {
			q := append([]byte{}, p...)
			q = append(q, ' ')
			return Options{SHA256Sums: sums(p), CarryProof: q}
		}},
		{"boundary class", func() Options {
			q := bytes.ReplaceAll(p, []byte(`"T"`), []byte(`"B"`))
			return Options{SHA256Sums: sums(q), CarryProof: q}
		}},
		{"empty commit", func() Options {
			q := bytes.ReplaceAll(p, []byte(`"commit":"c1"`), []byte(`"commit":""`))
			return Options{SHA256Sums: sums(q), CarryProof: q}
		}},
	} {
		r := Plan(context.Background(), h.probe(), tc.options())
		if r.Carry || status(r, "release.carry") != Warn {
			t.Errorf("%s: %+v", tc.name, r.Checks)
		}
	}
	// No live session: no carry.
	delete(h.ok, "/bin/launchctl print gui/6202")
	if r := Plan(context.Background(), h.probe(), Options{SHA256Sums: sums(p), CarryProof: p}); r.Carry {
		t.Fatal("carry without a live session")
	}
}

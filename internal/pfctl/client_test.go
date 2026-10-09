package pfctl

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"text/template"
	"time"
)

func recordingClient(t *testing.T) (*Client, *[][]string) {
	t.Helper()
	c, err := New("org.example/service")
	if err != nil {
		t.Fatal(err)
	}
	var calls [][]string
	c.run = func(ctx context.Context, args ...string) (Output, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 2*time.Second {
			t.Fatal("native invocation lacks bounded deadline")
		}
		calls = append(calls, slices.Clone(args))
		return Output{Stdout: "observed\n"}, nil
	}
	return c, &calls
}

func policyPath(t *testing.T, text string) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "policy.conf")
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestExactOwnedAnchorRequired(t *testing.T) {
	for _, path := range []string{"", "/", "*", "/*", "org.example/*", "/org.example/service", "org.example//service", "org.example/../service", "org.example/./service", "org.example/service/", "org.example/service\n", strings.Repeat("a", 64), strings.Repeat("a/", 8) + "b"} {
		if c, err := New(path); err == nil || c != nil || AnchorPath(path) {
			t.Fatalf("accepted non-exact scope %q", path)
		}
	}
	for _, path := range []string{"org.example/service", "org.example/peer-1", "_pf", "one/two/three"} {
		if _, err := New(path); err != nil || !AnchorPath(path) {
			t.Fatalf("refused canonical scope %q: %v", path, err)
		}
	}
}

func TestClientRefusesAllNonReadFormsBeforeRunner(t *testing.T) {
	c, calls := recordingClient(t)
	forms := [][]string{
		nil, {"-f", "/policy"}, {"-e"}, {"-d"}, {"-E"}, {"-X", "1"},
		{"-F", "all"}, {"-k", "0.0.0.0/0"}, {"-T", "flush"}, {"-nf", "/policy"},
		{"-sr", "-f", "/policy"}, {"-a", "org.example/service", "-f", "/policy"},
		{"-a", "", "-f", "/policy"}, {"-a", "*", "-f", "/policy"},
		{"-a", "/", "-f", "/policy"}, {"-a", "org.example/peer", "-f", "/policy"},
		{"-a", "org.example/service", "-F", "rules"}, {"-a", "org.example/peer", "-T", "replace", "-f", "/policy"},
		{"-a", "org.example/*", "-sr"}, {"-a", "org.example/../peer", "-sn"},
		{"-a", "org.example/peer", "-sr", "-a", "org.example/service"},
		{"-s", "info", "-z"}, {"-a", "org.example/service", "-vvsrz"},
	}
	for _, args := range forms {
		if _, err := c.Read(context.Background(), args...); err == nil {
			t.Fatalf("accepted unauthorized PF operation %q", args)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("refused operation reached native runner: %q", *calls)
	}
}

func TestLoadRejectsUnsafeFilesBeforeRunner(t *testing.T) {
	c, calls := recordingClient(t)
	file := policyPath(t, "block all\n")
	link := filepath.Join(filepath.Dir(file), "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	ancestor := filepath.Join(filepath.Dir(file), "linked-directory")
	if err := os.Symlink(filepath.Dir(file), ancestor); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"relative.conf", "", file + "/../policy.conf", link, filepath.Join(ancestor, "policy.conf"), filepath.Dir(file), file + ".absent", policyPath(t, ""), policyPath(t, strings.Repeat("#", maxPolicyBytes+1))} {
		if _, err := c.Load(context.Background(), path, LoadOptions{JobUID: 1502}); err == nil {
			t.Fatalf("accepted unsafe file %q", path)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("unsafe file reached PF: %q", *calls)
	}
}

func TestLoadRejectsSourceEscapesBeforeRunner(t *testing.T) {
	c, calls := recordingClient(t)
	for _, source := range []string{
		"anchor \"/foreign\" { pass all }\n", "anchor \"child\"\n", "load anchor \"foreign\" from \"/policy\"\n",
		"include \"/policy\"\n", "set skip on lo0\n", "table <clients> persist\n",
		"nat from any to any -> 192.0.2.1\n", "rdr from any to any -> 127.0.0.1\n", "scrub all\n",
		"block all; set skip on lo0\n", "block all\\\npass all\n", "block all\rset skip on lo0\n",
		"action = \"anchor\"\n$action \"/foreign\"\n", "action = \"pass all\\nset skip on lo0\"\nblock all\n",
		"value = \"1; set skip on lo0\"\nblock all\n", "value = \"$other\"\nblock all\n",
		"value = \"{ 1, anchor }\"\nblock all\n", "value = \"{ { 1 } }\"\nblock all\n",
		"block out user $undefined all\n", "block all label \"line\nbreak\"\n",
		"block all {\npass all\n}\n", "block all anchor \"/foreign\"\n", "block all label \"$nr\"\n",
		"block all\x00\n", "block all # inline directive\n", "block all label \"ok\" include \"/policy\"\n",
		"pass all nat-to 192.0.2.1\n", "pass all rdr-to 127.0.0.1\n",
	} {
		if _, err := c.Load(context.Background(), policyPath(t, ownedRules+source), LoadOptions{JobUID: 1502}); err == nil {
			t.Fatalf("accepted source escape %q", source)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("source escape reached PF: %q", *calls)
	}
}

func TestLoadAcceptsRenderedPolicyAndNarrowPass(t *testing.T) {
	tmpl, err := template.ParseFiles("../../assets/pf/org.macserve.conf.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	var rendered bytes.Buffer
	if err := tmpl.Execute(&rendered, map[string]any{"JobUID": 1502, "ProtectedPorts": "12345, 12346", "HostAddresses": "192.0.2.10, 2001:db8::10"}); err != nil {
		t.Fatal(err)
	}
	source := strings.Replace(rendered.String(), "# BEGIN OWNER-REVIEWED NARROW EXCEPTIONS", "pass out quick inet proto tcp from any to 192.0.2.20 port = 443 user $job_uid label \"reviewed-exception\"\n# BEGIN OWNER-REVIEWED NARROW EXCEPTIONS", 1)
	if err := validatePolicy(source, 1502); err != nil {
		t.Fatalf("rendered bounded filter policy refused: %v", err)
	}
	if err := validatePolicy(source, 1503); err == nil {
		t.Fatal("rendered policy accepted for a different job UID")
	}
	for _, destination := range []string{"127.0.0.0/8, ", "169.254.0.0/16, ", "::1/128, ", "fe80::/10, "} {
		if err := validatePolicy(strings.Replace(source, destination, "", 1), 1502); err == nil {
			t.Fatalf("rendered exception accepted without mandatory range %s", destination)
		}
	}
}

func TestReadDiagnosticsFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		output Output
		want   error
		ok     bool
	}{
		{"clean", Output{Stdout: "rules\n"}, nil, true},
		{"altq", Output{Stdout: "rules\n", Stderr: "No ALTQ support in kernel\nALTQ related functions disabled\n"}, nil, true},
		{"absent", Output{Stderr: "Anchor 'org.example/peer' not found.\n"}, ErrAnchorAbsent, false},
		{"altq-absent", Output{Stderr: "No ALTQ support in kernel\nALTQ related functions disabled\nAnchor 'org.example/peer' not found.\n"}, ErrAnchorAbsent, false},
		{"wrong-anchor", Output{Stderr: "Anchor 'org.example/other' not found.\n"}, nil, false},
		{"partial-absence", Output{Stdout: "partial", Stderr: "Anchor 'org.example/peer' not found.\n"}, nil, false},
		{"unknown", Output{Stderr: "permission denied\n"}, nil, false},
		{"oversized-output", Output{Stdout: strings.Repeat("x", (1<<20)+1)}, nil, false},
		{"oversized-diagnostic", Output{Stderr: strings.Repeat("x", 8193)}, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := New("org.example/service")
			if err != nil {
				t.Fatal(err)
			}
			c.run = func(context.Context, ...string) (Output, error) { return tc.output, nil }
			_, err = c.Read(context.Background(), "-a", "org.example/peer", "-v", "-s", "Anchors")
			if (err == nil) != tc.ok || tc.want != nil && !errors.Is(err, tc.want) || tc.want == nil && errors.Is(err, ErrAnchorAbsent) {
				t.Fatalf("diagnostic classification: %v", err)
			}
		})
	}
}

func TestAbsentRuleDiagnosticRequiresExactScopedReadAndExit(t *testing.T) {
	const missing = "pfctl: DIOCGETRULES: Invalid argument\n"
	const altq = "No ALTQ support in kernel\nALTQ related functions disabled\n"
	exitOne := exec.Command("/bin/sh", "-c", "exit 1").Run()
	exitTwo := exec.Command("/bin/sh", "-c", "exit 2").Run()
	if exitOne == nil || exitTwo == nil {
		t.Fatal("nonzero process fixtures unexpectedly succeeded")
	}
	for _, tc := range []struct {
		name   string
		args   []string
		output Output
		err    error
		absent bool
	}{
		{"filter", []string{"-a", "org.example/service", "-sr"}, Output{Stderr: missing}, nil, true},
		{"nat", []string{"-a", "org.example/service", "-sn"}, Output{Stderr: altq + missing}, nil, true},
		{"exit-one", []string{"-a", "org.example/service", "-sr"}, Output{Stderr: missing}, exitOne, false},
		{"exit-two", []string{"-a", "org.example/service", "-sr"}, Output{Stderr: missing}, exitTwo, false},
		{"runner-failure", []string{"-a", "org.example/service", "-sr"}, Output{Stderr: missing}, errors.New("runner failed"), false},
		{"partial-output", []string{"-a", "org.example/service", "-sr"}, Output{Stdout: "\n", Stderr: missing}, nil, false},
		{"permission", []string{"-a", "org.example/service", "-sr"}, Output{Stderr: "pfctl: DIOCGETRULES: Permission denied\n"}, nil, false},
		{"extra-diagnostic", []string{"-a", "org.example/service", "-sr"}, Output{Stderr: missing + "other failure\n"}, nil, false},
		{"missing-newline", []string{"-a", "org.example/service", "-sr"}, Output{Stderr: strings.TrimSuffix(missing, "\n")}, nil, false},
		{"extra-whitespace", []string{"-a", "org.example/service", "-sr"}, Output{Stderr: "\n" + missing}, nil, false},
		{"root-rules", []string{"-sr"}, Output{Stderr: missing}, nil, false},
		{"root-nat", []string{"-sn"}, Output{Stderr: missing}, nil, false},
		{"tables", []string{"-a", "org.example/service", "-s", "Tables"}, Output{Stderr: missing}, nil, false},
		{"verbose", []string{"-a", "org.example/service", "-vvsr"}, Output{Stderr: missing}, nil, false},
		{"wrong-ioctl", []string{"-a", "org.example/service", "-sr"}, Output{Stderr: "pfctl: DIOCGETRULE: Invalid argument\n"}, nil, false},
		{"anchor-exit-one", []string{"-a", "org.example/service", "-v", "-s", "Anchors"}, Output{Stderr: "Anchor 'org.example/service' not found.\n"}, exitOne, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := New("org.example/service")
			if err != nil {
				t.Fatal(err)
			}
			c.run = func(context.Context, ...string) (Output, error) { return tc.output, tc.err }
			_, err = c.Read(context.Background(), tc.args...)
			if err == nil || errors.Is(err, ErrAnchorAbsent) != tc.absent {
				t.Fatalf("absence classification=%v, want absent=%v", err, tc.absent)
			}
		})
	}
}

func TestCancelledReadNeverInvokesPF(t *testing.T) {
	c, calls := recordingClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Read(ctx, "-sr"); !errors.Is(err, context.Canceled) || len(*calls) != 0 {
		t.Fatalf("cancelled read invoked PF: calls=%q err=%v", *calls, err)
	}
	var zero Client
	if _, err := zero.Read(context.Background(), "-sr"); err == nil {
		t.Fatal("zero client permitted read")
	}
	if _, err := zero.Load(context.Background(), "/policy", LoadOptions{JobUID: 1502}); err == nil {
		t.Fatal("zero client permitted write")
	}
}

func TestProcessOutputCopyCannotBypassBound(t *testing.T) {
	buffer := &boundedBuffer{limit: 4}
	// Match os/exec's pipe-copy path without a source WriterTo optimization.
	source := struct{ io.Reader }{strings.NewReader("1234")}
	if n, err := io.Copy(buffer, source); err != nil || n != 4 || buffer.String() != "1234" {
		t.Fatalf("exact output bound refused: n=%d err=%v output=%q", n, err, buffer.String())
	}
	source = struct{ io.Reader }{strings.NewReader("5")}
	if n, err := io.Copy(buffer, source); err == nil || n != 0 || buffer.String() != "1234" {
		t.Fatalf("pipe copy bypassed output bound: n=%d err=%v output=%q", n, err, buffer.String())
	}
}

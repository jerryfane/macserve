package pfctl

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
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

func TestClientReadAndLoadInvocationContract(t *testing.T) {
	c, calls := recordingClient(t)
	reads := [][]string{
		{"-sr"}, {"-sn"}, {"-s", "info"}, {"-v", "-s", "Anchors"},
		{"-i", "lo0", "-v", "-s", "Interfaces"}, {"-a", "*", "-sr"}, {"-a", "", "-sn"},
	}
	for _, anchor := range []string{"org.example/service", "org.example/peer", "org.example", "_pf"} {
		for _, suffix := range [][]string{{"-sr"}, {"-sn"}, {"-vvsr"}, {"-s", "labels"}, {"-v", "-s", "Anchors"}} {
			reads = append(reads, append([]string{"-a", anchor}, suffix...))
		}
	}
	for _, args := range reads {
		if _, err := c.Read(context.Background(), args...); err != nil {
			t.Fatalf("read %q: %v", args, err)
		}
		if !slices.Equal((*calls)[len(*calls)-1], args) {
			t.Fatalf("read scope changed: %q", *calls)
		}
	}
	file := policyPath(t, "block drop out quick all\n")
	if _, err := c.Load(context.Background(), file); err != nil {
		t.Fatal(err)
	}
	if got := (*calls)[len(*calls)-1]; !slices.Equal(got, []string{"-a", "org.example/service", "-f", file}) {
		t.Fatalf("write escaped immutable owned scope: %q", got)
	}
	if len(*calls) != len(reads)+1 {
		t.Fatalf("unexpected PF operations: %q", *calls)
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
		if _, err := c.Load(context.Background(), path); err == nil {
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
		"pass all nat-to 192.0.2.1\n", "pass all rdr-to 127.0.0.1\n", "# only comments\n",
	} {
		if _, err := c.Load(context.Background(), policyPath(t, source)); err == nil {
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
	rendered.WriteString("pass out quick inet proto tcp from any to 192.0.2.20 port = 443 user $job_uid label \"reviewed-exception\"\n")
	c, calls := recordingClient(t)
	file := policyPath(t, rendered.String())
	if _, err := c.Load(context.Background(), file); err != nil {
		t.Fatalf("rendered bounded filter policy refused: %v", err)
	}
	if len(*calls) != 1 || !slices.Equal((*calls)[0], []string{"-a", "org.example/service", "-f", file}) {
		t.Fatalf("rendered policy load escaped scope: %q", *calls)
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
	if _, err := zero.Load(context.Background(), "/policy"); err == nil {
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

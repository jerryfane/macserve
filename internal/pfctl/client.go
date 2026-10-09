// Package pfctl is the sole native PF process boundary. Reads may inspect the
// whole firewall; writes can only replace the configured, exclusively owned leaf.
package pfctl

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"slices"
	"strings"
	"time"
)

var ErrAnchorAbsent = errors.New("PF anchor absent")

type Output struct {
	Stdout string
	Stderr string
}

type Client struct {
	anchor string
	run    func(context.Context, ...string) (Output, error)
}

func New(anchor string) (*Client, error) {
	if !AnchorPath(anchor) {
		return nil, errors.New("PF write scope must be an exact bounded owned anchor")
	}
	return &Client{anchor: anchor, run: native}, nil
}

// AnchorPath accepts only canonical, exact PF paths, never root or wildcards.
func AnchorPath(path string) bool {
	if path == "" || len(path) >= 1024 || strings.Count(path, "/") >= 8 {
		return false
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." || len(part) >= 64 {
			return false
		}
		for _, c := range part {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
				return false
			}
		}
	}
	return true
}

func (c *Client) Read(ctx context.Context, args ...string) (Output, error) {
	if !readArgs(args) {
		return Output{}, errors.New("PF read arguments are not allowlisted")
	}
	return c.execute(ctx, args...)
}

func readArgs(args []string) bool {
	if slices.Equal(args, []string{"-sr"}) || slices.Equal(args, []string{"-sn"}) ||
		slices.Equal(args, []string{"-s", "info"}) ||
		slices.Equal(args, []string{"-v", "-s", "Anchors"}) ||
		slices.Equal(args, []string{"-i", "lo0", "-v", "-s", "Interfaces"}) ||
		slices.Equal(args, []string{"-a", "*", "-sr"}) ||
		slices.Equal(args, []string{"-a", "", "-sn"}) {
		return true
	}
	if len(args) < 3 || args[0] != "-a" || !AnchorPath(args[1]) {
		return false
	}
	rest := args[2:]
	return slices.Equal(rest, []string{"-sr"}) || slices.Equal(rest, []string{"-sn"}) ||
		slices.Equal(rest, []string{"-vvsr"}) || slices.Equal(rest, []string{"-s", "labels"}) ||
		slices.Equal(rest, []string{"-v", "-s", "Anchors"})
}

// Load has deliberately no scope or argument parameter. The caller must stage
// reviewed bytes in a protected location that cannot change through execution.
func (c *Client) Load(ctx context.Context, file string) (Output, error) {
	if c == nil || !AnchorPath(c.anchor) || c.run == nil {
		return Output{}, errors.New("uninitialized PF client")
	}
	if err := policyFile(file); err != nil {
		return Output{}, err
	}
	return c.execute(ctx, "-a", c.anchor, "-f", file)
}

func (c *Client) execute(ctx context.Context, args ...string) (Output, error) {
	if c == nil || !AnchorPath(c.anchor) || c.run == nil {
		return Output{}, errors.New("uninitialized PF client")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return Output{}, err
	}
	out, err := c.run(ctx, args...)
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	if len(out.Stdout) > 1<<20 || len(out.Stderr) > 8192 {
		return out, errors.New("PF output limit exceeded")
	}
	text := strings.TrimSpace(out.Stderr)
	const altq = "No ALTQ support in kernel\nALTQ related functions disabled"
	if text == altq {
		text = ""
	} else {
		text = strings.TrimPrefix(text, altq+"\n")
	}
	var exitErr *exec.ExitError
	normalExit := err == nil || errors.As(err, &exitErr) && exitErr.ExitCode() == 1
	if normalExit && out.Stdout == "" && len(args) == 5 && args[0] == "-a" && AnchorPath(args[1]) &&
		args[2] == "-v" && args[3] == "-s" && args[4] == "Anchors" && text == "Anchor '"+args[1]+"' not found." {
		return out, ErrAnchorAbsent
	}
	if err != nil {
		return out, err
	}
	if text != "" {
		return out, errors.New("unrecognized PF diagnostic")
	}
	return out, nil
}

type boundedBuffer struct {
	buffer bytes.Buffer
	limit  int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.buffer.Len() {
		return 0, errors.New("PF output limit exceeded")
	}
	return b.buffer.Write(p)
}

func (b *boundedBuffer) String() string { return b.buffer.String() }

func native(ctx context.Context, args ...string) (Output, error) {
	cmd := exec.CommandContext(ctx, "/sbin/pfctl", args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}
	cmd.Dir = "/"
	cmd.WaitDelay = 100 * time.Millisecond
	out := boundedBuffer{limit: 1 << 20}
	diagnostic := boundedBuffer{limit: 8192}
	cmd.Stdout, cmd.Stderr = &out, &diagnostic
	err := cmd.Run()
	return Output{Stdout: out.String(), Stderr: diagnostic.String()}, err
}

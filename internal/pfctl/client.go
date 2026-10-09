// Package pfctl provides bounded, read-only opaque PF rule measurements.
package pfctl

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"
)

type Output struct {
	Stdout string
	Stderr string
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

func Read(ctx context.Context, args ...string) (Output, error) {
	return read(ctx, native, args...)
}

func readArgs(args []string) bool {
	if len(args) == 1 {
		return args[0] == "-sr" || args[0] == "-sn"
	}
	return len(args) == 3 && args[0] == "-a" && AnchorPath(args[1]) && (args[2] == "-sr" || args[2] == "-sn")
}

func read(ctx context.Context, run func(context.Context, ...string) (Output, error), args ...string) (Output, error) {
	if !readArgs(args) {
		return Output{}, errors.New("PF read arguments are not allowlisted")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return Output{}, err
	}
	out, err := run(ctx, args...)
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	if len(out.Stdout) > 1<<20 || len(out.Stderr) > 8192 {
		return out, errors.New("PF output limit exceeded")
	}
	if err != nil {
		return out, err
	}
	const altq = "No ALTQ support in kernel\nALTQ related functions disabled"
	if diagnostic := strings.TrimSpace(out.Stderr); diagnostic != "" && diagnostic != altq {
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

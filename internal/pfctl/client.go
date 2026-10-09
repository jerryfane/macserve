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
	store  ownershipStore
}

func New(anchor string) (*Client, error) {
	if !AnchorPath(anchor) {
		return nil, errors.New("PF client requires an exact bounded anchor")
	}
	return &Client{anchor: anchor, run: native, store: protectedOwnershipStore{}}, nil
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
		slices.Equal(rest, []string{"-v", "-s", "Anchors"}) || slices.Equal(rest, []string{"-s", "Tables"})
}

// LoadOptions binds policy scope and ownership to the installed configuration.
type LoadOptions struct {
	JobUID                      uint32
	CoexistingAnchors           []string
	ToleratedTranslationAnchors []string
}

// Load only initializes an empty leaf or replaces a protected, receipted prior
// load. The caller stages reviewed bytes in a location immutable during the call.
func (c *Client) Load(ctx context.Context, file string, options LoadOptions) (Output, error) {
	if c == nil || c.run == nil || c.store == nil {
		return Output{}, errors.New("uninitialized PF client")
	}
	if err := ValidateOwnedAnchor(c.anchor, options.CoexistingAnchors, options.ToleratedTranslationAnchors); err != nil {
		return Output{}, err
	}
	if err := policyFile(file, options.JobUID); err != nil {
		return Output{}, err
	}
	before, err := c.ownedState(ctx)
	if err != nil {
		return Output{}, err
	}
	if before != "" {
		if err := validateLoadedPolicy(before, options.JobUID); err != nil {
			return Output{}, err
		}
		prior, err := c.store.read(c.anchor)
		if err != nil {
			return Output{}, err
		}
		if prior != ownershipRecord(c.anchor, options.JobUID, before) {
			return Output{}, errors.New("PF populated anchor does not match protected ownership receipt")
		}
	}
	// Verify/create the protected receipt destination before changing PF.
	if err := c.store.prepare(); err != nil {
		return Output{}, err
	}
	out, err := c.execute(ctx, "-a", c.anchor, "-f", file)
	if err != nil {
		return out, err
	}
	after, err := c.ownedState(ctx)
	if err != nil {
		return out, err
	}
	if err := validateLoadedPolicy(after, options.JobUID); err != nil {
		return out, err
	}
	if err := ValidateMandatoryDeny(after, options.JobUID); err != nil {
		return out, err
	}
	if err := c.store.write(ownershipRecord(c.anchor, options.JobUID, after)); err != nil {
		return out, err
	}
	return out, nil
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

package signer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// SignSpec is one codesign invocation: the node to sign, the Apple
// Distribution identity by SHA-1, the signer keychain, and the entitlements
// plist file (empty for frameworks and dylibs, which carry none).
type SignSpec struct {
	Path         string
	Identity     string
	Keychain     string
	Entitlements string
}

// Tools is every Apple tool the signer runs. The signing key is only ever
// used through codesign; security only creates, unlocks and lists the
// keychain and decodes CMS profiles. Tests substitute fakes.
type Tools interface {
	// CreateKeychain creates an empty keychain protected by secret, with
	// no automatic lock.
	CreateKeychain(ctx context.Context, keychain, secret string) error
	// UnlockKeychain unlocks keychain with secret.
	UnlockKeychain(ctx context.Context, keychain, secret string) error
	// Identities lists the SHA-1 (upper-case hex) of every valid
	// code-signing identity in keychain: a certificate with its private key.
	Identities(ctx context.Context, keychain string) ([]string, error)
	// DecodeProfile returns the XML plist content of a CMS provisioning
	// profile file.
	DecodeProfile(ctx context.Context, path string) ([]byte, error)
	// Sign runs codesign --force --sign on spec.Path.
	Sign(ctx context.Context, spec SignSpec) error
	// Verify runs codesign --verify --strict on path.
	Verify(ctx context.Context, path string) error
	// Entitlements returns the XML entitlements plist signed into path.
	Entitlements(ctx context.Context, path string) ([]byte, error)
}

// ExecTools runs the system tools at fixed absolute paths with a fixed
// environment. Secrets reach security on standard input (security -i),
// never in argv, which every local user can list.
type ExecTools struct {
	// Home is the signer account's home (its state directory).
	Home string
	// Timeout bounds one invocation; zero means 10 minutes (codesign
	// --timestamp contacts Apple's timestamp service).
	Timeout time.Duration
	// security overrides securityPath in tests.
	security string
}

const (
	codesignPath = "/usr/bin/codesign"
	securityPath = "/usr/bin/security"
	maxToolBytes = 8 << 20
)

var (
	// keychainSecretPattern bounds a keychain secret to characters that
	// need no quoting in a security -i command line.
	keychainSecretPattern = regexp.MustCompile(`^[A-Za-z0-9]{32,128}$`)
	// toolPathPattern refuses quoting, whitespace and control characters
	// in paths passed through security -i.
	toolPathPattern = regexp.MustCompile(`^/[A-Za-z0-9._/+-]+$`)
	identityLine    = regexp.MustCompile(`^\s*\d+\)\s+([0-9A-F]{40})\s+"`)
)

func (t ExecTools) run(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	stdout, stderr, err := t.runOutputs(ctx, stdin, name, args...)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s", name, args[0], err, strings.TrimSpace(string(stderr)))
	}
	return stdout, nil
}

// runOutputs runs a tool and returns its bounded standard output and error.
func (t ExecTools) runOutputs(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, []byte, error) {
	timeout := t.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C", "HOME=" + t.Home}
	cmd.Dir = t.Home
	cmd.WaitDelay = time.Second
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr boundedBuffer
	stdout.max, stderr.max = maxToolBytes, 64<<10
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, stderr.Bytes(), err
	}
	if stdout.overflow {
		return nil, stderr.Bytes(), fmt.Errorf("output exceeds %d bytes", maxToolBytes)
	}
	return stdout.Bytes(), stderr.Bytes(), nil
}

// securityScript runs commands through security -i so a secret is never an
// argument. security has no exit command: interactive mode ends at EOF of
// its input and exits with the last command's status, so the script is the
// commands alone. A failed earlier command only prints a message, and
// successful keychain commands print nothing, so any output besides
// prompts also fails the call. The output is never returned: it may quote
// a command line.
func (t ExecTools) securityScript(ctx context.Context, lines ...string) error {
	binary := t.security
	if binary == "" {
		binary = securityPath
	}
	stdout, stderr, err := t.runOutputs(ctx, securityInput(lines), binary, "-i")
	if err != nil {
		return errors.New("security -i failed")
	}
	if !onlyPrompts(stdout) || !onlyPrompts(stderr) {
		return errors.New("security -i reported an error")
	}
	return nil
}

// securityInput is the security -i standard input for lines: each command
// on its own line, then EOF.
func securityInput(lines []string) []byte {
	return []byte(strings.Join(lines, "\n") + "\n")
}

// onlyPrompts reports whether out holds nothing but security -i prompts
// and whitespace.
func onlyPrompts(out []byte) bool {
	return strings.TrimSpace(strings.ReplaceAll(string(out), "security>", "")) == ""
}

func checkKeychainArgs(keychain, secret string) error {
	if !toolPathPattern.MatchString(keychain) {
		return errors.New("keychain path has characters security -i cannot take unquoted")
	}
	if !keychainSecretPattern.MatchString(secret) {
		return errors.New("keychain secret must be 32-128 ASCII letters and digits")
	}
	return nil
}

func (t ExecTools) CreateKeychain(ctx context.Context, keychain, secret string) error {
	if err := checkKeychainArgs(keychain, secret); err != nil {
		return err
	}
	return t.securityScript(ctx, "create-keychain -p "+secret+" "+keychain, "set-keychain-settings "+keychain)
}

func (t ExecTools) UnlockKeychain(ctx context.Context, keychain, secret string) error {
	if err := checkKeychainArgs(keychain, secret); err != nil {
		return err
	}
	return t.securityScript(ctx, "unlock-keychain -p "+secret+" "+keychain)
}

func (t ExecTools) Identities(ctx context.Context, keychain string) ([]string, error) {
	out, err := t.run(ctx, nil, securityPath, "find-identity", "-v", "-p", "codesigning", keychain)
	if err != nil {
		return nil, err
	}
	return parseIdentities(out), nil
}

// parseIdentities reads security find-identity lines `  1) <SHA-1> "name"`.
func parseIdentities(out []byte) []string {
	var identities []string
	for line := range strings.SplitSeq(string(out), "\n") {
		if match := identityLine.FindStringSubmatch(line); match != nil {
			identities = append(identities, match[1])
		}
	}
	return identities
}

func (t ExecTools) DecodeProfile(ctx context.Context, path string) ([]byte, error) {
	return t.run(ctx, nil, securityPath, "cms", "-D", "-i", path)
}

func (t ExecTools) Sign(ctx context.Context, spec SignSpec) error {
	args := []string{"--force", "--sign", spec.Identity, "--keychain", spec.Keychain}
	if spec.Entitlements != "" {
		args = append(args, "--entitlements", spec.Entitlements)
	}
	args = append(args, "--timestamp", "--", spec.Path)
	_, err := t.run(ctx, nil, codesignPath, args...)
	return err
}

func (t ExecTools) Verify(ctx context.Context, path string) error {
	_, err := t.run(ctx, nil, codesignPath, "--verify", "--strict", "--", path)
	return err
}

func (t ExecTools) Entitlements(ctx context.Context, path string) ([]byte, error) {
	return t.run(ctx, nil, codesignPath, "-d", "--entitlements", ":-", "--", path)
}

// boundedBuffer keeps at most max bytes and records overflow.
type boundedBuffer struct {
	bytes.Buffer
	max      int
	overflow bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	room := b.max - b.Len()
	if len(p) > room {
		b.overflow = true
		if room > 0 {
			b.Buffer.Write(p[:room])
		}
		return len(p), nil
	}
	return b.Buffer.Write(p)
}

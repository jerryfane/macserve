package worker

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jerryfane/macserve/internal/hostguard"
)

type RegisteredCode struct {
	Path        string `json:"path"`
	Executable  string `json:"executable"`
	Identifier  string `json:"identifier"`
	Team        string `json:"team"`
	CDHash      string `json:"cdhash"`
	Requirement string `json:"requirement"`
	TreeRoot    string `json:"tree_root"`
	TreeSHA256  string `json:"tree_sha256"`
}

// All commands and switches are fixed. Registered paths are passed as a single
// argument after --, never interpreted as switches or a shell program.
func codeCommand(ctx context.Context, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/codesign", args...)
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"}
	cmd.WaitDelay = 100 * time.Millisecond
	out := &boundedBuffer{max: 1 << 20}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Run(); err != nil {
		return "", errors.Join(errors.New("registered code signature command failed"), ctx.Err())
	}
	if out.err != nil {
		return "", out.err
	}
	return out.String(), nil
}

func signatureIdentity(output string) (RegisteredCode, error) {
	var code RegisteredCode
	seen, authorities := map[string]bool{}, 0
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "designated => ") {
			if code.Requirement != "" {
				return code, errors.New("duplicate designated requirement")
			}
			code.Requirement = strings.TrimPrefix(line, "designated => ")
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "Signature":
			if strings.Contains(strings.ToLower(value), "adhoc") {
				return code, errors.New("ad-hoc registrations are not eligible")
			}
		case "Authority":
			if value != "" {
				authorities++
			}
		case "Executable", "Identifier", "TeamIdentifier", "CDHash":
			if seen[key] || value == "" {
				return code, errors.New("ambiguous registered signature identity")
			}
			seen[key] = true
			switch key {
			case "Executable":
				code.Executable = value
			case "Identifier":
				code.Identifier = value
			case "TeamIdentifier":
				code.Team = value
			case "CDHash":
				code.CDHash = value
			}
		}
	}
	digest, err := hex.DecodeString(code.CDHash)
	if err != nil || len(digest) != 20 || code.Executable == "" || code.Identifier == "" || code.Team == "" || code.Team == "not set" || code.Requirement == "" || authorities == 0 {
		return code, errors.New("complete non-ad-hoc signed code identity unavailable")
	}
	return code, nil
}

func verifyRegisteredCode(ctx context.Context, path string, record BTMRecord) (RegisteredCode, error) {
	var code RegisteredCode
	if err := hostguard.RootDirectory(path); err != nil {
		return code, err
	}
	out, err := codeCommand(ctx, "--display", "--verbose=4", "--requirements", "-", "--", path)
	if err != nil {
		return code, err
	}
	code, err = signatureIdentity(out)
	if err != nil {
		return code, err
	}
	if code.Identifier != record.Fields["Bundle Identifier"] || code.Team != record.Fields["Team Identifier"] {
		return code, errors.New("registered bundle identity does not match its signed code")
	}
	rel, err := filepath.Rel(path, code.Executable)
	if err != nil || rel == "." || !filepath.IsLocal(rel) {
		return code, errors.New("signed executable is outside registered bundle")
	}
	if err := hostguard.RootConfig(code.Executable); err != nil {
		return code, err
	}
	if _, err := codeCommand(ctx, "--verify", "--strict", "--deep", "--test-requirement", "anchor apple generic", "--verbose=0", "--", path); err != nil {
		return code, err
	}
	return code, nil
}

// Hash names, ownership, modes, link text and all regular bytes beneath a
// protected bundle. os.Root forbids symlink traversal outside this tree; WalkDir
// itself never follows links. Root-owned privileged updaters remain trusted, but
// changed files during a read are refused, and any later change invalidates the
// accepted digest. One app tree is hashed once even when several nested services
// are registered. This deliberately does not trust only a parent app's signature.
func protectedTreeDigest(ctx context.Context, path string) (string, error) {
	if err := hostguard.RootDirectory(path); err != nil {
		return "", err
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return "", err
	}
	defer root.Close()
	h := sha256.New()
	buffer := make([]byte, 128<<10)
	var total int64
	entries := 0
	err = filepath.WalkDir(path, func(full string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		entries++
		if entries > 1<<20 {
			return errors.New("registered tree entry bound exceeded")
		}
		rel, err := filepath.Rel(path, full)
		if err != nil {
			return err
		}
		info, err := root.Lstat(rel)
		if err != nil {
			return err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			return errors.New("registered code tree is not root-owned")
		}
		link := info.Mode()&os.ModeSymlink != 0
		if !link && info.Mode().Perm()&0022 != 0 {
			return errors.New("registered code tree is writable outside root")
		}
		fmt.Fprintf(h, "%s\x00%d\x00%d\x00%d\x00", rel, info.Mode(), st.Uid, st.Gid)
		switch {
		case link:
			text, err := root.Readlink(rel)
			if err != nil {
				return err
			}
			if _, err := root.Stat(rel); err != nil {
				return errors.New("registered tree link escapes or is unresolved")
			}
			h.Write([]byte(text))
			h.Write([]byte{0})
		case info.IsDir():
		case info.Mode().IsRegular():
			if info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
				return errors.New("privileged executable in registered tree")
			}
			file, err := root.Open(rel)
			if err != nil {
				return err
			}
			defer file.Close()
			opened, err := file.Stat()
			if err != nil || !os.SameFile(info, opened) {
				return errors.New("registered file identity changed")
			}
			h.Write([]byte(strconv.FormatInt(info.Size(), 10)))
			h.Write([]byte{0})
			var read int64
			for {
				if err := ctx.Err(); err != nil {
					return err
				}
				n, e := file.Read(buffer)
				read += int64(n)
				total += int64(n)
				if total > 64<<30 {
					return errors.New("registered tree byte bound exceeded")
				}
				h.Write(buffer[:n])
				if e == io.EOF {
					break
				}
				if e != nil {
					return e
				}
			}
			after, err := file.Stat()
			if err != nil || read != info.Size() || after.Size() != info.Size() || after.ModTime() != info.ModTime() || after.Mode() != info.Mode() {
				return errors.New("registered file changed during inspection")
			}
		default:
			return errors.New("unsupported object in registered code tree")
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

var listedMode = regexp.MustCompile(`^[bcdlps-][rwxStTs-]{9}([+@ ])`)
var denyOnlyACL = regexp.MustCompile(`^[ \t]+[0-9]+: .+ deny [a-z_,]+$`)

func validateTreeACL(output string) error {
	scanner := bufio.NewScanner(strings.NewReader(output))
	scanner.Buffer(make([]byte, 4096), 256<<10)
	needsACL, sawACL := false, false
	entryOpen, sawEntry := false, false
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			if !entryOpen || !denyOnlyACL.MatchString(line) {
				return errors.New("registered tree ACL grants access or is unsupported")
			}
			sawACL = true
			continue
		}
		if needsACL && !sawACL {
			return errors.New("registered tree ACL listing incomplete")
		}
		needsACL, sawACL = false, false
		entryOpen = false
		if line == "" {
			continue
		}
		if match := listedMode.FindStringSubmatch(line); match != nil {
			needsACL = match[1] == "+"
			entryOpen, sawEntry = true, true
			continue
		}
		if strings.HasPrefix(line, "total ") {
			if _, err := strconv.ParseUint(strings.TrimPrefix(line, "total "), 10, 64); err == nil {
				continue
			}
		}
		if strings.HasPrefix(line, "/") && strings.HasSuffix(line, ":") {
			continue
		}
		return errors.New("unsupported registered tree ACL listing")
	}
	if scanner.Err() != nil || !sawEntry || needsACL && !sawACL {
		return errors.New("registered tree ACL listing unavailable")
	}
	return nil
}

func protectedTreeACL(ctx context.Context, path string) error {
	// Reuse the native protected-input ancestor policy, then inspect all children
	// in one bounded command rather than launching one process per tree entry.
	if err := hostguard.CheckProtectedPath(path, true); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "/bin/ls", "-laebR", path)
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"}
	cmd.WaitDelay = 100 * time.Millisecond
	out, diagnostic := &boundedBuffer{max: 64 << 20}, &boundedBuffer{max: 1 << 20}
	cmd.Stdout, cmd.Stderr = out, diagnostic
	if err := cmd.Run(); err != nil || out.err != nil || diagnostic.err != nil || diagnostic.Len() != 0 || out.Len() == 0 {
		return errors.New("registered tree ACL census unavailable")
	}
	return validateTreeACL(out.String())
}

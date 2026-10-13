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
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
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

// Registration code has a deliberately separate writer policy from broker
// configuration and macserve's own services. Never use it for trusted state.
type registrationWriters struct {
	ownerUID uint32
	resolve  func(kind, principal string) (uint32, error)
}

func registrationWriterPolicy(ctx context.Context, options Options) (registrationWriters, error) {
	member := func(account *user.User, gid string) (bool, error) {
		return registrationGroupMember(ctx, account.Uid, gid)
	}
	if err := registrationWriterIdentities(options, user.LookupId, user.LookupGroup, (*user.User).GroupIds, member); err != nil {
		return registrationWriters{}, err
	}
	return registrationWriters{ownerUID: options.OwnerUID, resolve: registrationPrincipal}, nil
}

// Directory Services membership resolves nested groups; GroupIds alone does not
// establish that a service identity is outside the trusted writer groups.
func registrationGroupMember(ctx context.Context, uid, gid string) (bool, error) {
	out, diagnostic, err := inspectCommand(ctx, nil, "/usr/bin/dsmemberutil", "checkmembership", "-u", uid, "-g", gid)
	if err != nil || strings.TrimSpace(diagnostic) != "" {
		return false, errors.Join(err, errors.New("registration service account memberships unavailable"))
	}
	switch strings.TrimSpace(out) {
	case "user is a member of the group":
		return true, nil
	case "user is not a member of the group":
		return false, nil
	default:
		return false, errors.New("registration service account memberships unavailable")
	}
}

func registrationWriterIdentities(options Options, lookup func(string) (*user.User, error), lookupGroup func(string) (*user.Group, error), groupIDs func(*user.User) ([]string, error), member func(*user.User, string) (bool, error)) error {
	if options.OwnerUID == 0 || options.JobUID == 0 || options.ControllerUID == 0 || options.OwnerUID == options.JobUID || options.OwnerUID == options.ControllerUID || options.JobUID == options.ControllerUID {
		return fmt.Errorf("%w: registration writers require distinct owner, job and controller identities", ErrContamination)
	}
	for name, gid := range map[string]string{"wheel": "0", "staff": "20", "admin": "80"} {
		group, err := lookupGroup(name)
		if err != nil || group == nil || group.Gid != gid {
			return errors.New("registration writer group identity unavailable")
		}
	}
	for _, uid := range []uint32{0, options.OwnerUID, options.JobUID, options.ControllerUID} {
		id := strconv.FormatUint(uint64(uid), 10)
		account, err := lookup(id)
		if err != nil || account == nil || account.Uid != id || account.Username == "" {
			return errors.New("registration writer account identity unavailable")
		}
		if uid == 0 || uid == options.OwnerUID {
			continue
		}
		groups, err := groupIDs(account)
		if err != nil || len(groups) == 0 {
			return errors.Join(err, errors.New("registration service account memberships unavailable"))
		}
		// Include the primary group explicitly: directory membership results
		// must not be assumed to include it, especially for staff.
		for i := 0; i <= len(groups); i++ {
			gid := account.Gid
			if i < len(groups) {
				gid = groups[i]
			}
			value, err := strconv.ParseUint(gid, 10, 32)
			if err != nil {
				return errors.New("registration service account membership is unknown")
			}
			if value == 0 || value == 20 || value == 80 {
				return fmt.Errorf("%w: registration job and controller must not belong to wheel, staff or admin", ErrContamination)
			}
		}
		for _, gid := range []string{"0", "20", "80"} {
			belongs, err := member(account, gid)
			if err != nil {
				return errors.Join(err, errors.New("registration service account memberships unavailable"))
			}
			if belongs {
				return fmt.Errorf("%w: registration job and controller must not belong to wheel, staff or admin", ErrContamination)
			}
		}
	}
	return nil
}

func registrationPrincipal(kind, principal string) (uint32, error) {
	var id string
	_, numeric := strconv.ParseUint(principal, 10, 32)
	switch kind {
	case "user":
		var account *user.User
		var err error
		if numeric == nil {
			account, err = user.LookupId(principal)
		} else {
			account, err = user.Lookup(principal)
		}
		if err != nil || account == nil {
			return 0, errors.New("registration ACL user identity unavailable")
		}
		id = account.Uid
	case "group":
		var group *user.Group
		var err error
		if numeric == nil {
			group, err = user.LookupGroupId(principal)
		} else {
			group, err = user.LookupGroup(principal)
		}
		if err != nil || group == nil {
			return 0, errors.New("registration ACL group identity unavailable")
		}
		id = group.Gid
	default:
		return 0, errors.New("unsupported registration ACL principal")
	}
	value, err := strconv.ParseUint(id, 10, 32)
	if err != nil {
		return 0, errors.New("registration ACL identity is not numeric")
	}
	return uint32(value), nil
}

func (writers registrationWriters) checkMode(info os.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("registered code ownership unavailable")
	}
	if st.Uid != 0 && st.Uid != writers.ownerUID {
		return fmt.Errorf("%w: registered code ownership is outside root and owner", ErrContamination)
	}
	// Symlink modes are not access controls; link ownership and the resolved
	// target's protection are checked, and escaping links remain forbidden.
	if info.Mode()&os.ModeSymlink == 0 && (info.Mode().Perm()&0002 != 0 || info.Mode().Perm()&0020 != 0 && st.Gid != 0 && st.Gid != 80) {
		return fmt.Errorf("%w: registered code has writers outside root, owner, wheel and admin", ErrContamination)
	}
	return nil
}

type registrationPathEntry struct {
	path string
	info os.FileInfo
}

func registrationPath(path string, directory bool, writers registrationWriters) ([]registrationPathEntry, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("registration requires a clean absolute path")
	}
	var entries []registrationPathEntry
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, fmt.Errorf("%w: registered path or ancestor missing: %w", ErrContamination, err)
			}
			return nil, err
		}
		validType := info.IsDir()
		if current == path && !directory {
			validType = info.Mode().IsRegular()
		}
		if !validType {
			return nil, fmt.Errorf("%w: registered path or ancestor is not a non-symlink directory/file", ErrContamination)
		}
		if err := writers.checkMode(info); err != nil {
			return nil, err
		}
		entries = append(entries, registrationPathEntry{path: current, info: info})
		if current == "/" {
			return entries, nil
		}
	}
}

func recheckRegistrationPath(entries []registrationPathEntry, writers registrationWriters) error {
	for _, entry := range entries {
		info, err := os.Lstat(entry.path)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("%w: registered path or ancestor disappeared: %w", ErrContamination, err)
			}
			return err
		}
		before, ok := entry.info.Sys().(*syscall.Stat_t)
		after, afterOK := info.Sys().(*syscall.Stat_t)
		if !ok || !afterOK {
			return errors.New("registered path or ancestor identity unavailable")
		}
		if !os.SameFile(entry.info, info) || entry.info.Mode() != info.Mode() || before.Uid != after.Uid || before.Gid != after.Gid {
			return fmt.Errorf("%w: registered path or ancestor changed during inspection", ErrContamination)
		}
		if err := writers.checkMode(info); err != nil {
			return err
		}
	}
	return nil
}

func verifyRegisteredCode(ctx context.Context, path string, record BTMRecord, writers registrationWriters, command func(context.Context, ...string) (string, error)) (RegisteredCode, error) {
	var code RegisteredCode
	ancestry, err := registrationPath(path, true, writers)
	if err != nil {
		return code, err
	}
	out, err := command(ctx, "--display", "--verbose=4", "--requirements", "-", "--", path)
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
	executableAncestry, err := registrationPath(code.Executable, false, writers)
	if err != nil {
		return code, err
	}
	// Compare directory identities, not path spelling: codesign can report
	// Plugins where BTM reports PlugIns on a case-insensitive filesystem. A
	// same-spelled directory on a case-sensitive filesystem is not equivalent.
	relative := ""
	for _, entry := range executableAncestry[1:] {
		if os.SameFile(ancestry[0].info, entry.info) {
			relative, err = filepath.Rel(entry.path, code.Executable)
			break
		}
	}
	if err != nil || relative == "." || !filepath.IsLocal(relative) {
		return code, errors.New("signed executable is outside registered bundle")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return code, err
	}
	defer root.Close()
	openedRoot, err := root.Stat(".")
	if err != nil || !os.SameFile(ancestry[0].info, openedRoot) {
		return code, errors.New("registered tree root changed during open")
	}
	if err := checkOpenedRegisteredExecutable(root, relative, executableAncestry[0].info); err != nil {
		return code, err
	}
	if _, err := command(ctx, "--verify", "--strict", "--deep", "--test-requirement", "=anchor apple generic", "--verbose=0", "--", path); err != nil {
		return code, err
	}
	if err := recheckRegistrationPath(executableAncestry, writers); err != nil {
		return code, err
	}
	return code, recheckRegistrationPath(ancestry, writers)
}

// Pin the descriptor actually opened beneath the verified root, not just the
// pathname observed before open. A replacement may preserve all mode metadata.
func checkOpenedRegisteredExecutable(root *os.Root, relative string, expected os.FileInfo) error {
	executable, err := root.Open(relative)
	if err != nil {
		return err
	}
	opened, statErr := executable.Stat()
	closeErr := executable.Close()
	if statErr != nil || closeErr != nil || !os.SameFile(expected, opened) {
		return errors.New("signed executable changed during inspection")
	}
	return nil
}

// Hash names, ownership, modes, link text and all regular bytes beneath a
// protected bundle. os.Root forbids symlink traversal outside this tree; WalkDir
// itself never follows links. Root, owner, wheel and administrator updaters are trusted,
// changed files during a read are refused, and any later change invalidates the
// accepted digest. One app tree is hashed once even when several nested services
// are registered. This deliberately does not trust only a parent app's signature.
func protectedTreeDigest(ctx context.Context, path string, writers registrationWriters) (string, error) {
	ancestry, err := registrationPath(path, true, writers)
	if err != nil {
		return "", err
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return "", err
	}
	defer root.Close()
	openedRoot, err := root.Stat(".")
	if err != nil || !os.SameFile(ancestry[0].info, openedRoot) {
		return "", errors.New("registered tree root changed during open")
	}
	h := sha256.New()
	buffer := make([]byte, 128<<10)
	var total int64
	entries := 0
	err = fs.WalkDir(root.FS(), ".", func(rel string, entry fs.DirEntry, walkErr error) error {
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
		info, err := root.Lstat(rel)
		if err != nil {
			return err
		}
		if err := writers.checkMode(info); err != nil {
			return err
		}
		st := info.Sys().(*syscall.Stat_t)
		link := info.Mode()&os.ModeSymlink != 0
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
			if err != nil {
				return err
			}
			afterStat, ok := after.Sys().(*syscall.Stat_t)
			if !ok || read != info.Size() || after.Size() != info.Size() || after.ModTime() != info.ModTime() || after.Mode() != info.Mode() || afterStat.Uid != st.Uid || afterStat.Gid != st.Gid {
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
	return hex.EncodeToString(h.Sum(nil)), recheckRegistrationPath(ancestry, writers)
}

var listedMode = regexp.MustCompile(`^[bcdlps-][rwxStTs-]{9}([+@ ])`)
var registrationACL = regexp.MustCompile(`^[ \t]+[0-9]+: (user|group):([A-Za-z0-9_.-]+)( inherited)? (allow|deny) ([a-z_,]+)$`)

func (writers registrationWriters) checkACL(line string) error {
	match := registrationACL.FindStringSubmatch(line)
	if match == nil {
		return errors.New("unsupported registration ACL entry")
	}
	mutating := false
	// ls does not quote principals: "admin inherited" can be a literal name,
	// indistinguishable from an inheritance marker on "admin". Refuse that
	// ambiguity rather than resolve the shorter, potentially trusted name.
	if match[3] != "" {
		return errors.New("ambiguous inherited registration ACL principal")
	}
	for _, right := range strings.Split(match[5], ",") {
		switch right {
		case "read", "list", "execute", "search", "readattr", "readextattr", "readsecurity", "synchronize",
			"file_inherit", "directory_inherit", "limit_inherit", "only_inherit":
		case "write", "append", "add_file", "add_subdirectory", "delete", "delete_child", "writeattr", "writeextattr", "writesecurity", "chown":
			mutating = true
		default:
			return errors.New("unknown registration ACL right")
		}
	}
	// everyone is a native special principal, not a directory-services group.
	everyone := match[1] == "group" && match[2] == "everyone"
	allowed := false
	if !everyone {
		id, err := writers.resolve(match[1], match[2])
		if err != nil {
			return err
		}
		allowed = match[1] == "user" && (id == 0 || id == writers.ownerUID) || match[1] == "group" && (id == 0 || id == 80)
	}
	if match[4] == "allow" && mutating && !allowed {
		return fmt.Errorf("%w: registration ACL grants writes outside root, owner, wheel and admin", ErrContamination)
	}
	return nil
}

func validateTreeACL(output string, writers registrationWriters) error {
	scanner := bufio.NewScanner(strings.NewReader(output))
	scanner.Buffer(make([]byte, 4096), 256<<10)
	needsACL, sawACL := false, false
	entryOpen, sawEntry := false, false
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			if !entryOpen {
				return errors.New("registered tree ACL has no listed object")
			}
			if err := writers.checkACL(line); err != nil {
				return err
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

func protectedTreeACL(ctx context.Context, path string, writers registrationWriters) error {
	ancestry, err := registrationPath(path, true, writers)
	if err != nil {
		return err
	}
	// The recursive census does not cover all ancestors. Inspect each one,
	// including inherited ACL entries, and bracket commands with identity checks.
	for _, entry := range ancestry {
		if err := registrationACLCommand(ctx, writers, "-ldeb", entry.path); err != nil {
			return err
		}
	}
	if err := registrationACLCommand(ctx, writers, "-laebR", path); err != nil {
		return err
	}
	return recheckRegistrationPath(ancestry, writers)
}

func registrationACLCommand(ctx context.Context, writers registrationWriters, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/ls", args...)
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"}
	cmd.WaitDelay = 100 * time.Millisecond
	out, diagnostic := &boundedBuffer{max: 64 << 20}, &boundedBuffer{max: 1 << 20}
	cmd.Stdout, cmd.Stderr = out, diagnostic
	if err := cmd.Run(); err != nil || out.err != nil || diagnostic.err != nil || diagnostic.Len() != 0 || out.Len() == 0 {
		return errors.New("registered tree ACL census unavailable")
	}
	return validateTreeACL(out.String(), writers)
}

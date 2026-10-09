package pfctl

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/jerryfane/macserve/internal/hostguard"
)

const ownershipDirectory = "/Library/macserve/var/pf-ownership"

// ValidateOwnedAnchor is deliberately stricter than the read-only AnchorPath.
// Apple children are reserved except our explicit macserve namespace. A write
// cannot claim a listed peer or an ancestor of a listed peer.
func ValidateOwnedAnchor(path string, exclusions ...[]string) error {
	if !AnchorPath(path) {
		return errors.New("owned PF anchor must be an exact bounded path")
	}
	parts := strings.Split(path, "/")
	for _, part := range parts {
		if part == "_pf" {
			return errors.New("reserved PF anchor cannot be owned")
		}
	}
	if parts[0] == "com.apple" && (len(parts) != 2 || parts[1] != "macserve" && !strings.HasPrefix(parts[1], "macserve-")) {
		return errors.New("Apple PF anchors are reserved outside the macserve leaf namespace")
	}
	for _, list := range exclusions {
		for _, peer := range list {
			if path == peer || strings.HasPrefix(peer, path+"/") {
				return errors.New("owned PF anchor overlaps a configured coexisting or translation anchor")
			}
		}
	}
	return nil
}

// All direct namespaces must be empty except filter rules; child absence is
// never used to excuse failed rule/table reads. Even a named-but-empty child
// makes the configured path a parent rather than an exclusively owned leaf.
func (c *Client) ownedState(ctx context.Context) (string, error) {
	children, err := c.Read(ctx, "-a", c.anchor, "-v", "-s", "Anchors")
	absent := errors.Is(err, ErrAnchorAbsent)
	if err != nil && !absent {
		return "", fmt.Errorf("PF ownership child observation: %w", err)
	}
	if children.Stdout != "" {
		return "", errors.New("owned PF anchor contains children")
	}
	// pfctl omits the reserved _pf child from ordinary anchor listings.
	// Even an empty reserved child makes this a parent, not an owned leaf.
	reserved := c.anchor + "/_pf"
	if _, err := c.Read(ctx, "-a", reserved, "-v", "-s", "Anchors"); !errors.Is(err, ErrAnchorAbsent) {
		return "", errors.New("owned PF anchor has a reserved child or its absence is unproven")
	}
	filter, err := c.Read(ctx, "-a", c.anchor, "-sr")
	if err != nil {
		return "", fmt.Errorf("PF ownership filter observation: %w", err)
	}
	for _, args := range [][]string{{"-sn"}, {"-s", "Tables"}} {
		out, err := c.Read(ctx, append([]string{"-a", c.anchor}, args...)...)
		if err != nil {
			return "", fmt.Errorf("PF ownership direct namespace observation: %w", err)
		}
		if out.Stdout != "" {
			return "", errors.New("owned PF anchor contains translation rules or tables")
		}
	}
	if absent && filter.Stdout != "" {
		return "", errors.New("PF ownership observations disagree about absent anchor")
	}
	return filter.Stdout, nil
}

func validateLoadedPolicy(text string, jobUID uint32) error {
	if text == "" || len(text) > maxPolicyBytes || !strings.HasSuffix(text, "\n") {
		return errors.New("owned PF loaded rules are empty, excessive, or incomplete")
	}
	marked := false
	for n, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		if n >= 4096 || len(line) > 8192 {
			return errors.New("owned PF loaded rule limit exceeded")
		}
		for _, ch := range line {
			if ch != '\t' && (ch < ' ' || ch > '~') {
				return errors.New("unsupported owned PF loaded rule characters")
			}
		}
		tokens, ok := filterTokens(line)
		if !ok || !jobScope(tokens, nil, jobUID) {
			return errors.New("owned PF loaded rule is not scoped to the outbound job UID")
		}
		for i := 1; i+1 < len(tokens); i++ {
			if tokens[0] == "block" && tokens[i] == "label" && tokens[i+1] == `"macserve-default-deny"` {
				marked = true
			}
		}
	}
	if !marked {
		return errors.New("populated PF anchor lacks the macserve default-deny marker")
	}
	return nil
}

type ownershipReceipt struct {
	Schema      int    `json:"schema"`
	Anchor      string `json:"anchor"`
	JobUID      uint32 `json:"job_uid"`
	RulesSHA256 string `json:"rules_sha256"`
}

func ownershipRecord(anchor string, uid uint32, rules string) ownershipReceipt {
	return ownershipReceipt{Schema: 1, Anchor: anchor, JobUID: uid, RulesSHA256: ownershipHash(rules)}
}

func ownershipHash(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

type ownershipStore interface {
	prepare() error
	read(string) (ownershipReceipt, error)
	write(ownershipReceipt) error
}

// No exported override: production ownership can only come from root-protected
// storage, never from an input receipt supplied by a qualification caller.
type protectedOwnershipStore struct{}

func protectedOwnershipPath(path string, directory bool, exactMode os.FileMode) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 || directory != info.IsDir() || !directory && (!info.Mode().IsRegular() || st.Nlink != 1) || exactMode != 0 && info.Mode().Perm() != exactMode {
		return nil, errors.New("PF ownership storage is not root-protected")
	}
	return info, nil
}

func ownershipAncestors(create bool) error {
	for _, path := range []string{"/", "/Library", "/Library/macserve", "/Library/macserve/var", ownershipDirectory} {
		mode := os.FileMode(0)
		if path == ownershipDirectory {
			mode = 0700
		}
		_, err := protectedOwnershipPath(path, true, mode)
		if errors.Is(err, os.ErrNotExist) && create && path == ownershipDirectory {
			if err = os.Mkdir(path, 0700); err == nil || errors.Is(err, os.ErrExist) {
				_, err = protectedOwnershipPath(path, true, mode)
			}
		}
		if err != nil {
			return err
		}
	}
	return hostguard.CheckProtectedPath(ownershipDirectory, true)
}

func (protectedOwnershipStore) prepare() error {
	return ownershipAncestors(true)
}

func (protectedOwnershipStore) read(anchor string) (ownershipReceipt, error) {
	var receipt ownershipReceipt
	if err := ownershipAncestors(false); err != nil {
		return receipt, err
	}
	path := filepath.Join(ownershipDirectory, ownershipHash(anchor)+".json")
	before, err := protectedOwnershipPath(path, false, 0600)
	if err != nil {
		return receipt, err
	}
	if err := hostguard.CheckProtectedPath(path, false); err != nil {
		return receipt, err
	}
	if before.Size() > 4096 {
		return receipt, errors.New("oversized PF ownership receipt")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return receipt, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		return receipt, errors.New("PF ownership receipt changed during read")
	}
	decoder := json.NewDecoder(io.LimitReader(file, 4097))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return receipt, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return receipt, errors.New("trailing PF ownership receipt content")
	}
	return receipt, nil
}

func (protectedOwnershipStore) write(receipt ownershipReceipt) error {
	if err := ownershipAncestors(false); err != nil {
		return err
	}
	path := filepath.Join(ownershipDirectory, ownershipHash(receipt.Anchor)+".json")
	if _, err := protectedOwnershipPath(path, false, 0600); err == nil {
		if err := hostguard.CheckProtectedPath(path, false); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	data, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(ownershipDirectory, ".receipt-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err != nil {
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(ownershipDirectory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

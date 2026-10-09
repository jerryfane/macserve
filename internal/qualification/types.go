// Package qualification collects bounded operator-reviewed boundary evidence.
// Network probes are informational; PF is never changed.
// It never changes launchd, accounts, GUI baselines, owner state, or health.
package qualification

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jerryfane/macserve/internal/deploy"
	"github.com/jerryfane/macserve/internal/hostguard"
	"github.com/jerryfane/macserve/internal/maintenance"
	"github.com/jerryfane/macserve/internal/model"
)

const maxArtifact = 4 << 20
const lifetime = 2 * time.Hour
const maintenancePath = "/Library/macserve/config/maintenance.json"

const networkStatus = "not enforced in phase 1"

var categories = []string{"network_reachability", "unix_socket_boundary", "owner_unaffected", "owner_home_denial", "fast_switch", "reboot", "tool_profiles"}

type Challenge struct {
	Schema            int                     `json:"schema"`
	ID                string                  `json:"id"`
	Created           time.Time               `json:"created"`
	Expires           time.Time               `json:"expires"`
	Environment       deploy.Environment      `json:"environment"`
	EnvironmentSHA256 string                  `json:"environment_sha256"`
	Observation       maintenance.Observation `json:"observation"`
	TCP               []string                `json:"tcp"`
	Allow             []string                `json:"allow"`
	UDP               []string                `json:"udp"`
	OwnerCanary       string                  `json:"owner_canary"`
	PrivatePaths      []string                `json:"private_paths"`
	Socket            string                  `json:"socket"`
	Profiles          []model.Profile         `json:"profiles"`
	Previous          string                  `json:"previous,omitempty"`
	PreviousSHA256    string                  `json:"previous_sha256,omitempty"`
}
type Result struct {
	Category string `json:"category"`
	Target   string `json:"target"`
	Attempt  int    `json:"attempt"`
	Success  bool   `json:"success"`
	Detail   string `json:"detail"`
	Nonce    string `json:"nonce,omitempty"`
}
type Report struct {
	Schema          int       `json:"schema"`
	ChallengeSHA256 string    `json:"challenge_sha256"`
	Role            string    `json:"role"`
	UID             int       `json:"uid"`
	Groups          []int     `json:"groups"`
	Started         time.Time `json:"started"`
	Finished        time.Time `json:"finished"`
	Results         []Result  `json:"results"`
	Refusal         string    `json:"refusal,omitempty"`
}
type Packet struct {
	Challenge string `json:"challenge"`
	Role      string `json:"role"`
	Attempt   int    `json:"attempt"`
	Nonce     string `json:"nonce"`
}
type Received struct {
	Packet Packet    `json:"packet"`
	At     time.Time `json:"at"`
	Peer   string    `json:"peer"`
}
type OwnerCanaryControl struct {
	Path     string    `json:"path"`
	At       time.Time `json:"at"`
	Readable bool      `json:"readable"`
	Detail   string    `json:"detail"`
}
type Receipts struct {
	Schema          int                `json:"schema"`
	ChallengeSHA256 string             `json:"challenge_sha256"`
	UID             int                `json:"uid"`
	Listen          string             `json:"listen"`
	Started         time.Time          `json:"started"`
	Finished        time.Time          `json:"finished"`
	Packets         []Received         `json:"packets"`
	OwnerBefore     OwnerCanaryControl `json:"owner_canary_before"`
	OwnerAfter      OwnerCanaryControl `json:"owner_canary_after"`
	Error           string             `json:"error,omitempty"`
}
type Snapshot struct {
	At          time.Time               `json:"at"`
	Observation maintenance.Observation `json:"observation"`
}
type Category struct {
	Status   string            `json:"status"`
	Reason   string            `json:"reason"`
	Evidence []string          `json:"evidence"`
	Probe    maintenance.Probe `json:"probe"`
}
type Candidate struct {
	Schema          int                              `json:"schema"`
	ChallengeSHA256 string                           `json:"challenge_sha256"`
	Collected       time.Time                        `json:"collected"`
	Observation     maintenance.Observation          `json:"observation"`
	Artifacts       map[string]string                `json:"artifacts"`
	Categories      map[string]Category              `json:"categories"`
	Coexistence     *maintenance.CoexistenceEvidence `json:"coexistence"`
}
type Attestation struct {
	Schema          int               `json:"schema"`
	ChallengeSHA256 string            `json:"challenge_sha256"`
	Category        string            `json:"category"`
	Recorded        time.Time         `json:"recorded"`
	ReviewerUID     uint32            `json:"reviewer_uid"`
	Reason          string            `json:"reason"`
	Artifact        string            `json:"artifact"`
	ArtifactSHA256  string            `json:"artifact_sha256"`
	Profiles        map[string]string `json:"profiles"`
}

func digest(b []byte) string       { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func encode(v any) ([]byte, error) { return json.MarshalIndent(v, "", "  ") }
func decode(b []byte, v any) error {
	if len(b) > maxArtifact {
		return errors.New("artifact exceeds 4 MiB")
	}
	if e := uniqueJSON(b); e != nil {
		return e
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func fresh(c Challenge, now time.Time) error {
	if c.Schema != 3 || len(c.ID) != 64 || c.Created.IsZero() || now.Before(c.Created) || !now.Before(c.Expires) || c.Expires.Sub(c.Created) != lifetime {
		return errors.New("invalid or expired challenge; begin a fresh sitting")
	}
	return nil
}
func sameObservation(a, b maintenance.Observation) bool {
	return a.JobUID == b.JobUID && a.Boot == b.Boot && a.BaselineSHA256 == b.BaselineSHA256 && maps.Equal(a.Profiles, b.Profiles) && b.IdentityValid && b.BaselineValid
}
func rootOnly() error {
	if runtime.GOOS != "darwin" || os.Getuid() != 0 || os.Geteuid() != 0 {
		return errors.New("requires actual macOS root; no host changes performed")
	}
	return nil
}
func cleanPath(p string) bool {
	return filepath.IsAbs(p) && filepath.Clean(p) == p && p != "/" && !strings.ContainsAny(p, "\x00\r\n")
}
func protectedDirectory(p string) error {
	if !cleanPath(p) {
		return errors.New("expected clean absolute protected directory")
	}
	return hostguard.CheckProtectedPath(p, true)
}

// readArtifact opens only bounded regular files, never follows the final symlink,
// and verifies stable identity and metadata across the snapshot. Untrusted input
// paths are read only; every destination lives under root-protected ancestors.
func readArtifact(p string, uid int) ([]byte, error) {
	if !cleanPath(p) {
		return nil, errors.New("artifact requires clean absolute path")
	}
	for q := p; q != "/"; q = filepath.Dir(q) {
		fi, e := os.Lstat(q)
		if e != nil {
			return nil, e
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("artifact symlink refused")
		}
	}
	f, e := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	before, e := f.Stat()
	if e != nil {
		return nil, e
	}
	st, ok := before.Sys().(*syscall.Stat_t)
	if !ok || !before.Mode().IsRegular() || before.Size() > maxArtifact || (uid >= 0 && st.Uid != uint32(uid)) {
		return nil, errors.New("artifact type, owner or size invalid")
	}
	b, e := io.ReadAll(io.LimitReader(f, maxArtifact+1))
	if e != nil {
		return nil, e
	}
	after, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if len(b) > maxArtifact || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || int64(len(b)) != after.Size() {
		return nil, errors.New("artifact changed while reading")
	}
	return b, nil
}
func protectedRead(p string) ([]byte, error) {
	if e := hostguard.CheckProtectedPath(p, false); e != nil {
		return nil, e
	}
	return readArtifact(p, 0)
}
func saveNew(p string, b []byte, mode os.FileMode) error {
	if len(b) > maxArtifact {
		return errors.New("artifact exceeds 4 MiB")
	}
	f, e := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	return e
}
func saveJSON(p string, v any, mode os.FileMode) error {
	b, e := encode(v)
	if e != nil {
		return e
	}
	return saveNew(p, b, mode)
}
func replaceJSON(p string, v any) error {
	b, e := encode(v)
	if e != nil {
		return e
	}
	return replace(p, b)
}
func replace(p string, b []byte) error { return replaceMode(p, b, 0600) }
func replaceMode(p string, b []byte, mode os.FileMode) error {
	if len(b) > maxArtifact {
		return errors.New("artifact exceeds 4 MiB")
	}
	if e := protectedDirectory(filepath.Dir(p)); e != nil {
		return e
	}
	if _, e := os.Lstat(p); e == nil {
		if _, e = protectedRead(p); e != nil {
			return e
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(p), ".qualification-")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(mode); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = os.Rename(name, p); e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(p))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func loadChallenge(dir string) (Challenge, []byte, error) {
	var c Challenge
	if e := protectedDirectory(dir); e != nil {
		return c, nil, e
	}
	b, e := protectedRead(filepath.Join(dir, "challenge.json"))
	if e != nil {
		return c, nil, e
	}
	if e = decode(b, &c); e != nil {
		return c, nil, e
	}
	return c, b, fresh(c, time.Now().UTC())
}
func randomID() (string, error) {
	b := make([]byte, 32)
	_, e := rand.Read(b)
	return hex.EncodeToString(b), e
}
func endpoints(s string) ([]string, error) {
	if s == "" {
		return nil, errors.New("explicit endpoint list required")
	}
	out := strings.Split(s, ",")
	if len(out) > 128 {
		return nil, errors.New("too many endpoints")
	}
	seen := map[string]bool{}
	for _, p := range out {
		h, port, e := net.SplitHostPort(p)
		if e != nil {
			return nil, e
		}
		ip := net.ParseIP(h)
		n, e := strconv.ParseUint(port, 10, 16)
		if ip == nil || e != nil || n == 0 || strconv.Itoa(int(n)) != port || ip.String() != h || ip.IsUnspecified() || ip.IsMulticast() || seen[p] {
			return nil, fmt.Errorf("invalid or duplicate literal endpoint %q", p)
		}
		seen[p] = true
	}
	return out, nil
}
func tcpTargets(e deploy.Environment) ([]string, error) {
	hosts := append([]string{"127.0.0.1", "::1", e.TailnetIP}, e.HostAddresses...)
	slices.Sort(hosts)
	hosts = slices.Compact(hosts)
	if len(e.ProtectedPorts) == 0 || len(hosts) > 512/len(e.ProtectedPorts) {
		return nil, errors.New("TCP matrix exceeds bounded session capacity; do not narrow deployment to bypass this limit")
	}
	out := make([]string, 0, len(hosts)*len(e.ProtectedPorts))
	for _, h := range hosts {
		for _, p := range e.ProtectedPorts {
			out = append(out, net.JoinHostPort(h, strconv.Itoa(int(p))))
		}
	}
	return out, nil
}
func unapproved(q maintenance.Qualification) ([]byte, error) {
	b, e := encode(q)
	if e != nil {
		return nil, e
	}
	var fields map[string]json.RawMessage
	if e = decode(b, &fields); e != nil {
		return nil, e
	}
	delete(fields, "approved_at")
	return encode(fields)
}

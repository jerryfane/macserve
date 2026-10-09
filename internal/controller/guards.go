package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jerryfane/macserve/internal/hostguard"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	ServiceBudgetBytes  int64 = 80 << 30
	JobReservationBytes int64 = 30 << 30
	AdmissionFloorBytes int64 = 120 << 30
	CancelFloorBytes    int64 = 100 << 30
)

// Health is written atomically by the root-managed maintenance helper. Boundary
// qualification is bound to the current PF policy and interface inventory. The
// controller cannot manufacture readiness from a live worker connection.
type Health struct {
	Schema                int               `json:"schema"`
	JobUID                uint32            `json:"job_uid"`
	PolicySHA256          string            `json:"policy_sha256"`
	InterfacesSHA256      string            `json:"interfaces_sha256"`
	BoundaryReceiptSHA256 string            `json:"boundary_receipt_sha256"`
	BoundaryValidated     bool              `json:"boundary_validated"`
	CheckedAt             time.Time         `json:"checked_at"`
	ExpiresAt             time.Time         `json:"expires_at"`
	AccountedBytes        int64             `json:"accounted_bytes"`
	MemoryPressure        bool              `json:"memory_pressure"`
	QualifiedProfiles     map[string]string `json:"qualified_profiles"`
}
type GuardOptions struct {
	Root, HealthFile, PolicySHA256, PauseFile string
	JobUID, OwnerUID                          uint32
	Profiles                                  map[string]string
	Now                                       func() time.Time
}
type Guard struct {
	options    GuardOptions
	readHealth func(string) (Health, error)
	freeBytes  func(string) (int64, error)
	interfaces func() (string, error)
	pause      func(string, uint32) (bool, error)
}

func NewGuard(o GuardOptions) (*Guard, error) {
	if !cleanAbsolute(o.Root) || !cleanAbsolute(o.HealthFile) || !digestString(o.PolicySHA256) || o.JobUID < 501 || o.OwnerUID == 0 || o.JobUID == o.OwnerUID {
		return nil, errors.New("invalid readiness guard configuration")
	}
	if o.PauseFile != "" && !cleanAbsolute(o.PauseFile) {
		return nil, errors.New("invalid pause marker")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	o.Profiles = cloneDigests(o.Profiles)
	for id, digest := range o.Profiles {
		if id == "" || !digestString(digest) {
			return nil, errors.New("invalid qualified profile digest")
		}
	}
	return &Guard{options: o, readHealth: readRootHealth, freeBytes: availableBytes, interfaces: InterfaceDigest, pause: ownerPause}, nil
}
func cloneDigests(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
func digestString(s string) bool {
	if len(s) != 64 || s != strings.ToLower(s) {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
func (g *Guard) Check(ctx context.Context) (GateState, error) {
	state := GateState{Blockers: []string{}}
	if err := ctx.Err(); err != nil {
		return state, err
	}
	fail := func(reason string, cancel bool) {
		state.Blockers = append(state.Blockers, reason)
		state.CancelActive = state.CancelActive || cancel
	}
	free, err := g.freeBytes(g.options.Root)
	if err != nil {
		fail("disk_accounting_unavailable", true)
	} else {
		state.FreeBytes = free
		if free < CancelFloorBytes {
			fail("disk_emergency", true)
		} else if free < AdmissionFloorBytes+JobReservationBytes {
			fail("disk_reservation_unavailable", false)
		}
	}
	health, err := g.readHealth(g.options.HealthFile)
	if err != nil {
		fail("isolation_unavailable", true)
	} else {
		now := g.options.Now()
		state.UsedBytes = health.AccountedBytes
		if health.Schema != 1 || health.JobUID != g.options.JobUID || health.PolicySHA256 != g.options.PolicySHA256 || !health.BoundaryValidated || !digestString(health.BoundaryReceiptSHA256) || health.CheckedAt.After(now.Add(5*time.Second)) || now.Sub(health.CheckedAt) > 45*time.Second || !health.ExpiresAt.After(now) || health.ExpiresAt.Sub(health.CheckedAt) > 45*time.Second || !health.ExpiresAt.After(health.CheckedAt) {
			fail("isolation_unavailable", true)
		}
		current, err := g.interfaces()
		if err != nil || current != health.InterfacesSHA256 {
			fail("network_inventory_changed", true)
		}
		if health.AccountedBytes < 0 || health.AccountedBytes > ServiceBudgetBytes {
			fail("service_disk_budget_exceeded", true)
		} else if health.AccountedBytes > ServiceBudgetBytes-JobReservationBytes {
			fail("service_disk_reservation_unavailable", false)
		}
		if health.MemoryPressure {
			fail("host_memory_pressure", false)
		}
		for id, digest := range g.options.Profiles {
			if health.QualifiedProfiles[id] != digest {
				fail("toolchain_validation_unavailable", true)
				break
			}
		}
	}
	if g.options.PauseFile != "" {
		paused, err := g.pause(g.options.PauseFile, g.options.OwnerUID)
		if err != nil {
			fail("owner_pause_unavailable", true)
		} else if paused {
			fail("owner_pause", false)
		}
	}
	state.Ready = len(state.Blockers) == 0
	return state, nil
}
func readRootHealth(path string) (Health, error) {
	var h Health
	if err := hostguard.RootConfig(path); err != nil {
		return h, err
	}
	file, err := os.Open(path)
	if err != nil {
		return h, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return h, err
	}
	if info.Size() > 256<<10 {
		return h, errors.New("oversized maintenance health")
	}
	dec := json.NewDecoder(io.LimitReader(file, (256<<10)+1))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&h); err != nil {
		return h, err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return h, errors.New("trailing maintenance health")
	}
	return h, nil
}
func availableBytes(path string) (int64, error) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0, err
	}
	if uint64(stat.Bsize) == 0 || uint64(stat.Bavail) > uint64((1<<63-1))/uint64(stat.Bsize) {
		return 0, errors.New("invalid filesystem capacity")
	}
	return int64(stat.Bavail) * int64(stat.Bsize), nil
}

// InterfaceDigest invalidates qualification after relevant address/interface
// changes. Link-local ranges are fixed-denied and do not affect qualification.
func InterfaceDigest() (string, error) {
	digest, _, err := observeInterfaces(false)
	return digest, err
}

// InterfaceSnapshot returns the digest and host addresses from the same public
// interface inventory, including loopback, aliases, and VM bridge gateways but
// excluding fixed-denied link-local ranges.
func InterfaceSnapshot() (string, []netip.Addr, error) {
	return observeInterfaces(true)
}

func observeInterfaces(includeAddresses bool) (string, []netip.Addr, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", nil, err
	}
	return interfaceInventory(interfaces, (*net.Interface).Addrs, includeAddresses)
}

// interfaceInventory accepts the public interface metadata reader separately so
// qualification drift can be exercised without mutating host interfaces.
func interfaceInventory(interfaces []net.Interface, addrs func(*net.Interface) ([]net.Addr, error), includeAddresses bool) (string, []netip.Addr, error) {
	var inventory []string
	var hosts []netip.Addr
	for _, iface := range interfaces {
		addresses, err := addrs(&iface)
		if err != nil {
			return "", nil, err
		}
		relevant := false
		for _, address := range addresses {
			text := address.String()
			prefix, err := netip.ParsePrefix(text)
			if err != nil {
				return "", nil, fmt.Errorf("unrecognized interface address: %w", err)
			}
			host := prefix.Addr().Unmap()
			if host.IsLinkLocalUnicast() {
				continue
			}
			relevant = true
			inventory = append(inventory, iface.Name+" "+text)
			if includeAddresses {
				hosts = append(hosts, host)
			}
		}
		if relevant {
			inventory = append(inventory, iface.Name+" flags="+iface.Flags.String())
		}
	}
	sort.Strings(inventory)
	sum := sha256.Sum256([]byte(strings.Join(inventory, "\n")))
	return hex.EncodeToString(sum[:]), hosts, nil
}
func ownerPause(path string, owner uint32) (bool, error) {
	present := false
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) && current == path {
			continue
		}
		if err != nil {
			return false, err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (stat.Uid != 0 && stat.Uid != owner) || info.Mode().Perm()&0022 != 0 || info.Mode()&os.ModeSymlink != 0 {
			return false, errors.New("unsafe owner pause path")
		}
		if current == path {
			if !info.Mode().IsRegular() {
				return false, errors.New("pause marker must be regular")
			}
			present = true
		} else if !info.IsDir() {
			return false, errors.New("unsafe pause ancestor")
		}
		if current == "/" {
			break
		}
	}
	return present, nil
}

// Package health is the controller readiness gate over the root-published
// health record. It is class B: the root maintenance daemon writes the record
// it reads, and both binaries link it.
package health

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jerryfane/macserve/internal/hostguard"
	"github.com/jerryfane/macserve/internal/model"
	"golang.org/x/sys/unix"
)

// GateState is the readiness gate's verdict.
type GateState struct {
	Ready        bool     `json:"ready"`
	CancelActive bool     `json:"cancel_active"`
	Blockers     []string `json:"blockers"`
	FreeBytes    int64    `json:"free_bytes"`
	UsedBytes    int64    `json:"used_bytes"`
	// CapacityOnly is set with CancelActive when every cancelling blocker
	// is a capacity fact (disk_emergency, service_disk_budget_exceeded):
	// cancelling the newest active job may restore the gate. Trust facts
	CapacityOnly bool `json:"-"`
	// ProbeFailures is the published health's count of consecutive
	// maintenance probes that failed without evidence (Health.ProbeFailures);
	// 0 for any other record.
	ProbeFailures int `json:"probe_failures,omitempty"`
}

const (
	// serviceBaseBytes is the service disk budget beyond the per-lane job
	// reservations (see ServiceBudget).
	serviceBaseBytes    int64 = 50 << 30
	JobReservationBytes int64 = 30 << 30
	AdmissionFloorBytes int64 = 120 << 30
	CancelFloorBytes    int64 = 100 << 30
)

// ProbeFailureLimit is the number of consecutive maintenance probes failing
// without evidence (see Health.ProbeFailures) that cancels active work (#53);
// health published for fewer blocks admission only. At the 10 s probe cadence
// the third such probe starts 30 s after the one behind the last valid health
// and publishes within its 8 s bound, before that health's 40 s lifetime
// ends: two failed probes in a row (about 20 s, the Studio's longest
// transient, #108) keep an active job, a third cancels it. The last valid
// health's expiry stays the hard bound: a failure record never outlives it,
// so slow or absent probes (a stopped daemon) cancel no later than before.
const ProbeFailureLimit = 3

// ServiceBudget is the disk macserve may account with lanes concurrent jobs
// (max_concurrent_jobs; values below 1 mean 1): one JobReservationBytes per
// lane above a fixed base. One lane is the single-job budget of 80 GiB.
func ServiceBudget(lanes int) int64 {
	return serviceBaseBytes + int64(max(lanes, 1))*JobReservationBytes
}

// capacityBlockers cancel the newest active job first (see GateState).
var capacityBlockers = map[string]bool{"disk_emergency": true, "service_disk_budget_exceeded": true}

// AdmitsAnother reports whether the disk facts of a ready gate leave room
// for one more job beside active running ones under a lanes budget: the
// free-space floor and the service budget each keep one JobReservationBytes
// for every active job and the new one. A ready gate already reserved one,
// so with no active job this is the gate itself.
func AdmitsAnother(g GateState, active, lanes int) bool {
	if !g.Ready || g.CancelActive {
		return false
	}
	need := int64(active+1) * JobReservationBytes
	return g.FreeBytes >= AdmissionFloorBytes+need && g.UsedBytes >= 0 && g.UsedBytes <= ServiceBudget(lanes)-need
}

// Health is written atomically by the root-managed maintenance helper. Boundary
// qualification is bound to non-network protections, not interface inventory.
// The controller cannot manufacture readiness from a live worker.
type Health struct {
	Schema                  int               `json:"schema"`
	JobUID                  uint32            `json:"job_uid"`
	BoundaryReceiptSHA256   string            `json:"boundary_receipt_sha256"`
	BoundaryValidated       bool              `json:"boundary_validated"`
	CheckedAt               time.Time         `json:"checked_at"`
	ExpiresAt               time.Time         `json:"expires_at"`
	AccountedBytes          int64             `json:"accounted_bytes"`
	MemoryPressure          bool              `json:"memory_pressure"`
	QualifiedProfiles       map[string]string `json:"qualified_profiles"`
	PersistenceLastVerified time.Time         `json:"persistence_last_verified"`
	PersistenceValid        bool              `json:"persistence_valid"`
	PersistenceNeedsReview  bool              `json:"persistence_needs_review"`
	PersistenceReason       string            `json:"persistence_reason,omitempty"`
	// AdmissionInconclusive is the reason of the broker's record of
	// admissions refused, without quarantine, for a persisting child of a
	// tolerated launch; the gate reports it as worker_admission_inconclusive.
	AdmissionInconclusive string `json:"admission_inconclusive,omitempty"`
	// ProbeFailures counts the consecutive maintenance probes since the last
	// valid health that failed without evidence (a deadline or a race the
	// maintenance daemon classifies as inconclusive; any other error is a
	// finding and publishes invalid health without it). While that health is
	// unexpired the daemon republishes it unchanged (same checked_at,
	// expires_at and facts) with this count; afterwards it publishes invalid
	// health with the count. The gate reports maintenance_probe_failed, which
	// blocks admission and, from ProbeFailureLimit, cancels active work.
	ProbeFailures int `json:"probe_failures,omitempty"`
}
type GuardOptions struct {
	Root, HealthFile, PauseFile string
	JobUID, OwnerUID            uint32
	Profiles                    map[string]string
	// Lanes is max_concurrent_jobs (0 means 1); it sizes ServiceBudget.
	Lanes int
	Now   func() time.Time
}
type Guard struct {
	options    GuardOptions
	readHealth func(string) (Health, error)
	freeBytes  func(string) (int64, error)
	pause      func(string, uint32) (bool, error)
}

func NewGuard(o GuardOptions) (*Guard, error) {
	if !cleanAbsolute(o.Root) || !cleanAbsolute(o.HealthFile) || o.JobUID < 501 || o.OwnerUID == 0 || o.JobUID == o.OwnerUID {
		return nil, errors.New("invalid readiness guard configuration")
	}
	if o.PauseFile != "" && !cleanAbsolute(o.PauseFile) {
		return nil, errors.New("invalid pause marker")
	}
	if o.Lanes < 0 || o.Lanes > model.MaxConcurrentJobs {
		return nil, errors.New("invalid readiness guard lanes")
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
	return &Guard{options: o, readHealth: readRootHealth, freeBytes: availableBytes, pause: ownerPause}, nil
}
func cloneDigests(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
func cleanAbsolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/" && !strings.ContainsRune(path, 0)
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
	trust := false
	fail := func(reason string, cancel bool) {
		state.Blockers = append(state.Blockers, reason)
		state.CancelActive = state.CancelActive || cancel
		trust = trust || cancel && !capacityBlockers[reason]
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
		state.UsedBytes = health.AccountedBytes
		state.ProbeFailures = health.ProbeFailures
		for _, b := range HealthBlockers(health, g.options.Now(), g.options.JobUID, g.options.Profiles, g.options.Lanes) {
			fail(b.Name, b.Cancel)
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
	state.CapacityOnly = state.CancelActive && !trust
	return state, nil
}

// A Blocker is one reason the readiness gate refuses admission; Cancel
// blockers also cancel active work.
type Blocker struct {
	Name   string
	Cancel bool
}

// HealthBlockers is the part of the readiness gate decided by a published
// health record, evaluated at now by a controller expecting jobUID and the
// qualified digests in profiles and lanes concurrent jobs (see
// ServiceBudget); nil profiles skip toolchain qualification. The maintenance
// daemon logs these for each health record it publishes. A record counting
// probes that failed without evidence (ProbeFailures) is the last valid
// health's, judged on its own timestamps and facts, plus
// maintenance_probe_failed, which cancels only from ProbeFailureLimit.
func HealthBlockers(health Health, now time.Time, jobUID uint32, profiles map[string]string, lanes int) []Blocker {
	var blockers []Blocker
	fail := func(name string, cancel bool) { blockers = append(blockers, Blocker{name, cancel}) }
	if health.Schema != 3 || health.JobUID != jobUID || !health.BoundaryValidated || !digestString(health.BoundaryReceiptSHA256) || health.CheckedAt.After(now.Add(5*time.Second)) || now.Sub(health.CheckedAt) > 45*time.Second || !health.ExpiresAt.After(now) || health.ExpiresAt.Sub(health.CheckedAt) > 45*time.Second || !health.ExpiresAt.After(health.CheckedAt) || health.ProbeFailures < 0 {
		fail("isolation_unavailable", true)
	}
	if health.ProbeFailures > 0 {
		fail("maintenance_probe_failed", health.ProbeFailures >= ProbeFailureLimit)
	}
	if !health.PersistenceValid || health.PersistenceNeedsReview || health.PersistenceLastVerified.IsZero() || health.PersistenceLastVerified.After(now) {
		fail("persistence_attestation_unavailable", false)
	}
	if health.AdmissionInconclusive != "" {
		fail("worker_admission_inconclusive", false)
	}
	if budget := ServiceBudget(lanes); health.AccountedBytes < 0 || health.AccountedBytes > budget {
		fail("service_disk_budget_exceeded", true)
	} else if health.AccountedBytes > budget-JobReservationBytes {
		fail("service_disk_reservation_unavailable", false)
	}
	if health.MemoryPressure {
		fail("host_memory_pressure", false)
	}
	for id, digest := range profiles {
		if health.QualifiedProfiles[id] != digest {
			fail("toolchain_validation_unavailable", true)
			break
		}
	}
	return blockers
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

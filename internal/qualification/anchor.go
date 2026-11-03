package qualification

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/jerryfane/macserve/internal/maintenance"
	"github.com/jerryfane/macserve/internal/workerclient"
)

// The activation anchor (v0.1.13) carries the owner's approval across reboots.
// Only the owner's password Approve writes it. It binds what defines the
// qualified configuration: every protected config file, the installed
// binaries, the LaunchDaemon plists, the reviewed persistence manifest, the
// profile digests, the account UIDs and the challenge parameters. It does not
// bind boot-bound facts (boot, GUI baseline, evidence, coexistence PIDs,
// persistence attestation), which every requalification measures again, and
// it deliberately does not bind the GUI baseline's process set: real baselines
// differ on every boot. The baseline executable policy constrains it instead.

const (
	anchorPath = "/Library/macserve/config/activation-anchor.json"
	configDir  = "/Library/macserve/config"
	binDir     = "/Library/macserve/bin"
	// anchorSchema 2 adds Carries. Schema-1 anchors (written before release
	// carry existed) still verify; only the owner's approve writes schema 2,
	// and only a schema-2 anchor can be carried.
	anchorSchema       = 2
	legacyAnchorSchema = 1
)

// mutableConfig are config files that approval or the owner change in normal
// operation; they are never configuration identity.
var mutableConfig = []string{"owner.pause", "qualification.json", "boundary-evidence.json", "activation-anchor.json"}

var daemonPlists = []string{"/Library/LaunchDaemons/org.macserve.controller.plist", "/Library/LaunchDaemons/org.macserve.maintenance.plist", "/Library/LaunchDaemons/org.macserve.worker.plist"}

type AnchorParameters struct {
	JobUID        uint32            `json:"job_uid"`
	OwnerUID      uint32            `json:"owner_uid"`
	ControllerUID uint32            `json:"controller_uid"`
	Profiles      map[string]string `json:"profiles"`
	TCP           []string          `json:"tcp"`
	UDP           []string          `json:"udp"`
	Allow         []string          `json:"allow"`
	PrivatePaths  []string          `json:"private_paths"`
	Socket        string            `json:"socket"`
}

type ActivationAnchor struct {
	Schema          int               `json:"schema"`
	ApprovedAt      time.Time         `json:"approved_at"`
	Session         string            `json:"session"`
	CandidateSHA256 string            `json:"candidate_sha256"`
	Bindings        map[string]string `json:"bindings"`
	Parameters      AnchorParameters  `json:"parameters"`
	// Carries lists, oldest first, every release carry since the owner's
	// approval (schema 2; empty after approve, absent in schema 1). Each one
	// rebound only the bin/macserve digest.
	Carries []AnchorCarry `json:"carries"`
}

// AnchorCarry is one boundary-preserving release committed by qualify carry.
type AnchorCarry struct {
	At               time.Time `json:"at"`
	Session          string    `json:"session"`
	FromBinarySHA256 string    `json:"from_binary_sha256"`
	ToBinarySHA256   string    `json:"to_binary_sha256"`
	ProofSHA256      string    `json:"proof_sha256"`
}

func anchorParameters(c Challenge) AnchorParameters {
	return AnchorParameters{JobUID: c.Environment.JobUID, OwnerUID: c.Environment.OwnerUID, ControllerUID: c.Environment.ControllerUID, Profiles: maps.Clone(c.Observation.Profiles), TCP: c.TCP, UDP: c.UDP, Allow: c.Allow, PrivatePaths: c.PrivatePaths, Socket: c.Socket}
}

func sameParameters(a, b AnchorParameters) bool {
	return a.JobUID == b.JobUID && a.OwnerUID == b.OwnerUID && a.ControllerUID == b.ControllerUID && maps.Equal(a.Profiles, b.Profiles) && slices.Equal(a.TCP, b.TCP) && slices.Equal(a.UDP, b.UDP) && slices.Equal(a.Allow, b.Allow) && slices.Equal(a.PrivatePaths, b.PrivatePaths) && a.Socket == b.Socket
}

// currentBindings hashes every configuration-identity file. Each must be a
// protected root file; any unprotected, added or removed file changes the set.
func currentBindings() (map[string]string, error) {
	out := map[string]string{}
	for _, dir := range []string{configDir, binDir} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if dir == configDir && slices.Contains(mutableConfig, entry.Name()) {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			d, err := fileDigest(path)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			out[path] = d
		}
	}
	for _, path := range daemonPlists {
		d, err := fileDigest(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		out[path] = d
	}
	mc, err := maintenance.LoadConfig(maintenancePath)
	if err != nil {
		return nil, err
	}
	wc, err := workerclient.LoadConfig(mc.WorkerConfig)
	if err != nil {
		return nil, err
	}
	if d, err := fileDigest(wc.PersistencePath); err != nil {
		return nil, fmt.Errorf("%s: %w", wc.PersistencePath, err)
	} else {
		out[wc.PersistencePath] = d
	}
	return out, nil
}

func newAnchor(dir string, c Challenge, v Candidate, at time.Time) (ActivationAnchor, error) {
	cb, err := protectedRead(filepath.Join(dir, "candidate.json"))
	if err != nil {
		return ActivationAnchor{}, err
	}
	bindings, err := currentBindings()
	if err != nil {
		return ActivationAnchor{}, err
	}
	return ActivationAnchor{Schema: anchorSchema, ApprovedAt: at, Session: dir, CandidateSHA256: digest(cb), Bindings: bindings, Parameters: anchorParameters(c), Carries: []AnchorCarry{}}, nil
}

func loadAnchor() (ActivationAnchor, error) {
	a, _, err := loadAnchorBytes()
	return a, err
}

func loadAnchorBytes() (ActivationAnchor, []byte, error) {
	var a ActivationAnchor
	b, err := protectedRead(anchorPath)
	if err != nil {
		return a, nil, fmt.Errorf("activation anchor unavailable (the owner's approve-and-start writes it): %w", err)
	}
	if err = decode(b, &a); err != nil {
		return a, nil, err
	}
	return a, b, validAnchor(a)
}

// validAnchor accepts a schema-1 anchor without carries, or a schema-2 anchor
// whose carries chain from one binary digest to the next within the cap and
// end at the bound bin/macserve digest.
func validAnchor(a ActivationAnchor) error {
	if (a.Schema != anchorSchema && a.Schema != legacyAnchorSchema) || a.Session == "" || len(a.Bindings) == 0 {
		return errors.New("unsupported activation anchor")
	}
	if a.Schema == legacyAnchorSchema {
		if a.Carries != nil {
			return errors.New("unsupported activation anchor: schema 1 has no carries")
		}
		return nil
	}
	if a.Carries == nil || len(a.Carries) > carryCap {
		return errors.New("unsupported activation anchor: invalid carries")
	}
	previous := a.ApprovedAt
	seen := map[string]bool{a.Session: true}
	for i, carry := range a.Carries {
		if carry.Session == "" || seen[carry.Session] || seen[carry.ProofSHA256] || len(carry.FromBinarySHA256) != 64 || len(carry.ToBinarySHA256) != 64 || len(carry.ProofSHA256) != 64 || carry.FromBinarySHA256 == carry.ToBinarySHA256 || !carry.At.After(previous) {
			return fmt.Errorf("unsupported activation anchor: invalid or replayed carry %d", i)
		}
		if i > 0 && carry.FromBinarySHA256 != a.Carries[i-1].ToBinarySHA256 {
			return fmt.Errorf("unsupported activation anchor: carry %d does not chain", i)
		}
		seen[carry.Session], seen[carry.ProofSHA256] = true, true
		previous = carry.At
	}
	if n := len(a.Carries); n > 0 && a.Bindings[installedHelper] != a.Carries[n-1].ToBinarySHA256 {
		return errors.New("unsupported activation anchor: binary binding differs from the last carry")
	}
	return nil
}

// anchoredConfiguration returns the anchor when every live binding equals it.
func anchoredConfiguration() (ActivationAnchor, error) {
	a, err := loadAnchor()
	if err != nil {
		return a, err
	}
	now, err := currentBindings()
	if err != nil {
		return a, err
	}
	if changed := bindingChanges(a.Bindings, now); len(changed) != 0 {
		return a, fmt.Errorf("configuration changed since the owner's approval (%v); the owner must approve again", changed)
	}
	return a, nil
}

// bindingChanges lists, sorted, every path whose digest differs between the
// anchored and live bindings, including paths present on only one side.
func bindingChanges(anchored, now map[string]string) []string {
	var changed []string
	for path, want := range anchored {
		if got, ok := now[path]; !ok || got != want {
			changed = append(changed, path)
		}
	}
	for path := range now {
		if _, ok := anchored[path]; !ok {
			changed = append(changed, path)
		}
	}
	slices.Sort(changed)
	return changed
}

// approvedOnBoot reports whether the installed qualification was approved on
// this boot: jobs may then have run, so an agent requalification refuses.
func approvedOnBoot(boot string) bool {
	mc, err := maintenance.LoadConfig(maintenancePath)
	if err != nil {
		return false
	}
	b, err := protectedRead(mc.QualificationFile)
	if err != nil {
		return false
	}
	var q maintenance.Qualification
	return decode(b, &q) == nil && q.Boot == boot
}

func requalifyAllowed(_ context.Context, c Challenge) error {
	if !c.Requalify {
		return errors.New("reapprove needs a requalify sitting (begin --requalify)")
	}
	a, err := anchoredConfiguration()
	if err != nil {
		return err
	}
	if c.Previous != a.Session {
		return errors.New("requalify sitting is not chained to the anchored session")
	}
	if !sameParameters(anchorParameters(c), a.Parameters) {
		return errors.New("challenge parameters differ from the anchored approval")
	}
	if approvedOnBoot(c.Observation.Boot) {
		return errors.New("a qualification was already approved on this boot, so jobs may have run; requalification needs a reboot or the owner's approve")
	}
	return nil
}

// ActivationCheck is read-only: the anchor matches the live configuration and
// the installed qualification yields valid health now.
func ActivationCheck(ctx context.Context) error {
	if err := rootOnly(); err != nil {
		return err
	}
	if _, err := anchoredConfiguration(); err != nil {
		return err
	}
	mc, err := maintenance.LoadConfig(maintenancePath)
	if err != nil {
		return err
	}
	_, err = maintenance.Check(ctx, mc)
	return err
}

package qualification

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/jerryfane/macserve/internal/deploy"
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
	// installedController is the controller daemon binary. Like every file in
	// binDir it is bound by the anchor; a release carry may rebind it.
	installedController = binDir + "/macserve-controller"
	// anchorSchema 3 records both binaries in each carry (macserve and
	// macserve-controller). Schema-2 anchors (single-binary carries) and
	// schema-1 anchors (no carries) still verify; only the owner's approve
	// writes schema 3, and only a schema-3 anchor can be carried.
	anchorSchema       = 3
	singleBinarySchema = 2
	legacyAnchorSchema = 1
)

// mutableConfig are config files that approval or the owner change in normal
// operation; they are never configuration identity. lanes.json only lowers
// concurrency (health.LanesOverrideFile).
var mutableConfig = []string{"owner.pause", "qualification.json", "boundary-evidence.json", "activation-anchor.json", "lanes.json"}

var daemonPlists = []string{"/Library/LaunchDaemons/org.macserve.controller.plist", "/Library/LaunchDaemons/org.macserve.keyholder.plist", "/Library/LaunchDaemons/org.macserve.maintenance.plist", "/Library/LaunchDaemons/org.macserve.worker.plist"}

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
	// approval (schema 2 and 3; empty after approve, absent in schema 1).
	// Each one rebound only the bin/macserve and (schema 3)
	// bin/macserve-controller digests.
	Carries []AnchorCarry `json:"carries"`
	// Rebinds lists, oldest first, every controller-only rebind since the
	// owner's approval (schema 3; qualify rebind-controller).
	Rebinds []AnchorRebind `json:"rebinds,omitempty"`
	// Release is the release digests of the bound binaries (schema 3). With
	// installed-binaries.json the bound on-disk bytes are Developer ID
	// signed and differ from them; without it they are equal.
	Release *CarryBinaries `json:"release_binaries,omitempty"`
}

// AnchorRebind is one controller-only rebind committed by qualify
// rebind-controller after an administrator controller carry. It rebinds
// bin/macserve-controller and installed-binaries.json and nothing else.
type AnchorRebind struct {
	At                      time.Time `json:"at"`
	FromControllerSHA256    string    `json:"from_controller_sha256"`
	ToControllerSHA256      string    `json:"to_controller_sha256"`
	ReleaseControllerSHA256 string    `json:"release_controller_sha256"`
	InventorySHA256         string    `json:"inventory_sha256"`
}

// AnchorCarry is one boundary-preserving release committed by qualify carry.
type AnchorCarry struct {
	At               time.Time `json:"at"`
	Session          string    `json:"session"`
	FromBinarySHA256 string    `json:"from_binary_sha256"`
	ToBinarySHA256   string    `json:"to_binary_sha256"`
	// FromControllerSHA256 and ToControllerSHA256 are the controller
	// binary before and after the carry (schema 3 only).
	FromControllerSHA256 string `json:"from_controller_sha256,omitempty"`
	ToControllerSHA256   string `json:"to_controller_sha256,omitempty"`
	ProofSHA256          string `json:"proof_sha256"`
}

func (c AnchorCarry) from() CarryBinaries {
	return CarryBinaries{Macserve: c.FromBinarySHA256, Controller: c.FromControllerSHA256}
}
func (c AnchorCarry) to() CarryBinaries {
	return CarryBinaries{Macserve: c.ToBinarySHA256, Controller: c.ToControllerSHA256}
}

// anchoredBinaries are the binary digests an anchor's bindings record.
func anchoredBinaries(bindings map[string]string) CarryBinaries {
	return CarryBinaries{Macserve: bindings[installedHelper], Controller: bindings[installedController]}
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
	// The optional signer daemon is configuration identity once installed:
	// its plist fixes the account the signer runs as.
	if d, err := fileDigest(deploy.SignerPlist); err == nil {
		out[deploy.SignerPlist] = d
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", deploy.SignerPlist, err)
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
	release, err := releaseBinaries(anchoredBinaries(bindings))
	if err != nil {
		return ActivationAnchor{}, err
	}
	return ActivationAnchor{Schema: anchorSchema, ApprovedAt: at, Session: dir, CandidateSHA256: digest(cb), Bindings: bindings, Parameters: anchorParameters(c), Carries: []AnchorCarry{}, Release: &release}, nil
}

// releaseBinaries maps installed (on-disk) binary digests to their release
// digests through installed-binaries.json; without it they are equal.
func releaseBinaries(installed CarryBinaries) (CarryBinaries, error) {
	inv, err := deploy.LoadInstalledBinaries()
	if err != nil {
		return CarryBinaries{}, err
	}
	var out CarryBinaries
	if out.Macserve, err = inv.ReleaseDigest("macserve", installed.Macserve); err != nil {
		return out, err
	}
	out.Controller, err = inv.ReleaseDigest("macserve-controller", installed.Controller)
	return out, err
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

// validAnchor accepts a schema-1 anchor without carries, or a schema-2 or
// schema-3 anchor whose carries (and, schema 3, controller rebinds) chain
// from one binary pair to the next in time order within the caps and end at
// the bound binary digests. A schema-2 carry names only bin/macserve; a
// schema-3 carry names bin/macserve and bin/macserve-controller and changes
// at least one of them; a rebind changes only bin/macserve-controller.
func validAnchor(a ActivationAnchor) error {
	if (a.Schema != anchorSchema && a.Schema != singleBinarySchema && a.Schema != legacyAnchorSchema) || a.Session == "" || len(a.Bindings) == 0 {
		return errors.New("unsupported activation anchor")
	}
	if a.Schema == legacyAnchorSchema {
		if a.Carries != nil || a.Rebinds != nil || a.Release != nil {
			return errors.New("unsupported activation anchor: schema 1 has no carries")
		}
		return nil
	}
	if a.Carries == nil || len(a.Carries) > carryCap {
		return errors.New("unsupported activation anchor: invalid carries")
	}
	if a.Schema == singleBinarySchema && (a.Rebinds != nil || a.Release != nil) {
		return errors.New("unsupported activation anchor: schema 2 has no rebinds")
	}
	if a.Schema == anchorSchema && (a.Release == nil || len(a.Rebinds) > rebindCap) {
		return errors.New("unsupported activation anchor: invalid release digests or rebinds")
	}
	type event struct {
		at    time.Time
		carry *AnchorCarry
		index int
	}
	events := make([]event, 0, len(a.Carries)+len(a.Rebinds))
	seen := map[string]bool{a.Session: true}
	for i := range a.Carries {
		carry := &a.Carries[i]
		var binaries bool
		if a.Schema == singleBinarySchema {
			binaries = carry.FromControllerSHA256 == "" && carry.ToControllerSHA256 == "" && validDigest(carry.FromBinarySHA256) && validDigest(carry.ToBinarySHA256) && carry.FromBinarySHA256 != carry.ToBinarySHA256
		} else {
			binaries = carry.from().valid() && carry.to().valid() && carry.from() != carry.to()
		}
		if carry.Session == "" || seen[carry.Session] || seen[carry.ProofSHA256] || !binaries || len(carry.ProofSHA256) != 64 {
			return fmt.Errorf("unsupported activation anchor: invalid or replayed carry %d", i)
		}
		seen[carry.Session], seen[carry.ProofSHA256] = true, true
		events = append(events, event{at: carry.At, carry: carry, index: i})
	}
	for i, r := range a.Rebinds {
		if !validDigest(r.FromControllerSHA256) || !validDigest(r.ToControllerSHA256) || r.FromControllerSHA256 == r.ToControllerSHA256 || !validDigest(r.ReleaseControllerSHA256) || !validDigest(r.InventorySHA256) {
			return fmt.Errorf("unsupported activation anchor: invalid rebind %d", i)
		}
		events = append(events, event{at: r.At, index: i})
	}
	slices.SortStableFunc(events, func(x, y event) int { return x.at.Compare(y.at) })
	previous := a.ApprovedAt
	var state CarryBinaries
	macKnown, controllerKnown := false, false
	for _, e := range events {
		if !e.at.After(previous) {
			return errors.New("unsupported activation anchor: carries and rebinds are not in time order")
		}
		previous = e.at
		if e.carry != nil {
			if macKnown && e.carry.FromBinarySHA256 != state.Macserve || controllerKnown && e.carry.FromControllerSHA256 != state.Controller {
				return fmt.Errorf("unsupported activation anchor: carry %d does not chain", e.index)
			}
			state = e.carry.to()
			macKnown, controllerKnown = true, a.Schema == anchorSchema
			continue
		}
		r := a.Rebinds[e.index]
		if controllerKnown && r.FromControllerSHA256 != state.Controller {
			return fmt.Errorf("unsupported activation anchor: rebind %d does not chain", e.index)
		}
		state.Controller, controllerKnown = r.ToControllerSHA256, true
	}
	bound := anchoredBinaries(a.Bindings)
	if macKnown && bound.Macserve != state.Macserve || controllerKnown && bound.Controller != state.Controller {
		return errors.New("unsupported activation anchor: binary binding differs from the last carry or rebind")
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

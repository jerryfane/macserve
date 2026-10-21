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
	anchorPath   = "/Library/macserve/config/activation-anchor.json"
	configDir    = "/Library/macserve/config"
	binDir       = "/Library/macserve/bin"
	anchorSchema = 1
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
	return ActivationAnchor{Schema: anchorSchema, ApprovedAt: at, Session: dir, CandidateSHA256: digest(cb), Bindings: bindings, Parameters: anchorParameters(c)}, nil
}

func loadAnchor() (ActivationAnchor, error) {
	var a ActivationAnchor
	b, err := protectedRead(anchorPath)
	if err != nil {
		return a, fmt.Errorf("activation anchor unavailable (the owner's approve-and-start writes it): %w", err)
	}
	if err = decode(b, &a); err != nil {
		return a, err
	}
	if a.Schema != anchorSchema || a.Session == "" || len(a.Bindings) == 0 {
		return a, errors.New("unsupported activation anchor")
	}
	return a, nil
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
	var changed []string
	for path := range maps.Keys(a.Bindings) {
		if now[path] != a.Bindings[path] {
			changed = append(changed, path)
		}
	}
	for path := range maps.Keys(now) {
		if _, ok := a.Bindings[path]; !ok {
			changed = append(changed, path)
		}
	}
	if len(changed) != 0 {
		slices.Sort(changed)
		return a, fmt.Errorf("configuration changed since the owner's approval (%v); the owner must approve again", changed)
	}
	return a, nil
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

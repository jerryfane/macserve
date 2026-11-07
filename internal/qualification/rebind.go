package qualification

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jerryfane/macserve/internal/deploy"
)

// rebindCap bounds controller-only rebinds since the owner's approval.
const rebindCap = 64

// RebindResult is qualify rebind-controller's one-line JSON output.
type RebindResult struct {
	Result                    string `json:"result"` // "rebound" or "already-bound"
	ControllerInstalledSHA256 string `json:"controller_installed_sha256"`
	ControllerReleaseSHA256   string `json:"controller_release_sha256"`
	// AnchorSHA256 is the activation anchor now in place; native setup's
	// ledger records it with the controller (setup.RecordControllerRebind).
	AnchorSHA256 string `json:"anchor_sha256"`
}

// RebindController commits a controller-only carry that the root
// administrator (macserve-admin) installed and health-checked: the live
// configuration may differ from the schema-3 anchor only in
// bin/macserve-controller (from the anchored digest from to to) and
// installed-binaries.json, which must record to as the controller's
// installed digest and keep bin/macserve's release digest. It rebinds those
// two paths, appends a rebinds[] record and runs the activation check.
// Authority for the new controller is the administrator's verified release
// manifest; this native step only keeps the anchor exact. Re-running after
// the anchor already binds to and equals the live configuration is a no-op.
func RebindController(ctx context.Context, from, to string) (RebindResult, error) {
	if err := rootOnly(); err != nil {
		return RebindResult{}, err
	}
	if !validDigest(from) || !validDigest(to) || from == to {
		return RebindResult{}, errors.New("--from-installed-sha256 and --to-installed-sha256 must be distinct lowercase SHA-256 digests")
	}
	unlock, err := anchorLock()
	if err != nil {
		return RebindResult{}, fmt.Errorf("activation anchor busy: %w", err)
	}
	defer unlock()
	a, anchorRaw, err := loadAnchorBytes()
	if err != nil {
		return RebindResult{}, err
	}
	live, err := currentBindings()
	if err != nil {
		return RebindResult{}, err
	}
	inv, err := deploy.LoadInstalledBinaries()
	if err != nil {
		return RebindResult{}, err
	}
	next, result, err := reboundAnchor(a, live, inv, from, to, time.Now().UTC())
	if err != nil {
		return RebindResult{}, err
	}
	result.AnchorSHA256 = digest(anchorRaw)
	if result.Result == "rebound" {
		nextRaw, err := encode(next)
		if err != nil {
			return RebindResult{}, err
		}
		result.AnchorSHA256 = digest(nextRaw)
		err = commitAnchor(anchorRaw, nextRaw, func() ([]byte, error) { return protectedRead(anchorPath) }, func() error { return nil }, func(b []byte) error { return replace(anchorPath, b) })
		if err != nil {
			return RebindResult{}, err
		}
	}
	if err := ActivationCheck(ctx); err != nil {
		return RebindResult{}, fmt.Errorf("activation check after rebind: %w", err)
	}
	return result, nil
}

// reboundAnchor is RebindController's decision on what it read.
func reboundAnchor(a ActivationAnchor, live map[string]string, inv *deploy.InstalledBinaries, from, to string, now time.Time) (ActivationAnchor, RebindResult, error) {
	if a.Schema != anchorSchema || a.Release == nil {
		return a, RebindResult{}, errors.New("activation anchor predates the two-binary anchor (schema 1 or 2); the owner's approve writes a rebindable anchor")
	}
	if inv == nil {
		return a, RebindResult{}, errors.New("controller rebind needs " + deploy.InstalledBinariesPath)
	}
	release, err := inv.ReleaseDigest("macserve-controller", to)
	if err != nil {
		return a, RebindResult{}, err
	}
	if live[installedController] != to {
		return a, RebindResult{}, fmt.Errorf("installed %s is not %s", installedController, to)
	}
	if mac, err := inv.ReleaseDigest("macserve", live[installedHelper]); err != nil || mac != a.Release.Macserve {
		return a, RebindResult{}, errors.Join(errors.New("installed-binaries.json does not keep the anchored bin/macserve release"), err)
	}
	result := RebindResult{ControllerInstalledSHA256: to, ControllerReleaseSHA256: release}
	changed := bindingChanges(a.Bindings, live)
	if len(changed) == 0 {
		if a.Release.Controller != release {
			return a, RebindResult{}, errors.New("anchored controller release digest differs from installed-binaries.json")
		}
		result.Result = "already-bound"
		return a, result, nil
	}
	if a.Bindings[installedController] != from {
		return a, RebindResult{}, fmt.Errorf("anchored %s is not %s", installedController, from)
	}
	for _, path := range changed {
		if path != installedController && path != deploy.InstalledBinariesPath {
			return a, RebindResult{}, fmt.Errorf("configuration changed beyond %s and %s since the owner's approval (%v); controller rebind refused", installedController, deploy.InstalledBinariesPath, changed)
		}
	}
	if len(a.Rebinds) >= rebindCap {
		return a, RebindResult{}, fmt.Errorf("controller rebind cap reached (%d since the owner's approval); the owner must approve again", rebindCap)
	}
	out := a
	out.Bindings = make(map[string]string, len(a.Bindings))
	for k, v := range a.Bindings {
		out.Bindings[k] = v
	}
	out.Bindings[installedController] = to
	out.Bindings[deploy.InstalledBinariesPath] = live[deploy.InstalledBinariesPath]
	r := *a.Release
	r.Controller = release
	out.Release = &r
	out.Rebinds = append(slices.Clone(a.Rebinds), AnchorRebind{At: now, FromControllerSHA256: from, ToControllerSHA256: to, ReleaseControllerSHA256: release, InventorySHA256: live[deploy.InstalledBinariesPath]})
	if err := validAnchor(out); err != nil {
		return a, RebindResult{}, err
	}
	result.Result = "rebound"
	return out, result, nil
}

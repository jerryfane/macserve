package setup

import (
	"errors"
	"fmt"
	"time"
)

// ControllerRebind is one controller-only change the root administrator
// (macserve-admin) installed and `macserve qualify rebind-controller`
// committed to the activation anchor: it replaced bin/macserve-controller
// outside macserve upgrade. The ledger records it so the binaries and the
// anchor it vouches for stay the ones on disk.
type ControllerRebind struct {
	At time.Time `json:"at"`
	// After is the number of releases recorded when the rebind was: it
	// sits after Releases[After-1] and before Releases[After].
	After int `json:"after"`
	// FromControllerSHA256 and ControllerSHA256 are the release digests of
	// the controller before and after (equal for a re-signed controller).
	FromControllerSHA256 string `json:"from_controller_sha256"`
	ControllerSHA256     string `json:"controller_sha256"`
	// AnchorSHA256 is the activation anchor the rebind wrote.
	AnchorSHA256 string `json:"anchor_sha256"`
}

// controllerAt is the controller release digest installed before release
// n (n == len(Releases): now): install's, then each finished release's and
// each rebind's in history order. A running release counts only once its
// effect is recorded.
func (l *Ledger) controllerAt(n int) string {
	current := l.installedControllerInput()
	for j := 0; j <= n; j++ {
		for _, r := range l.Rebinds {
			if r.After == j {
				current = r.ControllerSHA256
			}
		}
		if j < n && j < len(l.Releases) && l.Releases[j].Status == StatusDone {
			current = l.Releases[j].ControllerSHA256
		}
	}
	return current
}

// installedControllerInput is the controller digest the latest step
// recorded (install's).
func (l *Ledger) installedControllerInput() string {
	for i := len(l.Records) - 1; i >= 0; i-- {
		if d := l.Records[i].Inputs[ControllerInput]; d != "" {
			return d
		}
	}
	return ""
}

// validateRebinds checks the rebinds: in time order, after install, each
// from the controller installed before it, none while an upgrade runs.
func (l *Ledger) validateRebinds() error {
	if len(l.Rebinds) > 0 && l.record(StepInstall).Status != StatusDone {
		return errors.New("setup ledger: a controller rebind is recorded before install")
	}
	for i, r := range l.Rebinds {
		if r.At.IsZero() || r.After < 0 || r.After > len(l.Releases) || !sha256Hex.MatchString(r.FromControllerSHA256) || !sha256Hex.MatchString(r.ControllerSHA256) || !sha256Hex.MatchString(r.AnchorSHA256) {
			return fmt.Errorf("setup ledger: controller rebind %d is incomplete", i)
		}
		if i > 0 && (r.After < l.Rebinds[i-1].After || !r.At.After(l.Rebinds[i-1].At)) {
			return fmt.Errorf("setup ledger: controller rebind %d is out of order", i)
		}
		if r.After == len(l.Releases) && l.PendingRelease() != nil {
			return fmt.Errorf("setup ledger: controller rebind %d is recorded during an upgrade", i)
		}
	}
	current, k := l.installedControllerInput(), 0
	for j := 0; j <= len(l.Releases); j++ {
		for ; k < len(l.Rebinds) && l.Rebinds[k].After == j; k++ {
			if l.Rebinds[k].FromControllerSHA256 != current {
				return fmt.Errorf("setup ledger: controller rebind %d does not continue from the installed controller", k)
			}
			current = l.Rebinds[k].ControllerSHA256
		}
		if j < len(l.Releases) && l.Releases[j].Status == StatusDone {
			current = l.Releases[j].ControllerSHA256
		}
	}
	return nil
}

// rebindAnchor is the anchor the last rebind wrote when it is newer than
// base, the anchor approve or the last carried release recorded at
// baseAt; else base.
func (l *Ledger) rebindAnchor(base string, baseAt time.Time) string {
	if n := len(l.Rebinds); n > 0 && base != "" {
		if r := l.Rebinds[n-1]; r.After == len(l.Releases) && r.At.After(baseAt) {
			return r.AnchorSHA256
		}
	}
	return base
}

// CheckControllerRebind is the setup ledger's precondition for qualify
// rebind-controller, checked before the anchor changes: no native setup
// ledger (an installation set up otherwise), or an installed ledger with
// an approval and no upgrade running.
func CheckControllerRebind(s Store) error {
	l, loc, err := s.Load()
	if err != nil || l == nil {
		return err
	}
	if loc != LedgerInstalled {
		return errors.New("macserve setup has not installed macserve; nothing to rebind")
	}
	if l.PendingRelease() != nil {
		return errors.New("a macserve upgrade is running; finish it before a controller rebind")
	}
	if !ownApproval(l) || l.AnchorSHA256() == "" {
		return errors.New("the setup ledger records no approved activation anchor to rebind")
	}
	return nil
}

// RecordControllerRebind records in the native setup ledger that the
// installed controller is now release controller and the activation anchor
// anchorSHA256, after qualify rebind-controller committed them. Without a
// native setup ledger it does nothing. Re-running once recorded is a no-op.
func RecordControllerRebind(s Store, controller, anchorSHA256 string, now time.Time) error {
	if err := CheckControllerRebind(s); err != nil {
		return err
	}
	l, loc, err := s.Load()
	if err != nil || l == nil {
		return err
	}
	from := l.InstalledController()
	if from == controller && l.AnchorSHA256() == anchorSHA256 {
		return nil
	}
	if from == "" {
		return errors.New("the setup ledger records no installed controller (installed before the controller binary); upgrade with macserve upgrade first")
	}
	l.Rebinds = append(l.Rebinds, ControllerRebind{At: now.UTC(), After: len(l.Releases), FromControllerSHA256: from, ControllerSHA256: controller, AnchorSHA256: anchorSHA256})
	if err := l.validateRebinds(); err != nil {
		return err
	}
	return s.Save(l, loc)
}

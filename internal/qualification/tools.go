package qualification

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/jerryfane/macserve/internal/model"
)

func inspectTools(ctx context.Context, c Challenge, developer string) (bool, string) {
	ok := true
	log := boundedOutput{limit: 256 << 10}
	overflow := false
	run := func(exe string, args ...string) string {
		out, diag, err := command(ctx, developer, exe, args...)
		if _, writeErr := fmt.Fprintf(&log, "%s %q\nstdout:\n%sstderr:\n%serror: %v\n", exe, args, out, diag, err); writeErr != nil {
			ok = false
			overflow = true
		}
		if err != nil || strings.TrimSpace(out) == "" {
			ok = false
		}
		return out
	}
	run("/usr/bin/xcrun", "swift", "--version")
	run("/usr/bin/sw_vers", "-productVersion")
	run("/usr/bin/sw_vers", "-buildVersion")
	pins, sdks := simulatorPins(c, developer)
	for _, sdk := range sdks {
		run("/usr/bin/xcrun", "--sdk", sdk, "--show-sdk-version")
		run("/usr/bin/xcrun", "--sdk", sdk, "--show-sdk-build-version")
	}
	if len(pins) > 0 {
		raw := run("/usr/bin/xcrun", "simctl", "list", "runtimes", "--json")
		if !runtimePins([]byte(raw), pins) {
			ok = false
			log.WriteString("Pinned simulator runtime/build/device support mismatch\n")
		}
	}
	if overflow {
		return false, log.String() + "\nTool evidence exceeded bounded output; qualification refused."
	}
	return ok, log.String()
}

// simulatorPins returns the simulator pins of the recipes that use developer:
// each explicit profile's, and every pin of each test or script template (a
// job may select any of them at admission); and the SDKs to inspect for them,
// always with macosx, sorted and unique.
func simulatorPins(c Challenge, developer string) ([]model.Simulator, []string) {
	var pins []model.Simulator
	for _, p := range c.Profiles {
		if p.DeveloperDir == developer && p.Simulator != nil {
			pins = append(pins, *p.Simulator)
		}
	}
	for _, t := range c.Templates {
		if t.DeveloperDir == developer {
			pins = append(pins, t.Simulators...)
		}
	}
	sdks := []string{"macosx"}
	for _, pin := range pins {
		sdk := "iphonesimulator"
		if strings.Contains(pin.Runtime, "tvOS-") {
			sdk = "appletvsimulator"
		}
		if strings.Contains(pin.Runtime, "watchOS-") {
			sdk = "watchsimulator"
		}
		if strings.Contains(pin.Runtime, "xrOS-") {
			sdk = "xrsimulator"
		}
		sdks = append(sdks, sdk)
	}
	slices.Sort(sdks)
	return pins, slices.Compact(sdks)
}
func runtimePins(raw []byte, pins []model.Simulator) bool {
	var listing struct {
		Runtimes []struct {
			Identifier string `json:"identifier"`
			Build      string `json:"buildversion"`
			Available  bool   `json:"isAvailable"`
			Supported  []struct {
				Identifier string `json:"identifier"`
			} `json:"supportedDeviceTypes"`
		} `json:"runtimes"`
	}
	if len(raw) > 1<<20 || json.Unmarshal(raw, &listing) != nil {
		return false
	}
	for _, pin := range pins {
		matches := 0
		for _, r := range listing.Runtimes {
			if r.Identifier != pin.Runtime {
				continue
			}
			if !r.Available || r.Build != pin.RuntimeBuild {
				return false
			}
			matches++
			supported := false
			for _, d := range r.Supported {
				if d.Identifier == pin.DeviceType {
					supported = true
				}
			}
			if !supported {
				return false
			}
		}
		if matches != 1 {
			return false
		}
	}
	return true
}

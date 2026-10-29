//go:build darwin

package maintenance

import (
	"errors"
	"testing"
)

func TestMemoryPressureAdmitsWarnRefusesCritical(t *testing.T) {
	saved := readPressureLevel
	t.Cleanup(func() { readPressureLevel = saved })
	sysctlErr := errors.New("sysctl failed")
	for _, tc := range []struct {
		name     string
		level    uint32
		readErr  error
		pressure bool
		err      bool
	}{
		{name: "normal", level: 1},
		{name: "warn", level: 2},
		{name: "critical", level: 4, pressure: true},
		{name: "unknown", level: 3, pressure: true, err: true},
		{name: "sysctl error", readErr: sysctlErr, pressure: true, err: true},
	} {
		readPressureLevel = func() (uint32, error) { return tc.level, tc.readErr }
		pressure, err := memoryPressure()
		if pressure != tc.pressure || (err != nil) != tc.err || (tc.readErr != nil && !errors.Is(err, tc.readErr)) {
			t.Fatalf("%s: pressure=%v err=%v", tc.name, pressure, err)
		}
	}
}

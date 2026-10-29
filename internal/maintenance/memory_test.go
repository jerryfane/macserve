package maintenance

import "testing"

func TestPressureFromLevelBlocksOnlyCritical(t *testing.T) {
	for _, tc := range []struct {
		level    uint32
		pressure bool
		err      bool
	}{
		{level: 1},
		{level: 2},
		{level: 4, pressure: true},
		{level: 0, pressure: true, err: true},
		{level: 3, pressure: true, err: true},
	} {
		pressure, err := pressureFromLevel(tc.level)
		if pressure != tc.pressure || (err != nil) != tc.err {
			t.Fatalf("level %d: pressure=%v err=%v", tc.level, pressure, err)
		}
	}
}

package hostguard

import "testing"

func TestConsoleAdmissibleOnlyOwnerOrLoginWindow(t *testing.T) {
	for console, ok := range map[uint32]bool{0: true, 501: true, 6202: false, 502: false} {
		if err := ConsoleAdmissible(console, 501); (err == nil) != ok {
			t.Errorf("console uid %d: admissible=%t, want %t", console, err == nil, ok)
		}
	}
}

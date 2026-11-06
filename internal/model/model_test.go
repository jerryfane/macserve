package model

import (
	"strings"
	"testing"
)

func TestTerminalStatesCannotReopen(t *testing.T) {
	terminal := []State{Succeeded, Failed, TimedOut, Cancelled, Interrupted, Expired}
	states := []State{Queued, Preparing, Running, Cancelling, Finalizing, Succeeded, Failed, TimedOut, Cancelled, Interrupted, Expired}
	for _, from := range terminal {
		if !from.Terminal() {
			t.Fatalf("completed state %q is not terminal", from)
		}
		for _, to := range states {
			if from.CanTransition(to) {
				t.Errorf("terminal state %q permits transition to %q", from, to)
			}
		}
	}
}

func TestExecutionCannotSkipFinalization(t *testing.T) {
	for _, from := range []State{Preparing, Running, Cancelling} {
		for _, to := range []State{Succeeded, Failed, TimedOut, Cancelled, Interrupted} {
			if from.CanTransition(to) {
				t.Errorf("%q can reach %q without finalization", from, to)
			}
		}
		if !from.CanTransition(Finalizing) {
			t.Errorf("%q cannot enter finalization", from)
		}
	}
}

func TestValidBranch(t *testing.T) {
	for _, name := range []string{"main", "release/1.2", "dev_x-1", "v1.0", strings.Repeat("a", 255)} {
		if !ValidBranch(name) {
			t.Errorf("%q refused", name)
		}
	}
	for _, name := range []string{"", strings.Repeat("a", 256), "/main", "main/", "a//b", "a..b", ".hidden", "a/.b", "main.", "main.lock", "a.lock/b", "ma in", "main~1", "a^b", "a:b", "a?b", "a*b", "a[b", `a\b`, "@", "a@{1}", "mäin"} {
		if ValidBranch(name) {
			t.Errorf("%q accepted", name)
		}
	}
}

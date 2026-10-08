package model

import "testing"

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

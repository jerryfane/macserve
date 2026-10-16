//go:build !darwin

package worker

import (
	"context"
	"errors"

	"github.com/jerryfane/macserve/internal/launchctlprint"
)

// nativeAgents accepts no relaunches outside macOS launchd.
type nativeAgents struct{}

var errNoLaunchd = errors.New("launchd service inspection requires macOS")

func (nativeAgents) process(int) (agentProcess, error) { return agentProcess{}, errNoLaunchd }

func (nativeAgents) service(context.Context, string) (launchctlprint.Snapshot, error) {
	return launchctlprint.Snapshot{}, errNoLaunchd
}

func (nativeAgents) responsible(context.Context, int) (int, error) { return 0, errNoLaunchd }

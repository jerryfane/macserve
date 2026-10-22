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

func (nativeAgents) kernel(int) (agentProcess, error) { return agentProcess{}, errNoLaunchd }

func (nativeAgents) process(int) (agentProcess, error) { return agentProcess{}, errNoLaunchd }

func (nativeAgents) service(context.Context, string) (launchctlprint.Snapshot, error) {
	return launchctlprint.Snapshot{}, errNoLaunchd
}

func (nativeAgents) domain(context.Context, string) (launchctlprint.Domain, error) {
	return launchctlprint.Domain{}, errNoLaunchd
}

func (nativeAgents) restricted(string) error { return errNoLaunchd }

func (nativeAgents) resolve(string) (string, error) { return "", errNoLaunchd }

func (nativeAgents) plist(context.Context, string) ([]byte, error) { return nil, errNoLaunchd }

func (nativeAgents) toolchain(string, bool, int) error { return errNoLaunchd }

func (nativeAgents) bundleInfo(context.Context, string) (string, string, error) {
	return "", "", errNoLaunchd
}

func (nativeAgents) xpcEnvironment(context.Context, int) (map[string]string, error) {
	return nil, errNoLaunchd
}

package worker

import (
	"context"
	"errors"
)

// ObserveGUIBaseline checks every audited process without adopting or rejecting
// additional active-job processes. It never signals processes or writes state.
// Audited processes that are simply absent are returned as evidence rather
// than refused: launchd-managed Apple helpers in the job GUI session may exit
// on their own, and absence can neither hide nor retain job state. A changed
// UID or zombie is always an error, and so is a reused audited PID unless the
// new holder is a verified launchd relaunch (see processScope.census).
func ObserveGUIBaseline(ctx context.Context, path, persistencePath string, uid uint32) (string, []ProcessIdentity, error) {
	baseline, err := loadBaseline(path, uid)
	if err != nil {
		return "", nil, err
	}
	digest, err := PersistenceDigest(persistencePath, uid)
	if err != nil {
		return "", nil, err
	}
	if baseline.PersistenceSHA256 != digest {
		return "", nil, errors.New("reviewed persistence changed; baseline reset and requalification required")
	}
	samples, err := identityProcesses(ctx)
	if err != nil {
		return "", nil, err
	}
	scope := processScope{uid: int(uid), baseline: baseline, agents: nativeAgents{}}
	if _, err := scope.census(ctx, samples); err != nil {
		return "", nil, err
	}
	return baseline.Boot, baselineExited(baseline, samples), ctx.Err()
}

// baselineExited returns the audited identities no longer running: the PID is
// absent or now held by a process with another start identity.
func baselineExited(b GUIBaseline, samples []processSample) []ProcessIdentity {
	live := make(map[int]string, len(samples))
	for _, p := range samples {
		live[p.pid] = p.start
	}
	var exited []ProcessIdentity
	for _, p := range b.Processes {
		if start, ok := live[p.PID]; !ok || start != p.Start {
			exited = append(exited, p)
		}
	}
	return exited
}

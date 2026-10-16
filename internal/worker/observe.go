package worker

import (
	"context"
	"errors"
)

// ObserveGUIBaseline checks every audited process without adopting or rejecting
// additional active-job processes. It never signals processes or writes state.
// Audited processes that are simply absent are returned as evidence rather
// than refused: launchd-managed Apple helpers in the job GUI session may exit
// on their own, and absence can neither hide nor retain job state. A reused
// PID, changed UID or zombie is always an error.
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
	if err := baselineAlive(baseline, samples); err != nil {
		return "", nil, err
	}
	return baseline.Boot, baselineExited(baseline, samples), ctx.Err()
}

// baselineAlive refuses an audited PID that is now a different process (start
// token), another UID or a zombie. Absent audited PIDs and unaudited processes
// are not refusals here; see baselineExited.
func baselineAlive(b GUIBaseline, samples []processSample) error {
	trusted := make(map[int]string, len(b.Processes))
	for _, p := range b.Processes {
		trusted[p.PID] = p.Start
	}
	for _, p := range samples {
		start, ok := trusted[p.pid]
		if !ok {
			continue
		}
		if p.uid != int(b.JobUID) || p.start != start || p.zombie {
			return errors.New("audited GUI baseline process changed")
		}
	}
	return nil
}

// baselineExited returns the audited identities whose PID is absent.
func baselineExited(b GUIBaseline, samples []processSample) []ProcessIdentity {
	live := make(map[int]bool, len(samples))
	for _, p := range samples {
		live[p.pid] = true
	}
	var exited []ProcessIdentity
	for _, p := range b.Processes {
		if !live[p.PID] {
			exited = append(exited, p)
		}
	}
	return exited
}

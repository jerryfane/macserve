package worker

import (
	"context"
	"errors"
)

// ObserveGUIBaseline checks every audited process without adopting or rejecting
// additional active-job processes. It never signals processes or writes state.
func ObserveGUIBaseline(ctx context.Context, path, persistencePath string, uid uint32) (string, error) {
	baseline, err := loadBaseline(path, uid)
	if err != nil {
		return "", err
	}
	digest, err := PersistenceDigest(persistencePath, uid)
	if err != nil {
		return "", err
	}
	if baseline.PersistenceSHA256 != digest {
		return "", errors.New("reviewed persistence changed; baseline reset and requalification required")
	}
	samples, err := identityProcesses(ctx)
	if err != nil {
		return "", err
	}
	if err := baselineAlive(baseline, samples); err != nil {
		return "", err
	}
	return baseline.Boot, ctx.Err()
}

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
		delete(trusted, p.pid)
	}
	if len(trusted) != 0 {
		return errors.New("audited GUI baseline process missing")
	}
	return nil
}

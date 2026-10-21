package worker

import (
	"context"
	"errors"
)

const loginwindowExecutable = "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow"

// JobLoginwindows returns the PIDs of the platform-signed loginwindow
// processes running as uid: the job GUI session's own login process. It is
// read-only and uses kernel facts only.
func JobLoginwindows(ctx context.Context, uid uint32) ([]int, error) {
	samples, err := identityProcesses(ctx)
	if err != nil {
		return nil, err
	}
	return jobLoginwindows(samples, nativeAgents{}, uid)
}

func jobLoginwindows(samples []processSample, agents agentInspector, uid uint32) ([]int, error) {
	var pids []int
	for _, p := range samples {
		if p.uid != int(uid) || p.zombie {
			continue
		}
		facts, err := agents.kernel(p.pid)
		if err != nil || facts.start != p.start {
			continue
		}
		if facts.uid == int(uid) && facts.platform && facts.executable == loginwindowExecutable {
			pids = append(pids, p.pid)
		}
	}
	if len(pids) == 0 {
		return nil, errors.New("no job GUI loginwindow is running: log into the job account first")
	}
	return pids, nil
}

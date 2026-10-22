package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/jerryfane/macserve/internal/hostguard"
)

// ResetResult is the baseline worker-reset saved, with every way it differs
// from the administrator's selection.
type ResetResult struct {
	GUIBaseline
	// Dropped are requested processes absent at reset start and selected
	// processes that exited during reset without launchd provenance.
	Dropped []DroppedProcess
	// Exited are baseline entries with launchd provenance not running at the
	// audit and not yet relaunched: selected processes that exited, and
	// adopted instances that reset terminated. The baseline keeps them, as
	// after any later exit, so their relaunch is verified against it.
	Exited []ProcessIdentity
	// Relaunched pairs a baseline entry that exited during reset with
	// launchd's verified relaunch, which the baseline records instead.
	Relaunched []Relaunch
	// Adopted are the unselected system LaunchAgents the baseline records
	// (see adoption), as published; they may also be Exited or Relaunched.
	Adopted []ProcessIdentity
}

// DroppedProcess is a requested process the reset baseline does not contain.
// Start and Path (kernel executable) are empty when unknown.
type DroppedProcess struct {
	PID    int
	Start  string
	Path   string
	Reason string
}

type Relaunch struct {
	Exited, Relaunch ProcessIdentity
}

// GUI anchors are the selected processes that must survive reset unchanged;
// every other selected process may exit (see resetBaseline). They are the
// processes whose exit means the audited GUI session itself changed, not the
// on-demand helper lifecycle: loginwindow owns the job's Aqua login (it creates
// the gui launchd domain; its exit is a logout), and Dock and Finder are that
// session's always-on KeepAlive UI, so their exit is a crash or session
// restart. A selection must include all three. A selected Terminal or system
// shell is the administrator's chosen console, where the qualification job
// probe runs; it is an anchor when selected, because a replacement would be an
// unselected process that reset terminates. Nothing else qualifies: a smaller
// set lets a logout or console loss pass as a helper exit, and a larger one
// reinstates the v0.1.9 failure for helpers that exit on their own. Anchors
// are matched by kernel facts alone (effective UID, start, csops platform
// status and executable path; the paths are SIP-protected), never by the
// launch arguments, whose environment a SIP-enabled kernel withholds.
var (
	requiredAnchors = []string{
		"/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow",
		"/System/Library/CoreServices/Dock.app/Contents/MacOS/Dock",
		"/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder",
	}
	consoleAnchors = []string{
		"/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
		"/bin/zsh", "/bin/bash", "/bin/sh", "/bin/dash", "/bin/ksh", "/bin/tcsh", "/bin/csh",
	}
)

// selectAnchors returns the selected GUI anchors (PID to start) and each
// selected process's kernel executable path, and refuses a selection without
// the session's loginwindow, Dock and Finder.
func selectAnchors(agents agentInspector, b GUIBaseline) (anchors, paths map[int]string, err error) {
	anchors, paths = make(map[int]string), make(map[int]string, len(b.Processes))
	found := make(map[string]bool, len(requiredAnchors))
	for _, p := range b.Processes {
		facts, err := agents.kernel(p.PID)
		if err != nil || facts.start != p.Start {
			continue
		}
		paths[p.PID] = facts.executable
		if facts.uid == int(b.JobUID) && facts.platform && (slices.Contains(requiredAnchors, facts.executable) || slices.Contains(consoleAnchors, facts.executable)) {
			anchors[p.PID] = p.Start
			found[facts.executable] = true
		}
	}
	for _, path := range requiredAnchors {
		if !found[path] {
			return nil, nil, fmt.Errorf("audited selection lacks the job GUI's running %s; select its loginwindow, Dock and Finder", filepath.Base(path))
		}
	}
	return anchors, paths, nil
}

// auditReset publishes the reset baseline from two snapshots taken 100ms
// apart on the same boot, after cleanup settled. A residual job process, or a
// GUI anchor no longer running with its selected identity, refuses.
func (s *processScope) auditReset(ctx context.Context, anchors, paths map[int]string, boot func() (string, error), bootID string) (ResetResult, error) {
	var result ResetResult
	for pass := range 2 {
		if pass == 1 {
			timer := time.NewTimer(100 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return result, ctx.Err()
			case <-timer.C:
			}
		}
		samples, err := s.sample(ctx)
		if err != nil {
			return result, err
		}
		c, err := s.census(ctx, samples)
		if err != nil {
			return result, err
		}
		if len(c.residual) != 0 || len(c.vanished) != 0 {
			return result, errors.New("unselected job process remains during reset audit")
		}
		live := make(map[int]string, len(samples))
		for _, p := range samples {
			if p.uid == s.uid && !p.zombie {
				live[p.pid] = p.start
			}
		}
		for pid, start := range anchors {
			if live[pid] != start {
				return result, fmt.Errorf("audited GUI anchor PID %d (%s) exited during reset: the job GUI session changed; audit it again", pid, paths[pid])
			}
		}
		result = s.published(c, live, paths)
	}
	if second, err := boot(); err != nil || second != bootID {
		return result, errors.Join(err, errors.New("boot identity changed during reset"))
	}
	return result, validateBaseline(result.GUIBaseline, uint32(s.uid), bootID)
}

// published builds the reset result from one settled census of s.baseline,
// the selection plus adoptions. A running process keeps its identity; an
// exited one is replaced by its verified relaunch, kept as an exited identity
// if it has provenance, or dropped. A pid-domain XPC service's owner follows
// the owner's relaunch; once its owner is dropped its provenance cannot be
// verified and is cleared, and an exited entry kept only for it is dropped.
func (s *processScope) published(c processCensus, live, paths map[int]string) ResetResult {
	kept := make(map[int]ProcessIdentity, len(s.baseline.Processes))
	running := make(map[int]bool, len(s.baseline.Processes))
	for _, p := range s.baseline.Processes {
		if live[p.PID] == p.Start {
			kept[p.PID], running[p.PID] = p, true
		} else if r, ok := c.relaunched[p.PID]; ok {
			kept[p.PID], running[r.pid] = ProcessIdentity{PID: r.pid, Start: r.start, Service: p.Service}, true
		} else if p.Service.Domain != "" {
			kept[p.PID] = p
		}
	}
	reason := make(map[int]string)
	for changed := true; changed; {
		changed = false
		for pid, k := range kept {
			exited := k.PID == pid && k.Start != live[pid]
			if exited && running[pid] {
				// The exited PID number now belongs to another kept process.
				delete(kept, pid)
				reason[pid], changed = "exited during reset; PID now held by a verified relaunch", true
			} else if _, owned := kept[k.Service.Owner]; k.Service.Domain == "pid" && !owned {
				if exited {
					delete(kept, pid)
					reason[pid] = "exited during reset; its XPC owner was dropped"
				} else {
					k.Service = LaunchdService{}
					kept[pid] = k
				}
				changed = true
			}
		}
	}
	adopted := make(map[int]bool)
	if s.adopt != nil {
		for _, p := range s.adopt.adopted {
			adopted[p.PID] = true
		}
	}
	result := ResetResult{GUIBaseline: GUIBaseline{JobUID: s.baseline.JobUID, Boot: s.baseline.Boot, Launchd: s.baseline.Launchd}}
	for _, p := range s.baseline.Processes {
		k, ok := kept[p.PID]
		if !ok {
			why, path := reason[p.PID], paths[p.PID]
			if why == "" {
				why = "exited during reset; no launchd provenance to verify a relaunch"
			}
			if path == "" {
				path = p.Service.Executable
			}
			result.Dropped = append(result.Dropped, DroppedProcess{PID: p.PID, Start: p.Start, Path: path, Reason: why})
			continue
		}
		if k.Service.Domain == "pid" {
			k.Service.Owner = kept[k.Service.Owner].PID
		}
		if adopted[p.PID] {
			result.Adopted = append(result.Adopted, k)
		}
		if k.Start != p.Start {
			result.Relaunched = append(result.Relaunched, Relaunch{Exited: p, Relaunch: k})
		} else if live[k.PID] != k.Start {
			result.Exited = append(result.Exited, k)
		}
		result.Processes = append(result.Processes, k)
	}
	return result
}

// selectedBaseline trusts only explicit administrator selections. Extra job-UID
// processes are left outside this baseline so reset can terminate them safely.
// A requested PID that is no longer running cannot be part of any baseline and
// is dropped; one now held by another UID or a zombie is refused.
func selectedBaseline(uid uint32, pids []int, boot string, env *LaunchdEnvironment, samples []processSample) (GUIBaseline, []DroppedProcess, error) {
	baseline := GUIBaseline{JobUID: uid, Boot: boot, Launchd: env}
	if len(pids) == 0 || len(pids) > 4096 {
		return baseline, nil, errors.New("explicit audited GUI process PIDs required")
	}
	wanted := make(map[int]bool, len(pids))
	for _, pid := range pids {
		if pid <= 1 || wanted[pid] {
			return baseline, nil, errors.New("invalid or duplicate baseline PID")
		}
		wanted[pid] = true
	}
	for _, p := range samples {
		if !wanted[p.pid] {
			continue
		}
		if p.uid != int(uid) || p.zombie {
			return baseline, nil, errors.New("audited PID belongs to another UID or is a zombie")
		}
		baseline.Processes = append(baseline.Processes, ProcessIdentity{PID: p.pid, Start: p.start})
		delete(wanted, p.pid)
	}
	var dropped []DroppedProcess
	for _, pid := range pids {
		if wanted[pid] {
			dropped = append(dropped, DroppedProcess{PID: pid, Reason: "absent at reset start"})
		}
	}
	if err := validateBaseline(baseline, uid, boot); err != nil {
		return baseline, nil, err
	}
	return baseline, dropped, nil
}

func saveBaseline(path string, baseline GUIBaseline) error {
	if err := hostguard.RootDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	parent, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer parent.Close()
	data, err := json.Marshal(baseline)
	if err != nil {
		return err
	}
	return durableFile(parent, filepath.Base(path), data)
}

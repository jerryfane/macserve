package worker

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jerryfane/macserve/internal/hostguard"
)

// QualifyGUIBaseline records only the exact PIDs the administrator explicitly
// audited as trusted GUI services. It cannot run alongside the broker or adopt
// unlisted processes. Reboot/service identity changes require requalification.
func QualifyGUIBaseline(ctx context.Context, options Options, pids []int) error {
	if err := hostguard.BrokerIdentity(options.JobUID, options.JobGID, options.ControllerUID, options.OwnerUID); err != nil {
		return err
	}
	if err := hostguard.RootDirectory(options.Root); err != nil {
		return err
	}
	if err := hostguard.RootDirectory(filepath.Dir(options.BaselinePath)); err != nil {
		return err
	}
	if len(pids) == 0 || len(pids) > 4096 {
		return errors.New("explicit audited GUI process PIDs required")
	}
	root, err := os.OpenRoot(options.Root)
	if err != nil {
		return err
	}
	defer root.Close()
	lock, err := root.OpenFile("worker.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("stop the broker before GUI baseline qualification")
	}
	if dir, err := root.Open("manifests"); err == nil {
		names, readErr := dir.Readdirnames(-1)
		dir.Close()
		if readErr != nil {
			return readErr
		}
		if len(names) != 0 {
			return errors.New("unresolved job records forbid baseline qualification")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	wanted := make(map[int]bool, len(pids))
	for _, pid := range pids {
		if pid <= 1 || wanted[pid] {
			return errors.New("invalid or duplicate baseline PID")
		}
		wanted[pid] = true
	}
	boot, err := bootIdentity()
	if err != nil {
		return err
	}
	samples, err := identityProcesses(ctx)
	if err != nil {
		return err
	}
	baseline := GUIBaseline{JobUID: options.JobUID, Boot: boot}
	for _, p := range samples {
		if p.uid != int(options.JobUID) || p.zombie {
			continue
		}
		if !wanted[p.pid] {
			return errors.New("unqualified process remains in dedicated job UID")
		}
		baseline.Processes = append(baseline.Processes, ProcessIdentity{PID: p.pid, Start: p.start})
		delete(wanted, p.pid)
	}
	if len(wanted) != 0 {
		return errors.New("audited PID absent or belongs to another UID")
	}
	if err := validateBaseline(baseline, options.JobUID, boot); err != nil {
		return err
	}
	// Recheck stable identities; qualification never kills anything.
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
	}
	samples, err = identityProcesses(ctx)
	if err != nil {
		return err
	}
	scope := processScope{uid: int(options.JobUID), baseline: baseline}
	residual, err := scope.residual(samples)
	if err != nil {
		return err
	}
	if len(residual) != 0 {
		return errors.New("job UID changed during qualification")
	}
	parent, err := os.OpenRoot(filepath.Dir(options.BaselinePath))
	if err != nil {
		return err
	}
	defer parent.Close()
	data, err := json.Marshal(baseline)
	if err != nil {
		return err
	}
	return durableFile(parent, filepath.Base(options.BaselinePath), data)
}

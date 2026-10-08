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

// QualifyGUIBaseline is initial qualification only. It never clears admission
// quarantine or resolves retained manifests; use administrator reconciliation.
func QualifyGUIBaseline(ctx context.Context, options Options, pids []int) error {
	if err := hostguard.BrokerIdentity(options.JobUID, options.JobGID, options.ControllerUID, options.OwnerUID); err != nil {
		return err
	}
	if err := hostguard.RootDirectory(options.Root); err != nil {
		return err
	}
	if err := hostguard.RootConfig(options.HelperPath); err != nil {
		return err
	}
	if err := hostguard.RootDirectory(filepath.Dir(options.BaselinePath)); err != nil {
		return err
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
	if _, err := root.Lstat(admissionRecord); !os.IsNotExist(err) {
		return errors.Join(ErrRecovery, errors.New("qualification cannot clear administrator reconciliation requirement"), err)
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
	if err := nativePersistenceInspector(options)(ctx); err != nil {
		return err
	}
	baseline, err := auditedBaseline(ctx, options.JobUID, pids, bootIdentity, identityProcesses)
	if err != nil {
		return err
	}
	return saveBaseline(options.BaselinePath, baseline)
}

func auditedBaseline(ctx context.Context, uid uint32, pids []int, boot func() (string, error), sample processSampler) (GUIBaseline, error) {
	var baseline GUIBaseline
	if len(pids) == 0 || len(pids) > 4096 {
		return baseline, errors.New("explicit audited GUI process PIDs required")
	}
	wanted := make(map[int]bool, len(pids))
	for _, pid := range pids {
		if pid <= 1 || wanted[pid] {
			return baseline, errors.New("invalid or duplicate baseline PID")
		}
		wanted[pid] = true
	}
	bootID, err := boot()
	if err != nil {
		return baseline, err
	}
	samples, err := sample(ctx)
	if err != nil {
		return baseline, err
	}
	baseline = GUIBaseline{JobUID: uid, Boot: bootID}
	for _, p := range samples {
		if p.uid != int(uid) || p.zombie {
			continue
		}
		if !wanted[p.pid] {
			return baseline, errors.New("unqualified process remains in dedicated job UID")
		}
		baseline.Processes = append(baseline.Processes, ProcessIdentity{PID: p.pid, Start: p.start})
		delete(wanted, p.pid)
	}
	if len(wanted) != 0 {
		return baseline, errors.New("audited PID absent or belongs to another UID")
	}
	if err := validateBaseline(baseline, uid, bootID); err != nil {
		return baseline, err
	}
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return baseline, ctx.Err()
	case <-timer.C:
	}
	samples, err = sample(ctx)
	if err != nil {
		return baseline, err
	}
	secondBoot, err := boot()
	if err != nil || secondBoot != bootID {
		return baseline, errors.Join(err, errors.New("boot identity changed during audit"))
	}
	scope := processScope{uid: int(uid), baseline: baseline}
	residual, err := scope.residual(samples)
	if err != nil {
		return baseline, err
	}
	if len(residual) != 0 {
		return baseline, errors.New("job UID changed during qualification")
	}
	return baseline, nil
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

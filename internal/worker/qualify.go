package worker

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/jerryfane/macserve/internal/hostguard"
)

func auditedBaseline(ctx context.Context, uid uint32, pids []int, boot func() (string, error), sample processSampler) (GUIBaseline, error) {
	bootID, err := boot()
	if err != nil {
		return GUIBaseline{}, err
	}
	samples, err := sample(ctx)
	if err != nil {
		return GUIBaseline{}, err
	}
	baseline, err := selectedBaseline(uid, pids, bootID, samples)
	if err != nil {
		return baseline, err
	}
	scope := processScope{uid: int(uid), baseline: baseline}
	residual, err := scope.residual(samples)
	if err != nil {
		return baseline, err
	}
	if len(residual) != 0 {
		return baseline, errors.New("unselected job process remains during baseline audit")
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
	residual, err = scope.residual(samples)
	if err != nil {
		return baseline, err
	}
	if len(residual) != 0 {
		return baseline, errors.New("job UID changed during baseline audit")
	}
	return baseline, ctx.Err()
}

// selectedBaseline trusts only explicit administrator selections. Extra job-UID
// processes are left outside this baseline so reset can terminate them safely.
func selectedBaseline(uid uint32, pids []int, boot string, samples []processSample) (GUIBaseline, error) {
	baseline := GUIBaseline{JobUID: uid, Boot: boot}
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
	for _, p := range samples {
		if p.uid != int(uid) || p.zombie {
			continue
		}
		if !wanted[p.pid] {
			continue
		}
		baseline.Processes = append(baseline.Processes, ProcessIdentity{PID: p.pid, Start: p.start})
		delete(wanted, p.pid)
	}
	if len(wanted) != 0 {
		return baseline, errors.New("audited PID absent or belongs to another UID")
	}
	if err := validateBaseline(baseline, uid, boot); err != nil {
		return baseline, err
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

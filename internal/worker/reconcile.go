package worker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jerryfane/macserve/internal/hostguard"
)

// ReconcileGUIBaseline is the sole authority to replace a baseline while job
// records remain. The administrator must first remove persistence and explicitly
// audit every current job-UID process. Re-login alone is not a persistence reset.
func ReconcileGUIBaseline(ctx context.Context, options Options, pids []int) error {
	if err := hostguard.BrokerIdentity(options.JobUID, options.JobGID, options.ControllerUID, options.OwnerUID); err != nil {
		return err
	}
	// Never permit an injected runner to bypass production inspection/identity.
	options.Runner = nil
	engine, err := New(options)
	if err != nil {
		return fmt.Errorf("stop the broker before administrator reconciliation: %w", err)
	}
	defer engine.Close()
	if err := engine.markReconciliation(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	runner := engine.options.Runner.(*nativeRunner)
	if err := runner.persistence(ctx); err != nil {
		return err
	}
	baseline, err := auditedBaseline(ctx, options.JobUID, pids, bootIdentity, identityProcesses)
	if err != nil {
		return err
	}
	if err := saveBaseline(options.BaselinePath, baseline); err != nil {
		return err
	}
	return engine.reconcileRecords(ctx)
}

func (e *Engine) markReconciliation() error {
	// Replace even an existing marker durably; failures never remove the old one.
	return durableFile(e.root, admissionRecord, []byte(`{"administrator_reconciliation_required":true}`))
}

func validManifest(name string, m manifest) bool {
	return identifier.MatchString(m.JobID) && name == m.JobID+".json" && filepath.IsAbs(m.DeveloperDir) && (m.DeviceUDID == "" || udidPattern.MatchString(m.DeviceUDID))
}

// Caller holds the exclusive stopped-broker lock and has explicitly established
// the new baseline. On any error, quarantine and unresolved records survive.
func (e *Engine) reconcileRecords(ctx context.Context) error {
	names, err := e.registryNames()
	if err != nil {
		return err
	}
	for _, name := range names {
		var m manifest
		if err := readJSON(e.root, "manifests/"+name, &m); err != nil {
			return err
		}
		if !validManifest(name, m) {
			return ErrRecovery
		}
		if _, native := e.options.Runner.(*nativeRunner); native {
			if err := hostguard.ToolchainDirectory(m.DeveloperDir, e.options.JobUID); err != nil {
				return err
			}
		}
		// Re-check without killing any unrecorded current process. An audited
		// baseline is authority to resolve prior uncertainty, not to adopt drift.
		if inspector, ok := e.options.Runner.(interface{ Admission(context.Context) error }); ok {
			if err := inspector.Admission(ctx); err != nil {
				return err
			}
		}
		if err := e.options.Runner.Quiesce(ctx); err != nil {
			return err
		}
		m.Active, m.ProcessUncertain = false, true
		if err := e.saveManifest(m); err != nil {
			return err
		}
		if m.DeviceUDID != "" {
			if err := e.reconcileDevice(ctx, &m); err != nil {
				return err
			}
			if err := e.stopDevice(ctx, &m); err != nil {
				return err
			}
		}
		if err := e.options.Runner.Quiesce(ctx); err != nil {
			return err
		}
		if err := e.workspacePass(ctx, m.JobID, false, true); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := e.workspaces.RemoveAll(m.JobID); err != nil {
			return err
		}
		// Neither pending.json nor sealed exports/evidence are removed here.
		if err := e.root.Remove("manifests/" + name); err != nil {
			return err
		}
	}
	if inspector, ok := e.options.Runner.(interface{ Admission(context.Context) error }); ok {
		if err := inspector.Admission(ctx); err != nil {
			return err
		}
	}
	if err := e.options.Runner.Quiesce(ctx); err != nil {
		return err
	}
	if err := e.root.Remove(admissionRecord); err != nil && !os.IsNotExist(err) {
		return err
	}
	dir, err := e.root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return errors.Join(err, e.markReconciliation())
	}
	return nil
}

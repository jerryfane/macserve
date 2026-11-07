package maintenance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/jerryfane/macserve/internal/controllerconfig"
	"github.com/jerryfane/macserve/internal/health"
	"github.com/jerryfane/macserve/internal/hostguard"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/worker"
	"github.com/jerryfane/macserve/internal/workerclient"
)

func publish(path string, h health.Health) error {
	if err := hostguard.RootDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	data, err := json.Marshal(h)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".health-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0644); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// Check evaluates the installed approval against live state once, without
// publishing health. It requires macOS root and a protected loaded config.
func Check(ctx context.Context, c Config) (health.Health, error) {
	if c.path == "" {
		return health.Health{}, errors.New("check requires protected configuration")
	}
	return observe(ctx, c)
}
func observe(ctx context.Context, c Config) (health.Health, error) {
	invalid, _ := Evaluate(time.Now(), Qualification{}, BoundaryEvidence{}, Observation{})
	opts, err := persistenceOptions(c)
	if err != nil {
		return invalid, err
	}
	status, statusErr := worker.PersistenceAttestationStatus(opts)
	if statusErr != nil {
		status.Valid = false
	}
	invalid, _ = Evaluate(time.Now(), Qualification{}, BoundaryEvidence{}, Observation{Persistence: status})
	if statusErr != nil {
		return invalid, statusErr
	}
	qdata, err := protectedRead(c.QualificationFile)
	if err != nil {
		return invalid, err
	}
	var q Qualification
	if err = decode(qdata, &q); err != nil {
		return invalid, err
	}
	edata, err := protectedRead(c.BoundaryEvidenceFile)
	if err != nil {
		return invalid, err
	}
	var e BoundaryEvidence
	if err = decode(edata, &e); err != nil {
		return invalid, err
	}
	o, err := Inspect(ctx, c)
	if err != nil {
		return invalid, err
	}
	o.BoundaryEvidenceSHA256 = digest(edata)
	for p, old := range map[string][]byte{c.QualificationFile: qdata, c.BoundaryEvidenceFile: edata} {
		b, err := protectedRead(p)
		if err != nil || !bytes.Equal(b, old) {
			return invalid, fmt.Errorf("approval input changed: %s", p)
		}
	}
	return Evaluate(time.Now(), q, e, o)
}

// Inspect collects live facts without requiring approval records or publishing
// health. It cannot qualify the host or manufacture boundary evidence.
func Inspect(ctx context.Context, c Config) (Observation, error) {
	invalid := Observation{}
	if runtime.GOOS != "darwin" || os.Getuid() != 0 || os.Geteuid() != 0 {
		return invalid, errors.New("maintenance inspection requires macOS root")
	}
	if c.path == "" {
		return invalid, errors.New("inspection requires protected configuration")
	}
	loaded, err := LoadConfig(c.path)
	if err != nil {
		return invalid, err
	}
	c = loaded
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	for _, p := range []string{c.ControllerConfig, c.WorkerConfig} {
		if err := hostguard.RootConfig(p); err != nil {
			return invalid, err
		}
	}
	cc, err := controllerconfig.LoadConfig(c.ControllerConfig)
	if err != nil {
		return invalid, err
	}
	wc, err := workerclient.LoadConfig(c.WorkerConfig)
	if err != nil {
		return invalid, err
	}
	if cc.Root != "/Library/macserve/var/controller" || wc.Root != "/Library/macserve/var/broker" || wc.ExportRoot != "/Library/macserve/var/exports" || wc.WorkspaceRoot != "/Library/macserve/var/workspaces" || cc.HealthFile != "/Library/macserve/health/current.json" || cc.JobUID != wc.JobUID || cc.OwnerUID != wc.OwnerUID || cc.Socket != wc.Socket {
		return invalid, errors.New("unsupported maintenance deployment topology")
	}
	if err := hostguard.BrokerIdentity(wc.JobUID, wc.JobGID, wc.ControllerUID, wc.OwnerUID); err != nil {
		return invalid, err
	}
	account, err := user.LookupId(strconv.FormatUint(uint64(wc.JobUID), 10))
	if err != nil {
		return invalid, err
	}
	if account.HomeDir != "/Users/"+account.Username || account.Username == "" {
		return invalid, errors.New("unsupported job home")
	}
	o := Observation{JobUID: wc.JobUID, IdentityValid: true, Profiles: map[string]string{}}
	// Recorded, not refused: health stays publishable and is invalid while a
	// foreground job session (or any non-owner account) owns the console.
	o.ConsoleAdmissible = hostguard.CheckConsole(wc.OwnerUID) == nil
	baseline, err := protectedRead(wc.BaselinePath)
	if err != nil {
		return invalid, err
	}
	o.BaselineSHA256 = digest(baseline)
	persistence, err := protectedRead(wc.PersistencePath)
	if err != nil {
		return invalid, err
	}
	o.Boot, o.BaselineExited, err = worker.ObserveGUIBaseline(ctx, wc.BaselinePath, wc.PersistencePath, wc.JobUID)
	if err != nil {
		return invalid, err
	}
	o.BaselineValid = true
	opts, err := persistenceOptions(c)
	if err != nil {
		return invalid, err
	}
	o.Persistence, err = worker.PersistenceAttestationStatus(opts)
	if err != nil {
		// Missing/unreadable evidence is never readiness. Preserve the last
		// successful timestamp, when available, without claiming a fresh scan.
		o.Persistence.Valid = false
	}
	// Recorded, not refused: health stays valid and the controller's gate
	// reports a worker that keeps refusing admission inconclusively.
	o.AdmissionInconclusive, err = worker.ReadAdmissionInconclusive(wc.Root)
	if err != nil {
		return invalid, err
	}
	if err = hostguard.RootConfig(cc.ProfilesFile); err != nil {
		return invalid, err
	}
	registry, err := profiles.Load(cc.ProfilesFile)
	if err != nil {
		return invalid, err
	}
	// Profile digests are sha256 of each normalized profile's JSON; template
	// digests are sha256 of each normalized template's JSON.
	o.Profiles = registry.Digests()
	o.MemoryPressure, err = memoryPressure()
	if err != nil {
		return invalid, err
	}
	o.AccountedBytes, err = accountBytes(ctx, []string{"/Library/macserve/var", account.HomeDir}, account.HomeDir, wc.JobUID)
	if err != nil {
		return invalid, err
	}
	if err = ctx.Err(); err != nil {
		return invalid, err
	}
	// Protected records cannot be silently replaced between their digest and use.
	for p, old := range map[string][]byte{wc.BaselinePath: baseline, wc.PersistencePath: persistence} {
		b, err := protectedRead(p)
		if err != nil || !bytes.Equal(b, old) {
			return invalid, fmt.Errorf("approval input changed: %s", p)
		}
	}
	coexistence, err := ObserveCoexistence(ctx, c)
	if err != nil {
		return invalid, err
	}
	o.Coexistence = &coexistence
	return o, nil
}

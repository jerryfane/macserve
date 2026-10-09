package maintenance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/jerryfane/macserve/internal/controller"
	"github.com/jerryfane/macserve/internal/hostguard"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/worker"
	"github.com/jerryfane/macserve/internal/workerclient"
)

const DefaultPFAnchor = "com.apple/macserve"

type Config struct {
	ControllerConfig            string   `json:"controller_config"`
	WorkerConfig                string   `json:"worker_config"`
	QualificationFile           string   `json:"qualification_file"`
	BoundaryEvidenceFile        string   `json:"boundary_evidence_file"`
	PFPolicyFile                string   `json:"pf_policy_file"`
	PFAnchor                    string   `json:"pf_anchor"`
	ToleratedTranslationAnchors []string `json:"tolerated_translation_anchors,omitempty"`
	ApprovedGuestSubnets        []string `json:"approved_guest_subnets,omitempty"`
	CoexistingAnchors           []string `json:"coexisting_anchors,omitempty"`
	CoexistingServices          []string `json:"coexisting_services,omitempty"`
	IntervalSeconds             int      `json:"interval_seconds"`
	path                        string
}

func decode(data []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func protectedRead(path string) ([]byte, error) {
	if err := hostguard.RootConfig(path); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 1<<20 {
		return nil, errors.New("protected input too large")
	}
	return data, nil
}
func LoadConfig(path string) (Config, error) {
	var c Config
	data, err := protectedRead(path)
	if err != nil {
		return c, err
	}
	if err = decode(data, &c); err != nil {
		return c, err
	}
	c.path = path
	if c.IntervalSeconds == 0 {
		c.IntervalSeconds = 10
	}
	if c.IntervalSeconds < 5 || c.IntervalSeconds > 15 {
		return c, errors.New("unsupported maintenance interval")
	}
	if err := validatePFConfig(&c); err != nil {
		return c, err
	}
	if err := validateCoexistenceConfig(&c); err != nil {
		return c, err
	}
	for _, p := range []string{c.ControllerConfig, c.WorkerConfig, c.QualificationFile, c.BoundaryEvidenceFile, c.PFPolicyFile} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" {
			return c, errors.New("maintenance paths must be clean and absolute")
		}
	}
	return c, nil
}

// Run requires the protected fixed deployment topology. Every cycle reloads all
// approval inputs. Failure publishes invalid health, including shutdown; no
// failure path extends the lifetime of a successful observation.
func Run(ctx context.Context, c Config) error {
	if runtime.GOOS != "darwin" || os.Getuid() != 0 || os.Geteuid() != 0 {
		return errors.New("maintenance requires macOS root")
	}
	if c.path == "" {
		return errors.New("maintenance config must be loaded from a protected file")
	}
	const health = "/Library/macserve/health/current.json"
	if err := hostguard.RootDirectory(filepath.Dir(health)); err != nil {
		return err
	}
	invalid := func() error {
		h, _ := Evaluate(time.Now(), Qualification{}, BoundaryEvidence{}, Observation{})
		return publish(health, h)
	}
	if err := invalid(); err != nil {
		return err
	}
	defer invalid()
	for {
		started := time.Now()
		current, err := LoadConfig(c.path)
		interval := 10 * time.Second
		var h controller.Health
		if err == nil {
			interval = time.Duration(current.IntervalSeconds) * time.Second
			probeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
			h, err = observe(probeCtx, current, started)
			cancel()
		}
		if err != nil {
			h, _ = Evaluate(time.Now(), Qualification{}, BoundaryEvidence{}, Observation{})
		}
		if err = publish(health, h); err != nil {
			return err
		}
		// Anchor cadence to probe start; probe duration must not extend the interval.
		timer := time.NewTimer(max(0, time.Until(started.Add(interval))))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
func publish(path string, h controller.Health) error {
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
func observe(ctx context.Context, c Config, now time.Time) (controller.Health, error) {
	invalid := controller.Health{}
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
	return Evaluate(now, q, e, o)
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
	cc, err := controller.LoadConfig(c.ControllerConfig)
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
	policy, err := protectedRead(c.PFPolicyFile)
	if err != nil {
		return invalid, err
	}
	o.PolicySHA256 = digest(policy)
	if o.PolicySHA256 != cc.PolicySHA256 {
		return invalid, errors.New("controller policy digest differs")
	}
	baseline, err := protectedRead(wc.BaselinePath)
	if err != nil {
		return invalid, err
	}
	o.BaselineSHA256 = digest(baseline)
	o.Boot, err = worker.ObserveGUIBaseline(ctx, wc.BaselinePath, wc.JobUID)
	if err != nil {
		return invalid, err
	}
	o.BaselineValid = true
	if err = hostguard.RootConfig(cc.ProfilesFile); err != nil {
		return invalid, err
	}
	registry, err := profiles.Load(cc.ProfilesFile)
	if err != nil {
		return invalid, err
	}
	for _, p := range registry.List() {
		raw, err := json.Marshal(p)
		if err != nil {
			return invalid, err
		}
		o.Profiles[p.ID] = digest(raw)
	}
	var hostAddresses []netip.Addr
	o.InterfacesSHA256, hostAddresses, err = controller.InterfaceSnapshot()
	if err != nil {
		return invalid, err
	}
	if err = observePF(ctx, c, hostAddresses, &o); err != nil {
		return invalid, err
	}
	coexistence, err := ObserveCoexistence(ctx, c)
	if err != nil {
		return invalid, err
	}
	o.Coexistence = &coexistence
	interfacesAfter, err := controller.InterfaceDigest()
	if err != nil {
		return invalid, err
	}
	if interfacesAfter != o.InterfacesSHA256 {
		return invalid, errors.New("interfaces changed during PF observation")
	}
	o.MemoryPressure, err = memoryPressure()
	if err != nil {
		return invalid, err
	}
	o.AccountedBytes, err = accountBytes(ctx, []string{"/Library/macserve/var", account.HomeDir})
	if err != nil {
		return invalid, err
	}
	if err = ctx.Err(); err != nil {
		return invalid, err
	}
	// Protected records cannot be silently replaced between their digest and use.
	for p, old := range map[string][]byte{c.PFPolicyFile: policy, wc.BaselinePath: baseline} {
		b, err := protectedRead(p)
		if err != nil || !bytes.Equal(b, old) {
			return invalid, fmt.Errorf("approval input changed: %s", p)
		}
	}
	return o, ctx.Err()
}

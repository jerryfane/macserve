package qualification

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/jerryfane/macserve/internal/controller"
	"github.com/jerryfane/macserve/internal/maintenance"
)

func policyConfig(raw []byte, hash string) ([]byte, error) {
	var fields map[string]json.RawMessage
	if e := decode(raw, &fields); e != nil {
		return nil, e
	}
	if fields["policy_sha256"] == nil {
		return nil, errors.New("missing controller policy_sha256")
	}
	value, e := json.Marshal(hash)
	if e != nil {
		return nil, e
	}
	fields["policy_sha256"] = value
	return encode(fields)
}

// StagePolicy stages explicitly reviewed bytes; it neither validates PF syntax
// by invoking privileged tools nor loads/enables PF. Existing live-inspection
// gates still reject a missing, stale or unsupported effective policy.
func StagePolicy(file string) (string, error) {
	if e := rootOnly(); e != nil {
		return "", e
	}
	raw, e := protectedRead(file)
	if e != nil {
		return "", e
	}
	if len(raw) == 0 || len(raw) > 1<<20 {
		return "", errors.New("reviewed PF policy must be 1 byte..1 MiB")
	}
	mc, e := maintenance.LoadConfig(maintenancePath)
	if e != nil {
		return "", e
	}
	const controllerPath = "/Library/macserve/config/controller.json"
	const policyPath = "/Library/macserve/config/pf-anchor.conf"
	if mc.ControllerConfig != controllerPath || mc.PFPolicyFile != policyPath {
		return "", errors.New("unsupported policy staging topology")
	}
	oldConfig, e := protectedRead(controllerPath)
	if e != nil {
		return "", e
	}
	cc, e := controller.LoadConfig(controllerPath)
	if e != nil {
		return "", e
	}
	oldPolicy, e := protectedRead(policyPath)
	if e != nil {
		return "", e
	}
	if digest(oldPolicy) != cc.PolicySHA256 {
		return "", errors.New("existing policy/config digest mismatch; no implicit recovery")
	}
	hash := digest(raw)
	if hash == cc.PolicySHA256 {
		return "", errors.New("reviewed policy is unchanged")
	}
	updated, e := policyConfig(oldConfig, hash)
	if e != nil {
		return "", e
	}
	const parent = "/Library/macserve/var/qualification"
	if e = protectedDirectory(filepath.Dir(parent)); e != nil {
		return "", e
	}
	if e = os.Mkdir(parent, 0755); e != nil && !os.IsExist(e) {
		return "", e
	}
	unlock, e := sessionLock(parent)
	if e != nil {
		return "", e
	}
	defer unlock()
	id, e := randomID()
	if e != nil {
		return "", e
	}
	archive := filepath.Join(parent, "policy-"+id)
	if e = os.Mkdir(archive, 0700); e != nil {
		return "", e
	}
	for name, b := range map[string][]byte{"previous-controller.json": oldConfig, "previous-pf.conf": oldPolicy, "reviewed-pf.conf": raw, "staged-controller.json": updated} {
		if e = saveNew(filepath.Join(archive, name), b, 0600); e != nil {
			return "", e
		}
	}
	// Parsing staged bytes through the production loader catches any malformed
	// controller document before replacing either installed input.
	if _, e = controller.LoadConfig(filepath.Join(archive, "staged-controller.json")); e != nil {
		return "", e
	}
	current, e := protectedRead(controllerPath)
	if e != nil || digest(current) != digest(oldConfig) {
		return "", errors.New("controller configuration changed during policy staging")
	}
	current, e = protectedRead(policyPath)
	if e != nil || digest(current) != digest(oldPolicy) {
		return "", errors.New("PF policy changed during policy staging")
	}
	if e = replaceMode(policyPath, raw, 0644); e != nil {
		return "", e
	}
	if e = replaceMode(controllerPath, updated, 0644); e != nil {
		return "", e
	}
	return hash, nil
}

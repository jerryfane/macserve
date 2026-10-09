package qualification

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/jerryfane/macserve/internal/maintenance"
	"github.com/jerryfane/macserve/internal/pfctl"
)

const firewallPolicyFile = "firewall-policy.conf"
const firewallStepFile = "firewall-step.json"

type firewallStepRecord struct {
	Evidence maintenance.CoexistenceEvidence `json:"evidence"`
	Stdout   string                          `json:"stdout,omitempty"`
	Stderr   string                          `json:"stderr,omitempty"`
	Error    string                          `json:"error,omitempty"`
}

func loadFirewallPolicy(ctx context.Context, dir string, config maintenance.Config, jobUID uint32, policySHA string) (maintenance.CoexistenceEvidence, []byte, error) {
	var empty maintenance.CoexistenceEvidence
	policy, err := protectedRead(config.PFPolicyFile)
	if err != nil {
		return empty, nil, err
	}
	if digest(policy) != policySHA {
		return empty, nil, errors.New("reviewed policy differs from controller pin")
	}
	if err := saveNew(filepath.Join(dir, firewallPolicyFile), policy, 0600); err != nil {
		return empty, nil, err
	}
	client, err := pfctl.New(config.PFAnchor)
	if err != nil {
		return empty, nil, err
	}
	observe := func(ctx context.Context) (maintenance.CoexistenceState, error) {
		return maintenance.ObserveCoexistence(ctx, config)
	}
	load := func(ctx context.Context, file string) (pfctl.Output, error) {
		return client.Load(ctx, file, pfctl.LoadOptions{
			JobUID:                      jobUID,
			CoexistingAnchors:           config.CoexistingAnchors,
			ToleratedTranslationAnchors: config.ToleratedTranslationAnchors,
		})
	}
	return runFirewallStep(ctx, dir, config.PFAnchor, policySHA, observe, load)
}

// Persist the complete before-state before invoking the sole scoped mutation.
// After-state is attempted even when the load fails. No rollback can touch peers.
func runFirewallStep(ctx context.Context, dir, anchor, policySHA string, observe func(context.Context) (maintenance.CoexistenceState, error), load func(context.Context, string) (pfctl.Output, error)) (maintenance.CoexistenceEvidence, []byte, error) {
	record := firewallStepRecord{Evidence: maintenance.CoexistenceEvidence{OwnedAnchor: anchor, PolicySHA256: policySHA}}
	before, err := observe(ctx)
	record.Evidence.Before = before
	if err != nil {
		return record.Evidence, nil, err
	}
	if err := maintenance.SameCoexistence(before, before); err != nil {
		return record.Evidence, nil, err
	}
	if err := saveJSON(filepath.Join(dir, "firewall-before.json"), before, 0600); err != nil {
		return record.Evidence, nil, err
	}
	out, loadErr := load(ctx, filepath.Join(dir, firewallPolicyFile))
	record.Stdout, record.Stderr = out.Stdout, out.Stderr
	after, afterErr := observe(ctx)
	record.Evidence.AfterFirewall = after
	var compareErr error
	if afterErr == nil {
		compareErr = maintenance.SameCoexistence(before, after)
	}
	saveErr := saveJSON(filepath.Join(dir, "firewall-after.json"), after, 0600)
	err = errors.Join(loadErr, afterErr, compareErr, saveErr)
	if err != nil {
		record.Error = err.Error()
	}
	raw, encodeErr := encode(record)
	if encodeErr != nil {
		return record.Evidence, nil, errors.Join(err, encodeErr)
	}
	if saveErr := saveNew(filepath.Join(dir, firewallStepFile), raw, 0600); saveErr != nil {
		return record.Evidence, nil, errors.Join(err, saveErr)
	}
	if err != nil {
		return record.Evidence, raw, fmt.Errorf("owned firewall step refused; evidence retained and no rollback attempted: %w", err)
	}
	return record.Evidence, raw, nil
}

func loadFirewallStep(dir string, c Challenge) (maintenance.CoexistenceEvidence, error) {
	var record firewallStepRecord
	raw, err := protectedRead(filepath.Join(dir, firewallStepFile))
	if err != nil {
		return record.Evidence, err
	}
	if digest(raw) != c.FirewallStepSHA256 {
		return record.Evidence, errors.New("firewall step digest mismatch")
	}
	if err := decode(raw, &record); err != nil {
		return record.Evidence, err
	}
	e := record.Evidence
	if record.Error != "" || e.OwnedAnchor != c.Observation.PFAnchor || e.PolicySHA256 != c.Observation.PolicySHA256 || e.Before.RecordedAt.Before(c.Created) || e.AfterFirewall.RecordedAt.After(c.Expires) || !e.AfterQualification.RecordedAt.IsZero() {
		return e, errors.New("firewall step does not belong to this sitting")
	}
	if err := maintenance.SameCoexistence(e.Before, e.AfterFirewall); err != nil {
		return e, err
	}
	policy, err := protectedRead(filepath.Join(dir, firewallPolicyFile))
	if err != nil {
		return e, err
	}
	if digest(policy) != e.PolicySHA256 {
		return e, errors.New("preserved firewall policy digest mismatch")
	}
	for name, state := range map[string]maintenance.CoexistenceState{"firewall-before.json": e.Before, "firewall-after.json": e.AfterFirewall} {
		actual, err := protectedRead(filepath.Join(dir, name))
		if err != nil {
			return e, err
		}
		expected, err := encode(state)
		if err != nil {
			return e, err
		}
		if digest(actual) != digest(expected) {
			return e, errors.New("preserved firewall measurement mismatch")
		}
	}
	return e, nil
}

// Finalization copies the preserved firewall measurements and supplies a fresh
// post-qualification measurement. It never rewrites the firewall-step artifact.
func finalizeCoexistence(step maintenance.CoexistenceEvidence, current maintenance.Observation) (maintenance.CoexistenceEvidence, error) {
	if current.Coexistence == nil {
		return step, errors.New("missing current coexistence measurement")
	}
	step.AfterQualification = *current.Coexistence
	if err := maintenance.ValidateCoexistenceEvidence(step, *current.Coexistence, current.PFAnchor, current.PolicySHA256); err != nil {
		return step, err
	}
	return step, nil
}

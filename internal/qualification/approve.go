package qualification

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"time"

	"github.com/jerryfane/macserve/internal/maintenance"
)

func verifyArtifacts(dir string, v Candidate) error {
	if len(v.Artifacts) < 5 || len(v.Artifacts) > 256 {
		return errors.New("invalid artifact manifest")
	}
	for name, want := range v.Artifacts {
		if filepath.Base(name) != name || name == "." || len(want) != 64 {
			return errors.New("unsafe artifact reference")
		}
		b, e := protectedRead(filepath.Join(dir, name))
		if e != nil {
			return e
		}
		if digest(b) != want {
			return fmt.Errorf("artifact digest mismatch: %s", name)
		}
	}
	for _, name := range categories {
		cat, ok := v.Categories[name]
		if !ok || cat.Probe.Category != name || len(cat.Evidence) == 0 {
			return errors.New("missing category or artifact reference")
		}
		framing := map[string]string{}
		for _, p := range cat.Evidence {
			if v.Artifacts[p] == "" || framing[p] != "" {
				return errors.New("category references missing or duplicate artifact")
			}
			framing[p] = v.Artifacts[p]
		}
		b, _ := encode(framing)
		if cat.Probe.ArtifactSHA256 != digest(b) || v.Artifacts["category-"+name+".json"] != digest(b) {
			return errors.New("category artifact digest mismatch")
		}
	}
	if len(v.Categories) != len(categories) {
		return errors.New("unknown evidence category")
	}
	return nil
}
func readyAutomatic(v Candidate) error {
	for _, name := range []string{"unix_socket_boundary", "owner_unaffected", "owner_home_denial"} {
		if v.Categories[name].Status != "pass" {
			return fmt.Errorf("%s failed or incomplete; collect a fresh sitting", name)
		}
	}
	if v.Categories["tool_profiles"].Status == "fail" {
		return errors.New("tool inspection failed")
	}
	return nil
}
func compatibleSitting(a, b Challenge) bool {
	return a.EnvironmentSHA256 == b.EnvironmentSHA256 && a.Observation.JobUID == b.Observation.JobUID && maps.Equal(a.Observation.Profiles, b.Observation.Profiles) && slices.Equal(a.TCP, b.TCP) && slices.Equal(a.UDP, b.UDP) && slices.Equal(a.Allow, b.Allow)
}

// rebootTransition machine-checks the reboot category against the immediate
// predecessor sitting. It passes when the predecessor was collected on a
// different boot (both the kern.boottime digest and kern.bootsessionuuid
// changed; a clock step alone cannot pass), or when the predecessor itself
// passed reboot under the same compatible deployment. Owner requalification
// predecessors (the activation anchor's session) may be older than seven days.
func rebootTransition(c Challenge) (bool, string, error) {
	if c.Previous == "" {
		return false, "no predecessor sitting: reboot needs a collected sitting from an earlier boot", nil
	}
	previous, b, e := loadCollected(c.Previous)
	if e != nil {
		return false, "", e
	}
	if digest(b) != c.PreviousSHA256 {
		return false, "", errors.New("previous sitting changed after challenge creation")
	}
	if e = verifyArtifacts(c.Previous, previous); e != nil {
		return false, "", e
	}
	if e = readyAutomatic(previous); e != nil {
		return false, "", e
	}
	raw, e := protectedRead(filepath.Join(c.Previous, "challenge.json"))
	if e != nil {
		return false, "", e
	}
	var prior Challenge
	if e = decode(raw, &prior); e != nil {
		return false, "", e
	}
	if prior.Schema != schema || previous.ChallengeSHA256 != digest(raw) || !compatibleSitting(c, prior) || !sameObservation(prior.Observation, previous.Observation) || previous.Collected.After(c.Created) || (!c.Requalify && c.Created.Sub(previous.Collected) > 7*24*time.Hour) {
		return false, "", errors.New("previous sitting deployment/time/observation mismatch")
	}
	if prior.Observation.Boot != c.Observation.Boot && prior.BootSession != c.BootSession && prior.BootSession != "" && c.BootSession != "" {
		return true, "machine-observed boot transition: predecessor " + filepath.Base(c.Previous) + " collected on boot session " + prior.BootSession + ", this sitting on " + c.BootSession, nil
	}
	if prior.Observation.Boot == c.Observation.Boot && prior.BootSession == c.BootSession && previous.Categories["reboot"].Status == "pass" {
		return true, "same boot as predecessor " + filepath.Base(c.Previous) + ", which observed a boot transition under the same deployment", nil
	}
	return false, "no machine-observed boot transition from the predecessor sitting", nil
}

// Approve is the owner's password sitting (4-approve-and-start). It commits
// the qualification and writes the activation anchor. No administrator verb
// reaches it.
func Approve(ctx context.Context, dir string) error {
	return approve(ctx, dir, false)
}

// Reapprove is the agent-reachable requalification commit. It requires a
// requalify sitting chained to the anchored session, every live binding equal
// to the anchor, all categories machine-passed on this boot, and no earlier
// approval on this boot (so no job can have run in the job domains since
// boot). It never writes the anchor.
func Reapprove(ctx context.Context, dir string) error {
	return approve(ctx, dir, true)
}

func approve(ctx context.Context, dir string, requalify bool) error {
	if e := rootOnly(); e != nil {
		return e
	}
	unlock, e := sessionLock(dir)
	if e != nil {
		return e
	}
	defer unlock()
	c, raw, e := loadChallenge(dir)
	if e != nil {
		return e
	}
	v, _, e := loadCollected(dir)
	if e != nil {
		return e
	}
	if v.ChallengeSHA256 != digest(raw) {
		return errors.New("candidate challenge mismatch")
	}
	if e = verifyArtifacts(dir, v); e != nil {
		return e
	}
	if e = readyApproval(v); e != nil {
		return e
	}
	env, e := protectedRead(installedEnvironment)
	if e != nil {
		return e
	}
	if digest(env) != c.EnvironmentSHA256 {
		return errors.New("reviewed deployment environment changed")
	}
	if requalify {
		if e = requalifyAllowed(ctx, c); e != nil {
			return e
		}
	}
	current, e := snapshot(ctx)
	if e != nil {
		return e
	}
	if !sameObservation(v.Observation, current.Observation) || !sameObservation(c.Observation, current.Observation) {
		return errors.New("live observation differs from collected sitting")
	}
	boundaryRaw, e := protectedRead(filepath.Join(dir, "boundary-evidence.json"))
	if e != nil {
		return e
	}
	var boundary maintenance.BoundaryEvidence
	if e = decode(boundaryRaw, &boundary); e != nil {
		return e
	}
	qraw, e := protectedRead(filepath.Join(dir, "qualification.json"))
	if e != nil {
		return e
	}
	var q maintenance.Qualification
	if e = decode(qraw, &q); e != nil {
		return e
	}
	if !q.ApprovedAt.IsZero() {
		return errors.New("candidate already contains approval timestamp")
	}
	// Match inspectable candidate summaries to the preserved per-category manifest.
	if len(boundary.Probes) != len(categories) {
		return errors.New("boundary category mismatch")
	}
	for _, p := range boundary.Probes {
		cat, ok := v.Categories[p.Category]
		if !ok || cat.Probe != p {
			return errors.New("boundary summary differs from candidate")
		}
	}
	if q.BoundaryEvidenceSHA256 != digest(boundaryRaw) {
		return errors.New("boundary digest mismatch")
	}
	beforeRaw, e := protectedRead(filepath.Join(dir, "before.json"))
	if e != nil {
		return e
	}
	var before Snapshot
	if e = decode(beforeRaw, &before); e != nil {
		return e
	}
	collected, e := coexistenceWindow(before.Observation, v.Observation)
	if e != nil {
		return e
	}
	if _, e = coexistenceWindow(v.Observation, current.Observation); e != nil {
		return e
	}
	coexistence, e := coexistenceWindow(before.Observation, current.Observation)
	if e != nil {
		return e
	}
	expected, e := encode(collected)
	if e != nil {
		return e
	}
	for _, recorded := range []*maintenance.CoexistenceEvidence{v.Coexistence, boundary.Coexistence} {
		actual, err := encode(recorded)
		if err != nil || digest(actual) != digest(expected) {
			return errors.New("collected coexistence evidence differs from preserved before/after observations")
		}
	}
	// Preserve candidate/predecessor bytes. Approval binds the fresh after state.
	boundary.Coexistence = &coexistence
	boundary.RecordedAt = coexistence.After.RecordedAt
	boundaryRaw, e = encode(boundary)
	if e != nil {
		return e
	}
	q.BoundaryEvidenceSHA256 = digest(boundaryRaw)
	q.ApprovedAt = time.Now().UTC()
	current.Observation.BoundaryEvidenceSHA256 = digest(boundaryRaw)
	if e = fresh(c, q.ApprovedAt); e != nil {
		return e
	}
	if _, e = maintenance.Evaluate(q.ApprovedAt, q, boundary, current.Observation); e != nil {
		return e
	}
	config, e := maintenance.LoadConfig(maintenancePath)
	if e != nil {
		return e
	}
	if config.BoundaryEvidenceFile != "/Library/macserve/config/boundary-evidence.json" || config.QualificationFile != "/Library/macserve/config/qualification.json" {
		return errors.New("unsupported approval destinations")
	}
	var anchor ActivationAnchor
	if !requalify {
		if anchor, e = newAnchor(dir, c, v, q.ApprovedAt); e != nil {
			return e
		}
	}
	if e = saveJSON(filepath.Join(dir, "approval-intent.json"), struct {
		Qualification maintenance.Qualification `json:"qualification"`
		Snapshot      Snapshot                  `json:"snapshot"`
		Requalify     bool                      `json:"requalify"`
	}{q, current, requalify}, 0600); e != nil {
		return fmt.Errorf("approval already attempted or intent could not be preserved: %w", e)
	}
	if e = saveNew(filepath.Join(dir, "approved-boundary-evidence.json"), boundaryRaw, 0600); e != nil {
		return e
	}
	// Write evidence first, then the matching qualification commit. A crash or
	// error between writes leaves any old approval mismatched and failclosed.
	if e = replace(config.BoundaryEvidenceFile, boundaryRaw); e != nil {
		return e
	}
	if e = replaceJSON(config.QualificationFile, q); e != nil {
		return e
	}
	notice := "No health refresh, service activation, pause clearing, PF or owner changes performed."
	if !requalify {
		if e = replaceJSON(anchorPath, anchor); e != nil {
			return e
		}
		notice += " Activation anchor written: agent requalification may re-commit only this exact configuration."
	}
	return saveJSON(filepath.Join(dir, "approval.json"), struct {
		Approved      time.Time                 `json:"approved_at"`
		Qualification maintenance.Qualification `json:"qualification"`
		Requalify     bool                      `json:"requalify"`
		Notice        string                    `json:"notice"`
	}{q.ApprovedAt, q, requalify, notice}, 0600)
}

func readyApproval(v Candidate) error {
	for _, name := range categories {
		want := "pass"
		if name == "network_reachability" {
			want = networkStatus
		}
		if v.Categories[name].Status != want {
			return fmt.Errorf("approval blocked: %s is %s (%s)", name, v.Categories[name].Status, v.Categories[name].Reason)
		}
	}
	return nil
}

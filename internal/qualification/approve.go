package qualification

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
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
	for _, name := range []string{"tcp_denial", "udp_denial", "approved_allow", "unix_socket_boundary", "owner_unaffected", "owner_home_denial"} {
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
	return a.EnvironmentSHA256 == b.EnvironmentSHA256 && a.Observation.JobUID == b.Observation.JobUID && a.Observation.PFAnchor == b.Observation.PFAnchor && a.Observation.PolicySHA256 == b.Observation.PolicySHA256 && a.Observation.RootRulesSHA256 == b.Observation.RootRulesSHA256 && a.Observation.AnchorRulesSHA256 == b.Observation.AnchorRulesSHA256 && a.Observation.InterfacesSHA256 == b.Observation.InterfacesSHA256 && maps.Equal(a.Observation.Profiles, b.Observation.Profiles) && slices.Equal(a.TCP, b.TCP) && slices.Equal(a.UDP, b.UDP) && slices.Equal(a.Allow, b.Allow) && a.OwnerCanary == b.OwnerCanary && slices.Equal(a.PrivatePaths, b.PrivatePaths)
}

// Lifecycle evidence cannot be supplied by an arbitrary old artifact alone. A
// protected predecessor chain proves fresh full probes on each side. Reboot may
// be followed by a same-boot switch sitting; every sitting still re-probes all
// automatic categories and binds the current GUI baseline.
func lifecycle(dir string, current Challenge, category string) error {
	next := current
	seen := map[string]bool{dir: true}
	for range 8 {
		if next.Previous == "" || seen[next.Previous] {
			return errors.New("lifecycle needs distinct protected predecessor sittings")
		}
		seen[next.Previous] = true
		previous, b, e := loadCollected(next.Previous)
		if e != nil {
			return e
		}
		if digest(b) != next.PreviousSHA256 {
			return errors.New("previous sitting changed after challenge creation")
		}
		if e = verifyArtifacts(next.Previous, previous); e != nil {
			return e
		}
		if e = readyAutomatic(previous); e != nil {
			return e
		}
		raw, e := protectedRead(filepath.Join(next.Previous, "challenge.json"))
		if e != nil {
			return e
		}
		var prior Challenge
		if e = decode(raw, &prior); e != nil {
			return e
		}
		if previous.ChallengeSHA256 != digest(raw) || !compatibleSitting(current, prior) || !sameObservation(prior.Observation, previous.Observation) || previous.Collected.After(next.Created) || current.Created.Sub(previous.Collected) > 7*24*time.Hour {
			return errors.New("previous sitting deployment/time/observation mismatch")
		}
		if category == "fast_switch" {
			if prior.Observation.Boot != current.Observation.Boot {
				return errors.New("fast switch requires same-boot fresh pre/post sittings")
			}
			return nil
		}
		if next.Observation.Boot == current.Observation.Boot && prior.Observation.Boot != current.Observation.Boot {
			return nil
		}
		if prior.Observation.Boot != current.Observation.Boot {
			return errors.New("reboot predecessor does not lead to the current boot")
		}
		next = prior
	}
	return errors.New("lifecycle predecessor limit exceeded")
}
func Attest(ctx context.Context, dir, category, artifact, reason string) error {
	if e := rootOnly(); e != nil {
		return e
	}
	if !slices.Contains([]string{"delegated_boundary", "tool_profiles", "fast_switch", "reboot"}, category) {
		return errors.New("only delegated_boundary, tool_profiles, fast_switch and reboot permit manual review")
	}
	if len(strings.TrimSpace(reason)) < 20 || len(reason) > 4096 {
		return errors.New("explicit provenance and review reason required (20..4096 bytes)")
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
	if e = verifyArtifacts(dir, v); e != nil {
		return e
	}
	if v.ChallengeSHA256 != digest(raw) {
		return errors.New("candidate challenge mismatch")
	}
	if e = readyAutomatic(v); e != nil {
		return e
	}
	cat := v.Categories[category]
	if cat.Status != "pending" {
		return errors.New("attestation cannot overwrite failed or completed category")
	}
	if category == "fast_switch" || category == "reboot" {
		if e = lifecycle(dir, c, category); e != nil {
			return e
		}
	}
	current, e := snapshot(ctx)
	if e != nil {
		return e
	}
	if !sameObservation(v.Observation, current.Observation) {
		return errors.New("current observations differ; collect a fresh sitting")
	}
	// Existing artifacts may be owner-owned or root-owned, never job-owned. Root
	// explicitly reviews their contents and provenance; this command does not run
	// supplied commands or infer that an arbitrary file proves a recipe/UI test.
	b, e := readArtifact(artifact, int(c.Environment.OwnerUID))
	if e != nil {
		b, e = readArtifact(artifact, 0)
	}
	if e != nil {
		return e
	}
	if len(b) == 0 {
		return errors.New("empty manual artifact")
	}
	name := "manual-" + category + ".artifact"
	if e = preserve(dir, name, b, v.Artifacts); e != nil {
		return e
	}
	a := Attestation{Schema: 1, ChallengeSHA256: digest(raw), Category: category, Recorded: time.Now().UTC(), ReviewerUID: 0, Reason: reason, Artifact: name, ArtifactSHA256: digest(b), Profiles: maps.Clone(v.Observation.Profiles)}
	ab, _ := encode(a)
	aname := "attestation-" + category + ".json"
	if e = preserve(dir, aname, ab, v.Artifacts); e != nil {
		return e
	}
	cat.Status = "pass"
	cat.Reason = "explicit root approval of owner-reviewed existing artifacts: " + reason
	cat.Evidence = append(cat.Evidence, name, aname)
	cat.Probe.Passed = true
	if cat.Probe.Attempts == 0 {
		cat.Probe.Attempts = 1
	}
	v.Categories[category] = cat
	return writeCandidate(dir, c, v)
}
func Approve(ctx context.Context, dir string) error {
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
	step, e := loadFirewallStep(dir, c)
	if e != nil {
		return e
	}
	v, _, e := loadCollected(dir)
	if e != nil {
		return e
	}
	if v.ChallengeSHA256 != digest(raw) || v.Collected.Before(c.Created) || v.Collected.After(c.Expires) {
		return errors.New("candidate session mismatch")
	}
	if e = verifyArtifacts(dir, v); e != nil {
		return e
	}
	for _, name := range categories {
		if v.Categories[name].Status != "pass" {
			return fmt.Errorf("approval blocked: %s is %s (%s)", name, v.Categories[name].Status, v.Categories[name].Reason)
		}
	}
	env, e := protectedRead("/Library/macserve/config/deploy.env")
	if e != nil {
		return e
	}
	if digest(env) != c.EnvironmentSHA256 {
		return errors.New("reviewed deployment environment changed")
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
	coexistence, e := finalizeCoexistence(step, current.Observation)
	if e != nil {
		return e
	}
	collected, e := finalizeCoexistence(step, v.Observation)
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
			return errors.New("collected coexistence evidence differs from preserved firewall step")
		}
	}
	// Preserve candidate/predecessor bytes. The approved boundary adds the fresh
	// post-qualification measurement and gets its own exact-byte digest.
	boundary.Coexistence = &coexistence
	boundary.RecordedAt = coexistence.AfterQualification.RecordedAt
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
	if e = saveJSON(filepath.Join(dir, "approval-intent.json"), struct {
		Qualification maintenance.Qualification `json:"qualification"`
		Snapshot      Snapshot                  `json:"snapshot"`
	}{q, current}, 0600); e != nil {
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
	return saveJSON(filepath.Join(dir, "approval.json"), struct {
		Approved      time.Time                 `json:"approved_at"`
		Qualification maintenance.Qualification `json:"qualification"`
		Notice        string                    `json:"notice"`
	}{q.ApprovedAt, q, "No health refresh, service activation, pause clearing, PF or owner changes performed."}, 0600)
}

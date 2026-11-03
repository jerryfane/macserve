package qualification

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/jerryfane/macserve/internal/maintenance"
)

// Release carry (boundary-preserving releases): when the administrator proves
// mechanically that a release changes no boundary file, an agent re-measures
// the new binary in a carry sitting (begin --carry, the job probe and tool
// evidence) and commits it here. The commit rebinds only the anchor's
// bin/macserve digest and appends a carry record bound to the proof; the
// owner's session, candidate, parameters and approval time are unchanged, so
// a later reboot's agent requalification still chains to the owner.

const (
	// carryCap and carryWindow bound carries since the owner's approval
	// (owner decision D3): at most five, within fourteen days.
	carryCap    = 5
	carryWindow = 14 * 24 * time.Hour

	carryProofSchema = 1
	carryProofKind   = "release-carry-proof"
	carryEffect      = "QualificationCarried"
	carryProofFile   = "carry-proof.json"
	carryIntentFile  = "carry-intent.json"
	carryFile        = "carry.json"
)

// carryClasses are the BOUNDARY.json classes a carried release may change.
var carryClasses = []string{"C", "G", "T"}

// CarryRelease identifies one side of the proved release delta.
type CarryRelease struct {
	Tag          string `json:"tag"`
	TagObject    string `json:"tag_object"`
	Commit       string `json:"commit"`
	Tree         string `json:"tree"`
	SourceSHA256 string `json:"source_sha256"`
	BinarySHA256 string `json:"binary_sha256"`
}

// CarryChange is one changed path and its class; Old or New is absent for an
// added or removed path. Each is [mode, blob].
type CarryChange struct {
	Path  string   `json:"path"`
	Class string   `json:"class"`
	Old   []string `json:"old,omitempty"`
	New   []string `json:"new,omitempty"`
}

type CarryCI struct {
	Workflow   string `json:"workflow"`
	RunID      int64  `json:"run_id"`
	HeadSHA    string `json:"head_sha"`
	Conclusion string `json:"conclusion"`
}

type CarryProvenance struct {
	RebuiltSHA256           string `json:"rebuilt_sha256"`
	AttestationBundleSHA256 string `json:"attestation_bundle_sha256"`
}

// CarryProof is the administrator's sealed carry-proof.json. The native
// commit checks it binds the anchored and installed binaries and claims only
// carry classes; the path classification itself is the administrator's proof.
type CarryProof struct {
	Schema               int              `json:"schema"`
	Kind                 string           `json:"kind"`
	ReleaseEffect        string           `json:"release_effect"`
	From                 CarryRelease     `json:"from"`
	To                   CarryRelease     `json:"to"`
	BoundaryManifestBlob string           `json:"boundary_manifest_blob"`
	ClassesPresent       []string         `json:"classes_present"`
	Changed              []CarryChange    `json:"changed"`
	CI                   *CarryCI         `json:"ci,omitempty"`
	Provenance           *CarryProvenance `json:"provenance,omitempty"`
}

// CarryRecord is carry.json in the committed carry session.
type CarryRecord struct {
	At                 time.Time   `json:"at"`
	Session            string      `json:"session"`
	Carry              AnchorCarry `json:"carry"`
	CarryIndex         int         `json:"carry_index"`
	CarryCap           int         `json:"carry_cap"`
	AnchorBeforeSHA256 string      `json:"anchor_before_sha256"`
	AnchorAfterSHA256  string      `json:"anchor_after_sha256"`
	ActivationCheck    string      `json:"activation_check"`
}

// carryChanges accepts live bindings equal to the anchor except, at most, the
// installed macserve binary.
func carryChanges(anchored, now map[string]string) error {
	changed := bindingChanges(anchored, now)
	if now[installedHelper] != "" && (len(changed) == 0 || slices.Equal(changed, []string{installedHelper})) {
		return nil
	}
	return fmt.Errorf("configuration changed beyond %s since the owner's approval (%v); release carry refused, the owner must approve again", installedHelper, changed)
}

// carryableConfiguration returns the schema-2 anchor when the live
// configuration differs from it at most in bin/macserve.
func carryableConfiguration() (ActivationAnchor, error) {
	a, _, err := loadAnchorBytes()
	if err != nil {
		return a, err
	}
	if a.Schema != anchorSchema {
		return a, errors.New("activation anchor predates release carry (schema 1); the owner's approve writes a carryable anchor")
	}
	now, err := currentBindings()
	if err != nil {
		return a, err
	}
	return a, carryChanges(a.Bindings, now)
}

// carryAllowed enforces the carry cap: fewer than carryCap carries and less
// than carryWindow since the owner's approval.
func carryAllowed(a ActivationAnchor, now time.Time) error {
	if len(a.Carries) >= carryCap {
		return fmt.Errorf("release carry cap reached (%d carries since the owner's approval); the owner must approve again", carryCap)
	}
	if a.ApprovedAt.IsZero() || now.Before(a.ApprovedAt) || now.Sub(a.ApprovedAt) >= carryWindow {
		return fmt.Errorf("release carry window closed (%s since the owner's approval); the owner must approve again", carryWindow)
	}
	return nil
}

func installedQualification(mc maintenance.Config) (maintenance.Qualification, error) {
	var q maintenance.Qualification
	b, err := protectedRead(mc.QualificationFile)
	if err != nil {
		return q, err
	}
	return q, decode(b, &q)
}

// carryQualificationCurrent requires the kept installed approval to be the
// one for this boot and this GUI baseline.
func carryQualificationCurrent(q maintenance.Qualification, o maintenance.Observation) error {
	if q.ApprovedAt.IsZero() || q.Boot == "" || q.Boot != o.Boot {
		return errors.New("installed qualification is not from this boot; release carry refused (requalify after the reboot first)")
	}
	if q.BaselineSHA256 != o.BaselineSHA256 {
		return errors.New("GUI baseline changed since the installed qualification; release carry refused")
	}
	return nil
}

// loadApprovedChallenge reads the anchored session's challenge and its
// committed candidate, bound to each other.
func loadApprovedChallenge(dir string) (Challenge, Candidate, error) {
	var c Challenge
	v, _, err := loadCollected(dir)
	if err != nil {
		return c, v, err
	}
	raw, err := protectedRead(filepath.Join(dir, "challenge.json"))
	if err != nil {
		return c, v, err
	}
	if err = decode(raw, &c); err != nil {
		return c, v, err
	}
	if v.ChallengeSHA256 != digest(raw) {
		return c, v, errors.New("approved session challenge differs from its candidate")
	}
	return c, v, nil
}

// checkCarryProof binds the proof to the anchored and the installed binary
// and requires it to claim only carry classes.
func checkCarryProof(raw []byte, a ActivationAnchor, live map[string]string) (CarryProof, error) {
	var p CarryProof
	if err := decode(raw, &p); err != nil {
		return p, fmt.Errorf("carry proof: %w", err)
	}
	if p.Schema != carryProofSchema || p.Kind != carryProofKind || p.ReleaseEffect != carryEffect {
		return p, errors.New("carry proof is not a QualificationCarried release-carry proof")
	}
	if p.From.Tag == "" || p.To.Tag == "" || p.From.Tag == p.To.Tag || p.From.Commit == "" || p.To.Commit == "" || p.From.Commit == p.To.Commit || p.BoundaryManifestBlob == "" {
		return p, errors.New("carry proof release identities incomplete")
	}
	if len(p.From.BinarySHA256) != 64 || p.From.BinarySHA256 == p.To.BinarySHA256 {
		return p, errors.New("carry proof binary digests invalid")
	}
	if p.From.BinarySHA256 != a.Bindings[installedHelper] {
		return p, errors.New("carry proof starts from a binary other than the anchored one")
	}
	if p.To.BinarySHA256 != live[installedHelper] {
		return p, errors.New("carry proof names a binary other than the installed one")
	}
	if len(p.Changed) == 0 {
		return p, errors.New("carry proof lists no changed path")
	}
	var classes []string
	paths := map[string]bool{}
	for _, change := range p.Changed {
		if !slices.Contains(carryClasses, change.Class) {
			return p, fmt.Errorf("carry proof changes %s path %s", change.Class, change.Path)
		}
		if change.Path == "" || paths[change.Path] || (change.Old == nil && change.New == nil) {
			return p, errors.New("carry proof change list invalid")
		}
		paths[change.Path] = true
		classes = append(classes, change.Class)
	}
	slices.Sort(classes)
	if !slices.Equal(slices.Compact(classes), p.ClassesPresent) {
		return p, errors.New("carry proof classes_present differs from its changes")
	}
	return p, nil
}

// checkCarryJobProbe requires the carry sitting's launcher-captured job
// report to deny every protected socket, private path and owner home target,
// against the approved session's owner canary.
func checkCarryJobProbe(job Report, c Challenge, hash string, approved Challenge) error {
	if err := checkReport(job, c, hash, "job"); err != nil {
		return err
	}
	if c.OwnerCanary != approved.OwnerCanary {
		return errors.New("carry sitting owner canary differs from the approved session's")
	}
	if ok, _ := rows(job, "unix_socket_boundary", append([]string{c.Socket}, c.PrivatePaths...), 1); !ok {
		return errors.New("carry job probe: unix_socket_boundary not denied on every path")
	}
	if ok, _ := rows(job, "owner_home_denial", homeTargets(c), 1); !ok {
		return errors.New("carry job probe: owner_home_denial not denied on every path")
	}
	dirs := []string{c.Environment.DeveloperDir}
	for _, p := range c.recipes() {
		dirs = append(dirs, p.DeveloperDir)
	}
	slices.Sort(dirs)
	if ok, _ := rows(job, "tool_profiles", slices.Compact(dirs), 1); !ok {
		return errors.New("carry job probe: tool inspection failed")
	}
	return nil
}

// sameToolIdentity compares the Xcode, SDK, OS and runtime identities of two
// runs of one recipe.
func sameToolIdentity(a, b ToolRun) bool {
	x, y := a.Result.Observation, b.Result.Observation
	return x.Xcode == y.Xcode && x.SDKVersion == y.SDKVersion && x.SDKBuild == y.SDKBuild && x.OSVersion == y.OSVersion && x.OSBuild == y.OSBuild && x.RuntimeVersion == y.RuntimeVersion && x.RuntimeBuild == y.RuntimeBuild
}

// checkCarryToolIdentity requires every recipe's carry run to report the
// tool identities of the approved session's run.
func checkCarryToolIdentity(c Challenge, carried, approved ToolEvidence) error {
	for _, p := range c.recipes() {
		i := slices.IndexFunc(carried.Runs, func(r ToolRun) bool { return r.Profile == p.ID })
		j := slices.IndexFunc(approved.Runs, func(r ToolRun) bool { return r.Profile == p.ID })
		if i < 0 || j < 0 {
			return fmt.Errorf("tool evidence for profile %s missing in the carry or approved session", p.ID)
		}
		if !sameToolIdentity(carried.Runs[i], approved.Runs[j]) {
			return fmt.Errorf("profile %s Xcode, SDK or OS identity differs from the approved session", p.ID)
		}
	}
	return nil
}

// approvedToolEvidence returns the tool evidence the approved candidate
// preserved, verified against its artifact digest.
func approvedToolEvidence(dir string, v Candidate) (ToolEvidence, error) {
	var t ToolEvidence
	var names []string
	for name := range v.Artifacts {
		if strings.HasPrefix(name, "collect-") && strings.HasSuffix(name, "-"+toolEvidenceFile) {
			names = append(names, name)
		}
	}
	if len(names) != 1 {
		return t, errors.New("approved session preserved no single tool evidence artifact")
	}
	b, err := protectedRead(filepath.Join(dir, names[0]))
	if err != nil {
		return t, err
	}
	if digest(b) != v.Artifacts[names[0]] {
		return t, errors.New("approved session tool evidence digest mismatch")
	}
	return t, decode(b, &t)
}

// carriedAnchor is a with only the bin/macserve binding rebound and one carry
// appended. It must still be a valid anchor (cap, chain, no replay).
func carriedAnchor(a ActivationAnchor, record AnchorCarry) (ActivationAnchor, error) {
	out := a
	out.Bindings = make(map[string]string, len(a.Bindings))
	for k, v := range a.Bindings {
		out.Bindings[k] = v
	}
	if out.Bindings[installedHelper] != record.FromBinarySHA256 {
		return out, errors.New("carry does not start from the anchored binary")
	}
	out.Bindings[installedHelper] = record.ToBinarySHA256
	out.Carries = append(slices.Clone(a.Carries), record)
	if err := validAnchor(out); err != nil {
		return out, err
	}
	return out, nil
}

// Carry commits a release-carry sitting (qualify carry): the agent-run
// sitting began with --carry, its job probe and tool evidence re-measured the
// installed binary, and the administrator's proof binds the release delta.
// Under the session lock it rechecks the carryable configuration, the cap,
// the parameters, the probe denials, the tool identities and live health with
// the kept approval, then atomically rewrites the anchor with only the
// bin/macserve digest rebound and runs the activation check. It never writes
// qualification.json, boundary-evidence.json, owner.pause or services.
func Carry(ctx context.Context, dir, proofPath string) error {
	if err := rootOnly(); err != nil {
		return err
	}
	unlock, err := sessionLock(dir)
	if err != nil {
		return err
	}
	defer unlock()
	c, raw, err := loadChallenge(dir)
	if err != nil {
		return err
	}
	if !c.Carry {
		return errors.New("qualify carry needs a carry sitting (begin --carry)")
	}
	env, err := protectedRead(installedEnvironment)
	if err != nil {
		return err
	}
	if digest(env) != c.EnvironmentSHA256 {
		return errors.New("reviewed deployment environment changed")
	}
	a, anchorRaw, err := loadAnchorBytes()
	if err != nil {
		return err
	}
	if a.Schema != anchorSchema {
		return errors.New("activation anchor predates release carry (schema 1); the owner's approve writes a carryable anchor")
	}
	live, err := currentBindings()
	if err != nil {
		return err
	}
	if err = carryChanges(a.Bindings, live); err != nil {
		return err
	}
	now := time.Now().UTC()
	if err = carryAllowed(a, now); err != nil {
		return err
	}
	if c.Previous != a.Session {
		return errors.New("carry sitting is not chained to the anchored session")
	}
	if !sameParameters(anchorParameters(c), a.Parameters) {
		return errors.New("challenge parameters differ from the anchored approval")
	}
	approved, approvedCandidate, err := loadApprovedChallenge(a.Session)
	if err != nil {
		return err
	}
	if _, candidateRaw, err := loadCollected(a.Session); err != nil || digest(candidateRaw) != c.PreviousSHA256 || digest(candidateRaw) != a.CandidateSHA256 {
		return errors.Join(err, errors.New("anchored candidate changed since the carry sitting began"))
	}
	proofRaw, err := protectedRead(proofPath)
	if err != nil {
		return err
	}
	proof, err := checkCarryProof(proofRaw, a, live)
	if err != nil {
		return err
	}
	_, _, job, err := loadJobProbe(dir, c, raw)
	if err != nil {
		return err
	}
	if err = checkCarryJobProbe(job, c, digest(raw), approved); err != nil {
		return err
	}
	if len(c.recipes()) > 0 {
		tb, ok, reason := toolEvidencePasses(dir, c, raw)
		if !ok {
			return errors.New("carry tool evidence: " + reason)
		}
		var carried ToolEvidence
		if err = decode(tb, &carried); err != nil {
			return err
		}
		prior, err := approvedToolEvidence(a.Session, approvedCandidate)
		if err != nil {
			return err
		}
		if err = checkCarryToolIdentity(c, carried, prior); err != nil {
			return err
		}
	}
	mc, err := maintenance.LoadConfig(maintenancePath)
	if err != nil {
		return err
	}
	q, err := installedQualification(mc)
	if err != nil {
		return err
	}
	if q.Boot != c.Observation.Boot || q.BaselineSHA256 != c.Observation.BaselineSHA256 {
		return errors.New("installed qualification differs from the carry sitting's boot or baseline")
	}
	if _, err = maintenance.Check(ctx, mc); err != nil {
		return fmt.Errorf("health with the kept approval is not valid: %w", err)
	}
	record := AnchorCarry{At: now, Session: dir, FromBinarySHA256: proof.From.BinarySHA256, ToBinarySHA256: proof.To.BinarySHA256, ProofSHA256: digest(proofRaw)}
	next, err := carriedAnchor(a, record)
	if err != nil {
		return err
	}
	nextRaw, err := encode(next)
	if err != nil {
		return err
	}
	if err = fresh(c, time.Now().UTC()); err != nil {
		return err
	}
	// One commit per sitting: the proof and the intended anchor are preserved
	// before the anchor changes, and a second attempt cannot create them.
	if err = saveNew(filepath.Join(dir, carryProofFile), proofRaw, 0600); err != nil {
		return fmt.Errorf("carry already attempted for this sitting: %w", err)
	}
	if err = saveNew(filepath.Join(dir, carryIntentFile), nextRaw, 0600); err != nil {
		return err
	}
	if err = replace(anchorPath, nextRaw); err != nil {
		return err
	}
	if err = ActivationCheck(ctx); err != nil {
		return fmt.Errorf("activation check after carry: %w", err)
	}
	return saveJSON(filepath.Join(dir, carryFile), CarryRecord{At: time.Now().UTC(), Session: dir, Carry: record, CarryIndex: len(next.Carries), CarryCap: carryCap, AnchorBeforeSHA256: digest(anchorRaw), AnchorAfterSHA256: digest(nextRaw), ActivationCheck: "pass"}, 0600)
}

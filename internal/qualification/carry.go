package qualification

import (
	"context"
	"errors"
	"fmt"
	"os"
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
// carry classes; it is not authenticated on the host. The path
// classification, tree/tarball equality, CI and provenance are the
// administrator's proof, and the administrator independently verifies the
// committed anchor against it.
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

// carryChanges accepts live bindings that differ from the anchor in exactly
// the installed macserve binary. With no binary change there is nothing to
// carry (requalify instead).
func carryChanges(anchored, now map[string]string) error {
	changed := bindingChanges(anchored, now)
	if now[installedHelper] != "" && slices.Equal(changed, []string{installedHelper}) {
		return nil
	}
	if len(changed) == 0 {
		return fmt.Errorf("%s equals the anchored binary: nothing to carry", installedHelper)
	}
	return fmt.Errorf("configuration changed beyond %s since the owner's approval (%v); release carry refused, the owner must approve again", installedHelper, changed)
}

// carryableConfiguration returns the schema-2 anchor, its bytes and the live
// bindings when the live configuration differs from the anchor exactly in
// bin/macserve.
func carryableConfiguration() (ActivationAnchor, []byte, map[string]string, error) {
	a, raw, err := loadAnchorBytes()
	if err != nil {
		return a, nil, nil, err
	}
	if a.Schema != anchorSchema {
		return a, nil, nil, errors.New("activation anchor predates release carry (schema 1); the owner's approve writes a carryable anchor")
	}
	now, err := currentBindings()
	if err != nil {
		return a, nil, nil, err
	}
	return a, raw, now, carryChanges(a.Bindings, now)
}

// installedSelf requires this process to be the installed bin/macserve and
// returns that file's digest.
func installedSelf() (string, error) {
	self, err := os.Executable()
	if err == nil {
		self, err = filepath.EvalSymlinks(self)
	}
	if err != nil || self != installedHelper {
		return "", fmt.Errorf("release carry must run as the installed %s", installedHelper)
	}
	return fileDigest(installedHelper)
}

// carryBinary binds a carry sitting step to its binary: this process is the
// installed bin/macserve and its digest is the one the sitting began with.
func carryBinary(c Challenge) (string, error) {
	self, err := installedSelf()
	if err != nil {
		return "", err
	}
	if len(c.CarryBinarySHA256) != 64 || self != c.CarryBinarySHA256 {
		return "", errors.New("installed macserve differs from the binary this carry sitting began with")
	}
	return self, nil
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
	return ValidateCarryProof(raw, a.Bindings[installedHelper], live[installedHelper])
}

// ValidateCarryProof is every check qualify carry applies to the proof
// itself: the strict decoding, the kind, complete and distinct release
// identities, from binary fromSHA256 (the anchored one) to toSHA256 (the
// installed one), unique changed paths of carry classes only and
// classes_present equal to them. macserve upgrade's pre-check uses it too,
// so a proof it accepts is one qualify carry accepts.
func ValidateCarryProof(raw []byte, fromSHA256, toSHA256 string) (CarryProof, error) {
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
	if fromSHA256 == "" || p.From.BinarySHA256 != fromSHA256 {
		return p, errors.New("carry proof starts from a binary other than the anchored one")
	}
	if toSHA256 == "" || p.To.BinarySHA256 != toSHA256 {
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

// checkCarrySitting requires the carry sitting to chain to the anchored
// session with the anchored parameters: the socket, private paths, endpoints,
// UIDs and profiles its job probe denied are exactly the approved ones.
func checkCarrySitting(c Challenge, a ActivationAnchor) error {
	if !c.Carry {
		return errors.New("qualify carry needs a carry sitting (begin --carry)")
	}
	if c.Previous == "" || c.Previous != a.Session {
		return errors.New("carry sitting is not chained to the anchored session")
	}
	if !sameParameters(anchorParameters(c), a.Parameters) {
		return errors.New("challenge parameters differ from the anchored approval")
	}
	return nil
}

// checkCarryToolEvidence requires the carry sitting's tool evidence to be run
// by the carried binary with the approved session's tool identities.
func checkCarryToolEvidence(c Challenge, carried, approved ToolEvidence, binary string) error {
	if len(binary) != 64 || carried.ExecutableSHA256 != binary {
		return errors.New("carry tool evidence was not run by the carried binary")
	}
	return checkCarryToolIdentity(c, carried, approved)
}

// commitAnchor is the anchor compare-and-swap, run under the global anchor
// lock: the anchor must still be the bytes every carry check was made
// against, else nothing is written. prepare preserves the commit's evidence
// before write replaces the anchor.
func commitAnchor(expected, next []byte, read func() ([]byte, error), prepare func() error, write func([]byte) error) error {
	current, err := read()
	if err != nil {
		return err
	}
	if len(expected) == 0 || digest(current) != digest(expected) {
		return errors.New("activation anchor changed during the carry commit")
	}
	if err = prepare(); err != nil {
		return err
	}
	return write(next)
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
	unlockAnchor, err := anchorLock()
	if err != nil {
		return fmt.Errorf("activation anchor busy: %w", err)
	}
	defer unlockAnchor()
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
	binary, err := carryBinary(c)
	if err != nil {
		return err
	}
	a, anchorRaw, live, err := carryableConfiguration()
	if err != nil {
		return err
	}
	if live[installedHelper] != binary {
		return errors.New("installed macserve changed during the carry commit")
	}
	now := time.Now().UTC()
	if err = carryAllowed(a, now); err != nil {
		return err
	}
	if err = checkCarrySitting(c, a); err != nil {
		return err
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
		if err = checkCarryToolEvidence(c, carried, prior, binary); err != nil {
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
	err = commitAnchor(anchorRaw, nextRaw, func() ([]byte, error) { return protectedRead(anchorPath) }, func() error {
		// One commit per sitting: the proof and the intended anchor are
		// preserved before the anchor changes, and a second attempt cannot
		// create them.
		if err := saveNew(filepath.Join(dir, carryProofFile), proofRaw, 0600); err != nil {
			return fmt.Errorf("carry already attempted for this sitting: %w", err)
		}
		return saveNew(filepath.Join(dir, carryIntentFile), nextRaw, 0600)
	}, func(b []byte) error { return replace(anchorPath, b) })
	if err != nil {
		return err
	}
	if err = ActivationCheck(ctx); err != nil {
		return fmt.Errorf("activation check after carry: %w", err)
	}
	return saveJSON(filepath.Join(dir, carryFile), CarryRecord{At: time.Now().UTC(), Session: dir, Carry: record, CarryIndex: len(next.Carries), CarryCap: carryCap, AnchorBeforeSHA256: digest(anchorRaw), AnchorAfterSHA256: digest(nextRaw), ActivationCheck: "pass"}, 0600)
}

// CarryPreflight is the read-only pre-check macserve upgrade runs as root
// before it replaces bin/macserve, so a carry it starts is one qualify carry
// can commit: the anchor is schema 2 and still equals the live configuration
// (activation check), with the installed binary the anchored one; the carry
// cap and window allow one more; the proof passes ValidateCarryProof from
// that binary to target; and health is valid with the kept approval on this
// boot.
func CarryPreflight(ctx context.Context, proof []byte, target string) error {
	if err := rootOnly(); err != nil {
		return err
	}
	a, err := anchoredConfiguration()
	if err != nil {
		return err
	}
	if a.Schema != anchorSchema {
		return errors.New("activation anchor predates release carry (schema 1); the owner's approve writes a carryable anchor")
	}
	if err := carryAllowed(a, time.Now().UTC()); err != nil {
		return err
	}
	installed, err := fileDigest(installedHelper)
	if err != nil {
		return err
	}
	if installed != a.Bindings[installedHelper] {
		return fmt.Errorf("%s is not the anchored binary", installedHelper)
	}
	if _, err := ValidateCarryProof(proof, installed, target); err != nil {
		return err
	}
	return ActivationCheck(ctx)
}

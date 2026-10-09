package qualification

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jerryfane/macserve/internal/controller"
	"github.com/jerryfane/macserve/internal/deploy"
	"github.com/jerryfane/macserve/internal/maintenance"
	"github.com/jerryfane/macserve/internal/profiles"
)

type BeginOptions struct{ Environment, Session, Allow, UDP, OwnerCanary, PrivatePaths, Previous string }

func Plan(path string) (any, error) {
	e, err := deploy.LoadEnvironment(path)
	if err != nil {
		return nil, err
	}
	targets, err := tcpTargets(e)
	if err != nil {
		return nil, err
	}
	return struct {
		Environment deploy.Environment `json:"environment"`
		TCP         []string           `json:"required_tcp_targets"`
		Categories  []string           `json:"required_categories"`
		Notice      string             `json:"notice"`
	}{e, targets, categories, "Read-only plan. All TCP targets require live owner controls; UDP requires explicit controlled receivers. No services, PF, health or owner state will be changed."}, nil
}
func parseCounters(text string) (map[string]uint64, error) {
	out := map[string]uint64{}
	for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
		f := strings.Fields(line)
		if len(f) != 8 {
			return nil, errors.New("unsupported pfctl -s labels format")
		}
		for _, n := range f[1:] {
			if _, e := strconv.ParseUint(n, 10, 64); e != nil {
				return nil, e
			}
		}
		n, _ := strconv.ParseUint(f[2], 10, 64)
		if ^uint64(0)-out[f[0]] < n {
			return nil, errors.New("PF counter overflow")
		}
		out[f[0]] += n
	}
	for _, label := range []string{"macserve-protected", "macserve-private", "macserve-host", "macserve-default-deny"} {
		if _, ok := out[label]; !ok {
			return nil, fmt.Errorf("missing PF deny label %s", label)
		}
	}
	return out, nil
}
func snapshot(ctx context.Context) (Snapshot, error) {
	s := Snapshot{At: time.Now().UTC()}
	config, e := maintenance.LoadConfig(maintenancePath)
	if e != nil {
		return s, e
	}
	s.Observation, e = maintenance.Inspect(ctx, config)
	if e != nil {
		return s, e
	}
	text, diag, e := command(ctx, "", "/sbin/pfctl", "-a", "org.macserve", "-s", "labels")
	s.PFOutput = text
	s.PFStderr = diag
	if e != nil {
		return s, e
	}
	if !pfDiagnostic(diag) {
		return s, errors.New("unrecognized PF counter diagnostic")
	}
	s.Counters, e = parseCounters(text)
	if e != nil {
		return s, e
	}
	text, diag, e = command(ctx, "", "/sbin/pfctl", "-a", "org.macserve", "-vvsr")
	s.PFRules = text
	s.PFStderr += "\n" + diag
	if e != nil {
		return s, e
	}
	if !pfDiagnostic(diag) {
		return s, errors.New("unrecognized PF rule-counter diagnostic")
	}
	s.ProtocolCounters, e = protocolCounters(text)
	return s, e
}
func sessionLock(dir string) (func(), error) {
	if e := protectedDirectory(dir); e != nil {
		return nil, e
	}
	p := filepath.Join(dir, ".lock")
	if e := os.Mkdir(p, 0700); e != nil {
		return nil, fmt.Errorf("session busy or interrupted: %w", e)
	}
	return func() { _ = os.Remove(p) }, nil
}
func Begin(ctx context.Context, o BeginOptions) error {
	if e := rootOnly(); e != nil {
		return e
	}
	if o.Environment != "/Library/macserve/config/deploy.env" {
		return errors.New("reuse the installed reviewed /Library/macserve/config/deploy.env")
	}
	envRaw, e := protectedRead(o.Environment)
	if e != nil {
		return e
	}
	env, e := deploy.ParseEnvironment(envRaw)
	if e != nil {
		return e
	}
	const parent = "/Library/macserve/var/qualification"
	if filepath.Dir(o.Session) != parent || !cleanPath(o.Session) {
		return errors.New("session must be a new direct child of /Library/macserve/var/qualification")
	}
	if e = protectedDirectory(filepath.Dir(parent)); e != nil {
		return e
	}
	if e = os.Mkdir(parent, 0755); e != nil && !os.IsExist(e) {
		return e
	}
	if e = protectedDirectory(parent); e != nil {
		return e
	}
	allow, e := endpoints(o.Allow)
	if e != nil {
		return fmt.Errorf("allow: %w", e)
	}
	udp, e := endpoints(o.UDP)
	if e != nil {
		return fmt.Errorf("udp-canary: %w", e)
	}
	owner, e := user.LookupId(strconv.Itoa(int(env.OwnerUID)))
	if e != nil {
		return e
	}
	if owner.Username != env.OwnerUser || owner.HomeDir != "/Users/"+env.OwnerUser {
		return errors.New("owner account differs from reviewed identity/home")
	}
	if !cleanPath(o.OwnerCanary) || !strings.HasPrefix(o.OwnerCanary, owner.HomeDir+"/") {
		return errors.New("owner-canary must be an existing regular file inside the approved owner home")
	}
	if _, e = readArtifact(o.OwnerCanary, int(env.OwnerUID)); e != nil {
		return e
	}
	canaryInfo, err := os.Lstat(o.OwnerCanary)
	if err != nil {
		return err
	}
	if canaryInfo.Mode().Perm() != 0644 {
		return errors.New("owner canary must be mode 0644 so denial tests the home boundary, not file-only permissions")
	}
	private := []string{"/Library/macserve/var/controller", "/Library/macserve/var/broker", "/Library/macserve/var/exports", "/Library/macserve/var/controller/secrets"}
	if o.PrivatePaths != "" {
		private = append(private, strings.Split(o.PrivatePaths, ",")...)
	}
	slices.Sort(private)
	private = slices.Compact(private)
	if len(private) > 64 {
		return errors.New("too many private paths")
	}
	for _, p := range private {
		if !cleanPath(p) {
			return errors.New("invalid private path")
		}
		if _, e = os.Lstat(p); e != nil {
			return e
		}
	}
	mc, e := maintenance.LoadConfig(maintenancePath)
	if e != nil {
		return e
	}
	cc, e := controller.LoadConfig(mc.ControllerConfig)
	if e != nil {
		return e
	}
	if e = deploy.CheckProtectedPath(cc.ProfilesFile, false); e != nil {
		return e
	}
	registry, e := profiles.Load(cc.ProfilesFile)
	if e != nil {
		return e
	}
	targets, e := tcpTargets(env)
	if e != nil {
		return e
	}
	id, e := randomID()
	if e != nil {
		return e
	}
	now := time.Now().UTC()
	c := Challenge{Schema: 1, ID: id, Created: now, Expires: now.Add(lifetime), Environment: env, EnvironmentSHA256: digest(envRaw), TCP: targets, Allow: allow, UDP: udp, OwnerCanary: o.OwnerCanary, PrivatePaths: private, Socket: cc.Socket, Profiles: registry.List()}
	if o.Previous != "" {
		previous, b, err := loadCollected(o.Previous)
		if err != nil {
			return err
		}
		if previous.Collected.After(now) || now.Sub(previous.Collected) > 7*24*time.Hour {
			return errors.New("previous sitting must be within seven days")
		}
		c.Previous = o.Previous
		c.PreviousSHA256 = digest(b)
	}
	if e = os.Mkdir(o.Session, 0755); e != nil {
		return e
	}
	s, e := snapshot(ctx)
	if e != nil {
		_ = saveJSON(filepath.Join(o.Session, "begin-refusal.json"), struct {
			Snapshot Snapshot
			Error    string
		}{s, e.Error()}, 0600)
		return e
	}
	c.Observation = s.Observation
	if c.Observation.JobUID != env.JobUID {
		return errors.New("installed environment and observation job UID differ")
	}
	if e = saveJSON(filepath.Join(o.Session, "before.json"), s, 0600); e != nil {
		return e
	}
	return saveJSON(filepath.Join(o.Session, "challenge.json"), c, 0644)
}
func loadCollected(dir string) (Candidate, []byte, error) {
	var c Candidate
	if e := protectedDirectory(dir); e != nil {
		return c, nil, e
	}
	b, e := protectedRead(filepath.Join(dir, "candidate.json"))
	if e != nil {
		return c, nil, e
	}
	if e = decode(b, &c); e != nil {
		return c, nil, e
	}
	if c.Schema != 1 {
		return c, nil, errors.New("unsupported candidate")
	}
	return c, b, nil
}
func checkReport(r Report, c Challenge, hash, role string) error {
	uid := c.Environment.JobUID
	if role == "owner" {
		uid = c.Environment.OwnerUID
	}
	if r.Schema != 1 || r.ChallengeSHA256 != hash || r.Role != role || r.UID != int(uid) || len(r.Groups) == 0 || r.Started.Before(c.Created) || r.Finished.Before(r.Started) || r.Finished.After(c.Expires) || r.Finished.After(time.Now().UTC()) || len(r.Results) > 4096 {
		return errors.New("report identity, challenge or time mismatch")
	}
	if r.Refusal != "" {
		return errors.New("probe identity refused; review preserved report and use the actual GUI account")
	}
	nonces := map[string]bool{}
	for _, row := range r.Results {
		if !slices.Contains([]string{"tcp_denial", "udp_denial", "approved_allow", "unix_socket_boundary", "owner_home_denial", "tool_profiles"}, row.Category) || (role == "owner" && (row.Category == "tool_profiles" || row.Category == "unix_socket_boundary")) || len(row.Detail) > 1<<20 {
			return errors.New("unexpected report category or oversized diagnostic")
		}
		if row.Category == "udp_denial" {
			if len(row.Nonce) != 64 || nonces[row.Nonce] {
				return errors.New("missing or replayed UDP probe nonce")
			}
			nonces[row.Nonce] = true
		}
	}
	return nil
}
func preserve(dir, name string, b []byte, artifacts map[string]string) error {
	if e := saveNew(filepath.Join(dir, name), b, 0600); e != nil {
		return e
	}
	artifacts[name] = digest(b)
	return nil
}
func Collect(ctx context.Context, dir, jobPath, ownerPath, receiptPaths string) error {
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
	var job, owner Report
	jb, e := readArtifact(jobPath, int(c.Environment.JobUID))
	if e != nil {
		return e
	}
	if e = decode(jb, &job); e != nil {
		return e
	}
	ob, e := readArtifact(ownerPath, int(c.Environment.OwnerUID))
	if e != nil {
		return e
	}
	if e = decode(ob, &owner); e != nil {
		return e
	}
	if e = checkReport(job, c, digest(raw), "job"); e != nil {
		return e
	}
	if e = checkReport(owner, c, digest(raw), "owner"); e != nil {
		return e
	}
	beforeBytes, e := protectedRead(filepath.Join(dir, "before.json"))
	if e != nil {
		return e
	}
	var before Snapshot
	if e = decode(beforeBytes, &before); e != nil {
		return e
	}
	after, e := snapshot(ctx)
	if e != nil {
		_ = saveJSON(filepath.Join(dir, "collect-refusal.json"), struct {
			Snapshot Snapshot
			Error    string
		}{after, e.Error()}, 0600)
		return e
	}
	candidate := Candidate{Schema: 1, ChallengeSHA256: digest(raw), Collected: time.Now().UTC(), Observation: after.Observation, Artifacts: map[string]string{"challenge.json": digest(raw), "before.json": digest(beforeBytes)}, Categories: map[string]Category{}}
	if e = preserve(dir, "job-report.json", jb, candidate.Artifacts); e != nil {
		return e
	}
	if e = preserve(dir, "owner-report.json", ob, candidate.Artifacts); e != nil {
		return e
	}
	ab, _ := encode(after)
	if e = preserve(dir, "after.json", ab, candidate.Artifacts); e != nil {
		return e
	}
	var receipts []Receipts
	paths := []string{}
	if receiptPaths != "" {
		paths = strings.Split(receiptPaths, ",")
	}
	if len(paths) > 128 {
		return errors.New("too many receipt files")
	}
	for i, p := range paths {
		b, err := readArtifact(p, int(c.Environment.OwnerUID))
		if err != nil {
			return err
		}
		var r Receipts
		if err = decode(b, &r); err != nil {
			return err
		}
		if r.Schema != 1 || r.ChallengeSHA256 != digest(raw) || r.UID != int(c.Environment.OwnerUID) || r.Started.Before(c.Created) || r.Finished.Before(r.Started) || r.Finished.After(c.Expires) || r.Finished.After(candidate.Collected) || r.Error != "" || !slices.Contains(c.UDP, r.Listen) {
			return errors.New("invalid canary receipt document")
		}
		if err = preserve(dir, fmt.Sprintf("receipts-%03d.json", i), b, candidate.Artifacts); err != nil {
			return err
		}
		receipts = append(receipts, r)
	}
	candidate.Categories = aggregate(c, job, owner, receipts, before, after)
	evidence := make([]string, 0, len(candidate.Artifacts))
	for name := range candidate.Artifacts {
		evidence = append(evidence, name)
	}
	slices.Sort(evidence)
	for name, cat := range candidate.Categories {
		cat.Evidence = slices.Clone(evidence)
		candidate.Categories[name] = cat
	}
	if !sameObservation(c.Observation, before.Observation) || !sameObservation(c.Observation, after.Observation) {
		for name, cat := range candidate.Categories {
			cat.Status = "fail"
			cat.Reason = "maintenance bindings changed during sitting"
			cat.Probe.Passed = false
			candidate.Categories[name] = cat
		}
	}
	return writeCandidate(dir, c, candidate)
}
func rows(r Report, category string, targets []string, attempts int) (bool, int) {
	expected := map[string]bool{}
	for _, t := range targets {
		for n := 1; n <= attempts; n++ {
			expected[t+"\x00"+strconv.Itoa(n)] = false
		}
	}
	count := 0
	valid := true
	for _, v := range r.Results {
		if v.Category != category {
			continue
		}
		key := v.Target + "\x00" + strconv.Itoa(v.Attempt)
		seen, ok := expected[key]
		if !ok || seen || !v.Success {
			valid = false
		}
		expected[key] = true
		count++
	}
	for _, seen := range expected {
		if !seen {
			valid = false
		}
	}
	return valid && len(expected) > 0, count
}
func aggregate(c Challenge, j, o Report, receipts []Receipts, before, after Snapshot) map[string]Category {
	out := map[string]Category{}
	for _, name := range categories {
		out[name] = Category{Status: "pending", Reason: "genuine reviewed evidence required", Evidence: []string{"job-report.json", "owner-report.json", "before.json", "after.json"}, Probe: maintenance.Probe{Category: name}}
	}
	set := func(name string, ok bool, attempts, controls int, reason string) {
		v := out[name]
		v.Status = "fail"
		if ok {
			v.Status = "pass"
		}
		v.Reason = reason
		v.Probe.Passed = ok
		v.Probe.Attempts = attempts
		v.Probe.AuthorizedControlSuccesses = controls
		out[name] = v
	}
	tcpDelta, tcpPFOK := protocolDelta(before, after, "tcp")
	udpDelta, udpPFOK := protocolDelta(before, after, "udp")
	tcp, jc := rows(j, "tcp_denial", c.TCP, 3)
	tcpOwner, oc := rows(o, "tcp_denial", c.TCP, 3)
	set("tcp_denial", tcp && tcpOwner && tcpPFOK && tcpDelta >= int64(jc), jc, oc, "all reviewed address/port sockets x3; timeout denials, live owner controls and labeled TCP PF packet delta required")
	udp, uc := rows(j, "udp_denial", c.UDP, 3)
	udpOwner, uoc := rows(o, "udp_denial", c.UDP, 3)
	receiptOK, jobReceipts := validateReceipts(c, j, o, receipts)
	set("udp_denial", udp && udpOwner && receiptOK && jobReceipts == 0 && udpPFOK && udpDelta >= int64(uc), uc, uoc, "controlled nonce receiver must span both probes, observe every owner nonce and no job nonce; labeled UDP PF delta required")
	for _, name := range []string{"tcp_denial", "udp_denial"} {
		v := out[name]
		v.Probe.PFHitDelta = tcpDelta
		if name == "udp_denial" {
			v.Probe.PFHitDelta = udpDelta
			v.Probe.CanaryReceipts = jobReceipts
		}
		out[name] = v
	}
	allow, ac := rows(j, "approved_allow", c.Allow, 1)
	allowOwner, aoc := rows(o, "approved_allow", c.Allow, 1)
	set("approved_allow", allow && allowOwner, ac, aoc, "explicit allowed endpoints must connect as both actual accounts")
	paths := append([]string{c.Socket}, c.PrivatePaths...)
	unix, xc := rows(j, "unix_socket_boundary", paths, 1)
	set("unix_socket_boundary", unix, xc, 0, "permission denial required; protected ancestor denial does not claim a live worker socket/service was exercised")
	homes := homeTargets(c)
	home, hc := rows(j, "owner_home_denial", homes, 1)
	homeOwner, hoc := rows(o, "owner_home_denial", homes, 1)
	canaryControls, canaryCount := ownerCanaryControls(c, j, o, receipts)
	set("owner_home_denial", home && homeOwner && canaryControls, hc, hoc+canaryCount, "owner reads the exact canary before/after both probes and lists actual home; job must receive permission denial on every path")
	dirs := []string{c.Environment.DeveloperDir}
	for _, p := range c.Profiles {
		dirs = append(dirs, p.DeveloperDir)
	}
	slices.Sort(dirs)
	dirs = slices.Compact(dirs)
	tools, tc := rows(j, "tool_profiles", dirs, 1)
	set("owner_unaffected", tcpOwner && udpOwner && allowOwner && homeOwner && canaryControls, oc+uoc+aoc+hoc+canaryCount, oc+uoc+aoc+hoc+canaryCount, "live owner TCP/UDP/allowed/home controls required; no owner Apple tools or simulator operations")
	set("tool_profiles", tools, tc, 0, "actual job pinned tool inspection; zero profiles makes no recipe/UI success claim")
	if tools && len(c.Profiles) > 0 {
		v := out["tool_profiles"]
		v.Status = "pending"
		v.Reason = "tool pins inspected; owner must review genuine recipe/UI artifacts for EVERY enabled profile"
		v.Probe.Passed = false
		out["tool_profiles"] = v
	}
	return out
}
func validateReceipts(c Challenge, j, o Report, rr []Receipts) (bool, int) {
	valid := true
	jobCount := 0
	seenTargets := map[string]bool{}
	for _, target := range c.UDP {
		var matches []Receipts
		for _, r := range rr {
			if r.Listen == target {
				matches = append(matches, r)
			}
		}
		if len(matches) != 1 {
			valid = false
			continue
		}
		r := matches[0]
		seenTargets[target] = true
		if r.Started.After(j.Started) || r.Started.After(o.Started) || r.Finished.Before(j.Finished) || r.Finished.Before(o.Finished) {
			valid = false
		}
		ownerNonces := map[string]bool{}
		jobNonces := map[string]bool{}
		for _, v := range o.Results {
			if v.Category == "udp_denial" && v.Target == target {
				ownerNonces[v.Nonce] = false
			}
		}
		for _, v := range j.Results {
			if v.Category == "udp_denial" && v.Target == target {
				jobNonces[v.Nonce] = true
			}
		}
		if len(ownerNonces) != 3 || len(jobNonces) != 3 {
			valid = false
		}
		for _, p := range r.Packets {
			if p.At.Before(r.Started) || p.At.After(r.Finished) || p.Packet.Challenge != j.ChallengeSHA256 || p.Packet.Attempt < 1 || p.Packet.Attempt > 3 {
				valid = false
			}
			report := o
			if p.Packet.Role == "job" {
				report = j
			} else if p.Packet.Role != "owner" {
				valid = false
			}
			matched := false
			for _, row := range report.Results {
				if row.Category == "udp_denial" && row.Target == target && row.Attempt == p.Packet.Attempt && row.Nonce == p.Packet.Nonce {
					matched = true
				}
			}
			if !matched {
				valid = false
			}
			if p.Packet.Role == "job" {
				jobCount++
				if !jobNonces[p.Packet.Nonce] {
					valid = false
				}
			} else {
				if seen, ok := ownerNonces[p.Packet.Nonce]; !ok || seen {
					valid = false
				} else {
					ownerNonces[p.Packet.Nonce] = true
				}
			}
		}
		for n, seen := range ownerNonces {
			if len(n) != 64 || !seen || jobNonces[n] {
				valid = false
			}
		}
	}
	return valid && len(seenTargets) == len(c.UDP), jobCount
}
func ownerCanaryControls(c Challenge, j, o Report, receipts []Receipts) (bool, int) {
	if len(c.UDP) == 0 || len(receipts) != len(c.UDP) {
		return false, 0
	}
	seen := map[string]bool{}
	count := 0
	for _, r := range receipts {
		if !slices.Contains(c.UDP, r.Listen) || seen[r.Listen] {
			return false, count
		}
		seen[r.Listen] = true
		before, after := r.OwnerBefore, r.OwnerAfter
		if before.Path != c.OwnerCanary || after.Path != c.OwnerCanary || !before.Readable || !after.Readable || before.At.IsZero() || after.At.IsZero() || before.At.Before(r.Started) || before.At.After(j.Started) || before.At.After(o.Started) || after.At.Before(j.Finished) || after.At.Before(o.Finished) || after.At.After(r.Finished) {
			return false, count
		}
		count += 2
	}
	return true, count
}
func writeCandidate(dir string, c Challenge, v Candidate) error {
	boundary := maintenance.BoundaryEvidence{Schema: 1, RecordedAt: v.Collected, JobUID: c.Environment.JobUID, Boot: v.Observation.Boot}
	for _, name := range categories {
		cat := v.Categories[name]
		framing := map[string]string{}
		for _, p := range cat.Evidence {
			framing[p] = v.Artifacts[p]
		}
		b, e := encode(framing)
		if e != nil {
			return e
		}
		manifest := "category-" + name + ".json"
		if e = replace(filepath.Join(dir, manifest), b); e != nil {
			return e
		}
		v.Artifacts[manifest] = digest(b)
		cat.Probe.ArtifactSHA256 = digest(b)
		cat.Probe.Passed = cat.Status == "pass"
		v.Categories[name] = cat
		boundary.Probes = append(boundary.Probes, cat.Probe)
	}
	b, e := encode(boundary)
	if e != nil {
		return e
	}
	q := qualification(v.Observation)
	q.BoundaryEvidenceSHA256 = digest(b)
	// Candidate qualification intentionally has no approval timestamp.
	qb, e := unapproved(q)
	if e != nil {
		return e
	}
	if e = replace(filepath.Join(dir, "boundary-evidence.json"), b); e != nil {
		return e
	}
	if e = replace(filepath.Join(dir, "qualification.json"), qb); e != nil {
		return e
	}
	return replaceJSON(filepath.Join(dir, "candidate.json"), v)
}
func qualification(o maintenance.Observation) maintenance.Qualification {
	return maintenance.Qualification{Schema: 1, JobUID: o.JobUID, Boot: o.Boot, InterfacesSHA256: o.InterfacesSHA256, PolicySHA256: o.PolicySHA256, RootRulesSHA256: o.RootRulesSHA256, AnchorRulesSHA256: o.AnchorRulesSHA256, BaselineSHA256: o.BaselineSHA256, Profiles: maps.Clone(o.Profiles)}
}
func homeTargets(c Challenge) []string {
	out := []string{c.OwnerCanary, filepath.Dir(c.OwnerCanary), "/Users/" + c.Environment.OwnerUser}
	slices.Sort(out)
	return slices.Compact(out)
}

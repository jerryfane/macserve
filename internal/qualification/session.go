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
	"syscall"
	"time"

	"github.com/jerryfane/macserve/internal/controller"
	"github.com/jerryfane/macserve/internal/deploy"
	"github.com/jerryfane/macserve/internal/hostguard"
	"github.com/jerryfane/macserve/internal/maintenance"
	"github.com/jerryfane/macserve/internal/profiles"
)

type BeginOptions struct {
	Environment, Session, Allow, UDP, OwnerCanary, PrivatePaths, Previous string
}

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
	}{e, targets, categories, "Read-only plan. Network reachability is not enforced in phase 1. No services, PF, health or owner state will be changed."}, nil
}
func snapshot(ctx context.Context) (Snapshot, error) {
	s := Snapshot{At: time.Now().UTC()}
	config, e := maintenance.LoadConfig(maintenancePath)
	if e != nil {
		return s, e
	}
	s.Observation, e = maintenance.Inspect(ctx, config)
	return s, e
}
func sessionLock(dir string) (func(), error) {
	if e := protectedDirectory(dir); e != nil {
		return nil, e
	}
	return lockSessionFile(dir)
}

// Keep the inode after closing: unlinking it would permit two independent locks.
// The kernel releases this lock even when collection exits without cleanup.
func lockSessionFile(dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (func(), error) { _ = f.Close(); return nil, err }
	info, err := f.Stat()
	if err != nil {
		return fail(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return fail(errors.New("unsafe session lock"))
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fail(fmt.Errorf("session busy: %w", err))
	}
	return func() { _ = f.Close() }, nil
}

func collectionAttempt(dir string) (string, error) {
	if _, err := os.Lstat(filepath.Join(dir, "candidate.json")); err == nil {
		return "", errors.New("session already collected; begin a new session")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	id, err := randomID()
	if err != nil {
		return "", err
	}
	return "collect-" + id + "-", nil
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
	unlock, e := sessionLock(parent)
	if e != nil {
		return e
	}
	defer unlock()
	var allow, udp []string
	if o.Allow != "" {
		allow, e = endpoints(o.Allow)
		if e != nil {
			return fmt.Errorf("allow: %w", e)
		}
	}
	if o.UDP != "" {
		udp, e = endpoints(o.UDP)
		if e != nil {
			return fmt.Errorf("udp-canary: %w", e)
		}
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
	if e = hostguard.CheckProtectedPath(cc.ProfilesFile, false); e != nil {
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
	c := Challenge{Schema: 3, ID: id, Created: now, Expires: now.Add(lifetime), Environment: env, EnvironmentSHA256: digest(envRaw), TCP: targets, Allow: allow, UDP: udp, OwnerCanary: o.OwnerCanary, PrivatePaths: private, Socket: cc.Socket, Profiles: registry.List()}
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
	// Peer labels/PIDs and detailed coexistence measurements remain root-private.
	c.Observation.Coexistence = nil
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
	if c.Schema != 3 {
		return c, nil, errors.New("unsupported candidate")
	}
	return c, b, nil
}
func checkReport(r Report, c Challenge, hash, role string) error {
	uid := c.Environment.JobUID
	if role == "owner" {
		uid = c.Environment.OwnerUID
	}
	if r.Schema != 3 || r.ChallengeSHA256 != hash || r.Role != role || r.UID != int(uid) || len(r.Groups) == 0 || r.Started.Before(c.Created) || r.Finished.Before(r.Started) || r.Finished.After(c.Expires) || r.Finished.After(time.Now().UTC()) || len(r.Results) > 4096 {
		return errors.New("report identity, challenge or time mismatch")
	}
	if r.Refusal != "" {
		return errors.New("probe identity refused; review preserved report and use the actual GUI account")
	}
	nonces := map[string]bool{}
	for _, row := range r.Results {
		if !slices.Contains([]string{"network_reachability", "unix_socket_boundary", "owner_home_denial", "tool_profiles"}, row.Category) || (role == "owner" && (row.Category == "tool_profiles" || row.Category == "unix_socket_boundary")) || len(row.Detail) > 1<<20 {
			return errors.New("unexpected report category or oversized diagnostic")
		}
		if row.Nonce != "" {
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
	attempt, e := collectionAttempt(dir)
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
		saveErr := saveJSON(filepath.Join(dir, attempt+"refusal.json"), struct {
			Snapshot Snapshot
			Error    string
		}{after, e.Error()}, 0600)
		return errors.Join(e, saveErr)
	}
	candidate := Candidate{Schema: 3, ChallengeSHA256: digest(raw), Collected: time.Now().UTC(), Observation: after.Observation, Artifacts: map[string]string{"challenge.json": digest(raw), "before.json": digest(beforeBytes)}, Categories: map[string]Category{}}
	receipts, e := collectArtifacts(dir, attempt, c, candidate, jb, ob, after, receiptPaths)
	if e != nil {
		return e
	}
	if e = validateReceiptPackets(job, owner, receipts); e != nil {
		return e
	}
	coexistence, e := coexistenceWindow(before.Observation, after.Observation)
	if e != nil {
		return e
	}
	candidate.Coexistence = &coexistence
	candidate.Categories = aggregate(c, job, owner, receipts)
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
			if name == "network_reachability" {
				continue
			}
			cat.Status = "fail"
			cat.Reason = "maintenance bindings changed during sitting"
			cat.Probe.Status = "failed"
			candidate.Categories[name] = cat
		}
	}
	return writeCandidate(dir, c, candidate)
}

// Snapshot inputs before receipt validation. A failed attempt remains immutable;
// only a later complete attempt's hashes enter the committed candidate.
func collectArtifacts(dir, attempt string, c Challenge, candidate Candidate, job, owner []byte, after Snapshot, receiptPaths string) ([]Receipts, error) {
	if err := preserve(dir, attempt+"job-report.json", job, candidate.Artifacts); err != nil {
		return nil, err
	}
	if err := preserve(dir, attempt+"owner-report.json", owner, candidate.Artifacts); err != nil {
		return nil, err
	}
	ab, err := encode(after)
	if err != nil {
		return nil, err
	}
	if err := preserve(dir, attempt+"after.json", ab, candidate.Artifacts); err != nil {
		return nil, err
	}
	var receipts []Receipts
	var paths []string
	if receiptPaths != "" {
		paths = strings.Split(receiptPaths, ",")
	}
	if len(paths) > 128 {
		return nil, errors.New("too many receipt files")
	}
	for i, p := range paths {
		b, err := readArtifact(p, int(c.Environment.OwnerUID))
		if err != nil {
			return nil, err
		}
		if err = preserve(dir, attempt+fmt.Sprintf("receipts-%03d.json", i), b, candidate.Artifacts); err != nil {
			return nil, err
		}
		var r Receipts
		if err = decode(b, &r); err != nil {
			return nil, err
		}
		if r.Schema != 3 || r.ChallengeSHA256 != candidate.ChallengeSHA256 || r.UID != int(c.Environment.OwnerUID) || r.Started.Before(c.Created) || r.Finished.Before(r.Started) || r.Finished.After(c.Expires) || r.Finished.After(candidate.Collected) || (r.Listen != "" && !slices.Contains(c.UDP, r.Listen)) {
			return nil, errors.New("invalid canary receipt document")
		}
		receipts = append(receipts, r)
	}
	return receipts, nil
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
func aggregate(c Challenge, j, o Report, receipts []Receipts) map[string]Category {
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
		v.Probe.Status = "failed"
		if ok {
			v.Probe.Status = "passed"
		}
		v.Probe.Attempts = attempts
		v.Probe.AuthorizedControlSuccesses = controls
		out[name] = v
	}
	network := out["network_reachability"]
	network.Status = networkStatus
	network.Reason = "Actual TCP connections and UDP nonce echoes are observations only; missing observations and receiver errors do not establish isolation or block approval."
	network.Probe.Status = networkStatus
	for _, row := range j.Results {
		if row.Category == "network_reachability" {
			network.Probe.Attempts++
		}
	}
	for _, row := range o.Results {
		if row.Category == "network_reachability" && row.Success {
			network.Probe.AuthorizedControlSuccesses++
		}
	}
	for _, receipt := range receipts {
		for _, packet := range receipt.Packets {
			if packet.Packet.Role == "job" {
				network.Probe.CanaryReceipts++
			}
		}
	}
	out["network_reachability"] = network
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
	set("owner_unaffected", homeOwner && canaryControls, hoc+canaryCount, hoc+canaryCount, "owner home and before/after canary controls required; network observations are informational; no owner Apple tools or simulator operations")
	set("tool_profiles", tools, tc, 0, "actual job pinned tool inspection; zero profiles makes no recipe/UI success claim")
	if tools && len(c.Profiles) > 0 {
		v := out["tool_profiles"]
		v.Status = "pending"
		v.Reason = "tool pins inspected; owner must review genuine recipe/UI artifacts for EVERY enabled profile"
		v.Probe.Status = "failed"
		out["tool_profiles"] = v
	}
	return out
}
func ownerCanaryControls(c Challenge, j, o Report, receipts []Receipts) (bool, int) {
	if len(receipts) == 0 {
		return false, 0
	}
	count := 0
	for _, r := range receipts {
		if r.Listen != "" {
			continue
		}
		before, after := r.OwnerBefore, r.OwnerAfter
		if before.Path != c.OwnerCanary || after.Path != c.OwnerCanary || !before.Readable || !after.Readable || before.At.IsZero() || after.At.IsZero() || before.At.Before(r.Started) || before.At.After(j.Started) || before.At.After(o.Started) || after.At.Before(j.Finished) || after.At.Before(o.Finished) || after.At.After(r.Finished) {
			continue
		}
		count += 2
	}
	return count >= 2, count
}
func writeCandidate(dir string, c Challenge, v Candidate) error {
	boundary := maintenance.BoundaryEvidence{Schema: 3, RecordedAt: v.Collected, JobUID: c.Environment.JobUID, Boot: v.Observation.Boot, Coexistence: v.Coexistence}
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
		cat.Probe.Status = "failed"
		if cat.Status == "pass" {
			cat.Probe.Status = "passed"
		} else if name == "network_reachability" {
			cat.Probe.Status = networkStatus
		}
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
	return maintenance.Qualification{Schema: 3, JobUID: o.JobUID, Boot: o.Boot, BaselineSHA256: o.BaselineSHA256, Profiles: maps.Clone(o.Profiles)}
}
func homeTargets(c Challenge) []string {
	out := []string{c.OwnerCanary, filepath.Dir(c.OwnerCanary), "/Users/" + c.Environment.OwnerUser}
	slices.Sort(out)
	return slices.Compact(out)
}

func coexistenceWindow(before, after maintenance.Observation) (maintenance.CoexistenceEvidence, error) {
	if before.Coexistence == nil || after.Coexistence == nil {
		return maintenance.CoexistenceEvidence{}, errors.New("missing coexistence observations")
	}
	e := maintenance.CoexistenceEvidence{Before: *before.Coexistence, After: *after.Coexistence}
	return e, maintenance.SameCoexistence(e.Before, e.After)
}

// Missing packets and receiver errors are informational. Present packets must
// still bind to the actual report, challenge and receiver time window.
func validateReceiptPackets(job, owner Report, receipts []Receipts) error {
	for _, receipt := range receipts {
		for _, packet := range receipt.Packets {
			report := owner
			if packet.Packet.Role == "job" {
				report = job
			} else if packet.Packet.Role != "owner" {
				return errors.New("invalid receipt packet role")
			}
			if packet.Packet.Challenge != report.ChallengeSHA256 || packet.At.Before(receipt.Started) || packet.At.After(receipt.Finished) {
				return errors.New("receipt packet challenge or time mismatch")
			}
			matched := false
			for _, row := range report.Results {
				if row.Category == "network_reachability" && row.Target == receipt.Listen && row.Nonce != "" && row.Nonce == packet.Packet.Nonce && row.Attempt == packet.Packet.Attempt {
					matched = true
					break
				}
			}
			if !matched {
				return errors.New("receipt packet does not match preserved probe")
			}
		}
	}
	return nil
}

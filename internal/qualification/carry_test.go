package qualification

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/deploy"
	"github.com/jerryfane/macserve/internal/maintenance"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/worker"
)

var (
	oldBinary = strings.Repeat("a", 64)
	newBinary = strings.Repeat("b", 64)
	nextBin   = strings.Repeat("c", 64)
)

func carryBindings(binary string) map[string]string {
	return map[string]string{
		installedHelper:                                          binary,
		"/Library/macserve/bin/qualify.sh":                       "q1",
		"/Library/macserve/config/deploy.env":                    "e1",
		"/Library/macserve/config/worker.json":                   "w1",
		"/Library/LaunchDaemons/org.macserve.worker.plist":       "p1",
		"/Library/macserve/var/broker/reviewed-persistence.json": "m1",
	}
}

func carryAnchorFixture() ActivationAnchor {
	return ActivationAnchor{Schema: anchorSchema, ApprovedAt: time.Now().UTC().Add(-time.Hour), Session: "/Library/macserve/var/qualification/owner", CandidateSHA256: strings.Repeat("d", 64), Bindings: carryBindings(oldBinary), Parameters: AnchorParameters{JobUID: 502, OwnerUID: 501, ControllerUID: 503, Profiles: map[string]string{"ios": "digest"}, Socket: "/Library/macserve/var/broker/worker.sock"}, Carries: []AnchorCarry{}}
}

func carryRecord(from, to, session string, at time.Time) AnchorCarry {
	return AnchorCarry{At: at, Session: "/Library/macserve/var/qualification/" + session, FromBinarySHA256: from, ToBinarySHA256: to, ProofSHA256: digest([]byte(session))}
}

// Only the bin/macserve digest may differ for a carry; anchoredConfiguration
// (requalify, activation-check) refuses even that.
func TestCarryAnchorAllowsOnlyBinaryDigest(t *testing.T) {
	anchored := carryBindings(oldBinary)
	if err := carryChanges(anchored, carryBindings(oldBinary)); err == nil {
		t.Fatal("unchanged binary carried")
	}
	if err := carryChanges(anchored, carryBindings(newBinary)); err != nil {
		t.Fatalf("binary-only change refused: %v", err)
	}
	if len(bindingChanges(anchored, carryBindings(newBinary))) == 0 {
		t.Fatal("binary change invisible to the exact anchor comparison")
	}
	for name, mutate := range map[string]func(map[string]string){
		"config change":       func(m map[string]string) { m["/Library/macserve/config/deploy.env"] = "e2" },
		"qualify.sh change":   func(m map[string]string) { m["/Library/macserve/bin/qualify.sh"] = "q2" },
		"added bin file":      func(m map[string]string) { m["/Library/macserve/bin/extra"] = "x" },
		"added config file":   func(m map[string]string) { m["/Library/macserve/config/extra.json"] = "x" },
		"removed config file": func(m map[string]string) { delete(m, "/Library/macserve/config/worker.json") },
		"plist change":        func(m map[string]string) { m["/Library/LaunchDaemons/org.macserve.worker.plist"] = "p2" },
		"manifest change":     func(m map[string]string) { m["/Library/macserve/var/broker/reviewed-persistence.json"] = "m2" },
		"binary removed":      func(m map[string]string) { delete(m, installedHelper) },
	} {
		t.Run(name, func(t *testing.T) {
			now := carryBindings(newBinary)
			mutate(now)
			if err := carryChanges(anchored, now); err == nil {
				t.Fatal("non-binary configuration change carried")
			}
		})
	}
}

func TestAnchorSchema2AndSchema1Compatibility(t *testing.T) {
	legacy := carryAnchorFixture()
	legacy.Schema, legacy.Carries = legacyAnchorSchema, nil
	if err := validAnchor(legacy); err != nil {
		t.Fatalf("schema-1 anchor no longer verifies: %v", err)
	}
	// A schema-1 anchor on disk has no carries field; it still decodes.
	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "carries")
	raw, _ = json.Marshal(fields)
	var decoded ActivationAnchor
	if err = decode(raw, &decoded); err != nil || validAnchor(decoded) != nil {
		t.Fatalf("schema-1 anchor bytes refused: %v %v", err, validAnchor(decoded))
	}
	if err := validAnchor(carryAnchorFixture()); err != nil {
		t.Fatalf("approved schema-2 anchor refused: %v", err)
	}
	at := time.Now().UTC().Add(-30 * time.Minute)
	for name, mutate := range map[string]func(*ActivationAnchor){
		"unknown schema":           func(a *ActivationAnchor) { a.Schema = 3 },
		"schema 1 with carries":    func(a *ActivationAnchor) { a.Schema = legacyAnchorSchema },
		"schema 2 without carries": func(a *ActivationAnchor) { a.Carries = nil },
		"binding not last carry": func(a *ActivationAnchor) {
			a.Carries = []AnchorCarry{carryRecord(oldBinary, newBinary, "s1", at)}
		},
		"broken chain": func(a *ActivationAnchor) {
			a.Bindings[installedHelper] = nextBin
			a.Carries = []AnchorCarry{carryRecord(oldBinary, newBinary, "s1", at), carryRecord(oldBinary, nextBin, "s2", at.Add(time.Minute))}
		},
		"replayed proof": func(a *ActivationAnchor) {
			a.Bindings[installedHelper] = nextBin
			second := carryRecord(newBinary, nextBin, "s2", at.Add(time.Minute))
			second.ProofSHA256 = digest([]byte("s1"))
			a.Carries = []AnchorCarry{carryRecord(oldBinary, newBinary, "s1", at), second}
		},
		"replayed session": func(a *ActivationAnchor) {
			a.Bindings[installedHelper] = nextBin
			second := carryRecord(newBinary, nextBin, "s1", at.Add(time.Minute))
			second.ProofSHA256 = digest([]byte("s2"))
			a.Carries = []AnchorCarry{carryRecord(oldBinary, newBinary, "s1", at), second}
		},
		"owner session as carry": func(a *ActivationAnchor) {
			r := carryRecord(oldBinary, newBinary, "s1", at)
			r.Session = a.Session
			a.Bindings[installedHelper] = newBinary
			a.Carries = []AnchorCarry{r}
		},
		"carry before approval": func(a *ActivationAnchor) {
			a.Bindings[installedHelper] = newBinary
			a.Carries = []AnchorCarry{carryRecord(oldBinary, newBinary, "s1", a.ApprovedAt.Add(-time.Minute))}
		},
		"same binary carry": func(a *ActivationAnchor) {
			a.Carries = []AnchorCarry{carryRecord(oldBinary, oldBinary, "s1", at)}
		},
	} {
		t.Run(name, func(t *testing.T) {
			a := carryAnchorFixture()
			mutate(&a)
			if err := validAnchor(a); err == nil {
				t.Fatal("invalid anchor accepted")
			}
		})
	}
}

// The carried anchor differs from the approved one only in the bin/macserve
// binding and one appended carry; the owner's session still anchors a later
// agent requalification, whose exact comparison then passes on the new binary.
func TestCarriedAnchorRebindsOnlyBinaryAndReapprovesAfterCarry(t *testing.T) {
	a := carryAnchorFixture()
	record := carryRecord(oldBinary, newBinary, "s1", time.Now().UTC())
	next, err := carriedAnchor(a, record)
	if err != nil {
		t.Fatal(err)
	}
	if a.Bindings[installedHelper] != oldBinary || len(a.Carries) != 0 {
		t.Fatal("carriedAnchor mutated the input anchor")
	}
	if changed := bindingChanges(a.Bindings, next.Bindings); len(changed) != 1 || changed[0] != installedHelper {
		t.Fatalf("carry rebound %v", changed)
	}
	if next.Schema != a.Schema || next.Session != a.Session || next.CandidateSHA256 != a.CandidateSHA256 || !next.ApprovedAt.Equal(a.ApprovedAt) || !sameParameters(next.Parameters, a.Parameters) || len(next.Carries) != 1 || next.Carries[0] != record {
		t.Fatalf("carry changed more than the binary binding: %+v", next)
	}
	// Requalification compares the live bindings exactly and chains to the
	// owner's session: both hold after the carry.
	if changed := bindingChanges(next.Bindings, carryBindings(newBinary)); len(changed) != 0 || next.Session != a.Session {
		t.Fatalf("requalification after carry refused: %v", changed)
	}
	if _, err := carriedAnchor(next, record); err == nil {
		t.Fatal("replayed carry record accepted")
	}
	replay := carryRecord(newBinary, nextBin, "s2", time.Now().UTC().Add(time.Second))
	replay.ProofSHA256 = record.ProofSHA256
	if _, err := carriedAnchor(next, replay); err == nil {
		t.Fatal("replayed proof accepted on a later carry")
	}
}

func TestCarryCap(t *testing.T) {
	now := time.Now().UTC()
	a := carryAnchorFixture()
	if err := carryAllowed(a, now); err != nil {
		t.Fatalf("first carry refused: %v", err)
	}
	binary := oldBinary
	for i := range carryCap {
		to := strings.Repeat(string(rune('e'+i)), 64)
		next, err := carriedAnchor(a, carryRecord(binary, to, "s"+string(rune('0'+i)), a.ApprovedAt.Add(time.Duration(i+1)*time.Minute)))
		if err != nil {
			t.Fatalf("carry %d: %v", i, err)
		}
		a, binary = next, to
	}
	if err := carryAllowed(a, now); err == nil {
		t.Fatal("carry beyond the cap allowed")
	}
	if _, err := carriedAnchor(a, carryRecord(binary, oldBinary, "s9", now)); err == nil {
		t.Fatal("anchor beyond the cap accepted")
	}
	old := carryAnchorFixture()
	old.ApprovedAt = now.Add(-carryWindow)
	if err := carryAllowed(old, now); err == nil {
		t.Fatal("carry after the window allowed")
	}
	future := carryAnchorFixture()
	future.ApprovedAt = now.Add(time.Hour)
	if err := carryAllowed(future, now); err == nil {
		t.Fatal("carry before the approval allowed")
	}
}

func TestCarryRequiresSameBoot(t *testing.T) {
	q := maintenance.Qualification{Boot: "boot", BaselineSHA256: "baseline", ApprovedAt: time.Now()}
	if err := carryQualificationCurrent(q, maintenance.Observation{Boot: "boot", BaselineSHA256: "baseline"}); err != nil {
		t.Fatal(err)
	}
	for name, o := range map[string]maintenance.Observation{
		"reboot":           {Boot: "other", BaselineSHA256: "baseline"},
		"baseline changed": {Boot: "boot", BaselineSHA256: "other"},
	} {
		t.Run(name, func(t *testing.T) {
			if carryQualificationCurrent(q, o) == nil {
				t.Fatal("stale qualification carried")
			}
		})
	}
	if carryQualificationCurrent(maintenance.Qualification{Boot: "boot", BaselineSHA256: "baseline"}, maintenance.Observation{Boot: "boot", BaselineSHA256: "baseline"}) == nil {
		t.Fatal("unapproved qualification carried")
	}
}

func carryProofFixture() CarryProof {
	return CarryProof{Schema: carryProofSchema, Kind: carryProofKind, ReleaseEffect: carryEffect,
		From:                 CarryRelease{Tag: "v0.1.30", Commit: "c1", Tree: "t1", BinarySHA256: oldBinary},
		To:                   CarryRelease{Tag: "v0.1.31", Commit: "c2", Tree: "t2", BinarySHA256: newBinary},
		BoundaryManifestBlob: "blob", ClassesPresent: []string{"C", "T"},
		Changed: []CarryChange{{Path: "internal/worker/job_observation.go", Class: "C", Old: []string{"100644", "o"}, New: []string{"100644", "n"}}, {Path: "docs/install.md", Class: "T", Old: []string{"100644", "o"}, New: []string{"100644", "n"}}},
		CI:      &CarryCI{Workflow: "CI", RunID: 1, HeadSHA: "c2", Conclusion: "success"}}
}

func TestCarryProofBindsBinariesAndCarryClasses(t *testing.T) {
	a, live := carryAnchorFixture(), carryBindings(newBinary)
	encodeProof := func(p CarryProof) []byte {
		b, err := encode(p)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if _, err := checkCarryProof(encodeProof(carryProofFixture()), a, live); err != nil {
		t.Fatalf("valid proof refused: %v", err)
	}
	for name, mutate := range map[string]func(*CarryProof){
		"required effect":     func(p *CarryProof) { p.ReleaseEffect = "QualificationRequired" },
		"kind":                func(p *CarryProof) { p.Kind = "release-install" },
		"schema":              func(p *CarryProof) { p.Schema = 2 },
		"wrong from binary":   func(p *CarryProof) { p.From.BinarySHA256 = nextBin },
		"wrong to binary":     func(p *CarryProof) { p.To.BinarySHA256 = nextBin },
		"same binary":         func(p *CarryProof) { p.To.BinarySHA256 = oldBinary },
		"same tag":            func(p *CarryProof) { p.To.Tag = p.From.Tag },
		"boundary change":     func(p *CarryProof) { p.Changed[0].Class = "B"; p.ClassesPresent = []string{"B", "T"} },
		"unlisted change":     func(p *CarryProof) { p.Changed[0].Class = ""; p.ClassesPresent = []string{"", "T"} },
		"classes understated": func(p *CarryProof) { p.ClassesPresent = []string{"T"} },
		"no changes":          func(p *CarryProof) { p.Changed = nil; p.ClassesPresent = nil },
		"duplicate path":      func(p *CarryProof) { p.Changed[1].Path = p.Changed[0].Path },
	} {
		t.Run(name, func(t *testing.T) {
			p := carryProofFixture()
			mutate(&p)
			if _, err := checkCarryProof(encodeProof(p), a, live); err == nil {
				t.Fatal("invalid proof accepted")
			}
		})
	}
	t.Run("unknown field", func(t *testing.T) {
		raw := encodeProof(carryProofFixture())
		raw = []byte(strings.Replace(string(raw), "{", `{"force": true,`, 1))
		if _, err := checkCarryProof(raw, a, live); err == nil {
			t.Fatal("proof with unknown field accepted")
		}
	})
	t.Run("proof of an earlier carry", func(t *testing.T) {
		next, err := carriedAnchor(a, carryRecord(oldBinary, newBinary, "s1", time.Now().UTC()))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := checkCarryProof(encodeProof(carryProofFixture()), next, live); err == nil {
			t.Fatal("replayed proof accepted after its carry")
		}
	})
}

func carryChallengeFixture() Challenge {
	now := time.Now().UTC().Add(-time.Minute)
	return Challenge{Schema: schema, ID: strings.Repeat("a", 64), Created: now, Expires: now.Add(lifetime), Environment: deploy.Environment{JobUID: 502, JobGID: 20, OwnerUID: 501, OwnerUser: "owner", DeveloperDir: "/Applications/Xcode.app/Contents/Developer"}, OwnerCanary: "/Users/owner/private/canary", Socket: "/Library/macserve/var/broker/worker.sock", PrivatePaths: []string{"/Library/macserve/var/broker"}, Carry: true}
}

func deniedReport(c Challenge) Report {
	r := Report{Schema: schema, ChallengeSHA256: "h", Role: "job", Mode: jobProbeMode, UID: 502, AuditUID: 502, AuditSession: 100010, Groups: []int{20}, Started: c.Created, Finished: c.Created.Add(time.Second)}
	add := func(category, target string) {
		r.Results = append(r.Results, Result{Category: category, Target: target, Attempt: 1, Success: true})
	}
	for _, p := range append([]string{c.Socket}, c.PrivatePaths...) {
		add("unix_socket_boundary", p)
	}
	for _, p := range homeTargets(c) {
		add("owner_home_denial", p)
	}
	add("tool_profiles", c.Environment.DeveloperDir)
	return r
}

func TestCarryRequiresJobProbeDenials(t *testing.T) {
	c := carryChallengeFixture()
	approved := c
	approved.Carry = false
	if err := checkCarryJobProbe(deniedReport(c), c, "h", approved); err != nil {
		t.Fatalf("denied probe refused: %v", err)
	}
	for name, mutate := range map[string]func(*Report){
		"socket reachable": func(r *Report) { r.Results[0].Success = false },
		"private path readable": func(r *Report) {
			r.Results[1].Success = false
		},
		"owner home readable": func(r *Report) {
			for i := range r.Results {
				if r.Results[i].Category == "owner_home_denial" {
					r.Results[i].Success = false
					return
				}
			}
		},
		"owner home row missing": func(r *Report) {
			for i := range r.Results {
				if r.Results[i].Category == "owner_home_denial" {
					r.Results = append(r.Results[:i], r.Results[i+1:]...)
					return
				}
			}
		},
		"refused probe":        func(r *Report) { r.Refusal = "identity" },
		"other challenge":      func(r *Report) { r.ChallengeSHA256 = "other" },
		"foreground job login": func(r *Report) { r.ConsoleUID = 502 },
	} {
		t.Run(name, func(t *testing.T) {
			r := deniedReport(c)
			mutate(&r)
			if checkCarryJobProbe(r, c, "h", approved) == nil {
				t.Fatal("carry accepted a probe without every denial")
			}
		})
	}
	other := approved
	other.OwnerCanary = "/Users/owner/other/canary"
	if checkCarryJobProbe(deniedReport(c), c, "h", other) == nil {
		t.Fatal("carry accepted a canary other than the approved session's")
	}
}

func TestCarryBinaryBindsTheSitting(t *testing.T) {
	// Tests do not run as /Library/macserve/bin/macserve.
	if _, err := installedSelf(); err == nil {
		t.Fatal("test binary accepted as the installed macserve")
	}
	c := carryChallengeFixture()
	c.CarryBinarySHA256 = newBinary
	if _, err := carryBinary(c); err == nil {
		t.Fatal("carry step accepted from a binary other than the installed one")
	}
}

func TestCarryRequiresToolEvidenceIdentity(t *testing.T) {
	xcode := model.Xcode{Version: "26.0", Build: "17A"}
	c := carryChallengeFixture()
	c.Profiles = []model.Profile{{ID: "ios", Xcode: xcode}}
	run := func(o worker.Observation) ToolRun {
		return ToolRun{Profile: "ios", Result: worker.Result{State: model.Succeeded, Observation: o}}
	}
	base := worker.Observation{Xcode: xcode, SDKVersion: "26.0", SDKBuild: "23A", OSVersion: "26.1", OSBuild: "25B", RuntimeVersion: "26.0", RuntimeBuild: "23A1"}
	approved := ToolEvidence{Runs: []ToolRun{run(base)}}
	if err := checkCarryToolIdentity(c, ToolEvidence{Runs: []ToolRun{run(base)}}, approved); err != nil {
		t.Fatalf("identical tool identity refused: %v", err)
	}
	for name, mutate := range map[string]func(*worker.Observation){
		"xcode build": func(o *worker.Observation) { o.Xcode.Build = "17B" },
		"sdk":         func(o *worker.Observation) { o.SDKBuild = "23B" },
		"os":          func(o *worker.Observation) { o.OSBuild = "25C" },
		"runtime":     func(o *worker.Observation) { o.RuntimeBuild = "23A2" },
	} {
		t.Run(name, func(t *testing.T) {
			o := base
			mutate(&o)
			if checkCarryToolIdentity(c, ToolEvidence{Runs: []ToolRun{run(o)}}, approved) == nil {
				t.Fatal("changed tool identity carried")
			}
		})
	}
	if checkCarryToolIdentity(c, ToolEvidence{}, approved) == nil {
		t.Fatal("missing carry tool run accepted")
	}
}

// Carry sittings never reach collect, approve or reapprove: they decode only
// through loadApprovableChallenge, which refuses Carry.
func TestCarrySessionNotApprovable(t *testing.T) {
	c := carryChallengeFixture()
	raw, err := encode(c)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseChallenge(raw, time.Now().UTC())
	if err != nil || !parsed.Carry {
		t.Fatalf("carry challenge does not round-trip: %+v %v", parsed, err)
	}
	if approvable(parsed) == nil {
		t.Fatal("carry sitting approvable")
	}
	parsed.Carry = false
	if err := approvable(parsed); err != nil {
		t.Fatalf("ordinary sitting refused: %v", err)
	}
	fset := token.NewFileSet()
	calls := map[string]map[string]bool{}
	for _, file := range []string{"approve.go", "session.go", "carry.go"} {
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			seen := map[string]bool{}
			ast.Inspect(fn, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if id, ok := call.Fun.(*ast.Ident); ok {
						seen[id.Name] = true
					}
				}
				if sel, ok := n.(*ast.SelectorExpr); ok {
					seen[sel.Sel.Name] = true
				}
				return true
			})
			calls[fn.Name.Name] = seen
		}
	}
	for _, fn := range []string{"Collect", "approve"} {
		if !calls[fn]["loadApprovableChallenge"] || calls[fn]["loadChallenge"] {
			t.Fatalf("%s does not refuse carry sittings: %v", fn, slices.Sorted(maps.Keys(calls[fn])))
		}
	}
	if !calls["Carry"]["loadChallenge"] || !calls["Carry"]["fresh"] {
		t.Fatal("qualify carry does not load a fresh challenge")
	}
	// begin --carry scans with the strict build rebind, never the explicit
	// full scan, and gates on the carryable anchor, the cap and this boot.
	if reflect.ValueOf(persistenceScan(true)).Pointer() != reflect.ValueOf(maintenance.RebindPersistenceBuild).Pointer() || reflect.ValueOf(persistenceScan(false)).Pointer() != reflect.ValueOf(maintenance.VerifyPersistence).Pointer() || !calls["snapshot"]["persistenceScan"] {
		t.Fatal("carry snapshot does not select the strict build rebind")
	}
	for _, gate := range []string{"carryableConfiguration", "installedSelf", "carryAllowed", "carryQualificationCurrent", "loadApprovedChallenge"} {
		if !calls["Begin"][gate] {
			t.Fatalf("begin --carry skips %s", gate)
		}
	}
	// Tool evidence and the commit run as the binary the sitting began with,
	// and the commit swaps the anchor only if it is unchanged.
	toolrun, err := parser.ParseFile(fset, "toolrun.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range toolrun.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "RunToolEvidence" {
			found := false
			ast.Inspect(fn, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "carryBinary" {
						found = true
					}
				}
				return true
			})
			if !found {
				t.Fatal("carry tool evidence does not bind the carried binary")
			}
		}
	}
	for _, gate := range []string{"carryBinary", "carryableConfiguration", "protectedRead"} {
		if !calls["Carry"][gate] {
			t.Fatalf("qualify carry skips %s", gate)
		}
	}
}

package maintenance

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/pfctl"
)

const coexistenceLaunchOutput = `system/org.example.gateway = {
	active count = 1
	path = /Library/LaunchDaemons/org.example.gateway.plist
	type = LaunchDaemon
	state = running

	program = /usr/bin/true
	arguments = {
		/usr/bin/true
	}
	environment = {
		DESCRIPTION => "pid = 999; state = stopped; }"
	}
	domain = system
	runs = 1
	pid = 123
	last exit code = (never exited)
	resource coalition = {
		ID = 456
		state = active
		pid = 999
		name = org.example.gateway
	}
	properties = keepalive | runatload | inferred program
}
`

type coexistenceReply struct {
	out pfctl.Output
	err error
}

type coexistenceFixture map[string]coexistenceReply

func (f coexistenceFixture) command(ctx context.Context, args ...string) (pfctl.Output, error) {
	if err := ctx.Err(); err != nil {
		return pfctl.Output{}, err
	}
	key := strings.Join(args, " ")
	reply, ok := f[key]
	if !ok {
		return pfctl.Output{}, fmt.Errorf("unexpected coexistence command: %s", key)
	}
	return reply.out, reply.err
}

func coexistenceInputs() (Config, coexistenceFixture) {
	c := Config{
		PFAnchor:           "com.example/owned",
		CoexistingAnchors:  []string{"com.example/gateway", "com.example/empty"},
		CoexistingServices: []string{"org.example.gateway"},
	}
	// No table-content or verbose-rule/counter response exists: observations
	// requiring those changing values fail rather than silently consuming them.
	f := coexistenceFixture{
		"-sr":                                  {out: pfctl.Output{Stdout: "anchor \"com.example/*\" all\n"}},
		"-sn":                                  {out: pfctl.Output{Stdout: "nat-anchor \"com.example/*\" all\n"}},
		"-a com.example/empty -v -s Anchors":   {},
		"-a com.example/empty -sr":             {},
		"-a com.example/empty -sn":             {},
		"-a com.example/gateway -v -s Anchors": {out: pfctl.Output{Stdout: "  com.example/gateway/child\n"}},
		"-a com.example/gateway -sr":           {out: pfctl.Output{Stdout: "pass in on en0 from <clients> to any\n"}},
		"-a com.example/gateway -sn":           {out: pfctl.Output{Stdout: "nat on en0 inet from <clients> to any -> (en0)\n"}},
		"print system/org.example.gateway":     {out: pfctl.Output{Stdout: coexistenceLaunchOutput}},
	}
	return c, f
}

func TestCoexistenceConfigCanonicalization(t *testing.T) {
	c, _ := coexistenceInputs()
	original := c.CoexistingAnchors
	c.CoexistingServices = []string{"org.example.zeta", "org.example.alpha"}
	if err := validateCoexistenceConfig(&c); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.CoexistingAnchors, []string{"com.example/empty", "com.example/gateway"}) {
		t.Fatal("peer set was not canonicalized")
	}
	if !slices.Equal(c.CoexistingServices, []string{"org.example.alpha", "org.example.zeta"}) {
		t.Fatal("service set was not canonicalized")
	}
	if !slices.Equal(original, []string{"com.example/gateway", "com.example/empty"}) {
		t.Fatal("source configuration was mutated")
	}
	c = Config{CoexistingAnchors: []string{}, CoexistingServices: []string{}}
	if err := validateCoexistenceConfig(&c); err != nil || c.CoexistingAnchors != nil || c.CoexistingServices != nil {
		t.Fatalf("empty collections not normalized: %v", err)
	}
	c = Config{PFAnchor: "com.example/owned", CoexistingAnchors: []string{"com.example", "com.example/owned-other"}}
	if err := validateCoexistenceConfig(&c); err != nil {
		t.Fatalf("direct ancestor or disjoint sibling refused: %v", err)
	}
}

func TestCoexistenceConfigRejectsAmbiguousSelectors(t *testing.T) {
	for _, path := range []string{"", "*", "com.example/*", "com.example/owned", "com.example/owned/child", "/com.example/peer", "com.example/../peer", "peer\nother"} {
		t.Run("anchor "+path, func(t *testing.T) {
			c := Config{PFAnchor: "com.example/owned", CoexistingAnchors: []string{path}}
			if err := validateCoexistenceConfig(&c); err == nil {
				t.Fatal("unsafe peer path accepted")
			}
		})
	}
	for _, label := range []string{"", "*", "org.example.*", "system/org.example.peer", "gui/501/org.example.peer", "../peer", "-peer", "org.example:peer", "peer\nstate", "\"peer\"", strings.Repeat("x", 256)} {
		t.Run("service "+label, func(t *testing.T) {
			c := Config{CoexistingServices: []string{label}}
			if err := validateCoexistenceConfig(&c); err == nil {
				t.Fatal("unsafe service selector accepted")
			}
		})
	}
	for _, c := range []Config{
		{CoexistingAnchors: []string{"peer", "peer"}},
		{CoexistingServices: []string{"org.example.peer", "org.example.peer"}},
	} {
		if err := validateCoexistenceConfig(&c); err == nil {
			t.Fatal("duplicate or excessive config list accepted")
		}
	}
	anchors, services := make([]string, 65), make([]string, 65)
	for i := range anchors {
		anchors[i], services[i] = fmt.Sprintf("peer%d", i), fmt.Sprintf("org.example.peer%d", i)
	}
	atLimit := Config{CoexistingAnchors: anchors[:64], CoexistingServices: services[:64]}
	if err := validateCoexistenceConfig(&atLimit); err != nil {
		t.Fatalf("bounded exact lists refused: %v", err)
	}
	for _, c := range []Config{{CoexistingAnchors: anchors}, {CoexistingServices: services}} {
		if err := validateCoexistenceConfig(&c); err == nil {
			t.Fatal("excessive exact list accepted")
		}
	}
}

func TestCoexistenceObservationDetectsRuleAndPIDChanges(t *testing.T) {
	c, fixture := coexistenceInputs()
	before, err := observeCoexistenceWithCommands(context.Background(), c, fixture.command, fixture.command)
	if err != nil {
		t.Fatal(err)
	}
	unchanged, err := observeCoexistenceWithCommands(context.Background(), c, fixture.command, fixture.command)
	if err != nil || SameCoexistence(before, unchanged) != nil {
		t.Fatalf("unchanged direct rules and running PID refused: %v", err)
	}
	changes := map[string]string{
		"-sr":                              "anchor \"com.example/*\" all\nblock all\n",
		"-sn":                              "rdr-anchor \"com.example/*\" all\n",
		"-a com.example/empty -sr":         "block all\n",
		"-a com.example/gateway -sr":       "block in on en0 from <clients> to any\n",
		"-a com.example/gateway -sn":       "nat on en0 inet from <clients> to any -> 192.0.2.1\n",
		"print system/org.example.gateway": strings.Replace(coexistenceLaunchOutput, "\tpid = 123\n", "\tpid = 124\n", 1),
	}
	for command, text := range changes {
		t.Run(command, func(t *testing.T) {
			_, changed := coexistenceInputs()
			changed[command] = coexistenceReply{out: pfctl.Output{Stdout: text}}
			after, err := observeCoexistenceWithCommands(context.Background(), c, changed.command, changed.command)
			if err != nil {
				t.Fatal(err)
			}
			if err := SameCoexistence(before, after); err == nil {
				t.Fatal("changed coexisting rules or restarted service accepted")
			}
		})
	}
}

func TestCoexistenceStockAuxiliaryCallsRemainBound(t *testing.T) {
	c, fixture := coexistenceInputs()
	stock := "scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all\ndummynet-anchor \"com.apple/*\" all\n"
	fixture["-sr"] = coexistenceReply{out: pfctl.Output{Stdout: stock}}
	before, err := observeCoexistenceWithCommands(context.Background(), c, fixture.command, fixture.command)
	if err != nil {
		t.Fatalf("stock auxiliary anchor calls refused: %v", err)
	}
	for _, kind := range []string{"scrub-anchor", "dummynet-anchor"} {
		changed := strings.Replace(stock, kind+" \"com.apple/*\"", kind+" \"com.apple/normalizer\"", 1)
		fixture["-sr"] = coexistenceReply{out: pfctl.Output{Stdout: changed}}
		after, err := observeCoexistenceWithCommands(context.Background(), c, fixture.command, fixture.command)
		if err != nil {
			t.Fatal(err)
		}
		if err := SameCoexistence(before, after); err == nil {
			t.Fatalf("%s change disappeared from direct main evidence", kind)
		}
	}
}

func TestCoexistenceReadsOnlyDirectPeerRules(t *testing.T) {
	c, f := coexistenceInputs()
	c.CoexistingAnchors = []string{"com.example"}
	f["-a com.example -v -s Anchors"] = coexistenceReply{out: pfctl.Output{Stdout: "  com.example/owned\n"}}
	f["-a com.example -sr"] = coexistenceReply{out: pfctl.Output{Stdout: "anchor \"owned\" all\n"}}
	f["-a com.example -sn"] = coexistenceReply{}
	before, err := observeCoexistenceWithCommands(context.Background(), c, f.command, f.command)
	if err != nil {
		t.Fatal(err)
	}
	// Descendants may appear without changing this exact peer's direct rules.
	// Their rule/table contents are intentionally not observation inputs.
	f["-a com.example -v -s Anchors"] = coexistenceReply{out: pfctl.Output{Stdout: "  com.example/owned\n  com.example/other\n"}}
	after, err := observeCoexistenceWithCommands(context.Background(), c, f.command, f.command)
	if err != nil || SameCoexistence(before, after) != nil {
		t.Fatalf("direct ancestor measurement accidentally bound descendants: %v", err)
	}
}

func TestCoexistenceObservationRejectsIncompleteReads(t *testing.T) {
	cases := map[string]func(coexistenceFixture){
		"absent empty peer": func(f coexistenceFixture) {
			f["-a com.example/empty -v -s Anchors"] = coexistenceReply{err: pfctl.ErrAnchorAbsent}
		},
		"absent diagnostic without error": func(f coexistenceFixture) {
			f["-a com.example/empty -v -s Anchors"] = coexistenceReply{out: pfctl.Output{Stderr: "Anchor 'com.example/empty' not found.\n"}}
		},
		"missing peer filter read": func(f coexistenceFixture) { delete(f, "-a com.example/empty -sr") },
		"truncated anchor listing": func(f coexistenceFixture) {
			f["-a com.example/gateway -v -s Anchors"] = coexistenceReply{out: pfctl.Output{Stdout: "  com.example/gateway/child"}}
		},
		"unrelated anchor listing": func(f coexistenceFixture) {
			f["-a com.example/gateway -v -s Anchors"] = coexistenceReply{out: pfctl.Output{Stdout: "  com.example/other\n"}}
		},
		"truncated rules":       func(f coexistenceFixture) { f["-sr"] = coexistenceReply{out: pfctl.Output{Stdout: "block all"}} },
		"unknown PF diagnostic": func(f coexistenceFixture) { f["-sr"] = coexistenceReply{out: pfctl.Output{Stderr: "partial rules\n"}} },
		"counter output": func(f coexistenceFixture) {
			f["-sr"] = coexistenceReply{out: pfctl.Output{Stdout: "pass all\n  [ Evaluations: 1 ]\n"}}
		},
		"recursive output": func(f coexistenceFixture) {
			f["-sr"] = coexistenceReply{out: pfctl.Output{Stdout: "anchor \"peer\" all {\nblock all\n}\n"}}
		},
		"table contents": func(f coexistenceFixture) { f["-sr"] = coexistenceReply{out: pfctl.Output{Stdout: "192.0.2.1\n"}} },
		"service absent": func(f coexistenceFixture) {
			f["print system/org.example.gateway"] = coexistenceReply{err: errors.New("service not found")}
		},
		"service diagnostic": func(f coexistenceFixture) {
			f["print system/org.example.gateway"] = coexistenceReply{out: pfctl.Output{Stdout: coexistenceLaunchOutput, Stderr: "partial output\n"}}
		},
		"excess stdout": func(f coexistenceFixture) {
			f["-sr"] = coexistenceReply{out: pfctl.Output{Stdout: strings.Repeat("x", (1<<20)+1)}}
		},
		"excess stderr": func(f coexistenceFixture) {
			f["-sr"] = coexistenceReply{out: pfctl.Output{Stderr: strings.Repeat("x", 8193)}}
		},
		"aggregate limit": func(f coexistenceFixture) {
			for _, command := range []string{"-sr", "-a com.example/empty -sr", "-a com.example/gateway -sr"} {
				f[command] = coexistenceReply{out: pfctl.Output{Stdout: strings.Repeat("pass all\n", 110000)}}
			}
			for _, command := range []string{"-sn", "-a com.example/empty -sn", "-a com.example/gateway -sn"} {
				f[command] = coexistenceReply{out: pfctl.Output{Stdout: strings.Repeat("no nat all\n", 99000)}}
			}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			c, f := coexistenceInputs()
			change(f)
			state, err := observeCoexistenceWithCommands(context.Background(), c, f.command, f.command)
			if err == nil || !state.RecordedAt.IsZero() {
				t.Fatalf("incomplete observation published as successful: %v", err)
			}
		})
	}
}

func TestCoexistenceObservationCancellation(t *testing.T) {
	c, f := coexistenceInputs()
	ctx, cancel := context.WithCancel(context.Background())
	command := func(ctx context.Context, args ...string) (pfctl.Output, error) {
		out, err := f.command(ctx, args...)
		cancel()
		return out, err
	}
	state, err := observeCoexistenceWithCommands(ctx, c, command, f.command)
	if !errors.Is(err, context.Canceled) || !state.RecordedAt.IsZero() {
		t.Fatalf("canceled read accepted: %v", err)
	}
}

func TestCoexistenceNativeOutputBoundCannotBypassWrite(t *testing.T) {
	out := coexistenceBuffer{limit: 16}
	// LimitReader has no WriterTo: io.Copy must not discover a promoted
	// bytes.Buffer.ReadFrom and bypass the bounded writer.
	_, err := io.Copy(&out, io.LimitReader(strings.NewReader(strings.Repeat("x", 1024)), 1024))
	if err == nil || len(out.String()) > 16 {
		t.Fatal("native output bypassed the bounded writer")
	}
}

func TestCoexistenceLaunchctlParser(t *testing.T) {
	pid, err := coexistenceServicePID("org.example.gateway", coexistenceLaunchOutput)
	if err != nil || pid != 123 {
		t.Fatalf("running service did not retain its top-level PID: %d, %v", pid, err)
	}
	cases := map[string]string{
		"missing state":          strings.Replace(coexistenceLaunchOutput, "\tstate = running\n", "", 1),
		"missing PID":            strings.Replace(coexistenceLaunchOutput, "\tpid = 123\n", "", 1),
		"stopped":                strings.Replace(coexistenceLaunchOutput, "\tstate = running\n", "\tstate = waiting\n", 1),
		"duplicate state":        strings.Replace(coexistenceLaunchOutput, "\tstate = running\n", "\tstate = running\n\tstate = running\n", 1),
		"duplicate PID":          strings.Replace(coexistenceLaunchOutput, "\tpid = 123\n", "\tpid = 123\n\tpid = 123\n", 1),
		"quoted state":           strings.Replace(coexistenceLaunchOutput, "\tstate = running\n", "\tstate = \"running\"\n", 1),
		"quoted key":             strings.Replace(coexistenceLaunchOutput, "\tstate = running\n", "\t\"state\" = running\n", 1),
		"nested only":            "system/org.example.gateway = {\n\tenvironment = {\n\t\tstate = running\n\t\tpid = 123\n\t}\n}\n",
		"quoted only":            "system/org.example.gateway = {\n\ttext = \"state = running; pid = 123\"\n}\n",
		"multiline quoted spoof": "system/org.example.gateway = {\n\ttext = \"description\n\tstate = running\n\tpid = 123\n\tend\"\n}\n",
		"wrong label":            strings.Replace(coexistenceLaunchOutput, "system/org.example.gateway = {", "system/org.example.other = {", 1),
		"wrong domain":           strings.Replace(coexistenceLaunchOutput, "system/org.example.gateway = {", "gui/501/org.example.gateway = {", 1),
		"truncated newline":      strings.TrimSuffix(coexistenceLaunchOutput, "\n"),
		"unclosed dictionary":    strings.TrimSuffix(coexistenceLaunchOutput, "}\n"),
		"extra output":           coexistenceLaunchOutput + "pid = 999\n",
		"unmatched quote":        strings.Replace(coexistenceLaunchOutput, "\tdomain = system\n", "\tdomain = \"system\n", 1),
		"inline closing brace":   strings.Replace(coexistenceLaunchOutput, "\tdomain = system\n", "\tdomain = system }\n", 1),
	}
	for _, value := range []string{"0", "-1", "+123", "0123", "2147483648", "123 456", "123\t", "\"123\""} {
		cases["PID "+value] = strings.Replace(coexistenceLaunchOutput, "\tpid = 123\n", "\tpid = "+value+"\n", 1)
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			if pid, err := coexistenceServicePID("org.example.gateway", text); err == nil || pid != 0 {
				t.Fatalf("ambiguous service health accepted: %d, %v", pid, err)
			}
		})
	}
}

func coexistenceStateFixture(at time.Time) CoexistenceState {
	return CoexistenceState{
		RecordedAt:      at,
		MainRulesSHA256: digest([]byte("main")),
		Anchors:         []AnchorRulesDigest{{"com.example/peer", digest([]byte("filter")), digest([]byte("translation"))}},
		Services:        []ServicePID{{"org.example.peer", 123}},
	}
}

func TestSameCoexistenceValidatesShapeAndOrder(t *testing.T) {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	before := coexistenceStateFixture(at)
	later := coexistenceStateFixture(at.Add(time.Second))
	if err := SameCoexistence(before, later); err != nil {
		t.Fatalf("benign observation time difference refused: %v", err)
	}
	cases := map[string]func(*CoexistenceState){
		"zero time":                  func(s *CoexistenceState) { s.RecordedAt = time.Time{} },
		"backward time":              func(s *CoexistenceState) { s.RecordedAt = at.Add(-time.Second) },
		"invalid main digest":        func(s *CoexistenceState) { s.MainRulesSHA256 = "invalid" },
		"invalid peer digest":        func(s *CoexistenceState) { s.Anchors[0].FilterSHA256 = "invalid" },
		"invalid translation digest": func(s *CoexistenceState) { s.Anchors[0].TranslationSHA256 = "invalid" },
		"missing peer":               func(s *CoexistenceState) { s.Anchors = nil },
		"changed peer set":           func(s *CoexistenceState) { s.Anchors[0].Path = "com.example/other" },
		"duplicate peer":             func(s *CoexistenceState) { s.Anchors = append(s.Anchors, s.Anchors[0]) },
		"unsorted peers": func(s *CoexistenceState) {
			s.Anchors = append(s.Anchors, AnchorRulesDigest{"com.example/aaa", s.Anchors[0].FilterSHA256, s.Anchors[0].TranslationSHA256})
		},
		"missing service":   func(s *CoexistenceState) { s.Services = nil },
		"duplicate service": func(s *CoexistenceState) { s.Services = append(s.Services, s.Services[0]) },
		"PID zero":          func(s *CoexistenceState) { s.Services[0].PID = 0 },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			after := coexistenceStateFixture(at.Add(time.Second))
			change(&after)
			if err := SameCoexistence(before, after); err == nil {
				t.Fatal("invalid or changed snapshot accepted")
			}
		})
	}
	before.Anchors, before.Services = nil, nil
	later.Anchors, later.Services = []AnchorRulesDigest{}, []ServicePID{}
	if err := SameCoexistence(before, later); err != nil {
		t.Fatalf("nil and empty collections differed: %v", err)
	}
}

func TestCoexistenceEvidenceRequiresFinalRecheck(t *testing.T) {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	policy := digest([]byte("reviewed owned policy"))
	fresh := func() (CoexistenceEvidence, CoexistenceState) {
		return CoexistenceEvidence{
			OwnedAnchor: "com.example/owned", PolicySHA256: policy,
			Before:             coexistenceStateFixture(at),
			AfterFirewall:      coexistenceStateFixture(at.Add(time.Second)),
			AfterQualification: coexistenceStateFixture(at.Add(2 * time.Second)),
		}, coexistenceStateFixture(at.Add(3 * time.Second))
	}
	e, current := fresh()
	if err := ValidateCoexistenceEvidence(e, current, "com.example/owned", policy); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*CoexistenceEvidence, *CoexistenceState){
		"owned anchor mismatch": func(e *CoexistenceEvidence, _ *CoexistenceState) { e.OwnedAnchor = "com.example/other" },
		"policy mismatch":       func(e *CoexistenceEvidence, _ *CoexistenceState) { e.PolicySHA256 = digest([]byte("different policy")) },
		"missing final recheck": func(e *CoexistenceEvidence, _ *CoexistenceState) { e.AfterQualification = CoexistenceState{} },
		"main changed at firewall step": func(e *CoexistenceEvidence, _ *CoexistenceState) {
			e.AfterFirewall.MainRulesSHA256 = digest([]byte("changed"))
		},
		"peer changed at qualification": func(e *CoexistenceEvidence, _ *CoexistenceState) {
			e.AfterQualification.Anchors[0].TranslationSHA256 = digest([]byte("changed"))
		},
		"service restarted at qualification": func(e *CoexistenceEvidence, _ *CoexistenceState) { e.AfterQualification.Services[0].PID++ },
		"current peer changed": func(_ *CoexistenceEvidence, s *CoexistenceState) {
			s.Anchors[0].FilterSHA256 = digest([]byte("changed"))
		},
		"current service restarted": func(_ *CoexistenceEvidence, s *CoexistenceState) { s.Services[0].PID++ },
		"before follows firewall":   func(e *CoexistenceEvidence, _ *CoexistenceState) { e.Before.RecordedAt = at.Add(2 * time.Second) },
		"firewall follows qualification": func(e *CoexistenceEvidence, _ *CoexistenceState) {
			e.AfterFirewall.RecordedAt = at.Add(3 * time.Second)
		},
		"qualification follows current": func(e *CoexistenceEvidence, _ *CoexistenceState) {
			e.AfterQualification.RecordedAt = at.Add(4 * time.Second)
		},
		"owned peer": func(e *CoexistenceEvidence, s *CoexistenceState) {
			for _, state := range []*CoexistenceState{&e.Before, &e.AfterFirewall, &e.AfterQualification, s} {
				state.Anchors[0].Path = "com.example/owned/child"
			}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			e, current := fresh()
			change(&e, &current)
			if err := ValidateCoexistenceEvidence(e, current, "com.example/owned", policy); err == nil {
				t.Fatal("incomplete, reordered, or changed evidence accepted")
			}
		})
	}
}

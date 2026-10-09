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
		CoexistingAnchors:  []string{"com.example/gateway", "com.example/empty"},
		CoexistingServices: []string{"org.example.gateway"},
	}
	// No table-content or verbose-rule/counter response exists: observations
	// requiring those changing values fail rather than silently consuming them.
	f := coexistenceFixture{
		"-sr":                              {out: pfctl.Output{Stdout: "anchor \"com.example/*\" all\n"}},
		"-sn":                              {out: pfctl.Output{Stdout: "nat-anchor \"com.example/*\" all\n"}},
		"-a com.example/empty -sr":         {},
		"-a com.example/empty -sn":         {},
		"-a com.example/gateway -sr":       {out: pfctl.Output{Stdout: "pass in on en0 from <clients> to any\n"}},
		"-a com.example/gateway -sn":       {out: pfctl.Output{Stdout: "nat on en0 inet from <clients> to any -> (en0)\n"}},
		"print system/org.example.gateway": {out: pfctl.Output{Stdout: coexistenceLaunchOutput}},
	}
	return c, f
}

func TestCoexistenceConfigCanonicalization(t *testing.T) {
	c, _ := coexistenceInputs()
	original := c.CoexistingAnchors
	c.CoexistingServices = []string{"org.example.zeta", "org.example.alpha"}
	if err := ValidateCoexistenceConfig(&c); err != nil {
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
	if err := ValidateCoexistenceConfig(&c); err != nil || c.CoexistingAnchors != nil || c.CoexistingServices != nil {
		t.Fatalf("empty collections not normalized: %v", err)
	}
	c = Config{CoexistingAnchors: []string{"com.example", "com.example/owned-other"}}
	if err := ValidateCoexistenceConfig(&c); err != nil {
		t.Fatalf("direct ancestor or disjoint sibling refused: %v", err)
	}
}

func TestCoexistenceConfigRejectsAmbiguousSelectors(t *testing.T) {
	for _, path := range []string{"", "*", "com.example/*", "/com.example/peer", "com.example/../peer", "peer\nother"} {
		t.Run("anchor "+path, func(t *testing.T) {
			c := Config{CoexistingAnchors: []string{path}}
			if err := ValidateCoexistenceConfig(&c); err == nil {
				t.Fatal("unsafe peer path accepted")
			}
		})
	}
	for _, label := range []string{"", "*", "org.example.*", "system/org.example.peer", "gui/501/org.example.peer", "../peer", "-peer", "org.example:peer", "peer\nstate", "\"peer\"", strings.Repeat("x", 256)} {
		t.Run("service "+label, func(t *testing.T) {
			c := Config{CoexistingServices: []string{label}}
			if err := ValidateCoexistenceConfig(&c); err == nil {
				t.Fatal("unsafe service selector accepted")
			}
		})
	}
	for _, c := range []Config{
		{CoexistingAnchors: []string{"peer", "peer"}},
		{CoexistingServices: []string{"org.example.peer", "org.example.peer"}},
	} {
		if err := ValidateCoexistenceConfig(&c); err == nil {
			t.Fatal("duplicate or excessive config list accepted")
		}
	}
	anchors, services := make([]string, 65), make([]string, 65)
	for i := range anchors {
		anchors[i], services[i] = fmt.Sprintf("peer%d", i), fmt.Sprintf("org.example.peer%d", i)
	}
	atLimit := Config{CoexistingAnchors: anchors[:64], CoexistingServices: services[:64]}
	if err := ValidateCoexistenceConfig(&atLimit); err != nil {
		t.Fatalf("bounded exact lists refused: %v", err)
	}
	for _, c := range []Config{{CoexistingAnchors: anchors}, {CoexistingServices: services}} {
		if err := ValidateCoexistenceConfig(&c); err == nil {
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

func TestUnreadablePFRulesAreUnavailable(t *testing.T) {
	for _, command := range []string{"-sr", "-sn", "-a com.example/empty -sr", "-a com.example/empty -sn"} {
		for _, reply := range []coexistenceReply{
			{err: errors.New("permission denied")},
			{out: pfctl.Output{Stderr: "pfctl: DIOCGETRULES: Invalid argument\n"}},
			{out: pfctl.Output{Stdout: strings.Repeat("x", (1<<20)+1)}},
		} {
			c, f := coexistenceInputs()
			before, err := observeCoexistenceWithCommands(context.Background(), c, f.command, f.command)
			if err != nil {
				t.Fatal(err)
			}
			f[command] = reply
			after, err := observeCoexistenceWithCommands(context.Background(), c, f.command, f.command)
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(command, "-a") {
				a := after.Anchors[0]
				if a.Status != "unavailable" || a.FilterSHA256 != "" || a.TranslationSHA256 != "" {
					t.Fatalf("partial measurement retained: %+v", a)
				}
			} else if after.MainRulesStatus != "unavailable" || after.MainRulesSHA256 != "" {
				t.Fatalf("unreadable main retained: %+v", after)
			}
			if err := SameCoexistence(before, after); err != nil {
				t.Fatal(err)
			}
			recovered := before
			recovered.RecordedAt = after.RecordedAt.Add(time.Second)
			if err := SameCoexistence(after, recovered); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestCoexistenceServiceFailuresRemainFatal(t *testing.T) {
	for _, reply := range []coexistenceReply{
		{err: errors.New("service missing")},
		{out: pfctl.Output{Stdout: strings.Replace(coexistenceLaunchOutput, "state = running", "state = waiting", 1)}},
		{out: pfctl.Output{Stdout: coexistenceLaunchOutput, Stderr: "partial"}},
	} {
		c, f := coexistenceInputs()
		f["print system/org.example.gateway"] = reply
		if _, err := observeCoexistenceWithCommands(context.Background(), c, f.command, f.command); err == nil {
			t.Fatal("unproven running service admitted")
		}
	}
}

func TestCoexistenceRulesAreOpaqueBytes(t *testing.T) {
	c, f := coexistenceInputs()
	text := "unfamiliar native syntax without newline"
	f["-a com.example/empty -sr"] = coexistenceReply{out: pfctl.Output{Stdout: text}}
	state, err := observeCoexistenceWithCommands(context.Background(), c, f.command, f.command)
	if err != nil {
		t.Fatal(err)
	}
	if state.Anchors[0].FilterSHA256 != digest([]byte(text)) {
		t.Fatal("opaque bytes not measured exactly")
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
		MainRulesStatus: "available",
		MainRulesSHA256: digest([]byte("main")),
		Anchors:         []AnchorRulesDigest{{Path: "com.example/peer", Status: "available", FilterSHA256: digest([]byte("filter")), TranslationSHA256: digest([]byte("translation"))}},
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
			s.Anchors = append(s.Anchors, AnchorRulesDigest{Path: "com.example/aaa", Status: "available", FilterSHA256: s.Anchors[0].FilterSHA256, TranslationSHA256: s.Anchors[0].TranslationSHA256})
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

func TestCoexistenceEvidenceBindsWindowButOnlyCurrentServices(t *testing.T) {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	e := CoexistenceEvidence{Before: coexistenceStateFixture(at), After: coexistenceStateFixture(at.Add(time.Second))}
	current := coexistenceStateFixture(at.Add(2 * time.Second))
	current.MainRulesSHA256 = digest([]byte("current main changed"))
	current.Anchors[0].FilterSHA256 = digest([]byte("current peer changed"))
	if err := ValidateCoexistenceEvidence(e, current); err != nil {
		t.Fatal(err)
	}
	current.Services[0].PID++
	if err := ValidateCoexistenceEvidence(e, current); err == nil {
		t.Fatal("current PID drift accepted")
	}
	current.Services[0].PID--
	e.After.Anchors[0].TranslationSHA256 = digest([]byte("window drift"))
	if err := ValidateCoexistenceEvidence(e, current); err == nil {
		t.Fatal("recorded rule drift accepted")
	}
}

func TestPFDeadlineDoesNotInvalidateObservedServices(t *testing.T) {
	c, f := coexistenceInputs()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pf := func(context.Context, ...string) (pfctl.Output, error) {
		cancel()
		return pfctl.Output{}, context.Canceled
	}
	state, err := observeCoexistenceWithCommands(ctx, c, pf, f.command)
	if err != nil || state.MainRulesStatus != "unavailable" || len(state.Services) != 1 || state.Services[0].PID != 123 {
		t.Fatalf("PF cancellation discarded service evidence: %+v %v", state, err)
	}
	for _, anchor := range state.Anchors {
		if anchor.Status != "unavailable" || anchor.FilterSHA256 != "" || anchor.TranslationSHA256 != "" {
			t.Fatalf("PF cancellation produced available peer: %+v", anchor)
		}
	}
}

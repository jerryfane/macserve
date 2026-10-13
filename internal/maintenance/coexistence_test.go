package maintenance

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
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

// This read-only Studio capture contains paths and launchd metadata, not
// keyring contents or environment secrets. Keep its tabs and array close intact.
func keyringLaunchOutput(t *testing.T) string {
	t.Helper()
	text, err := os.ReadFile("testdata/keyring-launchctl.txt")
	if err != nil {
		t.Fatal(err)
	}
	return string(text)
}

func TestCoexistenceRejectsScalarArrayReparenting(t *testing.T) {
	probe := "system/org.gitmoot.keyring = {\n\tmetadata = [\n\t\t0 = foo ]\n\tstate = running\n\tpid = 2908\n}\n"
	if _, err := coexistenceServicePID("org.gitmoot.keyring", probe); err == nil {
		t.Fatal("scalar suffix reparented nested service authority")
	}
	if pid, err := coexistenceServicePID("org.gitmoot.keyring", keyringLaunchOutput(t)); err != nil || pid != 2908 {
		t.Fatalf("real empty-value array close refused: pid=%d err=%v", pid, err)
	}
}

func TestCoexistenceLaunchctlBalancedCapture(t *testing.T) {
	capture := keyringLaunchOutput(t)
	insert := func(body string) string {
		return strings.Replace(capture, "\tdomain = system\n", body+"\tdomain = system\n", 1)
	}
	accepted := map[string]string{
		"actual keyring":               capture,
		"quoted equals dictionaries":   strings.ReplaceAll(capture, "\" => ", "\" = "),
		"unquoted arrow containers":    strings.Replace(capture, "\tLWCR = {\n", "\tLWCR => {\n", 1),
		"nested health spoof":          insert("\tmetadata => {\n\t\t\"state\" => stopped\n\t\t\"pid\" = 999\n\t\tvalues => [\n\t\t\t0 = {\n\t\t\t\tstate = waiting\n\t\t\t\tpid = 888\n\t\t\t}\n\t\t\t1 = \"state = running; pid = 777; ] }\"\n\t\t]\n\t}\n"),
		"environment health spoof":     strings.Replace(capture, "\t\tOSLogRateLimit => 64\n", "\t\tstate => stopped\n\t\tpid => 999\n\t\tDESCRIPTION => \"state = running; pid = 777; ] }\"\n", 1),
		"array scalar same-line close": strings.Replace(capture, "0 = \t\t\t\t]", "0 = \"quoted ] and }\" ]", 1),
		"array bare elements":          strings.Replace(capture, "0 = \t\t\t\t]", "\"quoted ] and }\"\n\t\t\t\t]", 1),
		"empty inline containers":      insert("\tmetadata = {\n\t\t\"array\" => []\n\t\t\"dictionary\" = { }\n\t}\n"),
		"maximum nesting":              insert(strings.Repeat("\tmetadata = {\n", 15) + strings.Repeat("\t}\n", 15)),
	}
	for name, text := range accepted {
		t.Run(name, func(t *testing.T) {
			if pid, err := coexistenceServicePID("org.gitmoot.keyring", text); err != nil || pid != 2908 {
				t.Fatalf("balanced service snapshot refused or nested PID used: pid=%d err=%v", pid, err)
			}
		})
	}
	refused := map[string]string{
		"LWCR state cannot replace root":        strings.Replace(insert("\tmetadata => {\n\t\tstate = running\n\t\tpid = 999\n\t}\n"), "\tstate = running\n", "", 1),
		"LWCR PID cannot replace root":          strings.Replace(insert("\tmetadata => {\n\t\tstate = running\n\t\tpid = 999\n\t}\n"), "\tpid = 2908\n", "", 1),
		"environment state cannot replace root": strings.Replace(strings.Replace(capture, "\t\tOSLogRateLimit => 64\n", "\t\tstate => running\n", 1), "\tstate = running\n", "", 1),
		"environment PID cannot replace root":   strings.Replace(strings.Replace(capture, "\t\tOSLogRateLimit => 64\n", "\t\tpid => 999\n", 1), "\tpid = 2908\n", "", 1),
		"arrow root state":                      strings.Replace(capture, "\tstate = running\n", "\tstate => running\n", 1),
		"arrow root PID":                        strings.Replace(capture, "\tpid = 2908\n", "\tpid => 2908\n", 1),
		"duplicate quoted root state":           insert("\t\"state\" => running\n"),
		"duplicate quoted root PID":             insert("\t\"pid\" => 999\n"),
		"mismatched array close":                strings.Replace(capture, "0 = \t\t\t\t]", "0 = \t\t\t\t}", 1),
		"missing array close":                   strings.Replace(capture, "0 = \t\t\t\t]", "0 = ", 1),
		"extra array close":                     strings.Replace(capture, "0 = \t\t\t\t]", "0 = ] ]", 1),
		"array close trailing scalar":           strings.Replace(capture, "0 = \t\t\t\t]", "0 = ] trailing", 1),
		"array noncanonical index":              strings.Replace(capture, "0 = \t\t\t\t]", "00 = ]", 1),
		"array nonindex property":               strings.Replace(capture, "0 = \t\t\t\t]", "pid = 999 ]", 1),
		"array opening after scalar":            strings.Replace(capture, "\"$in\" => [", "\"$in\" => scalar [", 1),
		"dictionary close after scalar":         insert("\tmetadata = {\n\t\tvalue = scalar }\n"),
		"unclosed quoted key":                   strings.Replace(capture, "\"reqs\" => {", "\"reqs => {", 1),
		"quoted key fragments":                  strings.Replace(capture, "\"reqs\" => {", "\"re\"\"qs\" => {", 1),
		"excess nesting":                        insert(strings.Repeat("\tmetadata = {\n", 16) + strings.Repeat("\t}\n", 16)),
		"output limit":                          insert("\tpadding = " + strings.Repeat("x", 1<<20) + "\n"),
		"NUL":                                   insert("\tmetadata = nul\x00\n"),
		"DEL":                                   insert("\tmetadata = del\x7f\n"),
		"unicode control":                       insert("\tmetadata = control\u0085\n"),
		"carriage return":                       strings.Replace(capture, "\n", "\r\n", 1),
		"truncated newline":                     strings.TrimSuffix(capture, "\n"),
		"truncated dictionary":                  strings.TrimSuffix(capture, "}\n"),
		"trailing whitespace line":              capture + "\n",
		"trailing second service":               capture + capture,
	}
	for name, text := range refused {
		t.Run(name, func(t *testing.T) {
			if pid, err := coexistenceServicePID("org.gitmoot.keyring", text); err == nil || pid != 0 {
				t.Fatalf("malformed or spoofed service snapshot accepted: pid=%d err=%v", pid, err)
			}
		})
	}
}

func TestCoexistenceObservationLWCRCapture(t *testing.T) {
	c, fixture := coexistenceInputs()
	c.CoexistingServices = []string{"org.gitmoot.keyring"}
	fixture["print system/org.gitmoot.keyring"] = coexistenceReply{out: pfctl.Output{Stdout: keyringLaunchOutput(t)}}
	state, err := observeCoexistenceWithCommands(context.Background(), c, fixture.command, fixture.command)
	if err != nil || len(state.Services) != 1 || state.Services[0].Label != "org.gitmoot.keyring" || state.Services[0].PID != 2908 {
		t.Fatalf("real LWCR service failed coexistence observation: %+v %v", state.Services, err)
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

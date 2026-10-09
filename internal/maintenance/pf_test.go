package maintenance

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/pfctl"
)

const stockTranslationCalls = "nat-anchor \"com.apple/*\" all\nrdr-anchor \"com.apple/*\" all\n"

type pfReply struct {
	text string
	err  error
}

type pfFixture map[string][]pfReply

func stockPFFixture() pfFixture {
	return pfFixture{
		"-s info":                                 {{text: "Status: Enabled for 0 days 00:00:01           Debug: Urgent\n"}},
		"-i lo0 -v -s Interfaces":                 {{text: "lo0\n"}},
		"-sr":                                     {{text: "scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all\ndummynet-anchor \"com.apple/*\" all\n"}},
		"-a * -sr":                                {{text: "scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all {\nanchor \"macserve\" all {\n" + ownedFilterRules + "}\n}\ndummynet-anchor \"com.apple/*\" all\n"}},
		"-a com.apple -sr":                        {{}},
		"-a com.apple/empty -sr":                  {{}},
		"-a com.apple/macserve -sr":               {{text: ownedFilterRules}},
		"-v -s Anchors":                           {{text: "  com.apple\n  com.apple/empty\n  com.apple/macserve\n"}},
		"-a  -sn":                                 {{text: stockTranslationCalls}},
		"-a com.apple -sn":                        {{}},
		"-a com.apple/empty -sn":                  {{}},
		"-a com.apple/macserve -sn":               {{}},
		"-a _pf -v -s Anchors":                    {{err: pfctl.ErrAnchorAbsent}},
		"-a com.apple/_pf -v -s Anchors":          {{err: pfctl.ErrAnchorAbsent}},
		"-a com.apple/empty/_pf -v -s Anchors":    {{err: pfctl.ErrAnchorAbsent}},
		"-a com.apple/macserve/_pf -v -s Anchors": {{err: pfctl.ErrAnchorAbsent}},
	}
}

func (f pfFixture) command(ctx context.Context, args ...string) (string, error) {
	key := strings.Join(args, " ")
	replies, ok := f[key]
	if !ok || len(replies) == 0 {
		return "", fmt.Errorf("unobserved PF query: %s", key)
	}
	reply := replies[0]
	if len(replies) > 1 {
		f[key] = replies[1:]
	}
	return reply.text, reply.err
}

func TestStockEmptyTranslationAnchorsQualify(t *testing.T) {
	now, q, e, o := approvedFixture()
	if err := observePFWithCommand(context.Background(), Config{}, nil, &o, stockPFFixture().command); err != nil {
		t.Fatal(err)
	}
	q.RootRulesSHA256 = o.RootRulesSHA256
	q.AnchorRulesSHA256 = o.AnchorRulesSHA256
	if h, err := Evaluate(now, q, e, o); err != nil || !h.BoundaryValidated {
		t.Fatalf("stock empty translation anchors cannot qualify: %v", err)
	}

	changed := stockPFFixture()
	changed["-a  -sn"] = []pfReply{{text: "nat-anchor \"com.apple/*\" all\n"}}
	if err := observePFWithCommand(context.Background(), Config{}, nil, &o, changed.command); err != nil {
		t.Fatal(err)
	}
	if h, err := Evaluate(now, q, e, o); err == nil || h.BoundaryValidated {
		t.Fatal("translation call change retained qualification")
	}

	changed = stockPFFixture()
	changed["-v -s Anchors"] = []pfReply{{text: "  com.apple\n  com.apple/macserve\n"}}
	if err := observePFWithCommand(context.Background(), Config{}, nil, &o, changed.command); err != nil {
		t.Fatal(err)
	}
	if h, err := Evaluate(now, q, e, o); err == nil || h.BoundaryValidated {
		t.Fatal("translation topology change retained qualification")
	}
}

func TestPFTranslationObservationRefusesUnsafeOrIncompleteReads(t *testing.T) {
	cases := map[string]func(pfFixture){
		"root mapping": func(f pfFixture) { f["-a  -sn"] = []pfReply{{text: "rdr inet from any to any -> 127.0.0.1\n"}} },
		"child mapping": func(f pfFixture) {
			f["-a com.apple/empty -sn"] = []pfReply{{text: "nat inet from any to any -> 192.0.2.1\n"}}
		},
		"nested opaque call": func(f pfFixture) { f["-a com.apple/empty -sn"] = []pfReply{{text: "rdr-anchor \"hidden/*\" all\n"}} },
		"table reference": func(f pfFixture) {
			f["-a  -sn"] = []pfReply{{text: "nat-anchor \"com.apple/*\" from <clients> to any\n"}}
		},
		"dynamic interface":  func(f pfFixture) { f["-a  -sn"] = []pfReply{{text: "rdr-anchor \"com.apple/*\" from any to (en0)\n"}} },
		"unlisted target":    func(f pfFixture) { f["-a  -sn"] = []pfReply{{text: "nat-anchor \"unobserved/*\" all\n"}} },
		"missing child read": func(f pfFixture) { delete(f, "-a com.apple/empty -sn") },
		"child query error": func(f pfFixture) {
			f["-a com.apple/empty -sn"] = []pfReply{{err: errors.New("unrecognized PF diagnostic")}}
		},
		"reserved probe error": func(f pfFixture) {
			f["-a com.apple/_pf -v -s Anchors"] = []pfReply{{err: errors.New("permission denied")}}
		},
		"truncated listing": func(f pfFixture) { f["-v -s Anchors"] = []pfReply{{text: "  com.apple\n  com.apple/macserve"}} },
		"duplicate listing": func(f pfFixture) { f["-v -s Anchors"] = []pfReply{{text: "  com.apple\n  com.apple\n"}} },
		"omitted parent":    func(f pfFixture) { f["-v -s Anchors"] = []pfReply{{text: "  com.apple/empty\n  com.apple/macserve\n"}} },
		"malformed path":    func(f pfFixture) { f["-v -s Anchors"] = []pfReply{{text: "  com.apple/../hidden\n"}} },
		"excess depth":      func(f pfFixture) { f["-v -s Anchors"] = []pfReply{{text: "  " + strings.Repeat("a/", 8) + "b\n"}} },
		"excess anchors": func(f pfFixture) {
			var text strings.Builder
			for i := range 65 {
				fmt.Fprintf(&text, "  a%d\n", i)
			}
			f["-v -s Anchors"] = []pfReply{{text: text.String()}}
		},
		"oversized output": func(f pfFixture) { f["-v -s Anchors"] = []pfReply{{text: strings.Repeat("x", (1<<20)+1)}} },
		"changed enumeration": func(f pfFixture) {
			f["-v -s Anchors"] = append(f["-v -s Anchors"], pfReply{text: "  com.apple\n  com.apple/macserve\n"})
		},
		"changed root calls": func(f pfFixture) {
			f["-a  -sn"] = append(f["-a  -sn"], pfReply{text: "nat-anchor \"com.apple/*\" all\n"})
		},
		"mapping appears on recheck": func(f pfFixture) {
			f["-a com.apple/empty -sn"] = []pfReply{{}, {text: "rdr inet from any to any -> 127.0.0.1\n"}}
		},
		"truncated translation": func(f pfFixture) { f["-a  -sn"] = []pfReply{{text: strings.TrimSuffix(stockTranslationCalls, "\n")}} },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f := stockPFFixture()
			change(f)
			o := Observation{JobUID: 550}
			if err := observePFWithCommand(context.Background(), Config{}, nil, &o, f.command); err == nil {
				t.Fatal("unsafe PF observation accepted")
			}
			if o.RootRulesSHA256 != "" {
				t.Fatal("incomplete observation published a qualification digest")
			}
		})
	}
}

func TestPFReservedAnchorCannotHideMapping(t *testing.T) {
	f := stockPFFixture()
	f["-a com.apple/_pf -v -s Anchors"] = []pfReply{{text: "  com.apple/_pf/hidden\n"}}
	f["-a com.apple/_pf/_pf -v -s Anchors"] = []pfReply{{err: pfctl.ErrAnchorAbsent}}
	f["-a com.apple/_pf/hidden/_pf -v -s Anchors"] = []pfReply{{err: pfctl.ErrAnchorAbsent}}
	f["-a com.apple/_pf -sn"] = []pfReply{{}}
	f["-a com.apple/_pf/hidden -sn"] = []pfReply{{}}
	f["-a com.apple/_pf -sr"] = []pfReply{{}}
	f["-a com.apple/_pf/hidden -sr"] = []pfReply{{}}
	o := Observation{JobUID: 550}
	if err := observePFWithCommand(context.Background(), Config{}, nil, &o, f.command); err != nil {
		t.Fatalf("empty reserved subtree refused: %v", err)
	}
	f["-a com.apple/_pf/hidden -sn"] = []pfReply{{text: "rdr inet from any to any -> 127.0.0.1\n"}}
	if err := observePFWithCommand(context.Background(), Config{}, nil, &o, f.command); err == nil {
		t.Fatal("mapping hidden under reserved anchor accepted")
	}
}

func TestPFObservationHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	o := Observation{JobUID: 550}
	if err := observePFWithCommand(ctx, Config{}, nil, &o, stockPFFixture().command); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want cancellation", err)
	}
}

func guestPFFixture() (Config, []netip.Addr, pfFixture) {
	c := Config{
		PFAnchor:                    DefaultPFAnchor,
		ToleratedTranslationAnchors: []string{"com.apple/guest-router"},
		ApprovedGuestSubnets:        []string{"172.20.40.0/24"},
	}
	f := stockPFFixture()
	// Both reachable filters have identical text. Selecting the other one must
	// invalidate qualification even when topology and every ruleset stay fixed.
	f["-a com.apple/macserve-alt -sr"] = []pfReply{{text: ownedFilterRules}}
	f["-a com.apple/macserve-alt -sn"] = []pfReply{{}}
	f["-a com.apple/macserve-alt/_pf -v -s Anchors"] = []pfReply{{err: pfctl.ErrAnchorAbsent}}
	f["-a com.apple/guest-router -sr"] = []pfReply{{}}
	f["-a * -sr"] = []pfReply{{text: "anchor \"com.apple/*\" all {\nanchor \"macserve\" all {\n" + ownedFilterRules + "}\nanchor \"macserve-alt\" all {\n" + ownedFilterRules + "}\n}\n"}}
	f["-v -s Anchors"] = []pfReply{{text: "  com.apple\n  com.apple/empty\n  com.apple/guest-router\n  com.apple/macserve\n  com.apple/macserve-alt\n"}}
	f["-a com.apple/guest-router/_pf -v -s Anchors"] = []pfReply{{err: pfctl.ErrAnchorAbsent}}
	f["-a com.apple/guest-router -sn"] = []pfReply{{text: "nat on en0 inet from 172.20.40.0/24 to any -> (en0)\n"}}
	return c, []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")}, f
}

func TestGuestTranslationCoexistenceBindsQualification(t *testing.T) {
	now, q, evidence, o := approvedFixture()
	c, hosts, f := guestPFFixture()
	if err := observePFWithCommand(context.Background(), c, hosts, &o, f.command); err != nil {
		t.Fatal(err)
	}
	q.RootRulesSHA256, q.AnchorRulesSHA256 = o.RootRulesSHA256, o.AnchorRulesSHA256
	if health, err := Evaluate(now, q, evidence, o); err != nil || !health.BoundaryValidated {
		t.Fatalf("reviewed guest-only NAT cannot coexist: %v", err)
	}
	for name, change := range map[string]func(*Config, pfFixture){
		"translation bytes": func(_ *Config, f pfFixture) {
			f["-a com.apple/guest-router -sn"] = []pfReply{{text: "nat on en0 inet from 172.20.40.0/25 to any -> (en0)\n"}}
		},
		"reviewed guest scope": func(c *Config, _ pfFixture) {
			c.ApprovedGuestSubnets = []string{"172.20.40.0/23"}
		},
		"reviewed anchor scope": func(c *Config, _ pfFixture) {
			c.ToleratedTranslationAnchors = append(c.ToleratedTranslationAnchors, "com.apple/another-router")
		},
		"selected filter path": func(c *Config, _ pfFixture) {
			c.PFAnchor = "com.apple/macserve-alt"
		},
		"reviewed coexisting anchors": func(c *Config, _ pfFixture) {
			c.CoexistingAnchors = []string{"com.apple/guest-router"}
		},
		"reviewed coexisting services": func(c *Config, _ pfFixture) {
			c.CoexistingServices = []string{"org.example.peer"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			c, hosts, f := guestPFFixture()
			change(&c, f)
			current := o
			if err := observePFWithCommand(context.Background(), c, hosts, &current, f.command); err != nil {
				t.Fatal(err)
			}
			if health, err := Evaluate(now, q, evidence, current); err == nil || health.BoundaryValidated {
				t.Fatal("changed translation policy retained old qualification")
			}
		})
	}
}

func TestGuestTranslationObservationFailsClosed(t *testing.T) {
	for name, change := range map[string]func(*Config, *[]netip.Addr, pfFixture){
		"not opted in": func(c *Config, _ *[]netip.Addr, _ pfFixture) {
			c.ToleratedTranslationAnchors, c.ApprovedGuestSubnets = nil, nil
		},
		"host bridge inside guest prefix": func(_ *Config, hosts *[]netip.Addr, _ pfFixture) {
			*hosts = append(*hosts, netip.MustParseAddr("172.20.40.1"))
		},
		"source matches host job traffic": func(_ *Config, _ *[]netip.Addr, f pfFixture) {
			f["-a com.apple/guest-router -sn"] = []pfReply{{text: "nat on en0 inet from any to any -> (en0)\n"}}
		},
		"rdr targets host alias": func(_ *Config, _ *[]netip.Addr, f pfFixture) {
			f["-a com.apple/guest-router -sn"] = []pfReply{{text: "rdr on en0 inet proto tcp from 172.20.40.0/24 to any port = 443 -> 192.0.2.10 port 8443\n"}}
		},
		"unlisted second anchor": func(_ *Config, _ *[]netip.Addr, f pfFixture) {
			f["-a com.apple/empty -sn"] = f["-a com.apple/guest-router -sn"]
		},
		"allowlist does not include descendants": func(_ *Config, _ *[]netip.Addr, f pfFixture) {
			f["-v -s Anchors"] = []pfReply{{text: "  com.apple\n  com.apple/empty\n  com.apple/guest-router\n  com.apple/guest-router/child\n  com.apple/macserve\n  com.apple/macserve-alt\n"}}
			f["-a com.apple/guest-router/child/_pf -v -s Anchors"] = []pfReply{{err: pfctl.ErrAnchorAbsent}}
			f["-a com.apple/guest-router/child -sr"] = []pfReply{{}}
			f["-a com.apple/guest-router/child -sn"] = f["-a com.apple/guest-router -sn"]
		},
		"translation changes during read": func(_ *Config, _ *[]netip.Addr, f pfFixture) {
			f["-a com.apple/guest-router -sn"] = append(f["-a com.apple/guest-router -sn"], pfReply{text: "nat on en0 inet from 172.20.40.0/25 to any -> (en0)\n"})
		},
		"filter changes during read": func(_ *Config, _ *[]netip.Addr, f pfFixture) {
			f["-a * -sr"] = append(f["-a * -sr"], pfReply{text: "anchor \"com.apple/*\" all\n"})
		},
		"orphan filter": func(_ *Config, _ *[]netip.Addr, f pfFixture) {
			f["-sr"] = []pfReply{{text: "anchor \"unrelated/*\" all\n"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			c, hosts, f := guestPFFixture()
			change(&c, &hosts, f)
			o := Observation{JobUID: 550, RootRulesSHA256: "previous-digest", AnchorRulesSHA256: "previous-anchor"}
			if err := observePFWithCommand(context.Background(), c, hosts, &o, f.command); err == nil {
				t.Fatal("unsafe coexistence accepted")
			}
			if o.RootRulesSHA256 != "" || o.AnchorRulesSHA256 != "" {
				t.Fatal("failed observation retained usable approval bindings")
			}
		})
	}
}

func TestPFObservationRejectsFilterBypassAndBindsSafeSiblingChanges(t *testing.T) {
	f := stockPFFixture()
	o := Observation{JobUID: 550}
	if err := observePFWithCommand(context.Background(), Config{}, nil, &o, f.command); err != nil {
		t.Fatal(err)
	}
	before := o.RootRulesSHA256
	// A nonquick pass is safe only because the later owned catchall denies
	// terminate every protected domain. Its exact text still binds approval.
	f["-a com.apple/empty -sr"] = []pfReply{{text: "pass out all\n"}}
	if err := observePFWithCommand(context.Background(), Config{}, nil, &o, f.command); err != nil {
		t.Fatal(err)
	}
	if o.RootRulesSHA256 == before {
		t.Fatal("safe sibling change did not invalidate previous qualification")
	}
	f["-a com.apple/empty -sr"] = []pfReply{{text: "pass out quick all\n"}}
	if err := observePFWithCommand(context.Background(), Config{}, nil, &o, f.command); err == nil {
		t.Fatal("earlier sibling quick pass bypass accepted")
	}
	if o.RootRulesSHA256 != "" || o.AnchorRulesSHA256 != "" {
		t.Fatal("unsafe filter observation published qualification bindings")
	}
}

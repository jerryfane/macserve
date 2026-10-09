package maintenance

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

const stockTranslationCalls = "nat-anchor \"com.apple/*\" all\nrdr-anchor \"com.apple/*\" all\n"

type pfReply struct {
	text string
	err  error
}

type pfFixture map[string][]pfReply

func stockPFFixture() pfFixture {
	return pfFixture{
		"-s info":                              {{text: "Status: Enabled for 0 days 00:00:01           Debug: Urgent\n"}},
		"-i lo0 -v -s Interfaces":              {{text: "lo0\n"}},
		"-a * -sr":                             {{text: "anchor \"com.apple/*\" all {\n}\nanchor \"org.macserve\" all {\nblock drop out quick all\n}\n"}},
		"-a org.macserve -sr":                  {{text: "block drop out quick all\n"}},
		"-v -s Anchors":                        {{text: "  com.apple\n  com.apple/empty\n  org.macserve\n"}},
		"-a  -sn":                              {{text: stockTranslationCalls}},
		"-a com.apple -sn":                     {{}},
		"-a com.apple/empty -sn":               {{}},
		"-a org.macserve -sn":                  {{}},
		"-a _pf -v -s Anchors":                 {{err: errPFAnchorAbsent}},
		"-a com.apple/_pf -v -s Anchors":       {{err: errPFAnchorAbsent}},
		"-a com.apple/empty/_pf -v -s Anchors": {{err: errPFAnchorAbsent}},
		"-a org.macserve/_pf -v -s Anchors":    {{err: errPFAnchorAbsent}},
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
	if err := observePFWithCommand(context.Background(), &o, stockPFFixture().command); err != nil {
		t.Fatal(err)
	}
	q.RootRulesSHA256 = o.RootRulesSHA256
	q.AnchorRulesSHA256 = o.AnchorRulesSHA256
	if h, err := Evaluate(now, q, e, o); err != nil || !h.BoundaryValidated {
		t.Fatalf("stock empty translation anchors cannot qualify: %v", err)
	}

	changed := stockPFFixture()
	changed["-a  -sn"] = []pfReply{{text: "nat-anchor \"com.apple/*\" all\n"}}
	if err := observePFWithCommand(context.Background(), &o, changed.command); err != nil {
		t.Fatal(err)
	}
	if h, err := Evaluate(now, q, e, o); err == nil || h.BoundaryValidated {
		t.Fatal("translation call change retained qualification")
	}

	changed = stockPFFixture()
	changed["-v -s Anchors"] = []pfReply{{text: "  com.apple\n  org.macserve\n"}}
	if err := observePFWithCommand(context.Background(), &o, changed.command); err != nil {
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
		"truncated listing": func(f pfFixture) { f["-v -s Anchors"] = []pfReply{{text: "  com.apple\n  org.macserve"}} },
		"duplicate listing": func(f pfFixture) { f["-v -s Anchors"] = []pfReply{{text: "  com.apple\n  com.apple\n"}} },
		"omitted parent":    func(f pfFixture) { f["-v -s Anchors"] = []pfReply{{text: "  com.apple/empty\n  org.macserve\n"}} },
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
			f["-v -s Anchors"] = append(f["-v -s Anchors"], pfReply{text: "  com.apple\n  org.macserve\n"})
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
			var o Observation
			if err := observePFWithCommand(context.Background(), &o, f.command); err == nil {
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
	f["-a com.apple/_pf/_pf -v -s Anchors"] = []pfReply{{err: errPFAnchorAbsent}}
	f["-a com.apple/_pf/hidden/_pf -v -s Anchors"] = []pfReply{{err: errPFAnchorAbsent}}
	f["-a com.apple/_pf -sn"] = []pfReply{{}}
	f["-a com.apple/_pf/hidden -sn"] = []pfReply{{}}
	var o Observation
	if err := observePFWithCommand(context.Background(), &o, f.command); err != nil {
		t.Fatalf("empty reserved subtree refused: %v", err)
	}
	f["-a com.apple/_pf/hidden -sn"] = []pfReply{{text: "rdr inet from any to any -> 127.0.0.1\n"}}
	if err := observePFWithCommand(context.Background(), &o, f.command); err == nil {
		t.Fatal("mapping hidden under reserved anchor accepted")
	}
}

func TestPFObservationHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var o Observation
	if err := observePFWithCommand(ctx, &o, stockPFFixture().command); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want cancellation", err)
	}
}

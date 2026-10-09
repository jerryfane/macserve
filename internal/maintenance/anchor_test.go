package maintenance

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/pfctl"
)

const ownedFilterRules = "block drop out log quick proto tcp all user = 550 label \"macserve-default-deny\"\nblock drop out log quick proto udp all user = 550 label \"macserve-default-deny\"\n"

func mandatoryFilterRules() string {
	var rules strings.Builder
	for _, destination := range []string{"127.0.0.0/8", "169.254.0.0/16", "::1", "fe80::/10"} {
		family := "inet"
		if strings.Contains(destination, ":") {
			family = "inet6"
		}
		for _, protocol := range []string{"tcp", "udp"} {
			fmt.Fprintf(&rules, "block drop out log quick %s proto %s from any to %s user = 550 label \"macserve-private\"\n", family, protocol, destination)
		}
	}
	return rules.String()
}

type filterRulesFixture map[string]string

func (f filterRulesFixture) snapshot() []pfTranslation {
	paths := map[string]bool{"": true}
	for path := range f {
		for path != "" {
			paths[path] = true
			i := strings.LastIndexByte(path, '/')
			if i < 0 {
				break
			}
			path = path[:i]
		}
	}
	sorted := make([]string, 0, len(paths))
	for path := range paths {
		sorted = append(sorted, path)
	}
	slices.Sort(sorted)
	out := make([]pfTranslation, 0, len(sorted))
	for _, path := range sorted {
		out = append(out, pfTranslation{path, f[path]})
	}
	return out
}

func (f filterRulesFixture) query(_ context.Context, args ...string) (string, error) {
	switch {
	case slices.Equal(args, []string{"-v", "-s", "Anchors"}):
		var out strings.Builder
		for _, item := range f.snapshot() {
			if item.Path != "" {
				fmt.Fprintf(&out, "  %s\n", item.Path)
			}
		}
		return out.String(), nil
	case len(args) == 5 && args[0] == "-a" && args[2] == "-v":
		return "", pfctl.ErrAnchorAbsent
	case slices.Equal(args, []string{"-sr"}):
		return f[""], nil
	case len(args) == 3 && args[0] == "-a" && args[2] == "-sr":
		for _, item := range f.snapshot() {
			if item.Path == args[1] {
				return item.Rules, nil
			}
		}
	}
	return "", fmt.Errorf("unexpected filter query %v", args)
}

func TestFilterEvaluationOrder(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		root, before, own, after string
		want                     bool
	}{
		{"stock auxiliary calls", "scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all\ndummynet-anchor \"com.apple/*\" all\n", "", ownedFilterRules, "", true},
		{"earlier root quick bypass", "pass out quick proto tcp from any to 203.0.113.8 port = 443\nanchor \"com.apple/*\" all\n", "", ownedFilterRules, "", false},
		{"earlier sibling quick bypass", "", "pass out quick all\n", ownedFilterRules, "", false},
		{"interface is not disjoint", "", "pass out quick on en0 all\n", ownedFilterRules, "", false},
		{"other uid is disjoint", "", "pass out quick all user = 551\n", ownedFilterRules, "", true},
		{"incoming is disjoint", "", "pass in quick all\n", ownedFilterRules, "", true},
		{"icmp is disjoint", "", "pass out quick proto icmp all\n", ownedFilterRules, "", true},
		{"nonquick sibling overridden", "", "pass out all\n", ownedFilterRules, "", true},
		{"reviewed own exception after mandatory boundary", "", "pass out all\n", mandatoryFilterRules() + "pass out quick proto tcp from any to 203.0.113.9 port = 443 user = 550 flags S/SA keep state label \"reviewed-https\"\n" + ownedFilterRules, "", true},
		{"local exception before mandatory boundary", "", "", "pass out quick proto tcp from any to ::1 port = 443 user = 550\n" + mandatoryFilterRules() + ownedFilterRules, "", false},
		{"local exception after mandatory boundary cannot bypass", "", "", mandatoryFilterRules() + "pass out quick proto tcp from any to ::1 port = 443 user = 550\n" + ownedFilterRules, "", true},
		{"partial mandatory boundary before pass", "", "", strings.Replace(mandatoryFilterRules(), "inet6 proto udp from any to fe80::/10", "inet6 proto tcp from any to fe80::/10", 1) + "pass out quick proto tcp from any to fe80::1 port = 443 user = 550\n" + ownedFilterRules, "", false},
		{"interface scoped mandatory boundary", "", "", strings.ReplaceAll(mandatoryFilterRules(), "quick ", "quick on lo0 ") + "pass out quick all user = 550\n" + ownedFilterRules, "", false},
		{"port scoped mandatory boundary", "", "", strings.ReplaceAll(mandatoryFilterRules(), " user", " port = 443 user") + "pass out quick all user = 550\n" + ownedFilterRules, "", false},
		{"source scoped mandatory boundary", "", "", strings.ReplaceAll(mandatoryFilterRules(), "from any", "from 192.0.2.1") + "pass out quick all user = 550\n" + ownedFilterRules, "", false},
		{"family split catchalls override", "", "pass out all\n", "block drop out quick inet all user = 550\nblock drop out quick inet6 all user = 550\n", "", true},
		{"nonquick root overridden", "pass out all\nanchor \"com.apple/*\" all\n", "", ownedFilterRules, "", true},
		{"nonquick survives narrow deny", "", "pass out all\n", "block drop out quick proto tcp from any to 192.0.2.1 user = 550\n", "", false},
		{"tcp only deny leaves udp", "", "pass out all\n", "block drop out quick proto tcp all user = 550\n", "", false},
		{"v4 only deny leaves v6", "", "pass out all\n", "block drop out quick inet all user = 550\n", "", false},
		{"interface deny cannot override", "", "pass out all\n", "block drop out quick on lo0 all user = 550\n", "", false},
		{"later sibling quick unreachable", "", "", ownedFilterRules, "pass out quick all\n", true},
		{"later main quick unreachable", "anchor \"com.apple/*\" all\npass out quick all\n", "", ownedFilterRules, "", true},
		{"later sibling bypass without terminal deny", "", "", "block drop out proto tcp all user = 550\n", "pass out quick all\n", false},
		{"later main nonquick survives", "anchor \"com.apple/*\" all\npass out all\n", "", "block drop out all user = 550\n", "", false},
		{"later sibling nonquick survives", "", "", "block drop out all user = 550\n", "pass out all\n", false},
		{"later blanket block overrides nonquick", "anchor \"com.apple/*\" all\nblock drop out all\n", "pass out all\n", mandatoryFilterRules() + "block drop out proto tcp all user = 550\n", "", true},
		{"unknown syntax even disjoint", "", "pass in quick all probability 10%\n", ownedFilterRules, "", false},
		{"unknown syntax after terminal deny", "", "", ownedFilterRules, "pass out all probability 10%\n", false},
		{"wrong own uid cannot protect", "", "pass out all\n", "block drop out quick all user = 551\n", "", false},
		{"missing own uid cannot protect", "", "pass out all\n", "block drop out quick all\n", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := tc.root
			if root == "" {
				root = "anchor \"com.apple/*\" all\n"
			}
			f := filterRulesFixture{"": root, "com.apple/aaa": tc.before, "com.apple/macserve": tc.own, "com.apple/zzz": tc.after}
			// Reverse inventory order: neither map nor listing order determines
			// the order in which wildcard children execute.
			snapshot := f.snapshot()
			slices.Reverse(snapshot)
			err := proveFilterOrder("com.apple/macserve", 550, snapshot)
			if (err == nil) != tc.want {
				t.Fatalf("accepted=%v want=%v: %v", err == nil, tc.want, err)
			}
		})
	}
}

func TestFilterAnchorCalls(t *testing.T) {
	for name, f := range map[string]filterRulesFixture{
		"exact nested skips parent rules": {"": "anchor \"custom/service\" all\n", "custom": "pass out quick all\n", "custom/service": ownedFilterRules},
		"relative wildcard":               {"": "anchor \"custom\" all\n", "custom": "anchor \"*\" all\n", "custom/service": ownedFilterRules},
		"absolute from another branch":    {"": "anchor \"entry\" all\n", "entry": "anchor \"/custom/service\" all\n", "custom/service": ownedFilterRules},
		"absolute wildcard":               {"": "anchor \"entry\" all\n", "entry": "anchor \"/custom/*\" all\n", "custom/service": ownedFilterRules},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := observeFilterOrder(context.Background(), "custom/service", 550, f.query); err != nil {
				t.Fatal(err)
			}
		})
	}
	for name, root := range map[string]string{
		"orphan":                      "block drop all\n",
		"scrub is not filter edge":    "scrub-anchor \"custom/service\" all\n",
		"dummynet is not filter edge": "dummynet-anchor \"custom/service\" all\n",
		"wildcard not recursive":      "anchor \"*\" all\n",
		"conditional":                 "anchor \"custom/service\" out all\n",
		"quick call":                  "anchor \"custom/service\" quick all\n",
		"truncated":                   "anchor \"custom/service\" all",
		"recursive output":            "anchor \"custom/service\" all {\n}\n",
		"parent reference":            "anchor \"../custom/service\" all\n",
		"double slash wildcard":       "anchor \"//*\" all\n",
		"partial wildcard":            "anchor \"custom/serv*\" all\n",
		"multiline label":             "pass all label \"note\nanchor \"custom/service\" all\n\"\n",
		"unknown match":               "pass out all user != 551\nanchor \"custom/service\" all\n",
	} {
		t.Run(name, func(t *testing.T) {
			f := filterRulesFixture{"": root, "custom/service": ownedFilterRules}
			if _, err := observeFilterOrder(context.Background(), "custom/service", 550, f.query); err == nil {
				t.Fatal("unproven graph accepted")
			}
		})
	}
}

func TestFilterAnchorUnsupportedPrintForms(t *testing.T) {
	for _, kind := range []string{"anchor", "scrub-anchor", "dummynet-anchor", "nat-anchor", "rdr-anchor", "binat-anchor"} {
		for _, form := range []string{
			"\"custom/*\" out all",
			"\"custom/*\" quick all",
			"quick \"custom/*\" all",
			"\"custom/*\" all fragment",
			"\"custom/*\" all fragment reassemble extra",
			"\"custom/*\" out all fragment reassemble",
			"quick \"custom/*\" all fragment reassemble",
			"\"custom/*\" all fragment reassemble",
		} {
			if kind == "scrub-anchor" && form == "\"custom/*\" all fragment reassemble" {
				continue
			}
			t.Run(kind+" "+form, func(t *testing.T) {
				f := filterRulesFixture{
					"":               kind + " " + form + "\nanchor \"custom/*\" all\n",
					"custom/service": ownedFilterRules,
				}
				if _, err := observeFilterOrder(context.Background(), "custom/service", 550, f.query); err == nil {
					t.Fatal("unsupported anchor print form accepted")
				}
			})
		}
	}
}

func TestFilterSnapshotStabilityAndFailure(t *testing.T) {
	for _, change := range []string{"root", "sibling", "inventory", "error", "cancel"} {
		t.Run(change, func(t *testing.T) {
			f := filterRulesFixture{"": "anchor \"custom/*\" all\n", "custom/service": ownedFilterRules, "custom/aaa": ""}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			counts := map[string]int{}
			query := func(ctx context.Context, args ...string) (string, error) {
				key := strings.Join(args, " ")
				counts[key]++
				if change == "error" && key == "-a custom/aaa -sr" {
					return "", errors.New("permission denied")
				}
				if change == "cancel" {
					cancel()
				}
				if counts[key] > 1 {
					switch {
					case change == "root" && key == "-sr", change == "sibling" && key == "-a custom/aaa -sr":
						return "pass out quick all\n", nil
					case change == "inventory" && key == "-v -s Anchors":
						return "  custom\n  custom/service\n", nil
					}
				}
				return f.query(ctx, args...)
			}
			if _, err := observeFilterOrder(ctx, "custom/service", 550, query); err == nil {
				t.Fatal("unstable or incomplete filter proof accepted")
			}
		})
	}
}

func TestFilterEvaluationBounds(t *testing.T) {
	f := filterRulesFixture{"": "anchor \"custom\" all\n", "custom": ownedFilterRules}
	for _, uid := range []uint32{0, 500} {
		if _, err := observeFilterOrder(context.Background(), "custom", uid, f.query); err == nil {
			t.Fatal("missing/invalid UID accepted")
		}
	}
	for _, path := range []string{"", "custom/*", "/custom", "custom/../service", strings.Repeat("a/", 8) + "b"} {
		if _, err := observeFilterOrder(context.Background(), path, 550, f.query); err == nil {
			t.Fatalf("invalid selected path %q accepted", path)
		}
	}
	for name, f := range map[string]filterRulesFixture{
		"cycle":        {"": "anchor \"entry\" all\n", "entry": "anchor \"/entry\" all\nanchor \"/custom\" all\n", "custom": ownedFilterRules},
		"oversized":    {"": strings.Repeat("x", (1<<20)+1), "custom": ownedFilterRules},
		"excess rules": {"": strings.Repeat("block all\n", 65537), "custom": ownedFilterRules},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := observeFilterOrder(context.Background(), "custom", 550, f.query); err == nil {
				t.Fatal("unbounded filter proof accepted")
			}
		})
	}
	// A small DAG can expand exponentially when calls are repeated. Bound
	// evaluated visits, not just the number of distinct loaded anchors.
	f = filterRulesFixture{"": "anchor \"a0\" all\nanchor \"custom\" all\n", "custom": ownedFilterRules}
	for i := range 8 {
		f[fmt.Sprintf("a%d", i)] = strings.Repeat(fmt.Sprintf("anchor \"/a%d\" all\n", i+1), 4)
	}
	f["a8"] = ""
	if _, err := observeFilterOrder(context.Background(), "custom", 550, f.query); err == nil {
		t.Fatal("unbounded repeated calls accepted")
	}
}

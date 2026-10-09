package maintenance

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Keys are loaded ruleset paths, not an anchor inventory. A ruleset's mere
// presence here must never establish its attachment to the root filter graph.
type filterRulesFixture map[string]string

func (f filterRulesFixture) query(_ context.Context, args ...string) (string, error) {
	path := ""
	switch {
	case len(args) == 1 && args[0] == "-sr":
	case len(args) == 3 && args[0] == "-a" && args[2] == "-sr":
		path = args[1]
	default:
		return "", fmt.Errorf("not a direct filter query: %v", args)
	}
	text, ok := f[path]
	if !ok {
		return "", fmt.Errorf("ruleset %q unavailable", path)
	}
	return text, nil
}

func TestFilterAnchorReachableGraphs(t *testing.T) {
	cases := []struct {
		name  string
		path  string
		rules filterRulesFixture
	}{
		{
			name: "stock wildcard without standalone root call",
			path: "com.apple/macserve",
			rules: filterRulesFixture{
				"":                   "anchor \"com.apple/*\" all\n",
				"com.apple/macserve": "block drop out quick all\n",
			},
		},
		{
			name: "exact top level",
			path: "custom",
			rules: filterRulesFixture{
				"":       "anchor \"custom\" all\n",
				"custom": "block drop out quick all\n",
			},
		},
		{
			name: "exact nested reference skips parent rules",
			path: "custom/service",
			rules: filterRulesFixture{
				"":               "anchor \"custom/service\" all\n",
				"custom":         "anchor \"unrelated\" out all\n",
				"custom/service": "block drop out quick all\n",
			},
		},
		{
			name: "relative nested calls",
			path: "custom/service/guard",
			rules: filterRulesFixture{
				"":                     "anchor \"custom\" all\n",
				"custom":               "anchor \"service\" all\n",
				"custom/service":       "anchor \"guard\" all\n",
				"custom/service/guard": "block drop out quick all\n",
			},
		},
		{
			name: "wildcard child requires further call",
			path: "custom/service/guard",
			rules: filterRulesFixture{
				"":                     "anchor \"custom/*\" all\n",
				"custom/service":       "anchor \"guard\" all\n",
				"custom/service/guard": "block drop out quick all\n",
			},
		},
		{
			name: "absolute call from different branch",
			path: "custom/service",
			rules: filterRulesFixture{
				"":               "anchor \"entry\" all\n",
				"entry":          "anchor \"/custom/service\" all\n",
				"custom/service": "block drop out quick all\n",
			},
		},
		{
			name: "relative wildcard",
			path: "custom/service",
			rules: filterRulesFixture{
				"":               "anchor \"custom\" all\n",
				"custom":         "anchor \"*\" all\n",
				"custom/service": "block drop out quick all\n",
			},
		},
		{
			name: "absolute wildcard",
			path: "custom/service",
			rules: filterRulesFixture{
				"":               "anchor \"entry\" all\n",
				"entry":          "anchor \"/custom/*\" all\n",
				"custom/service": "block drop out quick all\n",
			},
		},
		{
			name: "cycle does not hide independent route",
			path: "custom",
			rules: filterRulesFixture{
				"":       "anchor \"entry\" all\n",
				"entry":  "anchor \"/entry\" all\nanchor \"/custom\" all\n",
				"custom": "block drop out quick all\n",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := filterAnchorReachable(context.Background(), tc.path, tc.rules.query); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFilterAnchorRefusesUnprovenGraphs(t *testing.T) {
	cases := map[string]string{
		"orphan":                         "block drop all\n",
		"comment":                        "# anchor \"custom/service\" all\n",
		"label":                          "pass all label \"anchor custom/service all\"\n",
		"multiline label":                "pass all label \"note\nanchor \"custom/service\" all\n\"\n",
		"translation only":               "nat-anchor \"custom/service\" all\nrdr-anchor \"custom/service\" all\nbinat-anchor \"custom/service\" all\n",
		"prefix confusion":               "anchor \"custom/service-other\" all\n",
		"wildcard prefix confusion":      "anchor \"customized/*\" all\n",
		"wildcard does not reach parent": "anchor \"custom/service/*\" all\n",
		"wildcard not recursive":         "anchor \"*\" all\n",
		"direction":                      "anchor \"custom/service\" out all\n",
		"interface":                      "anchor \"custom/service\" on lo0 all\n",
		"family":                         "anchor \"custom/service\" inet all\n",
		"protocol":                       "anchor \"custom/service\" inet proto tcp all\n",
		"source":                         "anchor \"custom/service\" from 192.0.2.1 to any\n",
		"quick modifier":                 "anchor \"custom/service\" quick all\n",
		"trailing label":                 "anchor \"custom/service\" all label \"note\"\n",
		"unquoted":                       "anchor custom/service all\n",
		"missing all":                    "anchor \"custom/service\"\n",
		"truncated":                      "anchor \"custom/service\" all",
		"recursive output":               "anchor \"unattached\" all {\nanchor \"custom/service\" all\n}\n",
		"anonymous inline":               "anchor all {\nanchor \"custom/service\" all\n}\n",
		"parent path":                    "anchor \"../custom/service\" all\n",
		"double absolute slash":          "anchor \"//custom/service\" all\n",
		"double absolute wildcard slash": "anchor \"//*\" all\n",
		"partial wildcard":               "anchor \"custom/serv*\" all\n",
		"escaped name":                   "anchor \"custom/serv\\ice\" all\n",
		"cycle":                          "anchor \"entry\" all\n",
	}
	for name, root := range cases {
		t.Run(name, func(t *testing.T) {
			f := filterRulesFixture{
				"":                     root,
				"custom":               "block drop all\n",
				"custom/service":       "block drop out quick all\n",
				"custom/service-other": "block drop all\n",
				"entry":                "anchor \"/other\" all\n",
				"other":                "anchor \"/entry\" all\n",
			}
			if err := filterAnchorReachable(context.Background(), "custom/service", f.query); err == nil {
				t.Fatal("unproven selected anchor accepted")
			}
		})
	}
}

func TestFilterAnchorReadFailuresAndCancellation(t *testing.T) {
	failure := errors.New("filter read unavailable")
	for _, failedPath := range []string{"", "entry", "custom"} {
		f := filterRulesFixture{
			"":       "anchor \"entry\" all\n",
			"entry":  "anchor \"/custom\" all\n",
			"custom": "block drop all\n",
		}
		query := func(ctx context.Context, args ...string) (string, error) {
			if failedPath == "" && len(args) == 1 || len(args) == 3 && args[1] == failedPath {
				return "", failure
			}
			return f.query(ctx, args...)
		}
		if err := filterAnchorReachable(context.Background(), "custom", query); !errors.Is(err, failure) {
			t.Fatalf("failure at %q: got %v", failedPath, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := filterAnchorReachable(ctx, "custom", filterRulesFixture{}.query); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled context: %v", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	query := func(context.Context, ...string) (string, error) {
		cancel()
		return "anchor \"custom\" all\n", nil
	}
	if err := filterAnchorReachable(ctx, "custom", query); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation during query: %v", err)
	}
}

func TestFilterAnchorTraversalBounds(t *testing.T) {
	for _, path := range []string{"", "custom/*", "/custom", "custom/../service", strings.Repeat("a/", 8) + "b"} {
		if err := filterAnchorReachable(context.Background(), path, filterRulesFixture{"": ""}.query); err == nil {
			t.Fatalf("invalid selected path %q accepted", path)
		}
	}
	f := filterRulesFixture{"": strings.Repeat("x", (1<<20)+1)}
	if err := filterAnchorReachable(context.Background(), "custom", f.query); err == nil {
		t.Fatal("oversized direct output accepted")
	}
	f = filterRulesFixture{}
	var root strings.Builder
	for i := range 65 {
		name := fmt.Sprintf("branch%d", i)
		fmt.Fprintf(&root, "anchor %q all\n", name)
		f[name] = ""
	}
	f[""] = root.String() + "anchor \"custom\" all\n"
	f["custom"] = "block drop all\n"
	if err := filterAnchorReachable(context.Background(), "custom", f.query); err == nil {
		t.Fatal("unbounded graph accepted")
	}
	f = filterRulesFixture{"": "anchor \"a\" all\n"}
	for i := range 8 {
		f[strings.TrimSuffix(strings.Repeat("a/", i+1), "/")] = "anchor \"a\" all\n"
	}
	if err := filterAnchorReachable(context.Background(), "custom", f.query); err == nil {
		t.Fatal("unbounded relative depth accepted")
	}
}

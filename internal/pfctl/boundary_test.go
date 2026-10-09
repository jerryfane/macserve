package pfctl

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

const mandatorySource = "local = \"{ 127.0.0.0/8, 169.254.0.0/16, ::1, fe80::/10 }\"\nblock drop out quick proto { tcp udp } from any to $local user 1502 label \"macserve-private\"\n"
const localPass = "pass out quick proto tcp from any to ::1 port 443 user 1502 label \"reviewed-local\"\n"

func TestMandatoryBoundaryBeforeEditedPolicyPass(t *testing.T) {
	for _, tc := range []struct {
		name, source string
		want         bool
	}{
		{"fixed ranges before local exception", mandatorySource + localPass + ownedRules, true},
		{"pass before mandatory deny", localPass + mandatorySource + ownedRules, false},
		{"nonquick pass before deny", strings.Replace(localPass, " quick", "", 1) + mandatorySource + ownedRules, false},
		{"public pass still requires early coverage", strings.Replace(localPass, "::1", "203.0.113.10", 1) + mandatorySource + ownedRules, false},
		{"catchall before pass", ownedRules + localPass, true},
		{"missing loopback", strings.Replace(mandatorySource, "127.0.0.0/8, ", "", 1) + localPass + ownedRules, false},
		{"missing ipv6 loopback", strings.Replace(mandatorySource, "::1, ", "", 1) + localPass + ownedRules, false},
		{"missing ipv4 link local", strings.Replace(mandatorySource, "169.254.0.0/16, ", "", 1) + localPass + ownedRules, false},
		{"missing ipv6 link local", strings.Replace(mandatorySource, "fe80::/10", "2001:db8::/32", 1) + localPass + ownedRules, false},
		{"tcp alone", strings.Replace(mandatorySource, "{ tcp udp }", "tcp", 1) + localPass + ownedRules, false},
		{"udp alone", strings.Replace(mandatorySource, "{ tcp udp }", "udp", 1) + localPass + ownedRules, false},
		{"nonquick deny", strings.Replace(mandatorySource, " quick", "", 1) + localPass + ownedRules, false},
		{"port restricted deny", strings.Replace(mandatorySource, "to $local", "to $local port 443", 1) + localPass + ownedRules, false},
		{"source restricted deny", strings.Replace(mandatorySource, "from any", "from 192.0.2.1", 1) + localPass + ownedRules, false},
		{"family restricted deny", strings.Replace(mandatorySource, "proto", "inet6 proto", 1) + localPass + ownedRules, false},
		{"narrow loopback deny", strings.Replace(mandatorySource, "127.0.0.0/8", "127.0.0.1", 1) + localPass + ownedRules, false},
		{"narrow link local deny", strings.Replace(mandatorySource, "fe80::/10", "fe80::/64", 1) + localPass + ownedRules, false},
		{"broader safe deny", strings.Replace(strings.Replace(mandatorySource, "127.0.0.0/8", "0.0.0.0/0", 1), "fe80::/10", "::/0", 1) + localPass + ownedRules, true},
		{"mandatory even without passes", strings.ReplaceAll(ownedRules, "quick ", ""), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePolicy(tc.source, 1502)
			if (err == nil) != tc.want {
				t.Fatalf("accepted=%v want=%v: %v", err == nil, tc.want, err)
			}
			if !tc.want {
				c, calls := recordingClient(t)
				if _, err := c.Load(context.Background(), policyPath(t, tc.source), LoadOptions{JobUID: 1502}); err == nil || len(*calls) != 0 {
					t.Fatal("unsafe staged policy reached native PF")
				}
			}
		})
	}
}

func normalizedMandatoryRules() string {
	var text strings.Builder
	for _, destination := range []string{"127.0.0.0/8", "169.254.0.0/16", "::1", "fe80::/10"} {
		family := "inet"
		if strings.Contains(destination, ":") {
			family = "inet6"
		}
		for _, protocol := range []string{"tcp", "udp"} {
			fmt.Fprintf(&text, "block drop out log quick %s proto %s from any to %s user = 1502 label \"macserve-private\"\n", family, protocol, destination)
		}
	}
	return text.String()
}

func TestMandatoryBoundaryNormalizedCoverage(t *testing.T) {
	fixed := normalizedMandatoryRules()
	pass := strings.Replace(localPass, "port 443", "port = 443", 1)
	for _, tc := range []struct {
		name, rules string
		want        bool
	}{
		{"expanded fixed deny", fixed + pass + ownedRules, true},
		{"pass too early", pass + fixed + ownedRules, false},
		{"missing udp for one range", strings.Replace(fixed, "inet6 proto udp from any to fe80::/10", "inet6 proto tcp from any to fe80::/10", 1) + pass + ownedRules, false},
		{"interface conditional", strings.ReplaceAll(fixed, "quick ", "quick on lo0 ") + pass + ownedRules, false},
		{"source conditional", strings.ReplaceAll(fixed, "from any", "from 192.0.2.1") + pass + ownedRules, false},
		{"port conditional", strings.ReplaceAll(fixed, " user", " port = 443 user") + pass + ownedRules, false},
		{"unknown predicate", strings.ReplaceAll(fixed, " user", " probability 50% user") + pass + ownedRules, false},
		{"tcp flags conditional", strings.ReplaceAll(fixed, " user", " flags S/SA user") + pass + ownedRules, false},
		{"wrong uid", strings.ReplaceAll(fixed, "1502", "1503") + pass + ownedRules, false},
		{"incoming", strings.ReplaceAll(fixed, " out ", " in ") + pass + ownedRules, false},
		{"nonquick even without passes", strings.ReplaceAll(ownedRules, "quick ", ""), false},
		{"incomplete output", strings.TrimSuffix(fixed+ownedRules, "\n"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateMandatoryDeny(tc.rules, 1502); (err == nil) != tc.want {
				t.Fatalf("boundary accepted=%v want=%v: %v", err == nil, tc.want, err)
			}
		})
	}
}

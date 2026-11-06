package signer

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseProfileAcceptsAppStoreProfile(t *testing.T) {
	raw := defaultProfile(appID).xml()
	p, err := parseProfile(raw, raw, appID, fixtureTeam, strings.ToLower(fixtureIdentity()), fixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	if p.UUID != uuidFor(appID) || p.TeamID != fixtureTeam || p.SHA256 != digestHex(raw) || p.Entitlements["aps-environment"] != "production" {
		t.Fatalf("profile %+v", p)
	}
}

// Every profile that is not this bundle's App Store distribution profile
// for the configured certificate is refused.
func TestParseProfileRefusals(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*profileSpec)
		want   string
	}{
		{"provisioned devices", func(p *profileSpec) { p.devices = true }, "ProvisionedDevices"},
		{"all devices", func(p *profileSpec) { p.allDevices = true }, "ProvisionsAllDevices"},
		{"expired", func(p *profileSpec) { p.expires = fixtureNow.Add(-time.Minute) }, "expired"},
		{"wrong team", func(p *profileSpec) { p.team = "ZZZZZ99999" }, "TeamIdentifier"},
		{"wrong team entitlement", func(p *profileSpec) { p.teamEntitlment = "ZZZZZ99999" }, "team-identifier"},
		{"wrong app id", func(p *profileSpec) { p.appID = fixtureTeam + ".com.example.other" }, "application-identifier"},
		{"wildcard app id", func(p *profileSpec) { p.appID = fixtureTeam + ".*" }, "application-identifier"},
		{"missing certificate", func(p *profileSpec) { p.certificate = []byte("someone-else") }, "distribution certificate"},
		{"get-task-allow", func(p *profileSpec) { p.getTaskAllow = true }, "get-task-allow"},
		{"no beta reports marker", func(p *profileSpec) { p.noBetaReports = true }, "beta-reports-active"},
		{"macOS platform", func(p *profileSpec) { p.platform = "OSX" }, "iOS"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec := defaultProfile(appID)
			c.mutate(&spec)
			raw := spec.xml()
			_, err := parseProfile(raw, raw, appID, fixtureTeam, fixtureIdentity(), fixtureNow)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error = %v; want %q", err, c.want)
			}
		})
	}
}

func testProfile(t *testing.T) Profile {
	t.Helper()
	raw := defaultProfile(appID).xml()
	p, err := parseProfile(raw, raw, appID, fixtureTeam, fixtureIdentity(), fixtureNow)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFinalEntitlementsDerivesProfileIdentifiers(t *testing.T) {
	requested := json.RawMessage(`{"aps-environment":"development","com.apple.developer.associated-domains":["applinks:example.com"],"keychain-access-groups":["$(AppIdentifierPrefix)com.example.shared"]}`)
	got, err := finalEntitlements(requested, testProfile(t), []string{"aps-environment"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"application-identifier":                 fixtureTeam + "." + appID,
		"com.apple.developer.team-identifier":    fixtureTeam,
		"get-task-allow":                         false,
		"beta-reports-active":                    true,
		"aps-environment":                        "production",
		"com.apple.developer.associated-domains": []any{"applinks:example.com"},
		"keychain-access-groups":                 []any{fixtureTeam + ".com.example.shared"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("entitlements %#v", got)
	}
}

// Requested keys the profile lacks, values it does not allow, malformed
// values and missing required keys are refused.
func TestFinalEntitlementsRefusals(t *testing.T) {
	cases := []struct {
		name      string
		requested string
		required  []string
		want      string
	}{
		{"key not in profile", `{"com.apple.developer.healthkit":true}`, nil, "not in the profile"},
		{"app group not allowed", `{"com.apple.security.application-groups":["group.com.other"]}`, nil, "not allowed"},
		{"keychain group of another team", `{"keychain-access-groups":["ZZZZZ99999.com.example.app"]}`, nil, "not allowed"},
		{"malformed array entry", `{"com.apple.security.application-groups":[7]}`, nil, "malformed"},
		{"duplicate array entry", `{"com.apple.security.application-groups":["group.com.example.shared","group.com.example.shared"]}`, nil, "duplicate"},
		{"object for array", `{"com.apple.security.application-groups":{"a":"b"}}`, nil, "malformed"},
		{"malformed aps-environment", `{"aps-environment":"staging"}`, nil, "malformed"},
		{"get-task-allow true", `{"get-task-allow":true}`, nil, "not allowed"},
		{"unresolved build setting", `{"keychain-access-groups":["$(PRODUCT_BUNDLE_IDENTIFIER)"]}`, nil, "unresolved"},
		{"foreign application-identifier", `{"application-identifier":"ABCDE12345.com.example.other"}`, nil, "contradicts"},
		{"null value", `{"aps-environment":null}`, nil, "null"},
		{"missing required", `{}`, []string{"aps-environment"}, "required aps-environment"},
		{"not an object", `[]`, nil, "not a JSON object"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := finalEntitlements(json.RawMessage(c.requested), testProfile(t), c.required)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error = %v; want %q", err, c.want)
			}
		})
	}
}

func TestPlistRoundTripAndStrictness(t *testing.T) {
	value := map[string]any{"a": []any{"x", int64(3), true, 1.5}, "b": map[string]any{"c": false}, "esc": "<&>"}
	encoded, err := encodePlist(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodePlist(encoded)
	if err != nil || !reflect.DeepEqual(decoded, value) {
		t.Fatalf("round trip %#v %v", decoded, err)
	}
	again, _ := encodePlist(value)
	if string(again) != string(encoded) {
		t.Fatal("encoding is not deterministic")
	}
	for _, bad := range []string{
		`<plist><dict><key>a</key><key>b</key></dict></plist>`,
		`<plist><dict><key>a</key><string>1</string><key>a</key><string>2</string></dict></plist>`,
		`<plist><dict><key>a</key></dict></plist>`,
		`<plist><string>a</string><string>b</string></plist>`,
		`<plist><integer>x</integer></plist>`,
		`<plist><unknown/></plist>`,
		`<notplist/>`,
	} {
		if _, err := decodePlist([]byte(bad)); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}

func TestParseIdentities(t *testing.T) {
	out := []byte("  1) 0123456789ABCDEF0123456789ABCDEF01234567 \"Apple Distribution: Example (ABCDE12345)\"\n     1 valid identities found\n")
	if got := parseIdentities(out); len(got) != 1 || got[0] != "0123456789ABCDEF0123456789ABCDEF01234567" {
		t.Fatalf("identities %v", got)
	}
}

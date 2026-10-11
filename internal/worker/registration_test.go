package worker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Entirely synthetic identities and paths. Only the native field grammar is
// represented; no captured private registration values are part of this fixture.
const syntheticBTM = `Records for UID 12345 : AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA
========================
ServiceManagement migrated: true
LaunchServices registered: true
Items:
#1:
UUID: 11111111-1111-1111-1111-111111111111
Name: Fixture
Developer Name: Example
Team Identifier: TESTTEAM01
Type: app (0x2)
Flags: [  ] (0)
Disposition: [disabled, allowed, notified] (0xa)
Identifier: 2.test.example.fixture
URL: /Applications/Fixture.app
Generation: 1
Bundle Identifier: test.example.fixture
#2:
UUID: 22222222-2222-2222-2222-222222222222
Name: Preview.appex
Developer Name: (null)
Team Identifier: TESTTEAM01
Type: quicklook (0x800)
Flags: [ sandboxed ] (0x40)
Disposition: [enabled, allowed, not notified] (0x3)
Identifier: 2048.test.example.fixture.preview
URL: Contents/PlugIns/Preview.appex
Generation: 0
Bundle Identifier: test.example.fixture.preview
Parent Identifier: 2.test.example.fixture
#3:
UUID: 33333333-3333-3333-3333-333333333333
Name: (null)
Developer Name: Example
Type: developer (0x20)
Flags: [  ] (0)
Disposition: [disabled, allowed, notified] (0xa)
Identifier: Example Developer
URL: (null)
Generation: 1
Embedded Item Identifiers:
 #1: 2.test.example.fixture
`

func registrationFixture(t *testing.T) PersistenceManifest {
	t.Helper()
	census, err := parseBackgroundItems(syntheticBTM, testJobUID)
	if err != nil {
		t.Fatal(err)
	}
	paths, problems := registrationPaths(census)
	if len(problems) != 0 || len(paths) != 2 {
		t.Fatalf("fixture eligibility: %v", problems)
	}
	m := PersistenceManifest{Version: 1, JobUID: testJobUID, OSBuild: "fixture-build", Census: census, Code: map[string]RegisteredCode{}}
	for id, path := range paths {
		m.Code[id] = RegisteredCode{Path: path, Executable: path + "/Contents/MacOS/fixture", Identifier: strings.SplitN(id, ".", 2)[1], Team: "TESTTEAM01", CDHash: strings.Repeat("a", 40), Requirement: "fixture requirement", TreeRoot: "/Applications/Fixture.app", TreeSHA256: strings.Repeat("b", 64)}
	}
	return m
}

func TestBackgroundCensusSeparatesRecordsAndEmbeddedReferences(t *testing.T) {
	census, err := parseBackgroundItems(syntheticBTM, testJobUID)
	if err != nil || len(census.Records) != 3 {
		t.Fatalf("records: %d %v", len(census.Records), err)
	}
	if len(census.Records[2].Embedded) != 1 {
		t.Fatal("embedded reference lost or counted as executable")
	}
	for name, change := range map[string]func(string) string{
		"missing-target":     func(s string) string { return strings.Replace(s, "UID 12345", "UID 99", 1) },
		"duplicate-target":   func(s string) string { return s + s },
		"unknown-field":      func(s string) string { return s + "Unknown field: value\n" },
		"duplicate-field":    func(s string) string { return strings.Replace(s, "Name: Fixture", "Name: Fixture\nName: Other", 1) },
		"missing-generation": func(s string) string { return strings.Replace(s, "Generation: 0\n", "", 1) },
		"duplicate-uuid": func(s string) string {
			return strings.ReplaceAll(s, "22222222-2222-2222-2222-222222222222", "11111111-1111-1111-1111-111111111111")
		},
		"incorrect-empty":   func(s string) string { return strings.Replace(s, "Items:", "Items: 0", 1) },
		"ambiguous-section": func(s string) string { return s + "Records for UID ???\n" },
		"missing-metadata":  func(s string) string { return strings.Replace(s, "LaunchServices registered: true\n", "", 1) },
		"record-sequence":   func(s string) string { return strings.Replace(s, "#2:", "#4:", 1) },
		"nul":               func(s string) string { return s + "\x00" },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseBackgroundItems(change(syntheticBTM), testJobUID); err == nil {
				t.Fatal("incomplete census accepted")
			}
		})
	}
}

func TestRegistrationEligibilityRejectsAutostartAndUnresolvedCode(t *testing.T) {
	for name, oldNew := range map[string][2]string{
		"unresolved-reference": {" #1: 2.test.example.fixture", " #1: 16.test.example.missing"},
		"autostart-type":       {"Type: app (0x2)", "Type: login item (0x4)"},
		"enabled-app":          {"[disabled, allowed, notified] (0xa)", "[enabled, allowed, notified] (0xb)"},
		"extension-escape":     {"Contents/PlugIns/Preview.appex", "../Preview.appex"},
		"absolute-extension":   {"Contents/PlugIns/Preview.appex", "/Applications/Other.appex"},
		"unresolved-parent":    {"Parent Identifier: 2.test.example.fixture", "Parent Identifier: missing"},
		"missing-team":         {"Team Identifier: TESTTEAM01", "Team Identifier: (null)"},
		"unknown-flags":        {"Flags: [ sandboxed ] (0x40)", "Flags: [ unknown ] (0x80)"},
	} {
		t.Run(name, func(t *testing.T) {
			census, err := parseBackgroundItems(strings.Replace(syntheticBTM, oldNew[0], oldNew[1], 1), testJobUID)
			if err != nil {
				t.Fatal(err)
			}
			if _, problems := registrationPaths(census); len(problems) == 0 {
				t.Fatal("registration authorized by familiar name/type alone")
			}
		})
	}
}

func TestReviewedPersistenceRefusesNewMissingChangedAndTamperedState(t *testing.T) {
	accepted := registrationFixture(t)
	for name, mutate := range map[string]func(*PersistenceManifest){
		"new": func(m *PersistenceManifest) {
			m.Census.Records = append(m.Census.Records, BTMRecord{Fields: map[string]string{"Identifier": "unreviewed"}})
		},
		"missing":     func(m *PersistenceManifest) { m.Census.Records = m.Census.Records[1:] },
		"generation":  func(m *PersistenceManifest) { m.Census.Records[0].Fields["Generation"] = "8" },
		"disposition": func(m *PersistenceManifest) { m.Census.Records[0].Fields["Disposition"] = "enabled" },
		"build":       func(m *PersistenceManifest) { m.OSBuild = "new-build" },
		"tree": func(m *PersistenceManifest) {
			c := m.Code["2.test.example.fixture"]
			c.TreeSHA256 = strings.Repeat("c", 64)
			m.Code["2.test.example.fixture"] = c
		},
		"signature": func(m *PersistenceManifest) {
			c := m.Code["2.test.example.fixture"]
			c.CDHash = strings.Repeat("d", 40)
			m.Code["2.test.example.fixture"] = c
		},
		"path": func(m *PersistenceManifest) {
			c := m.Code["2.test.example.fixture"]
			c.Path = "/other"
			m.Code["2.test.example.fixture"] = c
		},
	} {
		t.Run(name, func(t *testing.T) {
			current := registrationFixture(t)
			mutate(&current)
			if !errors.Is(matchPersistence(accepted, current), ErrContamination) {
				t.Fatal("changed state did not refuse as observed contamination")
			}
		})
	}
	if err := matchPersistence(accepted, registrationFixture(t)); err != nil {
		t.Fatal(err)
	}
	incomplete := registrationFixture(t)
	incomplete.Problems = []string{"signature inspection unavailable"}
	if err := matchPersistence(accepted, incomplete); err == nil || errors.Is(err, ErrContamination) {
		t.Fatal("inspection failure adopted or misclassified as contamination")
	}
	code := incomplete.Code["2.test.example.fixture"]
	code.TreeSHA256 = strings.Repeat("e", 64)
	incomplete.Code["2.test.example.fixture"] = code
	if !errors.Is(matchPersistence(accepted, incomplete), ErrContamination) {
		t.Fatal("observed changed bytes were hidden by a subsequent signature inspection failure")
	}
}

func TestSignatureIdentityRejectsUnsignedAdhocAndIncompleteResults(t *testing.T) {
	valid := "Executable=/Applications/Fixture.app/Contents/MacOS/Fixture\nIdentifier=test.example.fixture\nTeamIdentifier=TESTTEAM01\nCDHash=" + strings.Repeat("a", 40) + "\nAuthority=Example Developer\ndesignated => identifier test.example.fixture and anchor trusted\n"
	if _, err := signatureIdentity(valid); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"", valid + "Signature=adhoc\n", strings.Replace(valid, "Authority=Example Developer\n", "", 1), strings.Replace(valid, "TeamIdentifier=TESTTEAM01", "TeamIdentifier=not set", 1), valid + "Identifier=other\n", strings.Replace(valid, strings.Repeat("a", 40), "bad", 1)} {
		if _, err := signatureIdentity(invalid); err == nil {
			t.Fatal("incomplete or ad-hoc code identity accepted")
		}
	}
}

func privateRootFixture(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root-protected filesystem fixture")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	path, err := os.MkdirTemp(home, "macserve-registration-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(path) })
	return path
}

func TestProtectedCodeTreeDetectsTamperWritePermissionAndLinkEscape(t *testing.T) {
	root := privateRootFixture(t)
	path := filepath.Join(root, "Fixture.app")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(path, "code")
	if err := os.WriteFile(file, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := protectedTreeDigest(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("modified"), 0600); err != nil {
		t.Fatal(err)
	}
	after, err := protectedTreeDigest(context.Background(), path)
	if err != nil || after == before {
		t.Fatalf("tamper missed: %v", err)
	}
	if err := os.Chmod(file, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := protectedTreeDigest(context.Background(), path); err == nil {
		t.Fatal("writable code accepted")
	}
	if err := os.Chmod(file, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(file, 12345, 12345); err != nil {
		t.Fatal(err)
	}
	if _, err := protectedTreeDigest(context.Background(), path); err == nil {
		t.Fatal("job-owned code accepted")
	}
	if err := os.Chown(file, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../outside", filepath.Join(path, "escape")); err != nil {
		t.Fatal(err)
	}
	if _, err := protectedTreeDigest(context.Background(), path); err == nil {
		t.Fatal("escaping/unresolved link accepted")
	}
}

func TestRegisteredTreeACLRejectsGrantsAndIncompleteListings(t *testing.T) {
	valid := "/Applications/Fixture.app:\ntotal 1\n-rw-r--r--+ 1 root wheel 1 Jan 1 00:00 code\n 0: group:everyone deny delete\n"
	if err := validateTreeACL(valid); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{strings.Replace(valid, " deny delete", " allow write", 1), strings.Split(valid, " 0:")[0], strings.Replace(valid, " deny delete", " deny delete allow write", 1), valid + "unknown\n"} {
		if err := validateTreeACL(invalid); err == nil {
			t.Fatal("granting or unknown ACL accepted")
		}
	}
}

func TestReviewAuthorityRejectsPartialPublicOrAmbiguousFiles(t *testing.T) {
	root := privateRootFixture(t)
	path := filepath.Join(root, "review.json")
	valid := registrationFixture(t)
	data, err := persistenceBytes(valid)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	before, err := PersistenceDigest(path, testJobUID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := PersistenceDigest(path, testJobUID); err == nil {
		t.Fatal("nonprivate authority accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	invalid := valid
	invalid.Problems = []string{"unresolved code"}
	bad, _ := persistenceBytes(invalid)
	for _, body := range [][]byte{bad, append(data, []byte("{}")...), []byte(strings.Replace(string(data), `"version": 1`, `"version": 1, "version": 1`, 1))} {
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := PersistenceDigest(path, testJobUID); err == nil {
			t.Fatal("partial/ambiguous authority accepted")
		}
	}
	valid.OSBuild = "changed"
	changed, _ := persistenceBytes(valid)
	if err := os.WriteFile(path, changed, 0600); err != nil {
		t.Fatal(err)
	}
	after, err := PersistenceDigest(path, testJobUID)
	if err != nil || before == after {
		t.Fatal("qualification binding did not change")
	}
}

func TestPersistenceDigestRejectsCanonicalProblems(t *testing.T) {
	root := privateRootFixture(t)
	path := filepath.Join(root, "review.json")
	for name, poison := range map[string]func(*PersistenceManifest){
		"declared": func(m *PersistenceManifest) { m.Problems = []string{"native code verification unavailable"} },
		"derived":  func(m *PersistenceManifest) { m.Census.Records[2].Embedded = []string{"16.test.example.absent"} },
	} {
		t.Run(name, func(t *testing.T) {
			m := registrationFixture(t)
			valid, err := persistenceBytes(m)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, valid, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := PersistenceDigest(path, testJobUID); err != nil {
				t.Fatalf("valid authority refused: %v", err)
			}
			poison(&m)
			canonical, err := persistenceBytes(m)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, canonical, 0600); err != nil {
				t.Fatal(err)
			}
			if digest, err := PersistenceDigest(path, testJobUID); err == nil || digest != "" {
				t.Fatalf("problem-carrying canonical authority supplied a qualification digest: %q %v", digest, err)
			}
		})
	}
}

func TestVerifyPersistenceRefusesAuthoritySwapDuringCollection(t *testing.T) {
	root := privateRootFixture(t)
	path := filepath.Join(root, "review.json")
	for _, swap := range []bool{false, true} {
		t.Run(map[bool]string{false: "unchanged", true: "swapped"}[swap], func(t *testing.T) {
			expected := registrationFixture(t)
			data, err := persistenceBytes(expected)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			collected := false
			err = verifyPersistence(context.Background(), Options{JobUID: testJobUID, PersistencePath: path},
				func(context.Context, Options) (PersistenceManifest, error) {
					collected = true
					if swap {
						replacement := registrationFixture(t)
						replacement.OSBuild = "different-reviewed-build"
						other, err := persistenceBytes(replacement)
						if err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(path+".replacement", other, 0600); err != nil {
							t.Fatal(err)
						}
						if err := os.Rename(path+".replacement", path); err != nil {
							t.Fatal(err)
						}
					}
					// Inventory still matches the initially read authority. Only
					// the final on-disk authority read can detect the replacement.
					return expected, nil
				})
			if !collected {
				t.Fatal("inventory collection was not reached")
			}
			if swap && (err == nil || errors.Is(err, ErrContamination)) {
				t.Fatalf("authority replacement not refused as inspection instability: %v", err)
			}
			if !swap && err != nil {
				t.Fatalf("unchanged authority refused: %v", err)
			}
		})
	}
}

package worker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
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
	home, err = filepath.EvalSymlinks(home)
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

func registrationWritersFixture() registrationWriters {
	return registrationWriters{ownerUID: 501, resolve: func(kind, principal string) (uint32, error) {
		identities := map[string]uint32{
			"user:root": 0, "user:owner": 501, "user:job": 6202, "user:controller": 6201,
			"group:wheel": 0, "group:staff": 20, "group:admin": 80, "group:job": 6202,
		}
		if id, ok := identities[kind+":"+principal]; ok {
			return id, nil
		}
		return 0, errors.New("unresolved synthetic principal")
	}}
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
	writers := registrationWritersFixture()
	before, err := protectedTreeDigest(context.Background(), path, writers)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("modified"), 0600); err != nil {
		t.Fatal(err)
	}
	after, err := protectedTreeDigest(context.Background(), path, writers)
	if err != nil || after == before {
		t.Fatalf("tamper missed: %v", err)
	}
	if err := os.Chmod(file, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := protectedTreeDigest(context.Background(), path, writers); err == nil {
		t.Fatal("writable code accepted")
	}
	if err := os.Chmod(file, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(file, 6202, 6202); err != nil {
		t.Fatal(err)
	}
	if _, err := protectedTreeDigest(context.Background(), path, writers); err == nil {
		t.Fatal("job-owned code accepted")
	}
	if err := os.Chown(file, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../outside", filepath.Join(path, "escape")); err != nil {
		t.Fatal(err)
	}
	if _, err := protectedTreeDigest(context.Background(), path, writers); err == nil {
		t.Fatal("escaping/unresolved link accepted")
	}
}

func TestRegisteredTreeACLAllowsOnlyReviewedWriters(t *testing.T) {
	writers := registrationWritersFixture()
	listing := "/Applications/Fixture.app:\ntotal 1\n-rw-r--r--+ 1 owner admin 1 Jan 1 00:00 code\n"
	for name, acl := range map[string]string{
		"deny":          "group:everyone deny delete",
		"owner":         "user:owner allow write,append,writeattr,writeextattr,writesecurity,chown",
		"admin":         "group:admin allow add_file,add_subdirectory,delete_child,file_inherit,directory_inherit",
		"root":          "user:root allow write",
		"wheel":         "group:wheel allow write,append,add_file,delete_child",
		"job-read-only": "user:job allow read,readattr,readsecurity",
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateTreeACL(listing+" 0: "+acl+"\n", writers); err != nil {
				t.Fatal(err)
			}
		})
	}
	for name, acl := range map[string]string{
		"job":                  "user:job allow write",
		"controller":           "user:controller allow writesecurity",
		"job-group":            "group:job allow append",
		"inherited-job-group":  "group:job inherited allow delete_child,directory_inherit",
		"staff":                "group:staff allow write",
		"everyone":             "group:everyone allow delete",
		"unknown-user":         "user:unresolved deny write",
		"unknown-group":        "group:unresolved allow read",
		"unknown-right":        "user:owner allow future_right",
		"unknown-denied-right": "group:everyone deny future_right",
		"mixed":                "group:everyone deny delete allow write",
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateTreeACL(listing+" 0: "+acl+"\n", writers); err == nil {
				t.Fatal("unsafe or unknown ACL accepted")
			}
		})
	}
	for _, invalid := range []string{
		listing,
		listing + " 0: group:everyone deny delete\nunknown\n",
		listing + " 0: user:job deny write\n 1: user:job allow write\n",
	} {
		if err := validateTreeACL(invalid, writers); err == nil {
			t.Fatal("incomplete, ambiguous or still-granting ACL accepted")
		}
	}
}

func TestRegisteredOwnerBundleAndAdminAncestorsRequireRereview(t *testing.T) {
	testRegisteredOwnerBundleAndTrustedAncestorsRequireRereview(t, 80)
}

func TestRegisteredWheelWritableTreeAndAncestorsRequireRereview(t *testing.T) {
	testRegisteredOwnerBundleAndTrustedAncestorsRequireRereview(t, 0)
}

func testRegisteredOwnerBundleAndTrustedAncestorsRequireRereview(t *testing.T, gid int) {
	t.Helper()
	root := privateRootFixture(t)
	path := filepath.Join(root, "Applications", "Fixture.app")
	if err := os.MkdirAll(path, 0755); err != nil {
		t.Fatal(err)
	}
	applications := filepath.Dir(path)
	for dir, uid := range map[string]int{applications: 0, path: 501} {
		if err := os.Chown(dir, uid, gid); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0775); err != nil {
			t.Fatal(err)
		}
	}
	file := filepath.Join(path, "code")
	if err := os.WriteFile(file, []byte("reviewed owner app"), 0664); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(file, 501, gid); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0664); err != nil {
		t.Fatal(err)
	}
	staffFile := filepath.Join(path, "resource")
	if err := os.WriteFile(staffFile, []byte("owner:staff, not staff-writable"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(staffFile, 501, 20); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(path, "Current")
	if err := os.Symlink("code", link); err != nil {
		t.Fatal(err)
	}
	if err := os.Lchown(link, 501, gid); err != nil {
		t.Fatal(err)
	}
	writers := registrationWritersFixture()
	before, err := protectedTreeDigest(context.Background(), path, writers)
	if err != nil {
		t.Fatalf("reviewable owner/trusted-group bundle refused: %v", err)
	}
	accepted := registrationFixture(t)
	id := "2.test.example.fixture"
	code := accepted.Code[id]
	code.TreeSHA256 = before
	accepted.Code[id] = code
	if err := os.WriteFile(file, []byte("updated owner app!"), 0664); err != nil {
		t.Fatal(err)
	}
	after, err := protectedTreeDigest(context.Background(), path, writers)
	if err != nil || after == before {
		t.Fatalf("owner update did not change review binding: %v", err)
	}
	current := registrationFixture(t)
	code.TreeSHA256 = after
	current.Code[id] = code
	if err := matchPersistence(accepted, current); !errors.Is(err, ErrContamination) {
		t.Fatalf("owner app update did not require re-review: %v", err)
	}
}

func TestRegisteredTreeRejectsUntrustedOwnersAndWritableAncestors(t *testing.T) {
	for _, target := range []string{"code", "directory", "ancestor"} {
		for _, uid := range []int{6202, 6201, 502} {
			t.Run(target+"/"+strconv.Itoa(uid), func(t *testing.T) {
				root := privateRootFixture(t)
				path := filepath.Join(root, "Fixture.app")
				dir := filepath.Join(path, "directory")
				if err := os.MkdirAll(dir, 0755); err != nil {
					t.Fatal(err)
				}
				file := filepath.Join(path, "code")
				if err := os.WriteFile(file, []byte("code"), 0444); err != nil {
					t.Fatal(err)
				}
				item := map[string]string{"code": file, "directory": dir, "ancestor": root}[target]
				// Ownership is unsafe even without a write mode: owners can chmod.
				if err := os.Chown(item, uid, uid); err != nil {
					t.Fatal(err)
				}
				if _, err := protectedTreeDigest(context.Background(), path, registrationWritersFixture()); err == nil {
					t.Fatal("untrusted code/ancestor owner accepted")
				}
			})
		}
	}
	for _, gid := range []int{20, 6202, 6201} {
		t.Run("writable-group/"+strconv.Itoa(gid), func(t *testing.T) {
			root := privateRootFixture(t)
			path := filepath.Join(root, "Fixture.app")
			if err := os.Mkdir(path, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(root, 501, gid); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(root, 0770); err != nil {
				t.Fatal(err)
			}
			if _, err := protectedTreeDigest(context.Background(), path, registrationWritersFixture()); err == nil {
				t.Fatal("untrusted group-writable ancestor accepted")
			}
		})
	}
}

func TestRegistrationAncestryRecheckRejectsSymlinkSwap(t *testing.T) {
	root := privateRootFixture(t)
	ancestor := filepath.Join(root, "Applications")
	path := filepath.Join(ancestor, "Fixture.app")
	if err := os.MkdirAll(path, 0755); err != nil {
		t.Fatal(err)
	}
	writers := registrationWritersFixture()
	before, err := registrationPath(path, true, writers)
	if err != nil {
		t.Fatal(err)
	}
	if err := recheckRegistrationPath(before, writers); err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(root, "moved")
	if err := os.Rename(ancestor, moved); err != nil {
		t.Fatal(err)
	}
	// The app inode and bytes are unchanged; only ancestor traversal changed.
	if err := os.Symlink(moved, ancestor); err != nil {
		t.Fatal(err)
	}
	if err := recheckRegistrationPath(before, writers); err == nil {
		t.Fatal("symlink-swapped ancestry accepted")
	}
	if _, err := protectedTreeDigest(context.Background(), path, writers); err == nil {
		t.Fatal("symlink ancestry accepted on new inspection")
	}
}

func TestRegistrationACLRejectsAmbiguousPrincipalTokens(t *testing.T) {
	writers := registrationWritersFixture()
	for _, entry := range []string{
		"group:admin inherited allow write",
		"user:owner inherited allow write",
		"group:staff inherited deny write",
		"group:admin allow allow write",
		"group:admin deny allow write",
		"group:admin unexpected allow write",
		"user:owner inherited inherited allow write",
		"group:admin\tinherited allow write",
	} {
		if err := writers.checkACL(" 0: " + entry); err == nil {
			t.Errorf("ambiguous ACL accepted: %q", entry)
		}
	}
}

func TestRegistrationAncestryRejectsIdenticalMetadataReplacement(t *testing.T) {
	root := privateRootFixture(t)
	ancestor := filepath.Join(root, "ancestor")
	path := filepath.Join(ancestor, "Fixture.app")
	if err := os.MkdirAll(path, 0755); err != nil {
		t.Fatal(err)
	}
	writers := registrationWritersFixture()
	before, err := registrationPath(path, true, writers)
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.Stat(ancestor)
	if err != nil {
		t.Fatal(err)
	}
	parked := filepath.Join(root, "parked")
	if err := os.Rename(ancestor, parked); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(ancestor, original.Mode().Perm()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(parked, "Fixture.app"), path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(ancestor, original.ModTime(), original.ModTime()); err != nil {
		t.Fatal(err)
	}
	replacement, err := os.Stat(ancestor)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.Mode() != original.Mode() || replacement.ModTime() != original.ModTime() {
		t.Fatal("replacement metadata differs")
	}
	if os.SameFile(original, replacement) {
		t.Fatal("fixture did not replace ancestor inode")
	}
	if err := recheckRegistrationPath(before, writers); err == nil {
		t.Fatal("identical-metadata replacement ancestor accepted")
	}
}

func TestRegistrationWriterMembershipsFailClosed(t *testing.T) {
	options := Options{OwnerUID: 501, JobUID: 6202, ControllerUID: 6201}
	for _, role := range []uint32{options.JobUID, options.ControllerUID} {
		for _, primary := range []bool{false, true} {
			for _, gid := range []string{"0", "20", "80", "unknown", "unavailable", "dedicated"} {
				t.Run(fmt.Sprintf("%d/%t/%s", role, primary, gid), func(t *testing.T) {
					lookup := func(id string) (*user.User, error) {
						group := id
						if primary && id == strconv.FormatUint(uint64(role), 10) && gid != "dedicated" {
							group = gid
						}
						return &user.User{Uid: id, Gid: group, Username: "fixture" + id}, nil
					}
					lookupGroup := func(name string) (*user.Group, error) {
						return &user.Group{Name: name, Gid: map[string]string{"wheel": "0", "staff": "20", "admin": "80"}[name]}, nil
					}
					memberships := func(account *user.User) ([]string, error) {
						if account.Uid == strconv.FormatUint(uint64(role), 10) {
							if gid == "unavailable" {
								return nil, errors.New("directory services unavailable")
							}
							if !primary && gid != "dedicated" {
								return []string{account.Uid, gid}, nil
							}
						}
						return []string{account.Uid}, nil
					}
					err := registrationWriterIdentities(options, lookup, lookupGroup, memberships, func(*user.User, string) (bool, error) { return false, nil })
					if (err == nil) != (gid == "dedicated") {
						t.Fatalf("membership decision for %q: %v", gid, err)
					}
				})
			}
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

func TestPersistenceAttestationRefusesAuthoritySwapDuringCollection(t *testing.T) {
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
			err = verifyPersistenceAttestation(context.Background(), Options{JobUID: testJobUID, PersistencePath: path}, false,
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

func TestRegistrationWriterNestedMembershipsFailClosed(t *testing.T) {
	options := Options{OwnerUID: 501, JobUID: 6202, ControllerUID: 6201}
	lookup := func(id string) (*user.User, error) {
		return &user.User{Uid: id, Gid: id, Username: "fixture" + id}, nil
	}
	lookupGroup := func(name string) (*user.Group, error) {
		return &user.Group{Name: name, Gid: map[string]string{"wheel": "0", "staff": "20", "admin": "80"}[name]}, nil
	}
	directGroups := func(account *user.User) ([]string, error) {
		// The privileged membership is nested and absent from GroupIds.
		return []string{account.Gid, "6300"}, nil
	}
	for _, role := range []string{"6202", "6201"} {
		for _, gid := range []string{"0", "20", "80"} {
			for _, result := range []string{"member", "unavailable", "not-member"} {
				t.Run(role+"/"+gid+"/"+result, func(t *testing.T) {
					member := func(account *user.User, group string) (bool, error) {
						if account.Uid == "0" || account.Uid == "501" {
							t.Fatal("trusted updater membership treated as a service identity")
						}
						if account.Uid == role && group == gid {
							if result == "unavailable" {
								return false, errors.New("nested directory membership unavailable")
							}
							return result == "member", nil
						}
						return false, nil
					}
					err := registrationWriterIdentities(options, lookup, lookupGroup, directGroups, member)
					if (err == nil) != (result == "not-member") {
						t.Fatalf("nested membership %s: %v", result, err)
					}
				})
			}
		}
	}
}

func TestCollectRegistrationCodeRetainsFailedTreesAsProblems(t *testing.T) {
	root := privateRootFixture(t)
	path := filepath.Join(root, "Fixture.app")
	if err := os.Mkdir(path, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../outside", filepath.Join(path, "escape")); err != nil {
		t.Fatal(err)
	}
	m := registrationFixture(t)
	m.Code = map[string]RegisteredCode{}
	m.Census.Records[0].Fields["URL"] = path
	digestCalls := 0
	digest := func(ctx context.Context, path string, writers registrationWriters) (string, error) {
		digestCalls++
		return protectedTreeDigest(ctx, path, writers)
	}
	acl := func(context.Context, string, registrationWriters) error { return nil }
	command := func(context.Context, ...string) (string, error) {
		t.Fatal("failed tree reached code-signature inspection")
		return "", nil
	}
	if err := collectRegistrationCode(context.Background(), &m, registrationWritersFixture(), acl, digest, command); err != nil {
		t.Fatalf("failed tree aborted private candidate collection: %v", err)
	}
	if digestCalls != 1 || len(m.Code) != 0 || len(m.Problems) != 2 {
		t.Fatalf("failed shared tree was rechecked or lost: calls=%d code=%d problems=%v", digestCalls, len(m.Code), m.Problems)
	}
	for _, problem := range m.Problems {
		if !strings.Contains(problem, "protected code tree unavailable: registered tree link escapes or is unresolved") {
			t.Fatalf("tree failure lost from candidate: %q", problem)
		}
	}
	data, err := persistenceBytes(m)
	if err != nil || !strings.Contains(string(data), "registered tree link escapes or is unresolved") {
		t.Fatalf("private candidate cannot retain failed inspection: %v", err)
	}
	if err := matchPersistence(registrationFixture(t), m); err == nil {
		t.Fatal("unresolved private candidate accepted")
	}
}

func signedBundleFixture(t *testing.T) (string, string, BTMRecord) {
	t.Helper()
	root := privateRootFixture(t)
	path := filepath.Join(root, "Fixture.app", "Contents", "PlugIns", "Preview.appex")
	executable := filepath.Join(path, "Contents", "MacOS", "preview")
	if err := os.MkdirAll(filepath.Dir(executable), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, []byte("signed fixture code"), 0755); err != nil {
		t.Fatal(err)
	}
	record := BTMRecord{Fields: map[string]string{"Bundle Identifier": "test.example.preview", "Team Identifier": "TESTTEAM01"}}
	return path, executable, record
}

// Model codesign's distinction between an inline requirement (=...) and a
// filename, rather than accepting an arbitrary successful verification command.
func fixtureSignatureCommand(t *testing.T, executable string, verified *bool) func(context.Context, ...string) (string, error) {
	t.Helper()
	return func(_ context.Context, args ...string) (string, error) {
		if len(args) != 0 && args[0] == "--display" {
			return "Executable=" + executable + "\nIdentifier=test.example.preview\nTeamIdentifier=TESTTEAM01\nCDHash=" + strings.Repeat("a", 40) + "\nAuthority=Example Apple chain\ndesignated => identifier test.example.preview\n", nil
		}
		strict, deep, inline := false, false, false
		for i, arg := range args {
			switch arg {
			case "--strict":
				strict = true
			case "--deep":
				deep = true
			case "--test-requirement":
				inline = i+1 < len(args) && args[i+1] == "=anchor apple generic"
			}
		}
		if len(args) == 0 || args[0] != "--verify" || !strict || !deep || !inline {
			return "", errors.New("strict deep inline Apple-anchor verification required")
		}
		*verified = true
		return "", nil
	}
}

func TestVerifyRegisteredCodeUsesInlineAppleRequirement(t *testing.T) {
	path, executable, record := signedBundleFixture(t)
	verified := false
	code, err := verifyRegisteredCode(context.Background(), path, record, registrationWritersFixture(), fixtureSignatureCommand(t, executable, &verified))
	if err != nil || !verified || code.Executable != executable {
		t.Fatalf("signed bundle did not pass strict inline requirement verification: verified=%t code=%+v err=%v", verified, code, err)
	}
}

func TestVerifyRegisteredCodeAcceptsCaseInsensitiveBundleIdentity(t *testing.T) {
	path, executable, record := signedBundleFixture(t)
	alias := strings.Replace(executable, "/PlugIns/", "/Plugins/", 1)
	original, err := os.Stat(executable)
	if err != nil {
		t.Fatal(err)
	}
	alternate, err := os.Stat(alias)
	if os.IsNotExist(err) {
		t.Skip("requires a case-insensitive filesystem; no string-folding substitute")
	}
	if err != nil || !os.SameFile(original, alternate) {
		t.Fatalf("case alias fixture: %v", err)
	}
	verified := false
	if _, err := verifyRegisteredCode(context.Background(), path, record, registrationWritersFixture(), fixtureSignatureCommand(t, alias, &verified)); err != nil || !verified {
		t.Fatalf("same bundle filesystem identity refused: verified=%t err=%v", verified, err)
	}
}

func TestVerifyRegisteredCodeRefusesOutsideAndSymlinkExecutables(t *testing.T) {
	for _, kind := range []string{"outside-hardlink", "case-sensitive-sibling", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			path, executable, record := signedBundleFixture(t)
			other := filepath.Join(filepath.Dir(path), "outside")
			switch kind {
			case "case-sensitive-sibling":
				other = strings.Replace(executable, "/PlugIns/", "/Plugins/", 1)
				if _, err := os.Stat(other); err == nil {
					t.Skip("case-insensitive filesystem has no distinct case-only sibling")
				} else if !os.IsNotExist(err) {
					t.Fatal(err)
				}
				if err := os.MkdirAll(filepath.Dir(other), 0755); err != nil {
					t.Fatal(err)
				}
				fallthrough
			case "outside-hardlink":
				if err := os.Link(executable, other); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				other = filepath.Join(path, "alias")
				if err := os.Symlink(executable, other); err != nil {
					t.Fatal(err)
				}
			}
			verified := false
			if _, err := verifyRegisteredCode(context.Background(), path, record, registrationWritersFixture(), fixtureSignatureCommand(t, other, &verified)); err == nil || verified {
				t.Fatalf("outside or symlink code reached verification: verified=%t err=%v", verified, err)
			}
		})
	}
}

func TestVerifyRegisteredCodeRefusesAncestryReplacementDuringVerification(t *testing.T) {
	path, executable, record := signedBundleFixture(t)
	verified := false
	signature := fixtureSignatureCommand(t, executable, &verified)
	command := func(ctx context.Context, args ...string) (string, error) {
		out, err := signature(ctx, args...)
		if verified {
			if err := os.Rename(path, path+".old"); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(executable), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(executable, []byte("signed fixture code"), 0755); err != nil {
				t.Fatal(err)
			}
		}
		return out, err
	}
	if _, err := verifyRegisteredCode(context.Background(), path, record, registrationWritersFixture(), command); err == nil || !strings.Contains(err.Error(), "changed during inspection") {
		t.Fatalf("bundle replaced during verification was not refused: %v", err)
	}
}

func TestCollectRegistrationCodeRechecksSuccessfulTrees(t *testing.T) {
	path, executable, _ := signedBundleFixture(t)
	m := registrationFixture(t)
	m.Code = map[string]RegisteredCode{}
	m.Census.Records = m.Census.Records[:1]
	m.Census.Records[0].Fields["URL"] = filepath.Dir(filepath.Dir(filepath.Dir(path)))
	m.Census.Records[0].Fields["Bundle Identifier"] = "test.example.preview"
	m.Census.Records[0].Fields["Identifier"] = "2.test.example.preview"
	verified := false
	signature := fixtureSignatureCommand(t, executable, &verified)
	command := func(ctx context.Context, args ...string) (string, error) {
		out, err := signature(ctx, args...)
		if verified {
			if err := os.WriteFile(executable, []byte("updated by trusted writer"), 0755); err != nil {
				t.Fatal(err)
			}
		}
		return out, err
	}
	acl := func(context.Context, string, registrationWriters) error { return nil }
	err := collectRegistrationCode(context.Background(), &m, registrationWritersFixture(), acl, protectedTreeDigest, command)
	if err == nil || err.Error() != "registered code tree changed during inspection" || !verified {
		t.Fatalf("successfully measured tree was not rechecked: verified=%t err=%v problems=%v", verified, err, m.Problems)
	}
}

func TestOpenedRegisteredExecutableRejectsDescriptorSwap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "code")
	if err := os.WriteFile(path, []byte("same bytes"), 0755); err != nil {
		t.Fatal(err)
	}
	expected, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := checkOpenedRegisteredExecutable(root, "code", expected); err != nil {
		t.Fatalf("unchanged descriptor refused: %v", err)
	}
	// Retain the original inode so the filesystem cannot reuse it for the
	// replacement. The inspected name, bytes, owner and permissions are equal.
	if err := os.Rename(path, filepath.Join(dir, "original")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("same bytes"), expected.Mode().Perm()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, expected.ModTime(), expected.ModTime()); err != nil {
		t.Fatal(err)
	}
	replacement, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(expected, replacement) || expected.Mode() != replacement.Mode() || expected.Size() != replacement.Size() {
		t.Fatal("fixture did not replace executable with equivalent metadata")
	}
	if err := checkOpenedRegisteredExecutable(root, "code", expected); err == nil || err.Error() != "signed executable changed during inspection" {
		t.Fatalf("replacement descriptor accepted: %v", err)
	}
}

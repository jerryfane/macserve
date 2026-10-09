package pfctl

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const ownedRules = "block drop out log quick proto tcp from any to any user = 1502 label \"macserve-default-deny\"\nblock drop out log quick proto udp from any to any user = 1502 label \"macserve-default-deny\"\n"

type memoryOwnershipStore struct {
	receipt    ownershipReceipt
	readErr    error
	prepareErr error
	writeErr   error
	writes     int
}

func (s *memoryOwnershipStore) prepare() error { return s.prepareErr }
func (s *memoryOwnershipStore) read(string) (ownershipReceipt, error) {
	if s.receipt.Schema == 0 && s.readErr == nil {
		return ownershipReceipt{}, os.ErrNotExist
	}
	return s.receipt, s.readErr
}
func (s *memoryOwnershipStore) write(r ownershipReceipt) error {
	if s.writeErr != nil {
		return s.writeErr
	}
	s.receipt, s.writes = r, s.writes+1
	return nil
}

type ownershipFixture struct {
	before             string
	after              string
	children           string
	translation        string
	tables             string
	reserved           bool
	reservedUnreadable bool
	absent             bool
	readFail           string
	postFail           bool
	loadFail           bool
	loads              int
	calls              [][]string
}

func (f *ownershipFixture) run(_ context.Context, args ...string) (Output, error) {
	f.calls = append(f.calls, slices.Clone(args))
	if len(args) == 4 && args[2] == "-f" {
		f.loads++
		if f.loadFail {
			return Output{}, errors.New("load failed")
		}
		return Output{}, nil
	}
	query := strings.Join(args[2:], " ")
	if query == f.readFail || f.loads > 0 && f.postFail {
		return Output{}, errors.New("observation failed")
	}
	if strings.HasSuffix(args[1], "/_pf") {
		if f.reservedUnreadable {
			return Output{}, errors.New("reserved child unreadable")
		}
		if f.reserved {
			return Output{}, nil
		}
		return Output{Stderr: "Anchor '" + args[1] + "' not found.\n"}, nil
	}
	switch query {
	case "-v -s Anchors":
		if f.absent && f.loads == 0 {
			return Output{Stderr: "Anchor 'org.example/service' not found.\n"}, nil
		}
		return Output{Stdout: f.children}, nil
	case "-sr":
		if f.loads > 0 {
			return Output{Stdout: f.after}, nil
		}
		if f.absent && f.before == "" {
			return Output{Stderr: "pfctl: DIOCGETRULES: Invalid argument\n"}, nil
		}
		return Output{Stdout: f.before}, nil
	case "-sn":
		if f.absent && f.loads == 0 && f.translation == "" {
			return Output{Stderr: "pfctl: DIOCGETRULES: Invalid argument\n"}, nil
		}
		return Output{Stdout: f.translation}, nil
	case "-s Tables":
		return Output{Stdout: f.tables}, nil
	}
	return Output{}, errors.New("unexpected command")
}

func ownershipClient(t *testing.T, fixture *ownershipFixture, store *memoryOwnershipStore) *Client {
	t.Helper()
	c, err := New("org.example/service")
	if err != nil {
		t.Fatal(err)
	}
	c.run, c.store = fixture.run, store
	return c
}

func TestOwnershipInitializesEmptyOrAbsentThenReloadsReceipt(t *testing.T) {
	for _, absent := range []bool{false, true} {
		t.Run(map[bool]string{false: "empty", true: "absent"}[absent], func(t *testing.T) {
			fixture := &ownershipFixture{absent: absent, after: ownedRules}
			store := &memoryOwnershipStore{}
			c := ownershipClient(t, fixture, store)
			file := policyPath(t, ownedRules)
			options := LoadOptions{JobUID: 1502, CoexistingAnchors: []string{"org.example"}}
			if _, err := c.Load(context.Background(), file, options); err != nil {
				t.Fatal(err)
			}
			if fixture.loads != 1 || store.writes != 1 || store.receipt != ownershipRecord(c.anchor, 1502, ownedRules) {
				t.Fatalf("initial load did not persist exact loaded ownership: loads=%d receipt=%+v", fixture.loads, store.receipt)
			}
			fixture.before, fixture.absent = fixture.after, false
			if _, err := c.Load(context.Background(), file, options); err != nil {
				t.Fatal(err)
			}
			if fixture.loads != 2 || store.writes != 2 {
				t.Fatal("verified prior load could not reload")
			}
		})
	}
}

func TestOwnershipMissingRulesRequiresMissingAnchor(t *testing.T) {
	for _, query := range []string{"-sr", "-sn"} {
		t.Run(query, func(t *testing.T) {
			fixture := &ownershipFixture{after: ownedRules}
			store := &memoryOwnershipStore{}
			c := ownershipClient(t, fixture, store)
			c.run = func(ctx context.Context, args ...string) (Output, error) {
				if slices.Equal(args, []string{"-a", c.anchor, query}) {
					return Output{Stderr: "pfctl: DIOCGETRULES: Invalid argument\n"}, nil
				}
				return fixture.run(ctx, args...)
			}
			if _, err := c.Load(context.Background(), policyPath(t, ownedRules), LoadOptions{JobUID: 1502}); err == nil {
				t.Fatal("missing rules accepted for a separately observed existing anchor")
			}
			if fixture.loads != 0 || store.writes != 0 {
				t.Fatal("inconsistent absence reached a write")
			}
		})
	}
}

func TestOwnershipRefusesForeignOrUnprovenStateBeforeWrite(t *testing.T) {
	prior := ownershipRecord("org.example/service", 1502, ownedRules)
	for _, tc := range []struct {
		name       string
		fixture    ownershipFixture
		receipt    ownershipReceipt
		readErr    error
		prepareErr error
	}{
		{name: "unmarked-foreign", fixture: ownershipFixture{before: strings.ReplaceAll(ownedRules, "macserve-default-deny", "foreign-deny")}},
		{name: "marker-without-receipt", fixture: ownershipFixture{before: ownedRules}},
		{name: "changed-rules", fixture: ownershipFixture{before: strings.Replace(ownedRules, "log quick", "quick", 1)}, receipt: prior},
		{name: "different-path", fixture: ownershipFixture{before: ownedRules}, receipt: ownershipRecord("org.example/peer", 1502, ownedRules)},
		{name: "different-uid", fixture: ownershipFixture{before: ownedRules}, receipt: ownershipRecord("org.example/service", 1503, ownedRules)},
		{name: "receipt-unprotected", fixture: ownershipFixture{before: ownedRules}, receipt: prior, readErr: errors.New("unprotected receipt")},
		{name: "parent", fixture: ownershipFixture{children: "  org.example/service/child\n"}},
		{name: "hidden-reserved-child", fixture: ownershipFixture{reserved: true}},
		{name: "hidden-reserved-child-unreadable", fixture: ownershipFixture{reservedUnreadable: true}},
		{name: "translation", fixture: ownershipFixture{translation: "nat from any to any -> 192.0.2.1\n"}},
		{name: "tables", fixture: ownershipFixture{tables: "foreign\n"}},
		{name: "children-unreadable", fixture: ownershipFixture{readFail: "-v -s Anchors"}},
		{name: "filter-unreadable", fixture: ownershipFixture{readFail: "-sr"}},
		{name: "translation-unreadable", fixture: ownershipFixture{readFail: "-sn"}},
		{name: "tables-unreadable", fixture: ownershipFixture{readFail: "-s Tables"}},
		{name: "absent-but-filter-unreadable", fixture: ownershipFixture{absent: true, readFail: "-sr"}},
		{name: "absent-but-translation-unreadable", fixture: ownershipFixture{absent: true, readFail: "-sn"}},
		{name: "absent-but-tables-unreadable", fixture: ownershipFixture{absent: true, readFail: "-s Tables"}},
		{name: "absent-but-populated", fixture: ownershipFixture{absent: true, before: ownedRules}},
		{name: "receipt-destination-unprotected", prepareErr: errors.New("unprotected storage")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &memoryOwnershipStore{receipt: tc.receipt, readErr: tc.readErr, prepareErr: tc.prepareErr}
			c := ownershipClient(t, &tc.fixture, store)
			if _, err := c.Load(context.Background(), policyPath(t, ownedRules), LoadOptions{JobUID: 1502}); err == nil {
				t.Fatal("unproven ownership accepted")
			}
			if tc.fixture.loads != 0 || store.writes != 0 {
				t.Fatal("unproven ownership reached mutation")
			}
		})
	}
}

func TestOwnershipReceiptsOnlySuccessfulValidatedLoads(t *testing.T) {
	for _, tc := range []struct {
		name     string
		fixture  ownershipFixture
		writeErr error
	}{
		{name: "failed-native-load", fixture: ownershipFixture{loadFail: true, after: ownedRules}},
		{name: "failed-post-observation", fixture: ownershipFixture{postFail: true, after: ownedRules}},
		{name: "empty-post-state"},
		{name: "unmarked-post-state", fixture: ownershipFixture{after: strings.ReplaceAll(ownedRules, "macserve-default-deny", "foreign-deny")}},
		{name: "wrong-uid-post-state", fixture: ownershipFixture{after: strings.ReplaceAll(ownedRules, "1502", "1503")}},
		{name: "inbound-post-state", fixture: ownershipFixture{after: strings.ReplaceAll(ownedRules, " out ", " in ")}},
		{name: "missing-udp-post-state", fixture: ownershipFixture{after: strings.ReplaceAll(ownedRules, "proto udp", "proto tcp")}},
		{name: "local-pass-before-deny-post-state", fixture: ownershipFixture{after: localPass + ownedRules}},
		{name: "failed-receipt-write", fixture: ownershipFixture{after: ownedRules}, writeErr: errors.New("disk failure")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &memoryOwnershipStore{writeErr: tc.writeErr}
			c := ownershipClient(t, &tc.fixture, store)
			if _, err := c.Load(context.Background(), policyPath(t, ownedRules), LoadOptions{JobUID: 1502}); err == nil {
				t.Fatal("failed ownership finalization accepted")
			}
			if tc.fixture.loads != 1 || store.writes != 0 {
				t.Fatal("failed load was receipted or retried")
			}
		})
	}
}

func TestOwnedAnchorStaticExclusionsBeforeNativeReads(t *testing.T) {
	for _, anchor := range []string{"com.apple", "com.apple/250.ApplicationFirewall", "com.apple/InternetSharing", "com.apple/macserve/child", "_pf", "org.example/_pf", "org.example"} {
		fixture, store := &ownershipFixture{}, &memoryOwnershipStore{}
		c, err := New(anchor)
		if err != nil {
			t.Fatal(err)
		}
		c.run, c.store = fixture.run, store
		options := LoadOptions{JobUID: 1502, CoexistingAnchors: []string{"org.example/service"}}
		if _, err := c.Load(context.Background(), policyPath(t, ownedRules), options); err == nil || len(fixture.calls) != 0 {
			t.Fatalf("unsafe owned path %q reached native PF", anchor)
		}
		if !AnchorPath(anchor) {
			t.Fatalf("write validator narrowed read paths: %q", anchor)
		}
	}
	for _, options := range []LoadOptions{
		{JobUID: 1502, CoexistingAnchors: []string{"org.example/service"}},
		{JobUID: 1502, ToleratedTranslationAnchors: []string{"org.example/service"}},
		{JobUID: 1502, CoexistingAnchors: []string{"org.example/service/child"}},
	} {
		fixture := &ownershipFixture{}
		c := ownershipClient(t, fixture, &memoryOwnershipStore{})
		if _, err := c.Load(context.Background(), policyPath(t, ownedRules), options); err == nil || len(fixture.calls) != 0 {
			t.Fatal("listed ownership reached native PF")
		}
	}
}

func TestPolicyRequiresEveryRuleToHaveExactOutboundJobScope(t *testing.T) {
	for _, rule := range []string{
		"pass out all", "pass in all user 1502", "pass all user 1502", "pass out all user 1503",
		"pass out all group 1502", "pass out all user { 1502, 1503 }", "pass out all user != 1502",
		"pass out all user > 1502", "pass out all user 1502:1503", "pass out all user 1502 user 1503",
		"pass out all user $users", "pass out all user 1502 group 1502", "pass { out in } all user 1502",
		"pass out all user = { 1502 }", "pass out all user 1502,1503", "pass out all user $other",
	} {
		source := "users = \"{ 1502, 1503 }\"\nother = 1503\n" + ownedRules + rule + "\n"
		c, calls := recordingClient(t)
		if _, err := c.Load(context.Background(), policyPath(t, source), LoadOptions{JobUID: 1502}); err == nil || len(*calls) != 0 {
			t.Fatalf("unscoped rule reached native PF: %q", rule)
		}
	}
	for _, uid := range []uint32{0, 1503} {
		if err := validatePolicy(ownedRules, uid); err == nil {
			t.Fatalf("accepted configured UID %d", uid)
		}
	}
	if err := validatePolicy(strings.ReplaceAll(ownedRules, "macserve-default-deny", "foreign-deny"), 1502); err == nil {
		t.Fatal("markerless policy accepted")
	}
}

func TestOwnershipStorageRejectsSymlinksAndWritableModes(t *testing.T) {
	file := policyPath(t, "receipt")
	if err := os.Chmod(file, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := protectedOwnershipPath(file, false, 0600); err == nil {
		t.Fatal("writable receipt trusted")
	}
	link := filepath.Join(filepath.Dir(file), "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if _, err := protectedOwnershipPath(link, false, 0600); err == nil {
		t.Fatal("symlink receipt trusted")
	}
	if _, err := protectedOwnershipPath(filepath.Dir(file), false, 0600); err == nil {
		t.Fatal("directory receipt trusted")
	}
}

func TestOwnershipUpgradesReceiptedPolicyBeforeBoundaryCutover(t *testing.T) {
	previous := "pass out quick proto tcp from any to 203.0.113.10 port = 443 user = 1502\n" + ownedRules
	for _, receipted := range []bool{false, true} {
		t.Run(map[bool]string{false: "unreceipted-refused", true: "receipted-upgrade"}[receipted], func(t *testing.T) {
			fixture := &ownershipFixture{before: previous, after: ownedRules}
			store := &memoryOwnershipStore{}
			if receipted {
				store.receipt = ownershipRecord("org.example/service", 1502, previous)
			}
			c := ownershipClient(t, fixture, store)
			_, err := c.Load(context.Background(), policyPath(t, ownedRules), LoadOptions{JobUID: 1502})
			if receipted {
				if err != nil || fixture.loads != 1 || store.writes != 1 || store.receipt != ownershipRecord(c.anchor, 1502, ownedRules) {
					t.Fatalf("receipted prior policy could not upgrade: loads=%d writes=%d err=%v", fixture.loads, store.writes, err)
				}
			} else if err == nil || fixture.loads != 0 || store.writes != 0 {
				t.Fatalf("unreceipted prior policy adopted: loads=%d writes=%d err=%v", fixture.loads, store.writes, err)
			}
		})
	}
}

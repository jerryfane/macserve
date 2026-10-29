package worker

import (
	"bytes"
	"context"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// macOS 27.0 (26A428) sfltool dumpbtm layout: right-aligned field names,
// section rules and a volatile per-record "Last Use" line, observed on the
// job-UID records and on the root (UID -2) org.macserve legacy daemons. Identities
// and paths are synthetic; labels and plist locations are product constants.
const macOS27BTM = `========================
 Records for UID 12345 : AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA
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
             Last Use: 2026-10-29 12:01:07+04:00
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
             Last Use: 2026-10-29 12:01:08+04:00

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
             Last Use: 2026-10-29 12:01:09+04:00

 #4:
                 UUID: 44444444-4444-4444-4444-444444444444
                 Name: (null)
       Developer Name: macserve
                 Type: developer (0x20)
                Flags: [  ] (0)
          Disposition: [disabled, allowed, notified] (0xa)
           Identifier: Service Developer
                  URL: (null)
           Generation: 1
  Embedded Item Identifiers:
                   #1: 16.org.macserve.controller
                   #2: 16.org.macserve.worker
                   #3: 16.org.macserve.maintenance

========================
 Records for UID -2 : FFFFEEEE-DDDD-CCCC-BBBB-AAAAFFFFFFFE
========================

 ServiceManagement migrated: true
 LaunchServices registered: true

 Items:

 #1:
                 UUID: 55555555-5555-5555-5555-555555555555
                 Name: Unrelated
       Developer Name: (null)
                 Type: legacy daemon (0x10010)
                Flags: [ legacy ] (0x1)
          Disposition: [enabled, allowed, notified] (0xb)
           Identifier: 16.test.example.unrelated
                  URL: /Library/LaunchDaemons/test.example.unrelated.plist
      Executable Path: /usr/local/libexec/unrelated
           Generation: 2
    Assoc. Bundle IDs: [test.example.unrelated]
    Parent Identifier: Unrelated Developer
             Last Use: 2026-10-29 09:00:00+04:00

 #2:
                 UUID: 66666666-6666-6666-6666-666666666666
                 Name: macserve
       Developer Name: (null)
                 Type: legacy daemon (0x10010)
                Flags: [ legacy ] (0x1)
          Disposition: [enabled, allowed, notified] (0xb)
           Identifier: 16.org.macserve.controller
                  URL: /Library/LaunchDaemons/org.macserve.controller.plist
      Executable Path: /service/bin/macserve
           Generation: 1
    Parent Identifier: Service Developer
             Last Use: 2026-10-29 13:16:14+04:00

 #3:
                 UUID: 77777777-7777-7777-7777-777777777777
                 Name: macserve
       Developer Name: (null)
                 Type: legacy daemon (0x10010)
                Flags: [ legacy ] (0x1)
          Disposition: [enabled, allowed, notified] (0xb)
           Identifier: 16.org.macserve.worker
                  URL: /Library/LaunchDaemons/org.macserve.worker.plist
      Executable Path: /service/bin/macserve
           Generation: 1
             Last Use: 2026-10-29 13:16:15+04:00
    Parent Identifier: Service Developer

 #4:
                 UUID: 88888888-8888-8888-8888-888888888888
                 Name: macserve
       Developer Name: (null)
                 Type: legacy daemon (0x10010)
                Flags: [ legacy ] (0x1)
          Disposition: [enabled, allowed, notified] (0xb)
           Identifier: 16.org.macserve.maintenance
                  URL: /Library/LaunchDaemons/org.macserve.maintenance.plist
      Executable Path: /service/bin/macserve
           Generation: 1
    Parent Identifier: Service Developer
             Last Use: 2026-10-29 13:16:16+04:00
`

var lastUseLine = regexp.MustCompile(`(?m)^ *Last Use: .*\n`)

// The census exactly as reviewed: parsed, own services live-verified (here by
// their structural binding) and removed, then encoded as the protected manifest.
func lastUseManifest(t *testing.T, text string) (BTMCensus, PersistenceManifest, []byte) {
	t.Helper()
	census, err := parseBackgroundItems(text, testJobUID)
	if err != nil {
		t.Fatal(err)
	}
	if len(census.OwnServices) != 3 {
		t.Fatalf("owned root daemons not attributed: %d", len(census.OwnServices))
	}
	current, err := withoutOwnServices(context.Background(), census, "/service/bin/macserve", func(_ context.Context, r BTMRecord, helper string) error {
		return ownedServiceMetadata(r, helper)
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, problems := registrationPaths(current); len(problems) != 0 {
		t.Fatal(problems)
	}
	m := PersistenceManifest{Version: 1, JobUID: testJobUID, OSBuild: "26A428", Census: current, Code: map[string]RegisteredCode{}}
	data, err := persistenceBytes(m)
	if err != nil {
		t.Fatal(err)
	}
	return census, m, data
}

func TestMacOS27LastUseIsAcceptedAndNeverBound(t *testing.T) {
	if got := len(lastUseLine.FindAllString(macOS27BTM, -1)); got != 7 {
		t.Fatalf("fixture Last Use lines: %d", got)
	}
	withLastUse, _, manifest := lastUseManifest(t, macOS27BTM)
	without, _, baseline := lastUseManifest(t, lastUseLine.ReplaceAllString(macOS27BTM, ""))
	if !bytes.Equal(manifest, baseline) {
		t.Fatalf("Last Use reached the reviewed manifest:\n%s\nwant:\n%s", manifest, baseline)
	}
	if !reflect.DeepEqual(withLastUse, without) {
		t.Fatal("Last Use reached the job-UID census or owned service records")
	}
}

func TestMacOS27RecordsDifferingOnlyInLastUseAreEqual(t *testing.T) {
	accepted, expected, manifest := lastUseManifest(t, macOS27BTM)
	for name, values := range map[string][2]string{
		"later-run":     {"2026-10-30 08:00:01+04:00", "2026-10-30 08:00:02-07:00"},
		"utc":           {"2026-10-30 04:00:01Z", "2026-10-30 04:00:02Z"},
		"null":          {"(null)", "(null)"},
		"extreme-zones": {"2028-02-29 23:59:59+14:00", "2026-01-01 00:00:00-12:00"},
	} {
		t.Run(name, func(t *testing.T) {
			changed := strings.Replace(macOS27BTM, "Last Use: 2026-10-29 12:01:07+04:00", "Last Use: "+values[0], 1)
			changed = strings.Replace(changed, "Last Use: 2026-10-29 13:16:15+04:00", "Last Use: "+values[1], 1)
			if changed == macOS27BTM || !strings.Contains(changed, "Last Use: "+values[1]) {
				t.Fatal("fixture Last Use not replaced")
			}
			census, current, data := lastUseManifest(t, changed)
			if !bytes.Equal(manifest, data) || !reflect.DeepEqual(accepted, census) {
				t.Fatal("a later Last Use changed reviewed identity")
			}
			if err := matchPersistenceCensus(expected, current.OSBuild, current.Census); err != nil {
				t.Fatalf("persistence would fail after every job run: %v", err)
			}
		})
	}
}

func TestMacOS27LastUseRefusesDuplicateEmptyMalformedAndUnknown(t *testing.T) {
	// Control: the exact input accepted with one valid Last Use per record.
	lastUseManifest(t, macOS27BTM)
	for record, line := range map[string]string{
		"job-uid-app":            "Last Use: 2026-10-29 12:01:07+04:00",
		"job-uid-after-embedded": "Last Use: 2026-10-29 12:01:09+04:00",
		"owned-root-worker":      "Last Use: 2026-10-29 13:16:15+04:00",
	} {
		for name, replacement := range map[string]string{
			"duplicate":          line + "\n             " + line,
			"duplicate-distinct": line + "\n             Last Use: 2026-10-29 14:00:00+04:00",
			"empty":              "Last Use:",
			"blank":              "Last Use:    ",
			"no-zone":            "Last Use: 2026-10-29 13:16:14",
			"iso-t":              "Last Use: 2026-10-29T13:16:14+04:00",
			"fraction":           "Last Use: 2026-10-29 13:16:14.250+04:00",
			"compact-zone":       "Last Use: 2026-10-29 13:16:14+0400",
			"zone-hour-24":       "Last Use: 2026-10-29 13:16:14+24:00",
			"zone-hour-15":       "Last Use: 2026-10-29 13:16:14+15:00",
			"zone-minute-60":     "Last Use: 2026-10-29 13:16:14+00:60",
			"zone-minute-99":     "Last Use: 2026-10-29 13:16:14-03:99",
			"month":              "Last Use: 2026-13-29 13:16:14+04:00",
			"hour":               "Last Use: 2026-10-29 25:16:14+04:00",
			"day":                "Last Use: 2026-02-30 13:16:14+04:00",
			"trailing":           "Last Use: 2026-10-29 13:16:14+04:00 (cached)",
			"word":               "Last Use: never",
			"bare-null":          "Last Use: null",
			"lowercase-key":      "last use: 2026-10-29 13:16:14+04:00",
			"unknown-field":      "Last Opened: 2026-10-29 13:16:14+04:00",
			"unknown-suffix-key": "Last Use Count: 3",
		} {
			t.Run(record+"/"+name, func(t *testing.T) {
				if !strings.Contains(macOS27BTM, line) {
					t.Fatal("fixture line missing")
				}
				if _, err := parseBackgroundItems(strings.Replace(macOS27BTM, line, replacement, 1), testJobUID); err == nil {
					t.Fatal("invalid or unknown BTM record field accepted")
				}
			})
		}
	}
}

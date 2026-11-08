package worker

import (
	"context"
	"strings"
	"testing"
)

// The background-task census after macserve became Developer ID signed
// (shape observed on the Studio, 2026-11-08; values synthetic): the worker's
// record moved under its developer's container, while the old unsigned
// "Unknown Developer" container still references the maintenance daemon.
const signedOwnServicesBTM = `Records for UID 12345 : AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA
========================
ServiceManagement migrated: true
LaunchServices registered: true
Items:
#1:
UUID: 11111111-1111-1111-1111-111111111111
Name: (null)
Developer Name: (null)
Type: developer (0x20)
Flags: [  ] (0)
Disposition: [disabled, allowed, notified] (0xa)
Identifier: Unknown Developer
URL: (null)
Generation: 8
Embedded Item Identifiers:
 #1: 16.org.macserve.maintenance
#2:
UUID: 22222222-2222-2222-2222-222222222222
Name: Example Developer
Developer Name: Example Developer
Type: developer (0x20)
Flags: [  ] (0)
Disposition: [disabled, allowed, notified] (0xa)
Identifier: Example Developer
URL: (null)
Generation: 1
Embedded Item Identifiers:
 #1: 16.org.macserve.worker
Records for UID -2 : BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB
#7:
UUID: 44444444-4444-4444-4444-444444444444
Name: macserve
Developer Name: Example Developer
Team Identifier: TESTTEAM02
Type: legacy daemon (0x10010)
Flags: [ legacy ] (0x1)
Disposition: [enabled, allowed, notified] (0xb)
Identifier: 16.org.macserve.worker
URL: /Library/LaunchDaemons/org.macserve.worker.plist
Executable Path: /service/bin/macserve
Generation: 1
Parent Identifier: Example Developer
#8:
UUID: 55555555-5555-5555-5555-555555555555
Name: macserve
Developer Name: Example Developer
Team Identifier: TESTTEAM02
Type: legacy daemon (0x10010)
Flags: [ legacy ] (0x1)
Disposition: [enabled, allowed, notified] (0xb)
Identifier: 16.org.macserve.maintenance
URL: /Library/LaunchDaemons/org.macserve.maintenance.plist
Executable Path: /service/bin/macserve
Generation: 1
Parent Identifier: Example Developer
`

func TestSignedOwnServicesAreAttributedIncludingStaleUnsignedContainer(t *testing.T) {
	census, err := parseBackgroundItems(signedOwnServicesBTM, testJobUID)
	if err != nil {
		t.Fatal(err)
	}
	if _, problems := registrationPaths(census); len(problems) != 0 {
		t.Fatalf("signed own services not attributable: %v", problems)
	}
	verified := map[string]bool{}
	current, err := withoutOwnServices(context.Background(), census, "/service/bin/macserve", func(_ context.Context, r BTMRecord, helper string) error {
		verified[r.Fields["Identifier"]] = true
		return ownedServiceMetadata(r, helper)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(current.Records) != 0 || !verified["16.org.macserve.worker"] || !verified["16.org.macserve.maintenance"] {
		t.Fatalf("own containers not removed after live verification: %d left, verified %v", len(current.Records), verified)
	}

	for name, mutation := range map[string]string{
		// The stale-container allowance is only for a service that is now signed.
		"stale container for unsigned service": strings.Replace(signedOwnServicesBTM,
			"Team Identifier: TESTTEAM02\nType: legacy daemon (0x10010)\nFlags: [ legacy ] (0x1)\nDisposition: [enabled, allowed, notified] (0xb)\nIdentifier: 16.org.macserve.maintenance",
			"Type: legacy daemon (0x10010)\nFlags: [ legacy ] (0x1)\nDisposition: [enabled, allowed, notified] (0xb)\nIdentifier: 16.org.macserve.maintenance", 1),
		"stale container with a name":   strings.Replace(signedOwnServicesBTM, "Name: (null)\nDeveloper Name: (null)", "Name: Impostor\nDeveloper Name: (null)", 1),
		"other developer container":     strings.Replace(signedOwnServicesBTM, "Identifier: Unknown Developer", "Identifier: Other Developer", 1),
		"malformed team identifier":     strings.Replace(signedOwnServicesBTM, "Team Identifier: TESTTEAM02\nType: legacy daemon (0x10010)\nFlags: [ legacy ] (0x1)\nDisposition: [enabled, allowed, notified] (0xb)\nIdentifier: 16.org.macserve.worker", "Team Identifier: test-team\nType: legacy daemon (0x10010)\nFlags: [ legacy ] (0x1)\nDisposition: [enabled, allowed, notified] (0xb)\nIdentifier: 16.org.macserve.worker", 1),
		"signed container wrong parent": strings.Replace(signedOwnServicesBTM, "Parent Identifier: Example Developer\n#8:", "Parent Identifier: Someone Else\n#8:", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if mutation == signedOwnServicesBTM {
				t.Fatal("mutation did not apply")
			}
			changed, err := parseBackgroundItems(mutation, testJobUID)
			if err != nil {
				return
			}
			if _, problems := registrationPaths(changed); len(problems) == 0 {
				t.Fatal("unattributable own-service container accepted")
			}
		})
	}
}

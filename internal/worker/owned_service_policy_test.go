package worker

import (
	"fmt"
	"strings"
	"testing"
)

// Synthetic metadata only; labels and installed plist locations are public
// product constants, not values copied from native evidence.
func ownedServiceFixture(label string) string {
	job := strings.Replace(syntheticBTM, " #1: 2.test.example.fixture", " #1: 16."+label, 1)
	return job + fmt.Sprintf(`
Records for UID -2 : BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB
#7:
UUID: 44444444-4444-4444-4444-444444444444
Name: Synthetic service
Developer Name: (null)
Type: legacy daemon (0x10010)
Flags: [ legacy ] (0x1)
Disposition: [enabled, allowed, notified] (0xb)
Identifier: 16.%s
URL: /Library/LaunchDaemons/%s.plist
Executable Path: /service/bin/macserve
Generation: 1
Parent Identifier: Example Developer
`, label, label)
}

func TestOwnedServiceReferencesResolveOnlyExactRootDaemons(t *testing.T) {
	for _, label := range []string{"org.macserve.controller", "org.macserve.worker", "org.macserve.maintenance"} {
		t.Run(label, func(t *testing.T) {
			text := ownedServiceFixture(label)
			census, err := parseBackgroundItems(text, testJobUID)
			if err != nil {
				t.Fatal(err)
			}
			paths, problems := registrationPaths(census)
			if len(problems) != 0 || len(paths) != 2 {
				t.Fatalf("owned reference must be attributable without treating daemon as third-party signed code: %v", problems)
			}
			separated := text + "\n========================\nRecords for UID 0 : CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC\n========================\n"
			withSeparators, err := parseBackgroundItems(separated, testJobUID)
			if err != nil {
				t.Fatal(err)
			}
			if _, problems := registrationPaths(withSeparators); len(problems) != 0 {
				t.Fatalf("native section separators prevented attribution: %v", problems)
			}
			for name, mutation := range map[string]string{
				"extra-unresolved":   strings.Replace(text, " #1: 16."+label, " #1: 16."+label+"\n #2: 16.test.example.absent", 1),
				"extra-reviewed-app": strings.Replace(text, " #1: 16."+label, " #1: 16."+label+"\n #2: 2.test.example.fixture", 1),
				"wrong-uid":          strings.Replace(text, "Records for UID -2", "Records for UID -1", 1),
				"wrong-identifier":   strings.Replace(text, "Identifier: 16."+label, "Identifier: 16.test.example.foreign", 1),
				"wrong-url":          strings.Replace(text, "/Library/LaunchDaemons/"+label+".plist", "/Library/LaunchDaemons/test.example.foreign.plist", 1),
				"wrong-parent":       strings.Replace(text, "Parent Identifier: Example Developer", "Parent Identifier: Other Developer", 1),
				"wrong-type":         strings.Replace(text, "legacy daemon (0x10010)", "daemon (0x10)", 1),
				"missing-executable": strings.Replace(text, "Executable Path: /service/bin/macserve\n", "", 1),
				"duplicate-section":  text + "\nRecords for UID -2 : CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC\n",
			} {
				t.Run(name, func(t *testing.T) {
					changed, err := parseBackgroundItems(mutation, testJobUID)
					if err != nil {
						return
					}
					if _, problems := registrationPaths(changed); len(problems) == 0 {
						t.Fatal("unattributable or mixed container accepted")
					}
				})
			}
		})
	}
	t.Run("all-three", func(t *testing.T) {
		text := ownedServiceFixture("org.macserve.controller")
		text = strings.Replace(text, " #1: 16.org.macserve.controller", " #1: 16.org.macserve.controller\n #2: 16.org.macserve.worker\n #3: 16.org.macserve.maintenance", 1)
		for i, label := range []string{"org.macserve.worker", "org.macserve.maintenance"} {
			record := strings.SplitN(ownedServiceFixture(label), "#7:\n", 2)[1]
			record = strings.Replace(record, "44444444-4444-4444-4444-444444444444", fmt.Sprintf("%08d-5555-5555-5555-555555555555", i+5), 1)
			text += fmt.Sprintf("\n#%d:\n%s", i+8, record)
		}
		census, err := parseBackgroundItems(text, testJobUID)
		if err != nil {
			t.Fatal(err)
		}
		if paths, problems := registrationPaths(census); len(paths) != 2 || len(problems) != 0 {
			t.Fatalf("later owned labels made attribution fail: %v", problems)
		}
	})
}

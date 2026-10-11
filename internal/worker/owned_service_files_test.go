package worker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOwnedServiceFilesRequireProtectedPlistAndSameExecutable(t *testing.T) {
	root := privateRootFixture(t)
	helper := filepath.Join(root, "macserve")
	other := filepath.Join(root, "other")
	plist := filepath.Join(root, "service.plist")
	label := "org.macserve.worker"
	if err := os.WriteFile(helper, []byte("synthetic executable"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other, []byte("synthetic executable"), 0700); err != nil {
		t.Fatal(err)
	}
	valid := `<plist version="1.0"><dict><key>Label</key><string>` + label + `</string><key>ProgramArguments</key><array><string>` + helper + `</string><string>worker</string></array></dict></plist>`
	write := func(text string) {
		t.Helper()
		if err := os.WriteFile(plist, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(valid)
	if err := checkServiceFiles(plist, helper, helper, label); err != nil {
		t.Fatal(err)
	}
	if err := checkServiceFiles(plist, helper, other, label); err == nil {
		t.Fatal("same bytes in a different inode accepted as running executable")
	}
	for _, path := range []string{plist, helper} {
		if err := os.Chmod(path, 0666); err != nil {
			t.Fatal(err)
		}
		if err := checkServiceFiles(plist, helper, helper, label); err == nil {
			t.Fatal("writable service input accepted")
		}
		if err := os.Chmod(path, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for name, text := range map[string]string{
		"label":       strings.Replace(valid, label, "test.example.other", 1),
		"argv":        strings.Replace(valid, helper, other, 1),
		"program":     strings.Replace(valid, "</dict>", "<key>Program</key><string>"+other+"</string></dict>", 1),
		"duplicate":   strings.Replace(valid, "</dict>", "<key>Label</key><string>"+label+"</string></dict>", 1),
		"empty-array": strings.Replace(valid, "<string>"+helper+"</string><string>worker</string>", "", 1),
	} {
		t.Run(name, func(t *testing.T) {
			write(text)
			if err := checkServiceFiles(plist, helper, helper, label); err == nil {
				t.Fatal("invalid plist identity accepted")
			}
		})
	}
	write(valid)
	link := filepath.Join(root, "link")
	if err := os.Symlink(plist, link); err != nil {
		t.Fatal(err)
	}
	if err := checkServiceFiles(link, helper, helper, label); err == nil {
		t.Fatal("symlink plist accepted")
	}
	if err := os.Chmod(root, 0777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(root, 0700) })
	if err := checkServiceFiles(plist, helper, helper, label); err == nil {
		t.Fatal("writable ancestor accepted")
	}
}

func TestOwnedServiceMetadataRequiresConfiguredExecutable(t *testing.T) {
	census, err := parseBackgroundItems(ownedServiceFixture("org.macserve.controller"), testJobUID)
	if err != nil {
		t.Fatal(err)
	}
	if len(census.OwnServices) != 1 {
		t.Fatal("missing attributed service")
	}
	r := census.OwnServices[0]
	if err := ownedServiceMetadata(r, "/service/bin/macserve"); err != nil {
		t.Fatal(err)
	}
	if err := ownedServiceMetadata(r, "/different/macserve"); err == nil {
		t.Fatal("foreign configured executable accepted")
	}
}

func TestOwnServiceFilteringRequiresLiveVerification(t *testing.T) {
	census, err := parseBackgroundItems(ownedServiceFixture("org.macserve.worker"), testJobUID)
	if err != nil {
		t.Fatal(err)
	}
	checked := false
	current, err := withoutOwnServices(context.Background(), census, "/service/bin/macserve", func(_ context.Context, r BTMRecord, helper string) error {
		checked = true
		return ownedServiceMetadata(r, helper)
	})
	if err != nil || !checked || len(current.Records) != 2 || len(current.OwnServices) != 0 {
		t.Fatalf("own service was not separately verified/removed: %v", err)
	}
	if _, problems := registrationPaths(current); len(problems) != 0 {
		t.Fatal(problems)
	}
	if len(census.Records) != 3 {
		t.Fatal("input census mutated")
	}
	denied := errors.New("protected service file refused")
	if _, err := withoutOwnServices(context.Background(), census, "/service/bin/macserve", func(context.Context, BTMRecord, string) error { return denied }); !errors.Is(err, denied) {
		t.Fatal("failed native check hidden by normalization")
	}
	// Removing only our notification metadata never supplies third-party code
	// approval: the real admission comparator still observes an added app.
	expected := registrationFixture(t)
	expected.Census = current
	changed := registrationFixture(t)
	changed.Census = current
	changed.Census.Records = append(append([]BTMRecord{}, current.Records...), BTMRecord{Fields: map[string]string{"Identifier": "2.test.example.new"}})
	if !errors.Is(matchPersistence(expected, changed), ErrContamination) {
		t.Fatal("own-service filtering waived third-party census changes")
	}
}

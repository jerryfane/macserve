package worker

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"golang.org/x/sys/unix"
)

// jsonPlists is the tests' PlistDecoder: fixture plists are JSON already.
func jsonPlists(_ context.Context, data []byte) ([]byte, error) {
	if !json.Valid(data) {
		return nil, errors.New("not a JSON plist")
	}
	return data, nil
}

var fixtureRelease = model.ReleaseRequest{BuildName: "1.4.0", BuildNumber: "42"}

// machOBinary starts with the thin 64-bit Mach-O magic.
const machOBinary = "\xcf\xfa\xed\xfe\x0c\x00\x00\x01 fixture code"

const (
	fixtureApp = "App.xcarchive/Products/Applications/App.app"
	// Xcode's archive intermediates for the App target, and a simulator
	// build's, whose entitlements are never the archive's.
	appIntermediates       = "derived-data/Build/Intermediates.noindex/ArchiveIntermediates/App/IntermediateBuildFilesPath/App.build/Release-iphoneos/App.build"
	simulatorIntermediates = "derived-data/Build/Intermediates.noindex/ArchiveIntermediates/App/IntermediateBuildFilesPath/App.build/Debug-iphonesimulator/App.build"
)

type archiveFile struct {
	content string
	mode    os.FileMode
}

func bundlePlist(id, executable, packageType, short, version string) archiveFile {
	fields := map[string]string{"CFBundleIdentifier": id, "CFBundleExecutable": executable, "CFBundlePackageType": packageType}
	if short != "" {
		fields["CFBundleShortVersionString"] = short
	}
	if version != "" {
		fields["CFBundleVersion"] = version
	}
	data, _ := json.Marshal(fields)
	return archiveFile{string(data), 0644}
}

// archiveFixture is a workspace's archive and derived data, by workspace
// path: a root app with an app extension, a watch app, a framework at its
// own version, an embedded dylib, a resource, a non-code executable script
// and a dSYM, and the app's requested entitlements.
func archiveFixture() map[string]archiveFile {
	return map[string]archiveFile{
		"App.xcarchive/Info.plist":                                      {`{"Name":"App","SchemeName":"App"}`, 0644},
		fixtureApp + "/Info.plist":                                      bundlePlist("com.example.app", "App", "APPL", "1.4.0", "42"),
		fixtureApp + "/App":                                             {machOBinary, 0755},
		fixtureApp + "/Assets.car":                                      {"assets", 0644},
		fixtureApp + "/run.sh":                                          {"#!/bin/sh\n", 0700},
		fixtureApp + "/PlugIns/Widget.appex/Info.plist":                 bundlePlist("com.example.app.widget", "Widget", "XPC!", "1.4.0", "42"),
		fixtureApp + "/PlugIns/Widget.appex/Widget":                     {machOBinary, 0755},
		fixtureApp + "/Watch/Watch.app/Info.plist":                      bundlePlist("com.example.app.watchkitapp", "Watch", "APPL", "1.4.0", "42"),
		fixtureApp + "/Watch/Watch.app/Watch":                           {machOBinary, 0755},
		fixtureApp + "/Frameworks/Lib.framework/Info.plist":             bundlePlist("com.example.lib", "Lib", "FMWK", "3.0", "1"),
		fixtureApp + "/Frameworks/Lib.framework/Lib":                    {machOBinary, 0755},
		fixtureApp + "/Frameworks/libswift_Concurrency.dylib":           {machOBinary, 0755},
		"App.xcarchive/dSYMs/App.app.dSYM/Contents/Resources/DWARF/App": {machOBinary, 0644},
		appIntermediates + "/App.app.xcent":                             {`{"com.apple.security.application-groups":["group.com.example"],"aps-environment":"production"}`, 0644},
		simulatorIntermediates + "/App.app.xcent":                       {`{"get-task-allow":true}`, 0644},
	}
}

// writeArchiveFiles writes files below dir in the given name order with
// exact modes, creating parent directories with dirMode.
func writeArchiveFiles(t *testing.T, dir string, files map[string]archiveFile, names []string, dirMode os.FileMode) {
	t.Helper()
	for _, name := range names {
		f := files[name]
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), dirMode); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(f.content), f.mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, f.mode); err != nil {
			t.Fatal(err)
		}
	}
}

func sortedNames(files map[string]archiveFile) []string {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// archiveWorkspace writes files into a fresh workspace and opens it.
func archiveWorkspace(t *testing.T, files map[string]archiveFile) (string, *os.File) {
	t.Helper()
	dir := t.TempDir()
	writeArchiveFiles(t, dir, files, sortedNames(files), 0755)
	return dir, openWorkspace(t, dir)
}

func openWorkspace(t *testing.T, dir string) *os.File {
	t.Helper()
	workspace, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { workspace.Close() })
	return workspace
}

var fixtureLimits = archiveLimits{entries: maxArchiveEntries, bytes: 1 << 30}

// sealWorkspace builds the signing manifest of a workspace's archive, seals
// it and returns the tar bytes and the encoded manifest.
func sealWorkspace(t *testing.T, workspace *os.File, release model.ReleaseRequest) ([]byte, SigningManifest, []byte, error) {
	t.Helper()
	tree, m, err := archiveManifest(context.Background(), workspace, release, jsonPlists, fixtureLimits)
	if err != nil {
		return nil, m, nil, err
	}
	defer tree.root.Close()
	var sealed bytes.Buffer
	if m.Archive, m.Executables, err = sealArchive(context.Background(), tree, &sealed, fixtureLimits.bytes); err != nil {
		return nil, m, nil, err
	}
	encoded, err := EncodeSigningManifest(m, release)
	return sealed.Bytes(), m, encoded, err
}

func canonical(t *testing.T, entitlements string) (json.RawMessage, string) {
	t.Helper()
	raw, digest, err := canonicalEntitlements([]byte(entitlements))
	if err != nil {
		t.Fatal(err)
	}
	return raw, digest
}

// The manifest lists every signable bundle (root app, extension, watch app,
// framework) with its Info.plist identity and versions and the entitlements
// its Release-iphoneos build requested, embedded dylibs, and every 0755
// path; the tar holds exactly the archive, normalized, and its digest is
// the manifest's.
func TestArchiveManifestDescribesSealedArchive(t *testing.T) {
	_, workspace := archiveWorkspace(t, archiveFixture())
	sealed, m, encoded, err := sealWorkspace(t, workspace, fixtureRelease)
	if err != nil {
		t.Fatal(err)
	}
	appEntitlements, appDigest := canonical(t, `{"aps-environment":"production","com.apple.security.application-groups":["group.com.example"]}`)
	none, noneDigest := canonical(t, `{}`)
	app := "Products/Applications/App.app"
	digest := sha256.Sum256(sealed)
	want := SigningManifest{
		Schema: SigningManifestSchema, BuildName: "1.4.0", BuildNumber: "42",
		Archive: SealedArchive{Name: profiles.ArchiveArtifact, Root: profiles.ArchivePath, SHA256: hex.EncodeToString(digest[:]), SizeBytes: int64(len(sealed)), Entries: 28},
		Bundles: []SignableBundle{
			{Path: app, BundleID: "com.example.app", Executable: "App", PackageType: "APPL", ShortVersion: "1.4.0", Version: "42", Entitlements: appEntitlements, EntitlementsSHA256: appDigest},
			{Path: app + "/Frameworks/Lib.framework", BundleID: "com.example.lib", Executable: "Lib", PackageType: "FMWK", ShortVersion: "3.0", Version: "1", Entitlements: none, EntitlementsSHA256: noneDigest},
			{Path: app + "/PlugIns/Widget.appex", BundleID: "com.example.app.widget", Executable: "Widget", PackageType: "XPC!", ShortVersion: "1.4.0", Version: "42", Entitlements: none, EntitlementsSHA256: noneDigest},
			{Path: app + "/Watch/Watch.app", BundleID: "com.example.app.watchkitapp", Executable: "Watch", PackageType: "APPL", ShortVersion: "1.4.0", Version: "42", Entitlements: none, EntitlementsSHA256: noneDigest},
		},
		Dylibs: []string{app + "/Frameworks/libswift_Concurrency.dylib"},
		Executables: []string{
			app + "/App",
			app + "/Frameworks/Lib.framework/Lib",
			app + "/Frameworks/libswift_Concurrency.dylib",
			app + "/PlugIns/Widget.appex/Widget",
			app + "/Watch/Watch.app/Watch",
			app + "/run.sh",
		},
	}
	if !reflect.DeepEqual(m, want) {
		t.Fatalf("manifest\n%+v\nwant\n%+v", m, want)
	}
	parsed, err := ParseSigningManifest(encoded, fixtureRelease)
	if err != nil || !reflect.DeepEqual(parsed, want) {
		t.Fatalf("manifest round trip: %+v %v", parsed, err)
	}
	t.Logf("signing-manifest.json: %s", encoded)

	files := archiveFixture()
	reader := tar.NewReader(bytes.NewReader(sealed))
	var names []string
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, header.Name)
		if header.Uid != 0 || header.Gid != 0 || header.Uname != "" || header.Gname != "" || !header.ModTime.Equal(time.Unix(0, 0)) || !header.AccessTime.IsZero() || !header.ChangeTime.IsZero() || len(header.Xattrs) != 0 || len(header.PAXRecords) != 0 {
			t.Fatalf("%s is not normalized: %+v", header.Name, header)
		}
		if !strings.HasPrefix(header.Name, profiles.ArchivePath+"/") {
			t.Fatalf("entry %s outside the archive root", header.Name)
		}
		if header.Typeflag == tar.TypeDir {
			if header.Mode != 0o755 || !strings.HasSuffix(header.Name, "/") {
				t.Fatalf("directory %s mode %o", header.Name, header.Mode)
			}
			continue
		}
		rel := strings.TrimPrefix(header.Name, profiles.ArchivePath+"/")
		mode := int64(0o644)
		if slices.Contains(want.Executables, rel) {
			mode = 0o755
		}
		content, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		if header.Typeflag != tar.TypeReg || header.Mode != mode || string(content) != files[header.Name].content {
			t.Fatalf("file %s: type %c mode %o content %q", header.Name, header.Typeflag, header.Mode, content)
		}
	}
	if len(names) != want.Archive.Entries || names[0] != profiles.ArchivePath+"/" || !slices.IsSorted(names) {
		t.Fatalf("tar entries %q", names)
	}
}

// The same archive always seals to the same bytes and manifest, whatever
// the creation order, timestamps, ownership-independent permission bits and
// directory modes the build left.
func TestSealArchiveIsDeterministic(t *testing.T) {
	_, first := archiveWorkspace(t, archiveFixture())
	sealed, m, encoded, err := sealWorkspace(t, first, fixtureRelease)
	if err != nil {
		t.Fatal(err)
	}
	files := archiveFixture()
	for name, f := range files {
		switch {
		case f.mode&0o111 != 0:
			f.mode = 0o711
		default:
			f.mode = 0o600
		}
		files[name] = f
	}
	names := sortedNames(files)
	slices.Reverse(names)
	dir := t.TempDir()
	writeArchiveFiles(t, dir, files, names, 0o700)
	old := time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)
	if err := filepath.Walk(dir, func(path string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Chtimes(path, old, old)
	}); err != nil {
		t.Fatal(err)
	}
	again, m2, encoded2, err := sealWorkspace(t, openWorkspace(t, dir), fixtureRelease)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sealed, again) || !reflect.DeepEqual(m, m2) || !bytes.Equal(encoded, encoded2) {
		t.Fatalf("sealing is not deterministic:\n%s\n%s", encoded, encoded2)
	}
}

// Anything a signer could not sign exactly as listed refuses the archive:
// a second app, a version other than the release's on an app, extension or
// watch app, a shared bundle identifier, a wrong package type, a missing or
// non-Mach-O executable, code that no listed bundle owns, links, special
// files, unsafe or case-colliding names, conflicting requested entitlements,
// a missing or symlinked archive, and more entries or bytes than allowed.
func TestArchiveManifestRefusesUnsignableArchives(t *testing.T) {
	type special func(t *testing.T, workspace string)
	link := func(oldname, newname string, symbolic bool) special {
		return func(t *testing.T, workspace string) {
			var err error
			if symbolic {
				err = os.Symlink(oldname, filepath.Join(workspace, newname))
			} else {
				err = os.Link(filepath.Join(workspace, oldname), filepath.Join(workspace, newname))
			}
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	remove := func(name string) special {
		return func(t *testing.T, workspace string) {
			if err := os.RemoveAll(filepath.Join(workspace, name)); err != nil {
				t.Fatal(err)
			}
		}
	}
	cases := []struct {
		name    string
		edit    map[string]archiveFile
		special []special
		limits  *archiveLimits
		want    string
	}{
		{name: "second app", edit: map[string]archiveFile{"App.xcarchive/Products/Applications/Other.app/Info.plist": bundlePlist("com.example.other", "Other", "APPL", "1.4.0", "42")}, want: "exactly one .app"},
		{name: "app version", edit: map[string]archiveFile{fixtureApp + "/Info.plist": bundlePlist("com.example.app", "App", "APPL", "1.4.1", "42")}, want: "is not the release's"},
		{name: "extension build number", edit: map[string]archiveFile{fixtureApp + "/PlugIns/Widget.appex/Info.plist": bundlePlist("com.example.app.widget", "Widget", "XPC!", "1.4.0", "41")}, want: "is not the release's"},
		{name: "watch app without build number", edit: map[string]archiveFile{fixtureApp + "/Watch/Watch.app/Info.plist": bundlePlist("com.example.app.watchkitapp", "Watch", "APPL", "1.4.0", "")}, want: "is not the release's"},
		{name: "shared identifier", edit: map[string]archiveFile{fixtureApp + "/PlugIns/Widget.appex/Info.plist": bundlePlist("com.example.app", "Widget", "XPC!", "1.4.0", "42")}, want: "share identifier"},
		{name: "package type", edit: map[string]archiveFile{fixtureApp + "/PlugIns/Widget.appex/Info.plist": bundlePlist("com.example.app.widget", "Widget", "APPL", "1.4.0", "42")}, want: "package type"},
		{name: "plist without identifier", edit: map[string]archiveFile{fixtureApp + "/Info.plist": {`{"CFBundleExecutable":"App","CFBundlePackageType":"APPL","CFBundleShortVersionString":"1.4.0","CFBundleVersion":"42"}`, 0644}}, want: "lacks string CFBundleIdentifier"},
		{name: "missing executable", edit: map[string]archiveFile{fixtureApp + "/PlugIns/Widget.appex/Info.plist": bundlePlist("com.example.app.widget", "Missing", "XPC!", "1.4.0", "42")}, want: "is not a regular file"},
		{name: "executable not Mach-O", edit: map[string]archiveFile{fixtureApp + "/App": {"#!/bin/sh\n", 0755}}, want: "is not a Mach-O file"},
		{name: "unlisted code", edit: map[string]archiveFile{fixtureApp + "/Resources/helper": {machOBinary, 0755}}, want: "unlisted nested code"},
		{name: "dylib outside Frameworks", edit: map[string]archiveFile{fixtureApp + "/libs/libx.dylib": {machOBinary, 0755}}, want: "unlisted nested code"},
		{name: "framework in a framework", edit: map[string]archiveFile{
			fixtureApp + "/Frameworks/Lib.framework/Frameworks/Inner.framework/Info.plist": bundlePlist("com.example.inner", "Inner", "FMWK", "1.0", "1"),
			fixtureApp + "/Frameworks/Lib.framework/Frameworks/Inner.framework/Inner":      {machOBinary, 0755},
		}, want: "unlisted nested code"},
		{name: "case collision", edit: map[string]archiveFile{fixtureApp + "/assets.car": {"other", 0644}}, want: "collide case-insensitively"},
		{name: "backslash name", edit: map[string]archiveFile{fixtureApp + `/a\b`: {"x", 0644}}, want: "entry name"},
		{name: "conflicting entitlements", edit: map[string]archiveFile{strings.Replace(appIntermediates, "/App.build/Release", "/Other.build/Release", 1) + "/App.app.xcent": {`{"aps-environment":"development"}`, 0644}}, want: "conflicting entitlements"},
		{name: "entitlements not an object", edit: map[string]archiveFile{appIntermediates + "/App.app.xcent": {`["aps-environment"]`, 0644}}, want: "not a JSON object"},
		{name: "symlink", special: []special{link("App", fixtureApp+"/link", true)}, want: "symlink at"},
		{name: "hard link", special: []special{link(fixtureApp+"/Assets.car", fixtureApp+"/Assets2.car", false)}, want: "hard link at"},
		{name: "fifo", special: []special{func(t *testing.T, workspace string) {
			if err := unix.Mkfifo(filepath.Join(workspace, fixtureApp, "pipe"), 0o644); err != nil {
				t.Fatal(err)
			}
		}}, want: "special file at"},
		{name: "entitlements symlink", special: []special{remove(appIntermediates + "/App.app.xcent"), link("../../../../../../../../../App.xcarchive/Info.plist", appIntermediates+"/App.app.xcent", true)}, want: "not a singly linked regular file"},
		{name: "no archive", special: []special{remove("App.xcarchive")}, want: "open App.xcarchive"},
		{name: "symlinked archive", special: []special{func(t *testing.T, workspace string) {
			if err := os.Rename(filepath.Join(workspace, "App.xcarchive"), filepath.Join(workspace, "Real.xcarchive")); err != nil {
				t.Fatal(err)
			}
		}, link("Real.xcarchive", "App.xcarchive", true)}, want: "open App.xcarchive"},
		{name: "entries", limits: &archiveLimits{entries: 10, bytes: 1 << 30}, want: "more than"},
		{name: "bytes", limits: &archiveLimits{entries: maxArchiveEntries, bytes: 64}, want: "more than 64 bytes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := archiveFixture()
			for name, f := range tc.edit {
				files[name] = f
			}
			dir, workspace := archiveWorkspace(t, files)
			if tc.name == "case collision" && caseInsensitive(t, dir) {
				// Default APFS (macOS CI, the Studio) folds case: the second name
				// replaces the first, so no colliding pair can exist there. The
				// refusal guards case-sensitive volumes.
				t.Skip("case-insensitive filesystem cannot hold colliding names")
			}
			for _, s := range tc.special {
				s(t, dir)
			}
			limits := fixtureLimits
			if tc.limits != nil {
				limits = *tc.limits
			}
			tree, _, err := archiveManifest(context.Background(), workspace, fixtureRelease, jsonPlists, limits)
			if err == nil {
				tree.root.Close()
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

// caseInsensitive reports whether dir's filesystem folds ASCII case.
func caseInsensitive(t *testing.T, dir string) bool {
	t.Helper()
	probe := filepath.Join(dir, "CaseProbe")
	if err := os.WriteFile(probe, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(probe)
	_, err := os.Lstat(filepath.Join(dir, "caseprobe"))
	return err == nil
}

// The sealed tar may not exceed its byte budget, and a file that changes
// between scanning and sealing refuses the seal.
func TestSealArchiveRefusesOverBudgetAndChangedFiles(t *testing.T) {
	dir, workspace := archiveWorkspace(t, archiveFixture())
	tree, _, err := archiveManifest(context.Background(), workspace, fixtureRelease, jsonPlists, fixtureLimits)
	if err != nil {
		t.Fatal(err)
	}
	defer tree.root.Close()
	if _, _, err := sealArchive(context.Background(), tree, io.Discard, 4096); err == nil || !strings.Contains(err.Error(), "sealed archive exceeds 4096 bytes") {
		t.Fatalf("over budget: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, fixtureApp, "Assets.car"), []byte("changed after scanning"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := sealArchive(context.Background(), tree, io.Discard, fixtureLimits.bytes); err == nil || !strings.Contains(err.Error(), "changed after scanning") {
		t.Fatalf("changed file: %v", err)
	}
}

// Only canonical manifest bytes of the given release parse.
func TestParseSigningManifestRequiresCanonicalRelease(t *testing.T) {
	_, workspace := archiveWorkspace(t, archiveFixture())
	_, m, encoded, err := sealWorkspace(t, workspace, fixtureRelease)
	if err != nil {
		t.Fatal(err)
	}
	var indented bytes.Buffer
	if err := json.Indent(&indented, encoded, "", " "); err != nil {
		t.Fatal(err)
	}
	unknown := append(bytes.TrimSuffix(slices.Clone(encoded), []byte("}")), []byte(`,"extra":1}`)...)
	for name, raw := range map[string][]byte{"indented": indented.Bytes(), "unknown field": unknown, "trailing": append(slices.Clone(encoded), '\n', '{', '}'), "empty": nil} {
		if _, err := ParseSigningManifest(raw, fixtureRelease); err == nil {
			t.Errorf("%s manifest parsed", name)
		}
	}
	if _, err := ParseSigningManifest(encoded, model.ReleaseRequest{BuildName: "1.4.0", BuildNumber: "43"}); err == nil {
		t.Error("manifest parsed for another release")
	}
	for name, edit := range map[string]func(*SigningManifest){
		"unsorted executables": func(m *SigningManifest) { slices.Reverse(m.Executables) },
		"root executable not 0755": func(m *SigningManifest) {
			m.Executables = slices.DeleteFunc(slices.Clone(m.Executables), func(p string) bool { return p == "Products/Applications/App.app/App" })
		},
		"entitlements digest": func(m *SigningManifest) { m.Bundles[0].EntitlementsSHA256 = strings.Repeat("0", 64) },
		"orphan bundle": func(m *SigningManifest) {
			m.Bundles = append(slices.Clone(m.Bundles), SignableBundle{Path: "Products/Other.appex", BundleID: "com.example.orphan", Executable: "Other", PackageType: "XPC!", ShortVersion: "1.4.0", Version: "42", Entitlements: json.RawMessage("{}"), EntitlementsSHA256: m.Bundles[1].EntitlementsSHA256})
		},
		"archive identity": func(m *SigningManifest) { m.Archive.Name = "other.tar" },
	} {
		copied := m
		copied.Bundles = slices.Clone(m.Bundles)
		copied.Executables = slices.Clone(m.Executables)
		edit(&copied)
		if _, err := EncodeSigningManifest(copied, fixtureRelease); err == nil {
			t.Errorf("%s encoded", name)
		}
	}
}

// archiveTemplateJob admits a native ios_archive template job at
// fixtureRelease, bound to its default-branch head.
func archiveTemplateJob(t *testing.T) model.Job {
	t.Helper()
	template := model.Template{ID: "org-ios-archive-v1", Version: 1, Kind: model.IOSArchive, Owners: []string{"example-org"}, Xcode: model.Xcode{Version: "16.0", Build: "16A242d"}, DeveloperDir: "/Applications/Xcode.app/Contents/Developer"}
	registry, err := profiles.New(nil, []model.Template{template})
	if err != nil {
		t.Fatal(err)
	}
	release := fixtureRelease
	sha := strings.Repeat("a", 40)
	admission, err := registry.Resolve(model.Request{Repo: "example-org/new-app", SHA: sha, Kind: model.IOSArchive, Profile: template.ID, Xcode: template.Xcode, Release: &release})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(admission.Request)
	digest := sha256.Sum256(data)
	provenance := &model.ReleaseProvenance{RepositoryID: 7, DefaultBranch: "main", HeadSHA: sha, ResolvedAt: time.Now().UTC(), Source: model.ProvenanceGitHubApp}
	return model.Job{ID: "job-1", LeaseToken: "lease-1", WorkerEpoch: "epoch-1", State: model.Preparing, Request: admission.Request, Profile: admission.Profile, ProfileDigest: admission.ProfileDigest, RequestDigest: hex.EncodeToString(digest[:]), ReleaseProvenance: provenance}
}

// archiveHook plays xcodebuild archive: it writes files into the archive
// command's workspace and records the command.
func archiveHook(t *testing.T, files map[string]archiveFile, archive *Command) func(context.Context, Command, io.Writer, io.Writer) (bool, ProcessResult, error) {
	return func(_ context.Context, c Command, _, _ io.Writer) (bool, ProcessResult, error) {
		if !slices.Contains(c.Args, "archive") {
			return false, ProcessResult{}, nil
		}
		*archive = c
		archivePath := argValue(c.Args, "-archivePath")
		if filepath.Base(archivePath) != profiles.ArchivePath {
			t.Errorf("archive path %q", archivePath)
			return true, ProcessResult{ExitCode: 1, CleanupOK: true}, nil
		}
		writeArchiveFiles(t, filepath.Dir(archivePath), files, sortedNames(files), 0755)
		return true, ProcessResult{CleanupOK: true}, nil
	}
}

func archiveEngine(t *testing.T, runner Runner) *Engine {
	t.Helper()
	base := t.TempDir()
	engine, err := New(Options{Root: filepath.Join(base, "worker"), ExportRoot: filepath.Join(base, "exports"), WorkspaceRoot: filepath.Join(base, "workspaces"), Runner: runner, PlistJSON: jsonPlists})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := engine.Close(); err != nil {
			t.Error(err)
		}
	})
	return engine
}

const archiveConfig = `{"version":1,"work_dir":".","project":"App.xcodeproj","scheme":"App"}`

// An archive template job runs the unsigned Release archive with the
// release's version settings, then the worker seals the archive root-side and
// exports exactly the logs, App.xcarchive.tar and signing-manifest.json:
// files the job planted under those names in its workspace are never
// exported.
func TestArchiveJobExportsSealedArchiveAndSigningManifest(t *testing.T) {
	files := archiveFixture()
	files["App.xcarchive.tar"] = archiveFile{"planted tar", 0644}
	files["signing-manifest.json"] = archiveFile{`{"planted":true}`, 0644}
	var archive Command
	runner := &fakeRunner{}
	runner.hook = archiveHook(t, files, &archive)
	engine := archiveEngine(t, runner)
	job := archiveTemplateJob(t)
	source, data := checkoutFixture(t, map[string]string{".macserve.json": archiveConfig})
	result, err := engine.Execute(context.Background(), job, source, bytes.NewReader(data), nil)
	if err != nil || result.State != model.Succeeded || !result.CleanupOK {
		t.Fatalf("archive job failed: %+v %v", result, err)
	}
	workspace := filepath.Dir(archive.Dir)
	want := []string{"xcodebuild", "-project", "App.xcodeproj", "-scheme", "App", "-configuration", "Release", "-sdk", "iphoneos", "-destination", "generic/platform=iOS", "-archivePath", filepath.Join(workspace, "App.xcarchive"), "-derivedDataPath", filepath.Join(workspace, "derived-data"), "MARKETING_VERSION=1.4.0", "CURRENT_PROJECT_VERSION=42", "archive", "-jobs", "4", "CODE_SIGNING_ALLOWED=NO"}
	if archive.Executable != "/usr/bin/xcrun" || !slices.Equal(archive.Args, want) {
		t.Fatalf("archive command %s %q\nwant %q", archive.Executable, archive.Args, want)
	}
	if result.Summary != nil {
		t.Fatalf("archive job has test evidence: %+v", result.Summary)
	}
	byName := map[string][]byte{}
	var names []string
	for _, artifact := range result.Artifacts {
		names = append(names, artifact.Name)
		path, err := engine.ArtifactPath(job.ID, artifact.ID)
		if err != nil {
			t.Fatal(err)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(content)
		if hex.EncodeToString(digest[:]) != artifact.SHA256 || int64(len(content)) != artifact.SizeBytes {
			t.Fatalf("%s bytes differ from its record", artifact.Name)
		}
		byName[artifact.Name] = content
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{profiles.ArchiveArtifact, "evidence/stderr.log", "evidence/stdout.log", profiles.SigningManifestArtifact}) {
		t.Fatalf("exports: %q", names)
	}
	m, err := ParseSigningManifest(byName[profiles.SigningManifestArtifact], fixtureRelease)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(byName[profiles.ArchiveArtifact])
	if m.Archive.SHA256 != hex.EncodeToString(digest[:]) || m.Archive.SizeBytes != int64(len(byName[profiles.ArchiveArtifact])) || len(m.Bundles) != 4 {
		t.Fatalf("manifest does not describe the exported archive: %+v", m)
	}
	// The worker's evidence directory is gone with the job's cleanup.
	if _, err := os.Stat(filepath.Join(engine.options.Root, "evidence", job.ID)); !os.IsNotExist(err) {
		t.Fatalf("protected evidence survived cleanup: %v", err)
	}
}

// A run that leaves no archive, or one the manifest builder refuses, fails
// the job; nothing it left in its workspace is exported in the archive's
// place.
func TestArchiveJobWithoutSignableArchiveFails(t *testing.T) {
	refused := archiveFixture()
	refused[fixtureApp+"/Info.plist"] = bundlePlist("com.example.app", "App", "APPL", "9.9.9", "42")
	for name, tc := range map[string]struct {
		files map[string]archiveFile
		want  string
	}{
		"no archive": {map[string]archiveFile{"App.xcarchive.tar": {"planted tar", 0644}, "signing-manifest.json": {`{"planted":true}`, 0644}}, "open App.xcarchive"},
		"refused":    {refused, "is not the release's"},
	} {
		t.Run(name, func(t *testing.T) {
			var archive Command
			runner := &fakeRunner{}
			runner.hook = archiveHook(t, tc.files, &archive)
			engine := archiveEngine(t, runner)
			source, data := checkoutFixture(t, map[string]string{".macserve.json": archiveConfig})
			result, err := engine.Execute(context.Background(), archiveTemplateJob(t), source, bytes.NewReader(data), nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) || result.State != model.Failed || !result.CleanupOK {
				t.Fatalf("archive job without a signable archive: %+v %v", result, err)
			}
			for _, artifact := range result.Artifacts {
				if !strings.HasPrefix(artifact.Name, "evidence/") {
					t.Fatalf("exported %s", artifact.Name)
				}
			}
		})
	}
}

// Other kinds never build archive evidence, even when their workspace holds
// an archive.
func TestNonArchiveJobsNeverSealArchives(t *testing.T) {
	files := archiveFixture()
	runner := &fakeRunner{}
	runner.hook = func(_ context.Context, c Command, _, _ io.Writer) (bool, ProcessResult, error) {
		if slices.Contains(c.Args, "build") && c.Dir != "" && strings.Contains(c.Dir, string(filepath.Separator)+"checkout") {
			writeArchiveFiles(t, filepath.Dir(c.Dir), files, sortedNames(files), 0755)
		}
		return false, ProcessResult{}, nil
	}
	engine := archiveEngine(t, runner)
	source, data := checkoutFixture(t, map[string]string{".macserve.json": archiveConfig})
	result, err := engine.Execute(context.Background(), templateJob(t), source, bytes.NewReader(data), nil)
	if err != nil || result.State != model.Succeeded {
		t.Fatalf("build job failed: %+v %v", result, err)
	}
	for _, artifact := range result.Artifacts {
		if artifact.Name == profiles.ArchiveArtifact || artifact.Name == profiles.SigningManifestArtifact {
			t.Fatalf("build job exported %s", artifact.Name)
		}
	}
}

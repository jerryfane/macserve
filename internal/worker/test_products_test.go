package worker

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
)

const fixtureXctestrun = "Herdr_iphonesimulator27.1-arm64.xctestrun"

// productsFixture is a build-for-testing job's derived products, by path
// below Build/Products: the app and its UI-test runner, the one .xctestrun,
// and an unrelated top-level directory that is not exported.
func productsFixture() map[string]archiveFile {
	return map[string]archiveFile{
		"Debug-iphonesimulator/Herdr.app/Herdr":                                                  {"app binary", 0755},
		"Debug-iphonesimulator/Herdr.app/Info.plist":                                             {"plist", 0644},
		"Debug-iphonesimulator/HerdrUITests-Runner.app/HerdrUITests-Runner":                      {"runner", 0700},
		"Debug-iphonesimulator/HerdrUITests-Runner.app/PlugIns/HerdrUITests.xctest/HerdrUITests": {"bundle", 0755},
		fixtureXctestrun:               {"<plist>__TESTROOT__</plist>", 0644},
		"Release-iphoneos/Stale.app/x": {"not exported", 0644},
	}
}

func buildForTestingJob(t *testing.T) model.Job {
	t.Helper()
	template := model.Template{ID: "org-build-v1", Version: 1, Kind: model.Build, Owners: []string{"example-org"}, Xcode: model.Xcode{Version: "16.0", Build: "16A242d"}, DeveloperDir: "/Applications/Xcode.app/Contents/Developer"}
	registry, err := profiles.New(nil, []model.Template{template})
	if err != nil {
		t.Fatal(err)
	}
	admission, err := registry.Resolve(model.Request{Repo: "example-org/new-app", SHA: strings.Repeat("a", 40), Kind: model.Build, Profile: template.ID, Xcode: template.Xcode, BuildForTesting: true})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(admission.Request)
	digest := sha256.Sum256(data)
	return model.Job{ID: "job-1", LeaseToken: "lease-1", WorkerEpoch: "epoch-1", State: model.Preparing, Request: admission.Request, Profile: admission.Profile, ProfileDigest: admission.ProfileDigest, RequestDigest: hex.EncodeToString(digest[:])}
}

// buildForTestingHook plays xcodebuild build-for-testing: it writes files
// below the command's derived data products and plants planted in its
// workspace, and records the command.
func buildForTestingHook(t *testing.T, files, planted map[string]archiveFile, build *Command) func(context.Context, Command, io.Writer, io.Writer) (bool, ProcessResult, error) {
	return func(_ context.Context, c Command, _, _ io.Writer) (bool, ProcessResult, error) {
		if !slices.Contains(c.Args, "build-for-testing") {
			return false, ProcessResult{}, nil
		}
		*build = c
		derived := argValue(c.Args, "-derivedDataPath")
		writeArchiveFiles(t, filepath.Join(derived, "Build", "Products"), files, sortedNames(files), 0755)
		writeArchiveFiles(t, filepath.Dir(derived), planted, sortedNames(planted), 0755)
		return true, ProcessResult{CleanupOK: true}, nil
	}
}

// A build-for-testing job runs the arm64 build-for-testing, then the worker
// seals its products root-side and exports exactly the logs and
// test-products.tar: the platform directory and the one .xctestrun, nothing
// else of Build/Products, and never a file the job planted under that name.
// The tar is deterministic and the observation names the .xctestrun.
func TestBuildForTestingJobExportsSealedTestProducts(t *testing.T) {
	var build Command
	runner := &fakeRunner{}
	runner.hook = buildForTestingHook(t, productsFixture(), map[string]archiveFile{profiles.TestProductsArtifact: {"planted tar", 0644}}, &build)
	engine := archiveEngine(t, runner)
	job := buildForTestingJob(t)
	source, data := checkoutFixture(t, map[string]string{".macserve.json": archiveConfig})
	result, err := engine.Execute(context.Background(), job, source, bytes.NewReader(data), nil, nil)
	if err != nil || result.State != model.Succeeded || !result.CleanupOK {
		t.Fatalf("build-for-testing job failed: %+v %v", result, err)
	}
	workspace := filepath.Dir(build.Dir)
	want := []string{"xcodebuild", "-project", "App.xcodeproj", "-scheme", "App", "-configuration", "Debug", "-sdk", "iphonesimulator", "-destination", "generic/platform=iOS Simulator", "-derivedDataPath", filepath.Join(workspace, "derived-data"), "ARCHS=arm64", "build-for-testing", "-jobs", "4", "CODE_SIGNING_ALLOWED=NO"}
	if build.Executable != "/usr/bin/xcrun" || !slices.Equal(build.Args, want) {
		t.Fatalf("build command %s %q\nwant %q", build.Executable, build.Args, want)
	}
	if result.Observation.Xctestrun != fixtureXctestrun {
		t.Fatalf("observed xctestrun %q", result.Observation.Xctestrun)
	}
	var names []string
	var products []byte
	for _, artifact := range result.Artifacts {
		names = append(names, artifact.Name)
		if artifact.Name != profiles.TestProductsArtifact {
			continue
		}
		path, err := engine.ArtifactPath(job.ID, artifact.ID)
		if err != nil {
			t.Fatal(err)
		}
		if products, err = os.ReadFile(path); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(products)
		if hex.EncodeToString(digest[:]) != artifact.SHA256 || int64(len(products)) != artifact.SizeBytes {
			t.Fatal("test-products.tar bytes differ from its record")
		}
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"evidence/stderr.log", "evidence/stdout.log", profiles.TestProductsArtifact}) {
		t.Fatalf("exports: %q", names)
	}
	type entry struct {
		name string
		mode int64
		body string
	}
	var entries []entry
	reader := tar.NewReader(bytes.NewReader(products))
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if header.Uid != 0 || header.Gid != 0 || header.Uname != "" || header.Gname != "" || !header.ModTime.Equal(time.Unix(0, 0)) {
			t.Fatalf("%s header not normalized: %+v", header.Name, header)
		}
		body, _ := io.ReadAll(reader)
		entries = append(entries, entry{header.Name, header.Mode, string(body)})
	}
	wantEntries := []entry{
		{"Debug-iphonesimulator/", 0o755, ""},
		{"Debug-iphonesimulator/Herdr.app/", 0o755, ""},
		{"Debug-iphonesimulator/Herdr.app/Herdr", 0o755, "app binary"},
		{"Debug-iphonesimulator/Herdr.app/Info.plist", 0o644, "plist"},
		{"Debug-iphonesimulator/HerdrUITests-Runner.app/", 0o755, ""},
		{"Debug-iphonesimulator/HerdrUITests-Runner.app/HerdrUITests-Runner", 0o755, "runner"},
		{"Debug-iphonesimulator/HerdrUITests-Runner.app/PlugIns/", 0o755, ""},
		{"Debug-iphonesimulator/HerdrUITests-Runner.app/PlugIns/HerdrUITests.xctest/", 0o755, ""},
		{"Debug-iphonesimulator/HerdrUITests-Runner.app/PlugIns/HerdrUITests.xctest/HerdrUITests", 0o755, "bundle"},
		{fixtureXctestrun, 0o644, "<plist>__TESTROOT__</plist>"},
	}
	if !slices.Equal(entries, wantEntries) {
		t.Fatalf("tar entries %+v\nwant %+v", entries, wantEntries)
	}
	// The same products always seal to the same bytes.
	_, workspaceFile := archiveWorkspace(t, prefixed("derived-data/Build/Products/", productsFixture()))
	tree, xctestrun, err := scanTestProducts(context.Background(), workspaceFile, fixtureLimits)
	if err != nil || xctestrun != fixtureXctestrun {
		t.Fatalf("scan: %q %v", xctestrun, err)
	}
	defer tree.root.Close()
	var again bytes.Buffer
	if _, err := sealTree(context.Background(), tree, &again, fixtureLimits.bytes, testProductsTarName); err != nil || !bytes.Equal(again.Bytes(), products) {
		t.Fatalf("resealed products differ (%v)", err)
	}
}

func prefixed(prefix string, files map[string]archiveFile) map[string]archiveFile {
	out := make(map[string]archiveFile, len(files))
	for name, f := range files {
		out[prefix+name] = f
	}
	return out
}

// A build-for-testing run whose products cannot be sealed fails the job with
// a "test products:" reason and exports no test products, not even a file
// the job planted under that name.
func TestBuildForTestingJobWithoutSealableProductsFails(t *testing.T) {
	noXctestrun := productsFixture()
	delete(noXctestrun, fixtureXctestrun)
	var build Command
	runner := &fakeRunner{}
	runner.hook = buildForTestingHook(t, noXctestrun, map[string]archiveFile{profiles.TestProductsArtifact: {"planted tar", 0644}}, &build)
	engine := archiveEngine(t, runner)
	source, data := checkoutFixture(t, map[string]string{".macserve.json": archiveConfig})
	result, err := engine.Execute(context.Background(), buildForTestingJob(t), source, bytes.NewReader(data), nil, nil)
	if err == nil || result.State != model.Failed || !strings.HasPrefix(result.Reason, "test products: ") || !strings.Contains(result.Reason, "0 .xctestrun files, want exactly one") {
		t.Fatalf("result %+v err %v", result, err)
	}
	if !result.CleanupOK || result.Observation.Xctestrun != "" {
		t.Fatalf("result %+v", result)
	}
	for _, artifact := range result.Artifacts {
		if artifact.Name == profiles.TestProductsArtifact {
			t.Fatal("unsealed test products exported")
		}
	}
}

// The export refuses products a sealed tar may not hold, or that do not
// have the one-.xctestrun shape, and the 4 GiB-style byte cap.
func TestScanTestProductsRefuses(t *testing.T) {
	base := func(edit func(map[string]archiveFile)) map[string]archiveFile {
		files := productsFixture()
		edit(files)
		return prefixed("derived-data/Build/Products/", files)
	}
	for name, tc := range map[string]struct {
		files  map[string]archiveFile
		after  func(t *testing.T, dir string)
		limits archiveLimits
		want   string
	}{
		"no products":      {files: map[string]archiveFile{"derived-data/Build/x": {"x", 0644}}, want: "open derived-data/Build/Products"},
		"no platform":      {files: map[string]archiveFile{"derived-data/Build/Products/" + fixtureXctestrun: {"x", 0644}}, want: "no Debug-iphonesimulator directory"},
		"two xctestruns":   {files: base(func(f map[string]archiveFile) { f["Other.xctestrun"] = archiveFile{"x", 0644} }), want: "2 .xctestrun files"},
		"hidden xctestrun": {files: base(func(f map[string]archiveFile) { f[".hidden.xctestrun"] = archiveFile{"x", 0644} }), want: "is not a valid .xctestrun file"},
		"xctestrun dir": {files: base(func(f map[string]archiveFile) {
			delete(f, fixtureXctestrun)
			f["Dir.xctestrun/x"] = archiveFile{"x", 0644}
		}), want: "is not a valid .xctestrun file"},
		"symlink": {files: base(func(map[string]archiveFile) {}), after: func(t *testing.T, dir string) {
			symlink(t, "/etc/passwd", filepath.Join(dir, "derived-data/Build/Products/Debug-iphonesimulator/Herdr.app/link"))
		}, want: "symlink at"},
		"symlinked xctestrun": {files: base(func(f map[string]archiveFile) { delete(f, fixtureXctestrun) }), after: func(t *testing.T, dir string) {
			symlink(t, "/etc/passwd", filepath.Join(dir, "derived-data/Build/Products/"+fixtureXctestrun))
		}, want: "symlink at"},
		"hard link": {files: base(func(map[string]archiveFile) {}), after: func(t *testing.T, dir string) {
			products := filepath.Join(dir, "derived-data/Build/Products/Debug-iphonesimulator/Herdr.app")
			if err := os.Link(filepath.Join(products, "Herdr"), filepath.Join(products, "Copy")); err != nil {
				t.Fatal(err)
			}
		}, want: "hard link at"},
		"byte cap":    {files: base(func(map[string]archiveFile) {}), limits: archiveLimits{entries: maxArchiveEntries, bytes: 8}, want: "more than 8 bytes"},
		"entry limit": {files: base(func(map[string]archiveFile) {}), limits: archiveLimits{entries: 3, bytes: 1 << 20}, want: "more than 2 entries"},
	} {
		t.Run(name, func(t *testing.T) {
			dir, workspace := archiveWorkspace(t, tc.files)
			if tc.after != nil {
				tc.after(t, dir)
			}
			limits := tc.limits
			if limits.entries == 0 {
				limits = fixtureLimits
			}
			tree, _, err := scanTestProducts(context.Background(), workspace, limits)
			if err == nil {
				tree.root.Close()
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func symlink(t *testing.T, target, name string) {
	t.Helper()
	if err := os.Symlink(target, name); err != nil {
		t.Fatal(err)
	}
}

// The tar is capped while it is written, too.
func TestSealTestProductsCapsTarBytes(t *testing.T) {
	_, workspace := archiveWorkspace(t, prefixed("derived-data/Build/Products/", productsFixture()))
	tree, _, err := scanTestProducts(context.Background(), workspace, fixtureLimits)
	if err != nil {
		t.Fatal(err)
	}
	defer tree.root.Close()
	if _, err := sealTree(context.Background(), tree, io.Discard, 2048, testProductsTarName); err == nil || !strings.Contains(err.Error(), "exceeds 2048 bytes") {
		t.Fatalf("err = %v", err)
	}
	if profiles.MaxTestProductsBytes != 4<<30 {
		t.Fatalf("cap %d", profiles.MaxTestProductsBytes)
	}
}

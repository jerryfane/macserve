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
	"slices"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
)

// fixtureXctestrunPlist is a format-2 .xctestrun as Xcode writes for a
// generic simulator build-for-testing: every bundle is __TESTROOT__- or
// __TESTHOST__-relative and the injected libraries are in the pinned Xcode.
const fixtureXctestrunPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>TestConfigurations</key>
	<array>
		<dict>
			<key>Name</key>
			<string>Test Scheme Action</string>
			<key>TestTargets</key>
			<array>
				<dict>
					<key>BlueprintName</key>
					<string>HerdrUITests</string>
					<key>DependentProductPaths</key>
					<array>
						<string>__TESTROOT__/Debug-iphonesimulator/Herdr.app</string>
						<string>__TESTROOT__/Debug-iphonesimulator/HerdrUITests-Runner.app/PlugIns/HerdrUITests.xctest</string>
					</array>
					<key>EnvironmentVariables</key>
					<dict>
						<key>DYLD_FRAMEWORK_PATH</key>
						<string>__TESTROOT__/Debug-iphonesimulator:__PLATFORMS__/iPhoneSimulator.platform/Developer/Library/Frameworks</string>
						<key>OS_ACTIVITY_DT_MODE</key>
						<string>YES</string>
					</dict>
					<key>TestBundlePath</key>
					<string>__TESTHOST__/PlugIns/HerdrUITests.xctest</string>
					<key>TestHostPath</key>
					<string>__TESTROOT__/Debug-iphonesimulator/HerdrUITests-Runner.app</string>
					<key>UITargetAppPath</key>
					<string>__TESTROOT__/Debug-iphonesimulator/Herdr.app</string>
				</dict>
			</array>
		</dict>
	</array>
	<key>__xctestrun_metadata__</key>
	<dict>
		<key>FormatVersion</key>
		<integer>2</integer>
	</dict>
</dict>
</plist>
`

// sealedProducts seals productsFixture, with a real .xctestrun, as the
// producer's export does, and returns the tar and its SHA-256.
func sealedProducts(t *testing.T) ([]byte, string) {
	t.Helper()
	files := productsFixture()
	files[fixtureXctestrun] = archiveFile{fixtureXctestrunPlist, 0644}
	_, workspace := archiveWorkspace(t, prefixed("derived-data/Build/Products/", files))
	tree, _, err := scanTestProducts(context.Background(), workspace, fixtureLimits)
	if err != nil {
		t.Fatal(err)
	}
	defer tree.root.Close()
	var out bytes.Buffer
	if _, err := sealTree(context.Background(), tree, &out, fixtureLimits.bytes, testProductsTarName); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(out.Bytes())
	return out.Bytes(), hex.EncodeToString(sum[:])
}

const consumerConfig = `{"version":1,"work_dir":".","project":"Herdr.xcodeproj","scheme":"Herdr","xcodegen":true,"resolve_packages":true,"ui_test":{"shards":{"iphone-terminal":["HerdrUITests/TerminalControlTests","HerdrUITests/TerminalSearchTests"]}}}`

// consumerJob admits a UI-test template job of shard iphone-terminal that
// consumes the products of digest.
func consumerJob(t *testing.T, digest string) model.Job {
	t.Helper()
	template := model.Template{ID: "org-test-v1", Version: 1, Kind: model.SimulatorUITest, Owners: []string{"example-org"}, Xcode: model.Xcode{Version: "16.0", Build: "16A242d"}, DeveloperDir: "/Applications/Xcode.app/Contents/Developer", Simulators: []model.Simulator{fixtureSimulator}}
	registry, err := profiles.New(nil, []model.Template{template})
	if err != nil {
		t.Fatal(err)
	}
	admission, err := registry.Resolve(model.Request{Repo: "example-org/new-app", SHA: strings.Repeat("a", 40), Kind: template.Kind, Profile: template.ID, Xcode: template.Xcode, Shard: "iphone-terminal", Products: &model.ProductsRef{ProducerJobID: "producer-1", SHA256: digest, Xctestrun: fixtureXctestrun}})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(admission.Request)
	sum := sha256.Sum256(data)
	return model.Job{ID: "job-1", LeaseToken: "lease-1", WorkerEpoch: "epoch-1", State: model.Preparing, Request: admission.Request, Profile: admission.Profile, ProfileDigest: admission.ProfileDigest, RequestDigest: hex.EncodeToString(sum[:])}
}

// A consumer job verifies and imports the sealed products before anything
// of the job runs, then runs only test-without-building of the imported
// macserve.xctestrun on its own simulator with its shard's selectors: no
// xcodegen, no package resolution, no build. The observation names the
// verified digest.
func TestConsumerRunsTestWithoutBuildingFromVerifiedProducts(t *testing.T) {
	report, err := os.ReadFile(filepath.Join("..", "evidence", "testdata", "herdrup-uitests.json"))
	if err != nil {
		t.Fatal(err)
	}
	products, digest := sealedProducts(t)
	runner := &fakeRunner{tests: string(report)}
	var imported map[string]string
	runner.hook = func(_ context.Context, c Command, _, _ io.Writer) (bool, ProcessResult, error) {
		if i := slices.Index(c.Args, "-xctestrun"); i >= 0 && imported == nil {
			// What the job sees when it runs: the imported products.
			imported = map[string]string{}
			dir := filepath.Dir(c.Args[i+1])
			filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
				if err == nil && !d.IsDir() {
					rel, _ := filepath.Rel(dir, path)
					content, _ := os.ReadFile(path)
					imported[filepath.ToSlash(rel)] = string(content)
				}
				return nil
			})
		}
		return false, ProcessResult{}, nil
	}
	engine := engineFixture(t, runner)
	source, data := checkoutFixture(t, map[string]string{".macserve.json": consumerConfig})
	result, err := engine.Execute(context.Background(), consumerJob(t, digest), source, bytes.NewReader(data), bytes.NewReader(products), nil)
	if err != nil || result.State != model.Succeeded || !result.CleanupOK {
		t.Fatalf("consumer job failed: %+v %v", result, err)
	}
	commands := checkoutCommands(runner)
	if len(commands) != 1 {
		t.Fatalf("recipe commands: %+v", commands)
	}
	workspace := filepath.Dir(commands[0].Dir)
	args := commands[0].Args
	want := []string{"xcodebuild", "test-without-building", "-xctestrun", filepath.Join(workspace, "products", "macserve.xctestrun"), "-destination", "id=" + ownedUDID, "-resultBundlePath", filepath.Join(workspace, "results.xcresult"), "-only-testing:HerdrUITests/TerminalControlTests", "-only-testing:HerdrUITests/TerminalSearchTests", "-jobs", "4", "CODE_SIGNING_ALLOWED=NO"}
	if commands[0].Executable != "/usr/bin/xcrun" || !slices.Equal(args[:len(want)], want) {
		t.Fatalf("run %s %q\nwant prefix %q", commands[0].Executable, args, want)
	}
	for _, c := range runner.commands {
		if filepath.Base(c.Executable) == "xcodegen" || slices.Contains(c.Args, "build-for-testing") || slices.Contains(c.Args, "-resolvePackageDependencies") || slices.Contains(c.Args, "build") {
			t.Fatalf("a consumer built or prepared: %+v", c)
		}
	}
	wantFiles := map[string]string{
		"Debug-iphonesimulator/Herdr.app/Herdr":                                                  "app binary",
		"Debug-iphonesimulator/Herdr.app/Info.plist":                                             "plist",
		"Debug-iphonesimulator/HerdrUITests-Runner.app/HerdrUITests-Runner":                      "runner",
		"Debug-iphonesimulator/HerdrUITests-Runner.app/PlugIns/HerdrUITests.xctest/HerdrUITests": "bundle",
		profiles.ConsumerXctestrun:                                                               fixtureXctestrunPlist,
	}
	if len(imported) != len(wantFiles) {
		t.Fatalf("imported %v", imported)
	}
	for name, content := range wantFiles {
		if imported[name] != content {
			t.Fatalf("imported %s = %q, want %q", name, imported[name], content)
		}
	}
	if result.Observation.ImportedProducts != digest {
		t.Fatalf("imported products observation %q", result.Observation.ImportedProducts)
	}
	if summary := result.Summary; summary == nil || summary.Failed != 0 || summary.Passed == 0 {
		t.Fatalf("summary: %+v", summary)
	}
}

// Products that are not the sealed digest, or that never arrive, fail the
// consumer cleanly before anything is extracted or run: no source, no
// simulator, no command, no imported-products observation, and the engine
// is not quarantined (cleanup_ok; the next job runs).
func TestConsumerRefusesUnverifiedProductsBeforeAnythingRuns(t *testing.T) {
	products, digest := sealedProducts(t)
	tampered := bytes.Clone(products)
	tampered[len(tampered)/2] ^= 1
	for _, tc := range []struct {
		name     string
		products io.Reader
		reason   string
	}{
		{"tampered", bytes.NewReader(tampered), "test products: download SHA-256"},
		{"truncated", bytes.NewReader(products[:len(products)-1]), "test products: download SHA-256"},
		{"evicted", failedReader{errors.New("unavailable: 410 Gone")}, "test products: download: unavailable"},
		{"none", nil, "test products: none delivered"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &fakeRunner{}
			engine := engineFixture(t, runner)
			source, data := checkoutFixture(t, map[string]string{".macserve.json": consumerConfig})
			result, err := engine.Execute(context.Background(), consumerJob(t, digest), source, bytes.NewReader(data), tc.products, nil)
			if err == nil || result.State != model.Failed || !result.CleanupOK || !strings.HasPrefix(result.Reason, tc.reason) {
				t.Fatalf("result %+v err %v", result, err)
			}
			if result.Observation.ImportedProducts != "" || engine.VerifiedTree("job-1") != "" {
				t.Fatalf("imported or extracted unverified products: %+v", result.Observation)
			}
			if commands := checkoutCommands(runner); len(commands) != 0 || len(simctl(runner, "create")) != 0 {
				t.Fatalf("ran after a refused import: %+v", runner.commands)
			}
			if err := engine.checkQuarantine(); err != nil {
				t.Fatalf("a refused import quarantined the engine: %v", err)
			}
		})
	}
}

// failedReader stands in for the client's failed products request.
type failedReader struct{ err error }

func (r failedReader) Read([]byte) (int, error) { return 0, r.err }

// A job that consumes no products is given none.
func TestNonConsumerRefusesTestProducts(t *testing.T) {
	products, _ := sealedProducts(t)
	engine := engineFixture(t, &fakeRunner{})
	source, data := checkoutFixture(t, map[string]string{".macserve.json": consumerConfig})
	result, err := engine.Execute(context.Background(), testTemplateJob(t, model.SimulatorUITest, "iphone-terminal"), source, bytes.NewReader(data), bytes.NewReader(products), nil)
	if err == nil || result.State != model.Failed || !strings.Contains(result.Reason, "consumes none") {
		t.Fatalf("result %+v err %v", result, err)
	}
}

type tarEntry struct {
	name     string
	typeflag byte
	body     string
	link     string
}

func tarOf(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var out bytes.Buffer
	tw := tar.NewWriter(&out)
	for _, e := range entries {
		header := &tar.Header{Name: e.name, Typeflag: e.typeflag, Mode: 0644, Size: int64(len(e.body)), Linkname: e.link}
		if e.typeflag != tar.TypeReg {
			header.Size = 0
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Size > 0 {
			tw.Write([]byte(e.body))
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// The import extracts only the export's shape: the platform tree of
// regular files and directories and the one named .xctestrun, whose plist
// stays inside the products. Anything else refuses the products.
func TestExtractTestProductsRefuses(t *testing.T) {
	platform := tarEntry{name: "Debug-iphonesimulator/", typeflag: tar.TypeDir}
	app := tarEntry{name: "Debug-iphonesimulator/App.app/", typeflag: tar.TypeDir}
	xctestrun := tarEntry{name: fixtureXctestrun, typeflag: tar.TypeReg, body: fixtureXctestrunPlist}
	escaping := strings.Replace(fixtureXctestrunPlist, "__TESTROOT__/Debug-iphonesimulator/Herdr.app</string>", "__TESTROOT__/../../checkout/evil.app</string>", 1)
	absolute := strings.Replace(fixtureXctestrunPlist, "__TESTROOT__/Debug-iphonesimulator/HerdrUITests-Runner.app</string>", "/Users/attacker/Runner.app</string>", 1)
	absoluteDyld := strings.Replace(fixtureXctestrunPlist, "__PLATFORMS__/iPhoneSimulator.platform/Developer/Library/Frameworks", "/tmp/inject", 1)
	for _, tc := range []struct {
		name    string
		entries []tarEntry
		want    string
	}{
		{"symlink", []tarEntry{platform, {name: "Debug-iphonesimulator/App.app", typeflag: tar.TypeSymlink, link: "/etc"}, xctestrun}, "not a regular file or directory"},
		{"hard link", []tarEntry{platform, {name: "Debug-iphonesimulator/x", typeflag: tar.TypeLink, link: fixtureXctestrun}, xctestrun}, "not a regular file or directory"},
		{"traversal", []tarEntry{platform, {name: "Debug-iphonesimulator/../../checkout/x", typeflag: tar.TypeReg, body: "x"}, xctestrun}, "unsafe or duplicate entry"},
		{"duplicate", []tarEntry{platform, app, app, xctestrun}, "unsafe or duplicate entry"},
		{"outside the platform", []tarEntry{platform, {name: "Release-iphoneos/", typeflag: tar.TypeDir}, xctestrun}, "unexpected entry"},
		{"another xctestrun", []tarEntry{platform, {name: "Other.xctestrun", typeflag: tar.TypeReg, body: fixtureXctestrunPlist}}, "unexpected entry"},
		{"no xctestrun", []tarEntry{platform, app}, "lack"},
		{"no platform", []tarEntry{xctestrun}, "lack"},
		{"orphan", []tarEntry{{name: "Debug-iphonesimulator/App.app/x", typeflag: tar.TypeReg, body: "x"}, platform, xctestrun}, "precedes its directory"},
		{"escaping plist", []tarEntry{platform, {name: fixtureXctestrun, typeflag: tar.TypeReg, body: escaping}}, "not a path inside the products"},
		{"absolute test host", []tarEntry{platform, {name: fixtureXctestrun, typeflag: tar.TypeReg, body: absolute}}, "not a path inside the products"},
		{"absolute library path", []tarEntry{platform, {name: fixtureXctestrun, typeflag: tar.TypeReg, body: absoluteDyld}}, "not inside the products or Xcode"},
		{"binary plist", []tarEntry{platform, {name: fixtureXctestrun, typeflag: tar.TypeReg, body: "bplist00"}}, "not an XML property list"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			err = extractTestProducts(context.Background(), root, bytes.NewReader(tarOf(t, tc.entries...)), fixtureXctestrun, 1<<30)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
		})
	}
	// The producer's own export imports.
	products, _ := sealedProducts(t)
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := extractTestProducts(context.Background(), root, bytes.NewReader(products), fixtureXctestrun, 1<<30); err != nil {
		t.Fatalf("sealed products refused: %v", err)
	}
	other, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := extractTestProducts(context.Background(), other, bytes.NewReader(products), "Other.xctestrun", 1<<30); err == nil || !strings.Contains(err.Error(), "unexpected entry") {
		t.Fatalf("products imported under another .xctestrun name: %v", err)
	}
}

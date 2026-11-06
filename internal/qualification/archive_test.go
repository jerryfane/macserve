package qualification

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/maintenance"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/worker"
)

// archiveTemplate is an org ios_archive template.
func archiveTemplate() model.Template {
	return model.Template{ID: "org-ios-archive-v1", Version: 1, Kind: model.IOSArchive, Owners: []string{"themartianapp"}, Xcode: model.Xcode{Version: "27.1", Build: "27A9275"}, DeveloperDir: "/Applications/Xcode.app/Contents/Developer", DefaultTimeoutSeconds: 3600, MaxTimeoutSeconds: 5400, MemoryLimitMiB: 32768}
}

// An ios_archive template's source pin names the release its tool-evidence
// run archives at; a pin without one, with an invalid one, or naming a
// release for any other recipe does not pass.
func TestArchiveTemplateSourcePinNamesItsRelease(t *testing.T) {
	build := model.Template{ID: "org-build-v1", Version: 1, Kind: model.Build, Owners: []string{"themartianapp"}, Xcode: model.Xcode{Version: "27.1", Build: "27A9275"}, DeveloperDir: "/Applications/Xcode.app/Contents/Developer", DefaultTimeoutSeconds: 1800, MaxTimeoutSeconds: 3600, MemoryLimitMiB: 32768}
	registry, err := profiles.New(nil, []model.Template{archiveTemplate(), build})
	if err != nil {
		t.Fatal(err)
	}
	c := Challenge{Templates: registry.Templates(), Observation: maintenance.Observation{Profiles: registry.Digests()}}
	recipes := c.recipes()
	var archive, buildRecipe model.Profile
	for _, r := range recipes {
		if r.Kind == model.IOSArchive {
			archive = r
		} else {
			buildRecipe = r
		}
	}
	tail := `"commit":"` + strings.Repeat("a", 40) + `","tree":"` + strings.Repeat("b", 40) + `","sha256":"` + strings.Repeat("c", 64) + `","size_bytes":1`
	buildPin := `{"profile":"org-build-v1","repo":"themartianapp/herdrup",` + tail + `}`
	archivePin := func(release string) string {
		return `{"profile":"org-ios-archive-v1","repo":"themartianapp/herdrup",` + release + tail + `}`
	}
	parse := func(sources ...string) SourcePins {
		t.Helper()
		var pins SourcePins
		if err := decode([]byte(`{"schema":1,"sources":[`+strings.Join(sources, ",")+`]}`), &pins); err != nil {
			t.Fatal(err)
		}
		return pins
	}
	pins := parse(archivePin(`"release":{"build_name":"1.4.0","build_number":"42"},`), buildPin)
	if err := checkSourcePins(pins, recipes); err != nil {
		t.Fatal(err)
	}
	pin, _ := sourcePin(pins, archive.ID)
	admission, err := pinRequest(archive, pin, 3600)
	if err != nil || admission.Request.Kind != model.IOSArchive || !profiles.SameRelease(admission.Request.Release, &model.ReleaseRequest{BuildName: "1.4.0", BuildNumber: "42"}) || !profiles.SameRelease(admission.Profile.Release, admission.Request.Release) || admission.ProfileDigest != c.Observation.Profiles[archive.ID] {
		t.Fatalf("archive template pin admission %+v %v", admission, err)
	}
	refused := map[string]SourcePins{
		"archive pin without release":   parse(archivePin(``), buildPin),
		"archive pin bad build number":  parse(archivePin(`"release":{"build_name":"1.4.0","build_number":"042"},`), buildPin),
		"archive pin four-part name":    parse(archivePin(`"release":{"build_name":"1.4.0.1","build_number":"42"},`), buildPin),
		"native archive dart defines":   parse(archivePin(`"release":{"build_name":"1.4.0","build_number":"42","dart_defines":{"API_KEY":"k"}},`), buildPin),
		"archive pin with shard":        parse(archivePin(`"release":{"build_name":"1.4.0","build_number":"42"},"shard":"terminal",`), buildPin),
		"build pin with release":        parse(archivePin(`"release":{"build_name":"1.4.0","build_number":"42"},`), strings.Replace(buildPin, `"repo"`, `"release":{"build_name":"1.4.0","build_number":"42"},"repo"`, 1)),
		"archive pin without its build": parse(archivePin(`"release":{"build_name":"1.4.0","build_number":"42"},`)),
	}
	for name, pins := range refused {
		t.Run(name, func(t *testing.T) {
			if err := checkSourcePins(pins, recipes); err == nil {
				t.Fatal("invalid source pins accepted")
			}
		})
	}
	if _, err := pinRequest(buildRecipe, SourcePin{Profile: buildRecipe.ID, Repo: "themartianapp/herdrup", Commit: strings.Repeat("a", 40), Release: &model.ReleaseRequest{BuildName: "1", BuildNumber: "1"}}, 600); err == nil {
		t.Fatal("build template pin with a release admitted")
	}
	// An explicit profile's pin names neither shard nor release.
	profile := model.Profile{ID: "app-build", Kind: model.Build}
	explicit := parse(`{"profile":"app-build","release":{"build_name":"1.4.0","build_number":"42"},` + tail + `}`)
	if err := checkSourcePins(explicit, []model.Profile{profile}); err == nil {
		t.Fatal("explicit profile pin with a release accepted")
	}
	if err := checkSourcePins(parse(`{"profile":"app-build",`+tail+`}`), []model.Profile{profile}); err != nil {
		t.Fatal(err)
	}
}

// archiveRun writes a signing manifest of release 1.4.0 (42) naming an
// exported tar to dir, and returns the succeeded run's result: logs, the tar
// and the manifest artifacts. edit changes the manifest before encoding.
func archiveRun(t *testing.T, dir string, edit func(*worker.SigningManifest)) worker.Result {
	t.Helper()
	release := model.ReleaseRequest{BuildName: "1.4.0", BuildNumber: "42"}
	tarDigest := strings.Repeat("d", 64)
	m := worker.SigningManifest{
		Schema: worker.SigningManifestSchema, BuildName: release.BuildName, BuildNumber: release.BuildNumber,
		Archive:     worker.SealedArchive{Name: profiles.ArchiveArtifact, Root: profiles.ArchivePath, SHA256: tarDigest, SizeBytes: 10240, Entries: 6},
		Bundles:     []worker.SignableBundle{{Path: "Products/Applications/App.app", BundleID: "com.example.app", Executable: "App", PackageType: "APPL", ShortVersion: "1.4.0", Version: "42", Entitlements: json.RawMessage(`{}`), EntitlementsSHA256: hashHex([]byte(`{}`))}},
		Dylibs:      []string{},
		Executables: []string{"Products/Applications/App.app/App"},
	}
	if edit != nil {
		edit(&m)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	zero := 0
	return worker.Result{State: model.Succeeded, CleanupOK: true, ExitCode: &zero, Artifacts: []evidence.Artifact{
		{ID: "log", Name: "evidence/stdout.log", SizeBytes: 1},
		{ID: "tar", Name: profiles.ArchiveArtifact, SizeBytes: 10240, SHA256: tarDigest},
		{ID: "manifest", Name: profiles.SigningManifestArtifact, SizeBytes: int64(len(raw)), SHA256: hashHex(raw)},
	}}
}

func hashHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// An archive run's tool evidence needs exit 0, exactly one sealed tar and one
// signing manifest whose exported bytes match their artifact record, parse
// as a canonical manifest of the pinned release and name exactly the tar.
func TestArchiveToolEvidenceRequiresSigningManifest(t *testing.T) {
	release := model.ReleaseRequest{BuildName: "1.4.0", BuildNumber: "42"}
	archive := model.Profile{Kind: model.IOSArchive}
	dir := t.TempDir()
	locate := func(id string) (string, error) { return filepath.Join(dir, id), nil }
	good := archiveRun(t, dir, nil)
	if err := archiveOutput(good, release, locate); err != nil {
		t.Fatal(err)
	}
	if !archiveRunPasses(archive, good) || !archiveRunPasses(model.Profile{Kind: model.Build}, worker.Result{}) {
		t.Fatal("archive run evidence predicate")
	}
	refused := map[string]struct {
		edit    func(*worker.SigningManifest)
		result  func(*worker.Result)
		release model.ReleaseRequest
	}{
		"other build number":        {release: model.ReleaseRequest{BuildName: "1.4.0", BuildNumber: "43"}},
		"bundle at other version":   {edit: func(m *worker.SigningManifest) { m.Bundles[0].Version = "41" }},
		"manifest names other tar":  {edit: func(m *worker.SigningManifest) { m.Archive.SHA256 = strings.Repeat("e", 64) }},
		"manifest names other size": {edit: func(m *worker.SigningManifest) { m.Archive.SizeBytes = 10241 }},
		"manifest bytes tampered":   {result: func(r *worker.Result) { r.Artifacts[2].SHA256 = strings.Repeat("f", 64) }},
		"manifest size tampered":    {result: func(r *worker.Result) { r.Artifacts[2].SizeBytes++ }},
		"no manifest":               {result: func(r *worker.Result) { r.Artifacts = r.Artifacts[:2] }},
		"no archive":                {result: func(r *worker.Result) { r.Artifacts = append(r.Artifacts[:1], r.Artifacts[2]) }},
		"two archives": {result: func(r *worker.Result) {
			r.Artifacts = append(r.Artifacts, evidence.Artifact{ID: "tar2", Name: profiles.ArchiveArtifact, SizeBytes: 1})
		}},
		"two manifests":        {result: func(r *worker.Result) { r.Artifacts = append(r.Artifacts, r.Artifacts[2]) }},
		"gzipped archive name": {result: func(r *worker.Result) { r.Artifacts[1].Name = "App.xcarchive.tar.gz" }},
		"empty archive":        {result: func(r *worker.Result) { r.Artifacts[1].SizeBytes = 0 }},
	}
	for name, tc := range refused {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			locate := func(id string) (string, error) { return filepath.Join(dir, id), nil }
			result := archiveRun(t, dir, tc.edit)
			if tc.result != nil {
				tc.result(&result)
			}
			want := release
			if tc.release.BuildName != "" {
				want = tc.release
			}
			if err := archiveOutput(result, want, locate); err == nil {
				t.Fatal("unproven archive output accepted")
			}
		})
	}
	// A non-canonical manifest (re-indented, same content) does not parse.
	raw, err := os.ReadFile(filepath.Join(dir, "manifest"))
	if err != nil {
		t.Fatal(err)
	}
	var indented json.RawMessage = raw
	pretty, err := json.MarshalIndent(indented, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest"), pretty, 0600); err != nil {
		t.Fatal(err)
	}
	noncanonical := good
	noncanonical.Artifacts = append([]evidence.Artifact(nil), good.Artifacts...)
	noncanonical.Artifacts[2].SizeBytes, noncanonical.Artifacts[2].SHA256 = int64(len(pretty)), hashHex(pretty)
	if err := archiveOutput(noncanonical, release, locate); err == nil {
		t.Fatal("non-canonical signing manifest accepted")
	}
	for name, result := range map[string]worker.Result{
		"no manifest artifact": {State: model.Succeeded, ExitCode: good.ExitCode, Artifacts: good.Artifacts[:2]},
		"no archive artifact":  {State: model.Succeeded, ExitCode: good.ExitCode, Artifacts: []evidence.Artifact{good.Artifacts[0], good.Artifacts[2]}},
		"signalled":            {State: model.Succeeded, ExitCode: good.ExitCode, Signal: "SIGKILL", Artifacts: good.Artifacts},
		"no exit code":         {State: model.Succeeded, Artifacts: good.Artifacts},
	} {
		if archiveRunPasses(archive, result) {
			t.Errorf("%s: archive run passed", name)
		}
	}
	one := 1
	failed := good
	failed.ExitCode = &one
	if archiveRunPasses(archive, failed) {
		t.Fatal("failed archive run passed")
	}
}

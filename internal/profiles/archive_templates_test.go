package profiles_test

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
)

// Like the other template tests, these reach the release fields (kind,
// release, build_name, build_number, dart_defines) through their JSON
// spelling.

// archiveTemplate leaves its budgets to the kind's defaults.
const archiveTemplate = `{"id":"org-ios-archive-v1","version":1,"kind":"ios_archive","owners":["themartianapp","jerryfane"],"xcode":{"version":"27.1","build":"27A9275"},"developer_dir":"/Applications/Xcode.app/Contents/Developer","memory_limit_mib":32768}`

func archiveRequest(t *testing.T, release string) model.Request {
	t.Helper()
	if release != "" {
		release = `,"release":` + release
	}
	return decode[model.Request](t, `{"repo":"themartianapp/herdrup","sha":"`+strings.Repeat("ab", 20)+`","kind":"ios_archive","profile":"org-ios-archive-v1","xcode":{"version":"27.1","build":"27A9275"}`+release+`}`)
}

// flutterArchiveTemplate is the Flutter ios_archive template the Flutter
// tests' pin names.
func flutterArchiveTemplate() model.Template {
	pin := flutterPin
	t := flutterTemplate(model.IOSArchive, &pin)
	t.ID, t.Simulators = "org-flutter-ios-archive-v1", nil
	return t
}

func flutterArchiveRequest(t *testing.T, release string) model.Request {
	t.Helper()
	return decode[model.Request](t, `{"repo":"themartianapp/among-friends","sha":"`+strings.Repeat("a", 40)+`","kind":"ios_archive","profile":"org-flutter-ios-archive-v1","xcode":{"version":"27.1","build":"27A9275"},"flutter":{"version":"3.41.9"},"release":`+release+`}`)
}

func admitFlutterArchive(t *testing.T, release string) model.Admission {
	t.Helper()
	registry, err := profiles.New(nil, []model.Template{flutterArchiveTemplate()})
	if err != nil {
		t.Fatal(err)
	}
	admission, err := registry.Resolve(flutterArchiveRequest(t, release))
	if err != nil {
		t.Fatal(err)
	}
	return admission
}

// defines returns n distinct dart_defines keys of keyLength bytes, each
// with value.
func defines(n, keyLength int, value string) map[string]string {
	m := make(map[string]string, n)
	for i := range n {
		key := fmt.Sprintf("K%03d", i)
		m[key+strings.Repeat("X", keyLength-len(key))] = value
	}
	return m
}

// grown appends one byte to m[key].
func grown(m map[string]string, key string) map[string]string {
	m[key] += "v"
	return m
}

func TestValidateReleaseBounds(t *testing.T) {
	release := func(name, number string) model.ReleaseRequest {
		return model.ReleaseRequest{BuildName: name, BuildNumber: number}
	}
	flutter := func(dartDefines map[string]string) model.ReleaseRequest {
		return model.ReleaseRequest{BuildName: "1.4.0", BuildNumber: "42", DartDefines: dartDefines}
	}
	valid := map[string]struct {
		release model.ReleaseRequest
		flutter bool
	}{
		"one-part name":                {release("1", "1"), false},
		"two-part name":                {release("1.4", "1"), false},
		"three-part name":              {release("1.4.0", "1"), false},
		"four-digit parts":             {release("9999.9999.9999", "1"), false},
		"build number zero":            {release("1.0", "0"), false},
		"nine-digit build number":      {release("1.0", "999999999"), false},
		"native without defines":       {release("1.0", "1"), false},
		"flutter without defines":      {release("1.0", "1"), true},
		"empty defines on native":      {flutter(map[string]string{}), false},
		"32 defines":                   {flutter(defines(32, 8, "v")), true},
		"64-byte key":                  {flutter(defines(1, 64, "v")), true},
		"1024-byte value":              {flutter(defines(1, 8, strings.Repeat("v", 1024))), true},
		"4096 bytes in all":            {flutter(defines(4, 4, strings.Repeat("v", 1020))), true},
		"empty value":                  {flutter(map[string]string{"API_KEY": ""}), true},
		"printable ASCII value":        {flutter(map[string]string{"API_URL": "https://api.example.com/v1?a=b&c=~ {}"}), true},
		"underscore and digits in key": {flutter(map[string]string{"A_1_B2": "x"}), true},
	}
	for name, tc := range valid {
		t.Run(name, func(t *testing.T) {
			if err := profiles.ValidateRelease(tc.release, tc.flutter); err != nil {
				t.Fatal(err)
			}
		})
	}
	invalid := map[string]struct {
		release model.ReleaseRequest
		flutter bool
		want    error
	}{
		"empty name":                    {release("", "1"), false, profiles.ErrInvalid},
		"four-part name":                {release("1.4.0.1", "1"), false, profiles.ErrInvalid},
		"five-digit part":               {release("1.10000", "1"), false, profiles.ErrInvalid},
		"five-digit first part":         {release("10000", "1"), false, profiles.ErrInvalid},
		"leading dot":                   {release(".1.4", "1"), false, profiles.ErrInvalid},
		"trailing dot":                  {release("1.4.", "1"), false, profiles.ErrInvalid},
		"empty part":                    {release("1..4", "1"), false, profiles.ErrInvalid},
		"letters in name":               {release("1.4b", "1"), false, profiles.ErrInvalid},
		"name with newline":             {release("1.4\n", "1"), false, profiles.ErrInvalid},
		"empty build number":            {release("1.4", ""), false, profiles.ErrInvalid},
		"leading zero build number":     {release("1.4", "042"), false, profiles.ErrInvalid},
		"double zero build number":      {release("1.4", "00"), false, profiles.ErrInvalid},
		"ten-digit build number":        {release("1.4", "1234567890"), false, profiles.ErrInvalid},
		"dotted build number":           {release("1.4", "1.0"), false, profiles.ErrInvalid},
		"negative build number":         {release("1.4", "-1"), false, profiles.ErrInvalid},
		"defines on native":             {flutter(map[string]string{"API_KEY": "k"}), false, profiles.ErrUnsupported},
		"33 defines":                    {flutter(defines(33, 8, "v")), true, profiles.ErrInvalid},
		"lowercase key":                 {flutter(map[string]string{"api_key": "k"}), true, profiles.ErrInvalid},
		"key starting with digit":       {flutter(map[string]string{"1API": "k"}), true, profiles.ErrInvalid},
		"key starting with underscore":  {flutter(map[string]string{"_API": "k"}), true, profiles.ErrInvalid},
		"key with dash":                 {flutter(map[string]string{"API-KEY": "k"}), true, profiles.ErrInvalid},
		"key with equals":               {flutter(map[string]string{"API=KEY": "k"}), true, profiles.ErrInvalid},
		"empty key":                     {flutter(map[string]string{"": "k"}), true, profiles.ErrInvalid},
		"65-byte key":                   {flutter(defines(1, 65, "v")), true, profiles.ErrInvalid},
		"1025-byte value":               {flutter(defines(1, 8, strings.Repeat("v", 1025))), true, profiles.ErrInvalid},
		"dollar in value":               {flutter(map[string]string{"API_KEY": "${HOME}"}), true, profiles.ErrInvalid},
		"newline in value":              {flutter(map[string]string{"API_KEY": "a\nb"}), true, profiles.ErrInvalid},
		"tab in value":                  {flutter(map[string]string{"API_KEY": "a\tb"}), true, profiles.ErrInvalid},
		"NUL in value":                  {flutter(map[string]string{"API_KEY": "a\x00b"}), true, profiles.ErrInvalid},
		"DEL in value":                  {flutter(map[string]string{"API_KEY": "a\x7fb"}), true, profiles.ErrInvalid},
		"non-ASCII value":               {flutter(map[string]string{"API_KEY": "caf\u00e9"}), true, profiles.ErrInvalid},
		"4097 bytes in all":             {flutter(grown(defines(4, 4, strings.Repeat("v", 1020)), "K000")), true, profiles.ErrInvalid},
		"over 4096 bytes with 32 small": {flutter(defines(32, 64, strings.Repeat("v", 65))), true, profiles.ErrInvalid},
		"five 1000-byte values":         {flutter(defines(5, 4, strings.Repeat("v", 1000))), true, profiles.ErrInvalid},
	}
	for name, tc := range invalid {
		t.Run(name, func(t *testing.T) {
			if err := profiles.ValidateRelease(tc.release, tc.flutter); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestNormalizeArchiveTemplateBudgetsAndPins(t *testing.T) {
	r := templatesFile(t, buildTemplate+","+archiveTemplate)
	got := r.Templates()[1]
	if got.Kind != model.IOSArchive || len(got.Simulators) != 0 || got.DefaultTimeoutSeconds != 3600 || got.MaxTimeoutSeconds != 5400 {
		t.Fatalf("archive template: %+v", got)
	}
	if _, err := loadTemplates(strings.Replace(archiveTemplate, `"memory_limit_mib"`, `"max_timeout_seconds":5400,"memory_limit_mib"`, 1)); err != nil {
		t.Fatalf("5400-second archive maximum refused: %v", err)
	}
	if _, err := loadTemplates(strings.Replace(archiveTemplate, `"memory_limit_mib"`, `"simulators":[],"memory_limit_mib"`, 1)); err != nil {
		t.Fatalf("empty simulator list refused: %v", err)
	}
	pin := pinJSON(iPhone)
	pinned := strings.Replace(archiveTemplate, `"memory_limit_mib"`, `"simulators":[`+pin+`],"memory_limit_mib"`, 1)
	if _, err := loadTemplates(pinned); !errors.Is(err, profiles.ErrInvalid) {
		t.Fatalf("archive template with a simulator pin: %v", err)
	}
	if _, err := loadTemplates(strings.Replace(archiveTemplate, `"memory_limit_mib"`, `"max_timeout_seconds":5401,"memory_limit_mib"`, 1)); !errors.Is(err, profiles.ErrInvalid) {
		t.Fatalf("archive maximum above 5400: %v", err)
	}
	// A Flutter ios_archive template loads with no simulator.
	if _, err := profiles.New(nil, []model.Template{flutterArchiveTemplate()}); err != nil {
		t.Fatalf("Flutter archive template refused: %v", err)
	}
}

func TestExplicitProfilesCannotBeArchiveJobs(t *testing.T) {
	installed, err := profiles.Load("testdata/installed-profiles.json")
	if err != nil {
		t.Fatal(err)
	}
	archive := installed.List()[0]
	archive.Kind = model.IOSArchive
	if _, err := profiles.New([]model.Profile{archive}, nil); !errors.Is(err, profiles.ErrUnsupported) {
		t.Fatalf("explicit ios_archive profile: %v", err)
	}
	withRelease := installed.List()[0]
	withRelease.Release = &model.ReleaseRequest{BuildName: "1.0", BuildNumber: "1"}
	if _, err := profiles.New([]model.Profile{withRelease}, nil); !errors.Is(err, profiles.ErrInvalid) {
		t.Fatalf("explicit profile embedding a release: %v", err)
	}
	// An explicit profile's request carries no release.
	p := installed.List()[0]
	request := model.Request{Repo: p.Repo, SHA: strings.Repeat("a", 40), Kind: p.Kind, Profile: p.ID, Xcode: p.Xcode, Simulator: p.Simulator}
	if _, err := installed.Resolve(request); err != nil {
		t.Fatal(err)
	}
	request.Release = &model.ReleaseRequest{BuildName: "1.0", BuildNumber: "1"}
	if _, err := installed.Resolve(request); !errors.Is(err, profiles.ErrUnsupported) {
		t.Fatalf("explicit profile request with a release: %v", err)
	}
}

func TestResolveArchiveTemplateRequiresRelease(t *testing.T) {
	r := templatesFile(t, buildTemplate+","+uiTemplate+","+scriptTemplate+","+archiveTemplate)
	a, err := r.Resolve(archiveRequest(t, `{"build_name":"1.4.0","build_number":"42","dart_defines":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	// An empty dart_defines map is absent, in the request and the snapshot.
	if member(t, a.Request, "release") != `{"build_name":"1.4.0","build_number":"42"}` || a.Request.TimeoutSeconds != 3600 || a.Request.Simulator != nil || a.Request.Shard != "" {
		t.Fatalf("request not normalized: %+v %s", a.Request, member(t, a.Request, "release"))
	}
	if member(t, a.Profile, "release") != `{"build_name":"1.4.0","build_number":"42"}` || member(t, a.Profile, "kind") != `"ios_archive"` || a.Profile.Simulator != nil || a.Profile.Shard != "" || a.ProfileDigest != r.Digests()[a.Profile.ID] {
		t.Fatalf("snapshot: %+v", a.Profile)
	}
	if a.Profile.Release == a.Request.Release {
		t.Fatal("snapshot shares the request's release")
	}
	single, err := profiles.ForSnapshot(a.Profile)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := single.Resolve(a.Request); err != nil || !reflect.DeepEqual(again, a) {
		t.Fatalf("snapshot does not re-admit identically: %+v %v", again, err)
	}
	long := archiveRequest(t, `{"build_name":"1.4.0","build_number":"42"}`)
	long.TimeoutSeconds = 5400
	if b, err := r.Resolve(long); err != nil || b.Request.TimeoutSeconds != 5400 {
		t.Fatalf("5400-second archive job: %+v %v", b.Request, err)
	}
	long.TimeoutSeconds = 5401
	if _, err := r.Resolve(long); !errors.Is(err, profiles.ErrInvalid) {
		t.Fatalf("timeout above the archive maximum: %v", err)
	}
	release := `"release":{"build_name":"1.0","build_number":"1"}`
	refused := map[string]struct {
		request model.Request
		want    error
	}{
		"missing release":        {archiveRequest(t, ""), profiles.ErrInvalid},
		"null release":           {archiveRequest(t, `null`), profiles.ErrInvalid},
		"missing build number":   {archiveRequest(t, `{"build_name":"1.4.0"}`), profiles.ErrInvalid},
		"leading zero build":     {archiveRequest(t, `{"build_name":"1.4.0","build_number":"042"}`), profiles.ErrInvalid},
		"four-part name":         {archiveRequest(t, `{"build_name":"1.4.0.1","build_number":"42"}`), profiles.ErrInvalid},
		"native dart defines":    {archiveRequest(t, `{"build_name":"1.4.0","build_number":"42","dart_defines":{"API_KEY":"k"}}`), profiles.ErrUnsupported},
		"archive with shard":     {edit(t, archiveRequest(t, `{"build_name":"1.4.0","build_number":"42"}`), func(m map[string]any) { m["shard"] = "terminal" }), profiles.ErrUnsupported},
		"archive with simulator": {edit(t, archiveRequest(t, `{"build_name":"1.4.0","build_number":"42"}`), func(m map[string]any) { m["simulator"] = iPhone }), profiles.ErrUnsupported},
		"archive with flutter":   {edit(t, archiveRequest(t, `{"build_name":"1.4.0","build_number":"42"}`), func(m map[string]any) { m["flutter"] = map[string]any{"version": "3.41.9"} }), profiles.ErrUnsupported},
		"build kind on archive":  {edit(t, archiveRequest(t, `{"build_name":"1.4.0","build_number":"42"}`), func(m map[string]any) { m["kind"] = "build" }), profiles.ErrUnsupported},
		"archive kind on build": {edit(t, templateRequest("themartianapp/herdrup"), func(m map[string]any) {
			m["kind"] = "ios_archive"
			m["release"] = map[string]any{"build_name": "1.0", "build_number": "1"}
		}), profiles.ErrUnsupported},
		"release on build":         {decode[model.Request](t, `{"repo":"themartianapp/herdrup","sha":"`+strings.Repeat("ab", 20)+`","kind":"build","profile":"org-ios-sim-build-v1","xcode":{"version":"27.1","build":"27A9275"},`+release+`}`), profiles.ErrUnsupported},
		"release on UI test":       {edit(t, testRequest(t, model.SimulatorUITest, "terminal"), func(m map[string]any) { m["release"] = map[string]any{"build_name": "1.0", "build_number": "1"} }), profiles.ErrUnsupported},
		"release on script":        {edit(t, scriptRequest(t, "duo-screenshots"), func(m map[string]any) { m["release"] = map[string]any{"build_name": "1.0", "build_number": "1"} }), profiles.ErrUnsupported},
		"other owner":              {edit(t, archiveRequest(t, `{"build_name":"1.4.0","build_number":"42"}`), func(m map[string]any) { m["repo"] = "someone-else/app" }), profiles.ErrUnsupported},
		"other Xcode":              {edit(t, archiveRequest(t, `{"build_name":"1.4.0","build_number":"42"}`), func(m map[string]any) { m["xcode"] = map[string]any{"version": "27.0", "build": "27A100"} }), profiles.ErrUnsupported},
		"invalid release on build": {decode[model.Request](t, `{"repo":"themartianapp/herdrup","sha":"`+strings.Repeat("ab", 20)+`","kind":"build","profile":"org-ios-sim-build-v1","xcode":{"version":"27.1","build":"27A9275"},"release":{"build_name":"","build_number":""}}`), profiles.ErrUnsupported},
	}
	for name, tc := range refused {
		t.Run(name, func(t *testing.T) {
			if _, err := r.Resolve(tc.request); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

// A Flutter archive's admission copies its Dart defines: changing the
// client's map after admission changes neither the request nor the snapshot.
func TestResolveFlutterArchiveCopiesDartDefines(t *testing.T) {
	registry, err := profiles.New(nil, []model.Template{flutterArchiveTemplate()})
	if err != nil {
		t.Fatal(err)
	}
	request := flutterArchiveRequest(t, `{"build_name":"1.4.0","build_number":"42","dart_defines":{"API_BASE_URL":"https://api.example.com"}}`)
	a, err := registry.Resolve(request)
	if err != nil {
		t.Fatal(err)
	}
	request.Release.DartDefines["API_BASE_URL"] = "https://evil.example.com"
	request.Release.BuildNumber = "43"
	for _, release := range []*model.ReleaseRequest{a.Request.Release, a.Profile.Release} {
		if release == nil || release.BuildNumber != "42" || len(release.DartDefines) != 1 || release.DartDefines["API_BASE_URL"] != "https://api.example.com" {
			t.Fatalf("admitted release aliases the request: %+v", release)
		}
	}
	a.Request.Release.DartDefines["API_BASE_URL"] = "changed"
	if a.Profile.Release.DartDefines["API_BASE_URL"] != "https://api.example.com" {
		t.Fatal("snapshot shares the admitted request's dart_defines")
	}
	// A Flutter archive takes at most the bounded defines, like any release.
	if _, err := registry.Resolve(flutterArchiveRequest(t, `{"build_name":"1.4.0","build_number":"42","dart_defines":{"API_KEY":"${HOME}"}}`)); !errors.Is(err, profiles.ErrInvalid) {
		t.Fatalf("dart define with a placeholder: %v", err)
	}
}

func TestDeriveNativeArchiveArgvGolden(t *testing.T) {
	r := templatesFile(t, archiveTemplate)
	a, err := r.Resolve(archiveRequest(t, `{"build_name":"1.4.0","build_number":"42"}`))
	if err != nil {
		t.Fatal(err)
	}
	archive := []string{"-configuration", "Release", "-sdk", "iphoneos", "-destination", "generic/platform=iOS", "-archivePath", "${WORKSPACE}/App.xcarchive", "-derivedDataPath", "${DERIVED_DATA}", "CODE_SIGNING_ALLOWED=NO", "MARKETING_VERSION=1.4.0", "CURRENT_PROJECT_VERSION=42", "archive"}
	artifacts := []model.ArtifactRule{{Path: "App.xcarchive.tar", Required: true}, {Path: "signing-manifest.json", Required: true}}
	xcodegen := model.Command{Executable: "/Library/macserve/tools/xcodegen", Args: []string{"generate", "--spec", "project.yml"}}
	cases := []struct {
		name    string
		config  string
		workDir string
		prepare []model.Command
		run     model.Command
	}{
		{"project", `{"version":1,"work_dir":".","project":"App.xcodeproj","scheme":"App"}`, ".", nil,
			model.Command{Executable: "/usr/bin/xcrun", Args: append([]string{"xcodebuild", "-project", "App.xcodeproj", "-scheme", "App"}, archive...)}},
		{"workspace", `{"version":1,"work_dir":"apps/ios","workspace":"My App.xcworkspace","scheme":"My App"}`, "apps/ios", nil,
			model.Command{Executable: "/usr/bin/xcrun", Args: append([]string{"xcodebuild", "-workspace", "My App.xcworkspace", "-scheme", "My App"}, archive...)}},
		{"project with both steps", `{"version":1,"work_dir":"ios","project":"Herdr.xcodeproj","scheme":"Herdr","xcodegen":true,"resolve_packages":true}`, "ios",
			[]model.Command{xcodegen, {Executable: "/usr/bin/xcrun", Args: []string{"xcodebuild", "-project", "Herdr.xcodeproj", "-scheme", "Herdr", "-resolvePackageDependencies"}}},
			model.Command{Executable: "/usr/bin/xcrun", Args: append([]string{"xcodebuild", "-project", "Herdr.xcodeproj", "-scheme", "Herdr"}, archive...)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := parseConfig(t, tc.config)
			derived, err := profiles.Derive(a.Profile, config)
			if err != nil {
				t.Fatal(err)
			}
			if derived.WorkDir != tc.workDir || !reflect.DeepEqual(derived.Prepare, tc.prepare) || !reflect.DeepEqual(derived.Run, tc.run) || !reflect.DeepEqual(derived.Artifacts, artifacts) || len(derived.RequiredTests) != 0 || derived.Shard != "" {
				t.Fatalf("archive recipe:\n%+v\nwant prepare %+v run %+v", derived, tc.prepare, tc.run)
			}
			recipe := &model.RepoRecipe{ConfigSHA256: strings.Repeat("f", 64), Config: config, WorkDir: derived.WorkDir, Prepare: derived.Prepare, Run: derived.Run}
			if _, err := profiles.Effective(a.Profile, recipe); err != nil {
				t.Fatalf("archive recipe does not re-derive: %v", err)
			}
			// A recipe built at another version does not.
			moved := *recipe
			moved.Run.Args = append([]string(nil), recipe.Run.Args...)
			moved.Run.Args[len(moved.Run.Args)-2] = "CURRENT_PROJECT_VERSION=43"
			if _, err := profiles.Effective(a.Profile, &moved); err == nil {
				t.Fatal("archive recipe at another build number re-derived")
			}
		})
	}
}

func TestDeriveFlutterArchiveExactCommands(t *testing.T) {
	config, err := profiles.ParseRepoConfig([]byte(flutterRepoConfig))
	if err != nil {
		t.Fatal(err)
	}
	a := admitFlutterArchive(t, `{"build_name":"1.4.0","build_number":"42","dart_defines":{"API_BASE_URL":"https://api.example.com"}}`)
	derived, err := profiles.Derive(a.Profile, config)
	if err != nil {
		t.Fatal(err)
	}
	flutter := "${WORKSPACE}/flutter-sdk/bin/flutter"
	prepare := []model.Command{
		{Executable: "/bin/cp", Args: []string{"-c", "-R", "/Library/macserve/tools/flutter/3.41.9/flutter", "${WORKSPACE}/flutter-sdk"}},
		{Executable: "/bin/bash", Args: []string{flutter, "pub", "get", "--enforce-lockfile", "--suppress-analytics"}},
		{Executable: "/bin/bash", Args: []string{flutter, "build", "ios", "--config-only", "--release", "--no-codesign", "--build-name", "1.4.0", "--build-number", "42", "--dart-define", "API_BASE_URL=https://api.example.com", "--suppress-analytics"}},
		{Executable: "/Library/macserve/tools/ruby/62fe925f284c/bin/ruby", Args: []string{"${CHECKOUT}/scripts/add_call_directory_target.rb"}},
	}
	run := model.Command{Executable: "/usr/bin/xcrun", Args: []string{"xcodebuild", "-workspace", "ios/Runner.xcworkspace", "-scheme", "Runner", "-configuration", "Release", "-sdk", "iphoneos", "-destination", "generic/platform=iOS", "-archivePath", "${WORKSPACE}/App.xcarchive", "-derivedDataPath", "${DERIVED_DATA}", "CODE_SIGNING_ALLOWED=NO", "MARKETING_VERSION=1.4.0", "CURRENT_PROJECT_VERSION=42", "archive"}}
	artifacts := []model.ArtifactRule{{Path: "App.xcarchive.tar", Required: true}, {Path: "signing-manifest.json", Required: true}}
	if derived.WorkDir != "apps/mobile" || !reflect.DeepEqual(derived.Prepare, prepare) || !reflect.DeepEqual(derived.Run, run) || !reflect.DeepEqual(derived.Artifacts, artifacts) || len(derived.RequiredTests) != 0 {
		t.Fatalf("flutter archive recipe:\n%+v", derived)
	}
	recipe := &model.RepoRecipe{ConfigSHA256: strings.Repeat("f", 64), Config: config, WorkDir: derived.WorkDir, Prepare: derived.Prepare, Run: derived.Run}
	if _, err := profiles.Effective(a.Profile, recipe); err != nil {
		t.Fatalf("flutter archive recipe does not re-derive: %v", err)
	}
	// The snapshot's defines derive the recipe: another value does not match.
	other := admitFlutterArchive(t, `{"build_name":"1.4.0","build_number":"42","dart_defines":{"API_BASE_URL":"https://staging.example.com"}}`)
	if _, err := profiles.Effective(other.Profile, recipe); err == nil {
		t.Fatal("recipe re-derived under other dart defines")
	}
	// Several defines are passed in key order, whatever the map's order.
	sorted, err := profiles.Derive(admitFlutterArchive(t, `{"build_name":"2.0","build_number":"7","dart_defines":{"Z_LAST":"z","A_FIRST":"a=b","M_MID":""}}`).Profile, config)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{flutter, "build", "ios", "--config-only", "--release", "--no-codesign", "--build-name", "2.0", "--build-number", "7", "--dart-define", "A_FIRST=a=b", "--dart-define", "M_MID=", "--dart-define", "Z_LAST=z", "--suppress-analytics"}
	if !reflect.DeepEqual(sorted.Prepare[2].Args, want) {
		t.Fatalf("dart define order: %q", sorted.Prepare[2].Args)
	}
}

// Derive refuses an ios_archive snapshot without a valid release, or with
// a shard or simulator, whatever admission recorded.
func TestDeriveArchiveRefusesSnapshotWithoutRelease(t *testing.T) {
	r := templatesFile(t, archiveTemplate)
	a, err := r.Resolve(archiveRequest(t, `{"build_name":"1.4.0","build_number":"42"}`))
	if err != nil {
		t.Fatal(err)
	}
	config := parseConfig(t, `{"version":1,"work_dir":".","project":"App.xcodeproj","scheme":"App"}`)
	flutterConfig, err := profiles.ParseRepoConfig([]byte(flutterRepoConfig))
	if err != nil {
		t.Fatal(err)
	}
	flutter := admitFlutterArchive(t, `{"build_name":"1.4.0","build_number":"42"}`)
	for name, tc := range map[string]struct {
		snapshot model.Profile
		config   model.RepoConfig
	}{
		"no release":      {edit(t, a.Profile, func(m map[string]any) { delete(m, "release") }), config},
		"invalid release": {edit(t, a.Profile, func(m map[string]any) { m["release"] = map[string]any{"build_name": "1.4.0", "build_number": "042"} }), config},
		"native dart defines": {edit(t, a.Profile, func(m map[string]any) {
			m["release"] = map[string]any{"build_name": "1.4.0", "build_number": "42", "dart_defines": map[string]any{"API_KEY": "k"}}
		}), config},
		"shard":                   {edit(t, a.Profile, func(m map[string]any) { m["shard"] = "terminal" }), config},
		"simulator":               {edit(t, a.Profile, func(m map[string]any) { m["simulator"] = iPhone }), config},
		"flutter without release": {edit(t, flutter.Profile, func(m map[string]any) { delete(m, "release") }), flutterConfig},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := profiles.Derive(tc.snapshot, tc.config); !errors.Is(err, profiles.ErrInvalid) {
				t.Fatalf("got %v, want ErrInvalid", err)
			}
		})
	}
}

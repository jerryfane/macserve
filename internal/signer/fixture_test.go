package signer

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/receipt"
	"github.com/jerryfane/macserve/internal/worker"
)

var (
	fixtureNow  = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	fixtureCert = []byte("apple-distribution-certificate-der")
	fixtureTeam = "ABCDE12345"
	fixtureSecr = strings.Repeat("s", 64)
)

func fixtureIdentity() string {
	sum := sha1.Sum(fixtureCert)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// fakeTools stands in for codesign and security. Sign records the order
// of signed paths and leaves a _CodeSignature/CodeResources (and, for an
// entitled bundle, a copy of its entitlements) in each bundle, which
// Verify and Entitlements read back.
type fakeTools struct {
	mu         sync.Mutex
	identities []string
	signed     []string
	unlocked   int
	unlockErr  error
	signErr    error
}

func (f *fakeTools) CreateKeychain(_ context.Context, keychain, _ string) error {
	return os.WriteFile(keychain, []byte("keychain"), 0o600)
}

func (f *fakeTools) UnlockKeychain(context.Context, string, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unlocked++
	return f.unlockErr
}

func (f *fakeTools) Identities(context.Context, string) ([]string, error) {
	return f.identities, nil
}

func (f *fakeTools) DecodeProfile(_ context.Context, path string) ([]byte, error) {
	// Fixture profiles are their own plist content.
	return os.ReadFile(path)
}

func (f *fakeTools) Sign(_ context.Context, spec SignSpec) error {
	f.mu.Lock()
	f.signed = append(f.signed, spec.Path)
	f.mu.Unlock()
	if f.signErr != nil {
		return f.signErr
	}
	info, err := os.Stat(spec.Path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return nil
	}
	dir := filepath.Join(spec.Path, "_CodeSignature")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "CodeResources"), []byte("signed by "+spec.Identity), 0o644); err != nil {
		return err
	}
	if spec.Entitlements == "" {
		return nil
	}
	data, err := os.ReadFile(spec.Entitlements)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "entitlements.plist"), data, 0o644)
}

func (f *fakeTools) Verify(_ context.Context, path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		_, err = os.Stat(filepath.Join(path, "_CodeSignature", "CodeResources"))
	}
	return err
}

func (f *fakeTools) Entitlements(_ context.Context, path string) ([]byte, error) {
	return os.ReadFile(filepath.Join(path, "_CodeSignature", "entitlements.plist"))
}

// profileSpec describes a fixture provisioning profile.
type profileSpec struct {
	bundleID       string
	team           string
	appID          string
	expires        time.Time
	devices        bool
	allDevices     bool
	getTaskAllow   bool
	noBetaReports  bool
	certificate    []byte
	platform       string
	extraEntitles  string
	teamEntitlment string
}

func defaultProfile(bundleID string) profileSpec {
	return profileSpec{bundleID: bundleID, team: fixtureTeam, expires: fixtureNow.Add(30 * 24 * time.Hour), certificate: fixtureCert, platform: "iOS"}
}

func (p profileSpec) xml() []byte {
	appID := p.appID
	if appID == "" {
		appID = p.team + "." + p.bundleID
	}
	teamEntitlement := p.teamEntitlment
	if teamEntitlement == "" {
		teamEntitlement = p.team
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>AppIDName</key><string>Example</string>
	<key>CreationDate</key><date>2026-01-01T00:00:00Z</date>
	<key>Platform</key><array><string>` + p.platform + `</string></array>
	<key>DeveloperCertificates</key><array><data>` + base64.StdEncoding.EncodeToString([]byte("another-certificate")) + `</data><data>
	` + base64.StdEncoding.EncodeToString(p.certificate) + `
	</data></array>
	<key>Entitlements</key>
	<dict>
		<key>application-identifier</key><string>` + appID + `</string>
		<key>com.apple.developer.team-identifier</key><string>` + teamEntitlement + `</string>
		<key>keychain-access-groups</key><array><string>` + p.team + `.*</string><string>com.apple.token</string></array>
		<key>aps-environment</key><string>production</string>
		<key>com.apple.security.application-groups</key><array><string>group.com.example.shared</string></array>
		<key>com.apple.developer.associated-domains</key><string>*</string>
`)
	if p.getTaskAllow {
		b.WriteString("\t\t<key>get-task-allow</key><true/>\n")
	} else {
		b.WriteString("\t\t<key>get-task-allow</key><false/>\n")
	}
	if !p.noBetaReports {
		b.WriteString("\t\t<key>beta-reports-active</key><true/>\n")
	}
	b.WriteString(p.extraEntitles)
	b.WriteString(`	</dict>
	<key>ExpirationDate</key><date>` + p.expires.UTC().Format(time.RFC3339) + `</date>
	<key>Name</key><string>Example App Store</string>
`)
	if p.devices {
		b.WriteString("\t<key>ProvisionedDevices</key><array><string>00008110-000000000000001E</string></array>\n")
	}
	if p.allDevices {
		b.WriteString("\t<key>ProvisionsAllDevices</key><true/>\n")
	}
	b.WriteString(`	<key>TeamIdentifier</key><array><string>` + p.team + `</string></array>
	<key>UUID</key><string>` + uuidFor(p.bundleID) + `</string>
	<key>Version</key><integer>1</integer>
</dict>
</plist>
`)
	return []byte(b.String())
}

func uuidFor(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	h := hex.EncodeToString(sum[:16])
	return strings.ToUpper(h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32])
}

// tarEntry is one entry of a fixture archive tar.
type tarEntry struct {
	name     string
	typeflag byte
	mode     int64
	body     []byte
	link     string
	uid      int
}

func dirEntry(name string) tarEntry {
	return tarEntry{name: name + "/", typeflag: tar.TypeDir, mode: 0o755}
}
func fileEntry(name string, mode int64, body string) tarEntry {
	return tarEntry{name: name, typeflag: tar.TypeReg, mode: mode, body: []byte(body)}
}

func buildTar(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buffer bytes.Buffer
	tw := tar.NewWriter(&buffer)
	for _, e := range entries {
		header := &tar.Header{Name: e.name, Typeflag: e.typeflag, Mode: e.mode, Size: int64(len(e.body)), Linkname: e.link, Uid: e.uid, ModTime: time.Unix(0, 0), Format: tar.FormatPAX}
		if e.typeflag != tar.TypeReg {
			header.Size = 0
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if e.typeflag == tar.TypeReg {
			if _, err := tw.Write(e.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

const (
	appPath  = "Products/Applications/Example.app"
	extPath  = appPath + "/PlugIns/Widget.appex"
	fmwkPath = appPath + "/Frameworks/Lib.framework"
	dylib    = appPath + "/Frameworks/libswiftCore.dylib"
	appID    = "com.example.app"
	extID    = "com.example.app.widget"
)

var machO = string([]byte{0xcf, 0xfa, 0xed, 0xfe}) + "binary"

// archiveEntries is a sealed-archive-shaped tree: root app with an app
// extension, a framework and a loose dylib.
func archiveEntries() []tarEntry {
	r := profiles.ArchivePath + "/"
	return []tarEntry{
		dirEntry(profiles.ArchivePath),
		fileEntry(r+"Info.plist", 0o644, "archive info"),
		dirEntry(r + "Products"),
		dirEntry(r + "Products/Applications"),
		dirEntry(r + appPath),
		fileEntry(r+appPath+"/Example", 0o755, machO+"app"),
		dirEntry(r + appPath + "/Frameworks"),
		dirEntry(r + fmwkPath),
		fileEntry(r+fmwkPath+"/Info.plist", 0o644, "fmwk info"),
		fileEntry(r+fmwkPath+"/Lib", 0o755, machO+"lib"),
		fileEntry(r+dylib, 0o755, machO+"dylib"),
		fileEntry(r+appPath+"/Info.plist", 0o644, "app info"),
		dirEntry(r + appPath + "/PlugIns"),
		dirEntry(r + extPath),
		fileEntry(r+extPath+"/Info.plist", 0o644, "ext info"),
		fileEntry(r+extPath+"/Widget", 0o755, machO+"ext"),
	}
}

func sortedEntries(entries []tarEntry) []tarEntry {
	out := slices.Clone(entries)
	slices.SortStableFunc(out, func(a, b tarEntry) int { return strings.Compare(a.name, b.name) })
	return out
}

func executablesOf(entries []tarEntry) []string {
	var out []string
	for _, e := range entries {
		if e.typeflag == tar.TypeReg && e.mode == 0o755 {
			out = append(out, strings.TrimPrefix(e.name, profiles.ArchivePath+"/"))
		}
	}
	slices.Sort(out)
	return out
}

func entitlementsJSON(t *testing.T, value map[string]any) (json.RawMessage, string) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return raw, hex.EncodeToString(sum[:])
}

var fixtureRelease = model.ReleaseRequest{BuildName: "2.0.1", BuildNumber: "17"}

// manifestFor is the canonical signing manifest of a tar.
func manifestFor(t *testing.T, tarBytes []byte, entries []tarEntry, appEntitlements map[string]any) worker.SigningManifest {
	t.Helper()
	sum := sha256.Sum256(tarBytes)
	empty, emptySHA := entitlementsJSON(t, map[string]any{})
	appEnt, appSHA := entitlementsJSON(t, appEntitlements)
	m := worker.SigningManifest{
		Schema: worker.SigningManifestSchema, BuildName: fixtureRelease.BuildName, BuildNumber: fixtureRelease.BuildNumber,
		Archive: worker.SealedArchive{Name: profiles.ArchiveArtifact, Root: profiles.ArchivePath, SHA256: hex.EncodeToString(sum[:]), SizeBytes: int64(len(tarBytes)), Entries: len(entries)},
		Bundles: []worker.SignableBundle{
			{Path: appPath, BundleID: appID, Executable: "Example", PackageType: "APPL", ShortVersion: "2.0.1", Version: "17", Entitlements: appEnt, EntitlementsSHA256: appSHA},
			{Path: fmwkPath, BundleID: "com.example.lib", Executable: "Lib", PackageType: "FMWK", Entitlements: empty, EntitlementsSHA256: emptySHA},
			{Path: extPath, BundleID: extID, Executable: "Widget", PackageType: "XPC!", ShortVersion: "2.0.1", Version: "17", Entitlements: empty, EntitlementsSHA256: emptySHA},
		},
		Dylibs:      []string{dylib},
		Executables: executablesOf(entries),
	}
	slices.SortFunc(m.Bundles, func(a, b worker.SignableBundle) int { return strings.Compare(a.Path, b.Path) })
	return m
}

// receiptSpec mutates a valid job receipt payload before signing.
type receiptSpec func(*receipt.Payload)

func digestHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// jobReceipt is a compact, complete, succeeded ios_archive receipt for
// jobID binding manifestSHA, signed by key under keyID.
func jobReceipt(t *testing.T, key ed25519.PrivateKey, keyID, jobID, manifestSHA string, mutate ...receiptSpec) []byte {
	t.Helper()
	sha := strings.Repeat("c", 40)
	release := fixtureRelease
	request := model.Request{Repo: "example-org/example-app", SHA: sha, Kind: model.IOSArchive, Profile: "org-ios-archive-v1", Xcode: model.Xcode{Version: "27.0", Build: "27A100"}, Release: &release, TimeoutSeconds: 3600}
	requestJSON, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	deadline := fixtureNow.Add(-time.Hour)
	exit := 0
	log := func(name string) evidence.Artifact {
		return evidence.Artifact{ID: digestHex([]byte(name)), Name: name, MediaType: "text/plain", SizeBytes: 1, SHA256: digestHex([]byte(name)), ExpiresAt: fixtureNow.Add(time.Hour)}
	}
	manifestDigest := strings.Repeat("e", 64)
	payloadRelease := release
	p := receipt.Payload{
		Schema: 1, JobID: jobID, AttemptID: jobID, InputDigest: strings.Repeat("1", 64),
		Service:    receipt.ServiceIdentity{ID: "macserve", HostID: "studio", Version: "test", BinarySHA256: strings.Repeat("2", 64)},
		Repository: receipt.Repository{ID: 77, Name: request.Repo},
		Approval:   receipt.Approval{Intake: "private_api", Identity: "releaser", AttemptID: jobID},
		Request:    request, Release: &payloadRelease,
		ReleaseProvenance:     &model.ReleaseProvenance{RepositoryID: 77, DefaultBranch: "main", HeadSHA: sha, ResolvedAt: fixtureNow.Add(-3 * time.Hour), Source: model.ProvenanceGitHubApp},
		SigningManifestSHA256: manifestSHA,
		RequestDigest:         digestHex(requestJSON), ProfileDigest: strings.Repeat("3", 64), ProfileVersion: 1,
		Source:      worker.Source{Commit: sha, Tree: strings.Repeat("d", 40), SHA256: strings.Repeat("4", 64), SizeBytes: 100},
		Observation: receipt.Observation{Xcode: request.Xcode, SDKVersion: "27.0", SDKBuild: "27A100", SwiftVersion: "6.2", OSVersion: "26.1", OSBuild: "25B1", Architecture: "arm64"},
		State:       model.Succeeded, ExitCode: &exit,
		CreatedAt: fixtureNow.Add(-2 * time.Hour), StartedAt: fixtureNow.Add(-2 * time.Hour), FinishedAt: fixtureNow.Add(-90 * time.Minute), Deadline: &deadline, SealedAt: fixtureNow.Add(-89 * time.Minute),
		WorkerEpoch:  "epoch",
		Resources:    receipt.ResourcePolicy{TimeoutSeconds: 3600, MemoryLimitMiB: 1024, PeakMemoryMiB: 10, CleanupRequired: true, CleanupOK: true},
		Tests:        receipt.TestEvidence{Status: "tests_not_run", Required: nil},
		Logs:         []evidence.Artifact{log("evidence/stdout.log"), log("evidence/stderr.log")},
		Digests:      receipt.EvidenceDigests{Commands: strings.Repeat("5", 64), Artifacts: strings.Repeat("6", 64), Generated: strings.Repeat("7", 64), Lockfiles: strings.Repeat("8", 64), TestCases: strings.Repeat("9", 64)},
		CommandCount: 3, ArtifactCount: 4, Complete: true, Missing: []string{},
		Manifest: &receipt.ManifestReference{SHA256: manifestDigest, SizeBytes: 100, URL: "/v1/jobs/" + jobID + "/receipt/manifest?sha256=" + manifestDigest},
	}
	for _, m := range mutate {
		m(&p)
	}
	return signJobReceipt(t, p, key, keyID)
}

func signJobReceipt(t *testing.T, p receipt.Payload, key ed25519.PrivateKey, keyID string) []byte {
	t.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := receipt.Canonical(raw)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := json.Marshal(receipt.Envelope{Payload: canonical, Signature: receipt.Signature{Algorithm: "Ed25519", KeyID: keyID, Encoding: "base64", Value: base64.StdEncoding.EncodeToString(ed25519.Sign(key, canonical))}})
	if err != nil {
		t.Fatal(err)
	}
	out, err := receipt.Canonical(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// world is a complete signing setup in a temp directory.
type world struct {
	t           *testing.T
	dir         string
	config      Config
	policy      Policy
	tools       *fakeTools
	engine      *Engine
	receiptKey  ed25519.PrivateKey
	signerKey   ed25519.PrivateKey
	entries     []tarEntry
	tarBytes    []byte
	manifest    worker.SigningManifest
	manifestRaw []byte
	jobID       string
	profiles    map[string][]byte
}

func newWorld(t *testing.T) *world {
	t.Helper()
	dir := t.TempDir()
	w := &world{t: t, dir: dir, tools: &fakeTools{identities: []string{"0000000000000000000000000000000000000000", fixtureIdentity()}}, jobID: "job-1", profiles: map[string][]byte{}}
	_, w.receiptKey, _ = ed25519.GenerateKey(nil)
	_, w.signerKey, _ = ed25519.GenerateKey(nil)
	state := filepath.Join(dir, "state")
	for _, d := range []string{state, filepath.Join(dir, "inbox"), filepath.Join(dir, "profiles")} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	w.config = Config{SignerUID: 1, SignerGID: 2, RPCGID: 3, ControllerUID: 4, JobUID: 5, JobGID: 6, StateDir: state, Socket: filepath.Join(dir, "run", "signer.sock"), Inbox: filepath.Join(dir, "inbox"), Keychain: filepath.Join(state, "keychain", "signing.keychain-db"), KeychainSecretFile: filepath.Join(state, "keychain", "keychain.secret"), KeyFile: filepath.Join(state, "key", "signer-receipt.key"), KeyID: "signer-test", PolicyFile: filepath.Join(dir, "policy.json")}
	w.policy = Policy{IdentitySHA1: strings.ToLower(fixtureIdentity()), Apps: map[string]AppPolicy{}}
	for _, id := range []string{appID, extID} {
		path := filepath.Join(dir, "profiles", id+".mobileprovision")
		w.setProfile(id, defaultProfile(id))
		w.policy.Apps[id] = AppPolicy{ProfilePath: path, TeamID: fixtureTeam}
	}
	app := w.policy.Apps[appID]
	app.RequiredEntitlements = []string{"aps-environment"}
	w.policy.Apps[appID] = app
	w.entries = sortedEntries(archiveEntries())
	w.setArchive(w.entries, map[string]any{"aps-environment": "development", "com.apple.security.application-groups": []any{"group.com.example.shared"}})
	w.newEngine()
	return w
}

func (w *world) setProfile(bundleID string, spec profileSpec) {
	w.t.Helper()
	data := spec.xml()
	w.profiles[bundleID] = data
	if err := os.WriteFile(filepath.Join(w.dir, "profiles", bundleID+".mobileprovision"), data, 0o644); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) setArchive(entries []tarEntry, appEntitlements map[string]any) {
	w.t.Helper()
	w.entries = entries
	w.tarBytes = buildTar(w.t, entries)
	w.manifest = manifestFor(w.t, w.tarBytes, entries, appEntitlements)
	raw, err := worker.EncodeSigningManifest(w.manifest, fixtureRelease)
	if err != nil {
		w.t.Fatal(err)
	}
	w.manifestRaw = raw
	w.writeInputs()
}

func (w *world) writeInputs() {
	w.t.Helper()
	archive, manifest := RequestPaths(w.config.Inbox, w.jobID)
	if err := os.MkdirAll(filepath.Dir(archive), 0o700); err != nil {
		w.t.Fatal(err)
	}
	if err := os.WriteFile(archive, w.tarBytes, 0o600); err != nil {
		w.t.Fatal(err)
	}
	if err := os.WriteFile(manifest, w.manifestRaw, 0o600); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) newEngine() {
	w.t.Helper()
	engine, err := NewEngine(Options{Config: w.config, Policy: w.policy, Tools: w.tools, PrivateKey: w.signerKey, ReceiptKeys: map[string]ed25519.PublicKey{"controller": w.receiptKey.Public().(ed25519.PublicKey)}, KeychainSecret: fixtureSecr, Now: func() time.Time { return fixtureNow }})
	if err != nil {
		w.t.Fatal(err)
	}
	w.engine = engine
}

func (w *world) request(mutate ...receiptSpec) Request {
	archive, manifest := RequestPaths(w.config.Inbox, w.jobID)
	return Request{JobID: w.jobID, Receipt: jobReceipt(w.t, w.receiptKey, "controller", w.jobID, digestHex(w.manifestRaw), mutate...), ArchivePath: archive, ManifestPath: manifest}
}

func (w *world) sign(req Request) (*Signed, error) {
	return w.engine.Sign(context.Background(), req)
}

// requireRefusal requires a *RefusalError whose reason contains want.
func requireRefusal(t *testing.T, err error, want string) {
	t.Helper()
	var refused *RefusalError
	if !errors.As(err, &refused) || !strings.Contains(refused.Reason, want) {
		t.Fatalf("error = %v; want refusal containing %q", err, want)
	}
}

func relativeSigned(w *world) []string {
	base := filepath.Join(w.config.StateDir, "work")
	var out []string
	for _, p := range w.tools.signed {
		i := strings.Index(p, profiles.ArchivePath+"/")
		if i < 0 {
			out = append(out, fmt.Sprintf("?%s", strings.TrimPrefix(p, base)))
			continue
		}
		out = append(out, p[i+len(profiles.ArchivePath)+1:])
	}
	return out
}

package signer

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/receipt"
)

// A valid request signs inside-out, embeds each exact profile, signs the
// planned entitlements, and returns a receipt the signer key verifies.
func TestSignInsideOutEmbedsProfilesAndSealsReceipt(t *testing.T) {
	w := newWorld(t)
	signed, err := w.sign(w.request())
	if err != nil {
		t.Fatal(err)
	}
	defer signed.Close()
	order := relativeSigned(w)
	want := []string{dylib, fmwkPath, extPath, appPath}
	if !slices.Equal(order, want) {
		t.Fatalf("signing order %v; want %v", order, want)
	}
	payload, err := VerifyReceipt(signed.Receipt, map[string]ed25519.PublicKey{"signer-test": w.engine.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	if payload.JobID != w.jobID || payload.IPA.SHA256 != signed.IPASHA256 || payload.IPA.SizeBytes != signed.IPASize || payload.Archive.SHA256 != w.manifest.Archive.SHA256 || payload.SigningManifestSHA256 != digestHex(w.manifestRaw) || payload.IdentitySHA1 != fixtureIdentity() || payload.TeamID != fixtureTeam || payload.Repository.ID != 77 || payload.BuildNumber != "17" || !slices.Equal(payload.Dylibs, []string{dylib}) {
		t.Fatalf("payload %+v", payload)
	}
	bundles := map[string]SignedBundle{}
	for _, b := range payload.Bundles {
		bundles[b.Path] = b
	}
	if b := bundles[appPath]; b.ProfileUUID != uuidFor(appID) || b.ProfileSHA256 != digestHex(w.profiles[appID]) || b.EntitlementsSHA256 == "" {
		t.Fatalf("app bundle %+v", b)
	}
	if b := bundles[fmwkPath]; b.ProfileUUID != "" || b.EntitlementsSHA256 != "" {
		t.Fatalf("framework bundle %+v", b)
	}
	data, err := io.ReadAll(signed.IPA)
	if err != nil || int64(len(data)) != signed.IPASize || digestHex(data) != signed.IPASHA256 {
		t.Fatalf("ipa bytes: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]*zip.File{}
	for _, f := range zr.File {
		files[f.Name] = f
	}
	for path, id := range map[string]string{"Payload/Example.app/embedded.mobileprovision": appID, "Payload/Example.app/PlugIns/Widget.appex/embedded.mobileprovision": extID} {
		f := files[path]
		if f == nil {
			t.Fatalf("ipa lacks %s", path)
		}
		r, _ := f.Open()
		got, _ := io.ReadAll(r)
		r.Close()
		if !bytes.Equal(got, w.profiles[id]) {
			t.Fatalf("%s is not the exact profile", path)
		}
	}
	if f := files["Payload/Example.app/Example"]; f == nil || f.Mode().Perm() != 0o755 {
		t.Fatal("app executable is not 0755 in the ipa")
	}
	if f := files["Payload/Example.app/Info.plist"]; f == nil || f.Mode().Perm() != 0o644 {
		t.Fatal("Info.plist is not 0644 in the ipa")
	}
	entitlements, err := os.ReadFile(filepath.Join(signed.work, "entitlements", bundles[appPath].EntitlementsSHA256+".plist"))
	if err != nil {
		t.Fatal(err)
	}
	value, err := decodePlist(entitlements)
	if err != nil {
		t.Fatal(err)
	}
	wantEntitlements := map[string]any{
		"application-identifier":                fixtureTeam + "." + appID,
		"com.apple.developer.team-identifier":   fixtureTeam,
		"get-task-allow":                        false,
		"beta-reports-active":                   true,
		"aps-environment":                       "production",
		"keychain-access-groups":                []any{fixtureTeam + "." + appID},
		"com.apple.security.application-groups": []any{"group.com.example.shared"},
	}
	if !reflect.DeepEqual(value, wantEntitlements) {
		t.Fatalf("app entitlements %#v", value)
	}
	if w.tools.unlocked == 0 {
		t.Fatal("keychain was never unlocked")
	}
	work := signed.work
	signed.Close()
	if _, err := os.Stat(work); !os.IsNotExist(err) {
		t.Fatalf("work directory kept: %v", err)
	}
}

// The same archive and inputs yield the same ipa bytes.
func TestIPAIsDeterministic(t *testing.T) {
	w := newWorld(t)
	first, err := w.sign(w.request())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := w.sign(w.request())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if first.IPASHA256 != second.IPASHA256 || first.IPASize != second.IPASize {
		t.Fatalf("ipa differs across signings: %s %s", first.IPASHA256, second.IPASHA256)
	}
	root, err := os.OpenRoot(filepath.Join(first.work, "tree"))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	var a, b bytes.Buffer
	app := profiles.ArchivePath + "/" + appPath
	if err := writeIPA(t.Context(), root, app, &a); err != nil {
		t.Fatal(err)
	}
	if err := writeIPA(t.Context(), root, app, &b); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) || digestHex(a.Bytes()) != first.IPASHA256 {
		t.Fatal("writeIPA is not deterministic")
	}
}

// Every receipt refusal happens before the archive is read: each case
// runs with the archive removed.
func TestSignRefusesReceipts(t *testing.T) {
	otherKey := func() ed25519.PrivateKey { _, k, _ := ed25519.GenerateKey(nil); return k }()
	cases := []struct {
		name    string
		request func(*world) Request
		want    string
	}{
		{"unknown key", func(w *world) Request {
			r := w.request()
			r.Receipt = jobReceipt(t, otherKey, "controller", w.jobID, digestHex(w.manifestRaw))
			return r
		}, "signature"},
		{"tampered payload", func(w *world) Request {
			r := w.request()
			r.Receipt = bytes.Replace(r.Receipt, []byte(`"build_number":"17"`), []byte(`"build_number":"18"`), 1)
			return r
		}, "signature"},
		{"failed job", func(w *world) Request {
			return w.request(func(p *receipt.Payload) { p.State = model.Failed })
		}, "success"},
		{"not ios_archive", func(w *world) Request {
			return w.request(func(p *receipt.Payload) { p.Request.Kind = model.Build })
		}, "ios_archive"},
		{"provenance not github_app", func(w *world) Request {
			return w.request(func(p *receipt.Payload) { p.ReleaseProvenance.Source = "pin" })
		}, "release provenance"},
		{"provenance head differs", func(w *world) Request {
			return w.request(func(p *receipt.Payload) { p.ReleaseProvenance.HeadSHA = strings.Repeat("f", 40) })
		}, "release provenance"},
		{"provenance repository differs", func(w *world) Request {
			return w.request(func(p *receipt.Payload) { p.ReleaseProvenance.RepositoryID = 78 })
		}, "release provenance"},
		{"cleanup failed", func(w *world) Request {
			return w.request(func(p *receipt.Payload) { p.Resources.CleanupOK = false })
		}, "cleanup"},
		{"other job", func(w *world) Request {
			r := w.request()
			r.Receipt = jobReceipt(t, w.receiptKey, "controller", "job-2", digestHex(w.manifestRaw))
			return r
		}, "job-2"},
		{"manifest digest differs", func(w *world) Request {
			return w.request(func(p *receipt.Payload) { p.SigningManifestSHA256 = strings.Repeat("a", 64) })
		}, "signing manifest SHA-256"},
		{"path outside inbox", func(w *world) Request {
			r := w.request()
			r.ArchivePath = filepath.Join(w.dir, "App.xcarchive.tar")
			return r
		}, "archive and manifest must be"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t)
			req := c.request(w)
			archive, _ := RequestPaths(w.config.Inbox, w.jobID)
			if err := os.Remove(archive); err != nil {
				t.Fatal(err)
			}
			_, err := w.sign(req)
			requireRefusal(t, err, c.want)
			if len(w.tools.signed) != 0 {
				t.Fatal("refused request reached codesign")
			}
		})
	}
}

// The manifest's archive size and SHA-256 must match the archive file.
func TestSignRefusesArchiveIdentityMismatch(t *testing.T) {
	t.Run("digest", func(t *testing.T) {
		w := newWorld(t)
		archive, _ := RequestPaths(w.config.Inbox, w.jobID)
		changed := bytes.Clone(w.tarBytes)
		changed[len(changed)-1] ^= 1
		if err := os.WriteFile(archive, changed, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := w.sign(w.request())
		requireRefusal(t, err, "SHA-256 or size")
	})
	t.Run("size", func(t *testing.T) {
		w := newWorld(t)
		archive, _ := RequestPaths(w.config.Inbox, w.jobID)
		if err := os.WriteFile(archive, append(bytes.Clone(w.tarBytes), 0), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := w.sign(w.request())
		requireRefusal(t, err, "manifest's")
	})
	t.Run("symlink", func(t *testing.T) {
		w := newWorld(t)
		archive, _ := RequestPaths(w.config.Inbox, w.jobID)
		target := filepath.Join(w.dir, "elsewhere.tar")
		if err := os.WriteFile(target, w.tarBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(archive); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, archive); err != nil {
			t.Fatal(err)
		}
		_, err := w.sign(w.request())
		requireRefusal(t, err, "archive")
	})
}

// An archive that already embeds a provisioning profile is refused.
func TestSignRefusesPreexistingEmbeddedProfile(t *testing.T) {
	w := newWorld(t)
	entries := append(archiveEntries(), fileEntry(profiles.ArchivePath+"/"+appPath+"/embedded.mobileprovision", 0o644, "stale"))
	w.setArchive(sortedEntries(entries), map[string]any{"aps-environment": "development"})
	_, err := w.sign(w.request())
	requireRefusal(t, err, "embedded.mobileprovision")
	if len(w.tools.signed) != 0 {
		t.Fatal("signed despite embedded profile")
	}
}

// Policy, profile and entitlement refusals happen before any codesign.
func TestSignRefusesPolicyProfileAndEntitlements(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*world)
		want  string
	}{
		{"bundle not in policy", func(w *world) {
			delete(w.policy.Apps, extID)
			w.newEngine()
		}, "not allowed by the signing policy"},
		{"ad hoc profile", func(w *world) {
			p := defaultProfile(appID)
			p.devices = true
			w.setProfile(appID, p)
		}, "ProvisionedDevices"},
		{"missing required entitlement", func(w *world) {
			app := w.policy.Apps[appID]
			app.RequiredEntitlements = []string{"com.apple.developer.icloud-services"}
			w.policy.Apps[appID] = app
			w.newEngine()
		}, "required com.apple.developer.icloud-services"},
		{"requested entitlement absent from profile", func(w *world) {
			w.setArchive(w.entries, map[string]any{"aps-environment": "development", "com.apple.developer.healthkit": true})
		}, "not in the profile"},
		{"identity missing from keychain", func(w *world) {
			w.tools.identities = []string{"0000000000000000000000000000000000000000"}
		}, "no valid identity"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t)
			c.setup(w)
			_, err := w.sign(w.request())
			requireRefusal(t, err, c.want)
			if len(w.tools.signed) != 0 {
				t.Fatal("refused request reached codesign")
			}
		})
	}
}

// A codesign failure fails the signing and leaves no work directory.
func TestSignCleansUpOnToolFailure(t *testing.T) {
	w := newWorld(t)
	w.tools.signErr = os.ErrPermission
	if _, err := w.sign(w.request()); err == nil || !strings.Contains(err.Error(), "codesign") {
		t.Fatalf("error = %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(w.config.StateDir, "work"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("work directories left: %v %v", entries, err)
	}
}

// Ready requires the configured identity after unlocking.
func TestReadyRequiresIdentity(t *testing.T) {
	w := newWorld(t)
	if err := w.engine.Ready(t.Context()); err != nil {
		t.Fatal(err)
	}
	w.tools.identities = nil
	if err := w.engine.Ready(t.Context()); err == nil {
		t.Fatal("ready without identity")
	}
	w.tools.unlockErr = os.ErrPermission
	if err := w.engine.Ready(t.Context()); err == nil || !strings.Contains(err.Error(), "unlock") {
		t.Fatalf("ready with locked keychain: %v", err)
	}
}

// Init creates the key, secret and keychain privately once and keeps them.
func TestInitCreatesPrivateStateOnce(t *testing.T) {
	w := newWorld(t)
	first, err := Init(t.Context(), w.config, w.tools)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{w.config.KeyFile, w.config.KeychainSecretFile, w.config.Keychain} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", path, info, err)
		}
		dir, err := os.Stat(filepath.Dir(path))
		if err != nil || dir.Mode().Perm() != 0o700 {
			t.Fatalf("%s dir: %v", path, err)
		}
	}
	second, err := Init(t.Context(), w.config, w.tools)
	if err != nil || second != first || first.KeyID != "signer-test" {
		t.Fatalf("second init %+v %+v %v", first, second, err)
	}
	key, err := ReadKey(w.config.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if secret, err := ReadSecret(w.config.KeychainSecretFile); err != nil || len(secret) != 64 {
		t.Fatalf("secret: %v", err)
	}
	if err := os.Chmod(w.config.KeyFile, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadKey(w.config.KeyFile); err == nil {
		t.Fatal("group-readable key accepted")
	}
	_ = key
}

// A bundle that requests no entitlements is still signed with
// beta-reports-active true from its App Store profile, and a packaged app
// whose signature lacks it is refused.
func TestSignDerivesBetaReportsActiveFromProfile(t *testing.T) {
	w := newWorld(t)
	app := w.policy.Apps[appID]
	app.RequiredEntitlements = nil
	w.policy.Apps[appID] = app
	w.newEngine()
	w.setArchive(w.entries, map[string]any{})
	signed, err := w.sign(w.request())
	if err != nil {
		t.Fatal(err)
	}
	defer signed.Close()
	for _, b := range signed.Payload.Bundles {
		if b.EntitlementsSHA256 == "" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(signed.work, "verify", "Payload", "Example.app", strings.TrimPrefix(strings.TrimPrefix(b.Path, appPath), "/"), "_CodeSignature", "entitlements.plist"))
		if err != nil {
			t.Fatal(err)
		}
		value, err := decodePlist(raw)
		if err != nil || value.(map[string]any)["beta-reports-active"] != true {
			t.Fatalf("%s packaged entitlements %v %v", b.Path, value, err)
		}
	}
	w.tools.dropSigned = "beta-reports-active"
	_, err = w.sign(w.request())
	requireRefusal(t, err, "entitlements differ")
}

func TestFinalEntitlementsRequireBetaReportsGrant(t *testing.T) {
	p := testProfile(t)
	got, err := finalEntitlements(json.RawMessage(`{}`), p, nil)
	if err != nil || got["beta-reports-active"] != true {
		t.Fatalf("empty request: %v %v", got, err)
	}
	if got, err := finalEntitlements(json.RawMessage(`{"beta-reports-active":false}`), p, nil); err != nil || got["beta-reports-active"] != true {
		t.Fatalf("requested false: %v %v", got, err)
	}
	if _, err := finalEntitlements(json.RawMessage(`{"beta-reports-active":"yes"}`), p, nil); err == nil {
		t.Fatal("malformed beta-reports-active accepted")
	}
	delete(p.Entitlements, "beta-reports-active")
	if _, err := finalEntitlements(json.RawMessage(`{}`), p, nil); err == nil || !strings.Contains(err.Error(), "beta-reports-active") {
		t.Fatalf("profile without grant: %v", err)
	}
}

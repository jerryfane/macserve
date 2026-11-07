package workerclient

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
)

// fixtureProfile and fixtureTemplate are the root registry of the lease
// tests; fixtureRequest is a request the registry admits.
var (
	fixtureProfile   = model.Profile{ID: "app-build", Version: 1, Repo: "acme/app", Kind: model.Build, Xcode: model.Xcode{Version: "27.0", Build: "27A100"}, DeveloperDir: "/Applications/Xcode.app/Contents/Developer", WorkDir: ".", Run: model.Command{Executable: "/usr/bin/xcrun", Args: []string{"xcodebuild", "build"}}}
	fixtureTemplate  = model.Template{ID: "org-build-v1", Version: 1, Kind: model.Build, Owners: []string{"acme"}, Xcode: model.Xcode{Version: "27.0", Build: "27A100"}, DeveloperDir: "/Applications/Xcode.app/Contents/Developer"}
	fixtureSim       = model.Simulator{Runtime: "com.apple.CoreSimulator.SimRuntime.iOS-27-0", RuntimeBuild: "24A434", DeviceType: "com.apple.CoreSimulator.SimDeviceType.iPhone-18-Pro"}
	fixtureUITest    = model.Template{ID: "org-uitest-v1", Version: 1, Kind: model.SimulatorUITest, Owners: []string{"acme"}, Xcode: model.Xcode{Version: "27.0", Build: "27A100"}, DeveloperDir: "/Applications/Xcode.app/Contents/Developer", Simulators: []model.Simulator{fixtureSim}}
	fixtureFlutter   = model.FlutterPin{Version: "3.41.9", SDKSHA256: strings.Repeat("b", 64), RubySHA256: strings.Repeat("c", 64), CocoaPodsVersion: "1.16.2", GemsSHA256: strings.Repeat("e", 64)}
	fixtureArchive   = model.Template{ID: "org-flutter-archive-v1", Version: 1, Kind: model.IOSArchive, Owners: []string{"acme"}, Xcode: model.Xcode{Version: "27.0", Build: "27A100"}, DeveloperDir: "/Applications/Xcode.app/Contents/Developer", Flutter: &fixtureFlutter}
	fixtureTemplates = []model.Template{fixtureTemplate, fixtureUITest, fixtureArchive}
	fixtureRequest   = model.Request{Repo: "acme/app", SHA: strings.Repeat("a", 40), Kind: model.Build, Profile: "app-build", Xcode: model.Xcode{Version: "27.0", Build: "27A100"}}
)

// withLeaseAuthority writes the root registry, a qualification record of
// exactly its profiles and a seal key into dir and names them in cfg.
func withLeaseAuthority(t *testing.T, cfg *Config, dir string) {
	t.Helper()
	registry, err := profiles.New([]model.Profile{fixtureProfile}, fixtureTemplates)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, value any) string {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	cfg.ProfilesFile = write("profiles.json", map[string]any{"profiles": []model.Profile{fixtureProfile}, "templates": fixtureTemplates})
	cfg.QualificationFile = write("qualification.json", map[string]any{"schema": 4, "profiles": registry.Digests()})
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cfg.SealKeyFile = filepath.Join(dir, "seal-key.pem")
	if err := os.WriteFile(cfg.SealKeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	cfg.SealKeyID = "macserve-worker-test"
}

// testChecks let the test's non-root files stand in for root-owned ones.
var testChecks = Checks{RootConfig: func(string) error { return nil }, ReadPrivateKey: os.ReadFile}

// admittedJob is a job the fixture registry admits, leased to epoch.
func admittedJob(t *testing.T, id, epoch string, deadline *time.Time, request model.Request) model.Job {
	t.Helper()
	registry, err := profiles.New([]model.Profile{fixtureProfile}, fixtureTemplates)
	if err != nil {
		t.Fatal(err)
	}
	admission, err := registry.Resolve(request)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(admission.Request)
	if err != nil {
		t.Fatal(err)
	}
	return model.Job{ID: id, WorkerEpoch: epoch, State: model.Preparing, Deadline: deadline, Request: admission.Request, Profile: admission.Profile, ProfileDigest: admission.ProfileDigest, RequestDigest: sha256Hex(raw)}
}

func sha256Hex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

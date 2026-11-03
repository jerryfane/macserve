package boundary

import (
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// TestEveryTrackedFileClassified runs the full check on this repository:
// every tracked file has exactly one class and every C/G file obeys the
// source rules. Run with -v to print the non-boundary files.
func TestEveryTrackedFileClassified(t *testing.T) {
	root := repoRoot(t)
	files, err := TrackedFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	classes, problems, err := Check(root, files)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Error(p)
	}
	counts := map[string]int{}
	var carry []string
	for file, class := range classes {
		counts[class]++
		if class != ClassB {
			carry = append(carry, class+" "+file)
		}
	}
	sort.Strings(carry)
	t.Logf("%d tracked files: B=%d G=%d C=%d T=%d", len(files), counts[ClassB], counts[ClassG], counts[ClassC], counts[ClassT])
	if testing.Verbose() {
		t.Logf("non-boundary files:\n%s", strings.Join(carry, "\n"))
	}
}

// TestBoundaryManifestPinsAssets keeps the paths that define, build, guard
// and install the boundary in class B, whatever else BOUNDARY.json says.
// Paths need not exist: a file added later under them is still B.
func TestBoundaryManifestPinsAssets(t *testing.T) {
	root := repoRoot(t)
	m, err := LoadManifest(filepath.Join(root, ManifestFile))
	if err != nil {
		t.Fatal(err)
	}
	pinned := []string{
		ManifestFile, "go.mod", "go.sum", ".gitattributes", ".gitignore",
		".github/workflows/ci.yml", ".github/workflows/release.yml", ".github/workflows/new.yml",
		"checks/boundary/rules.go", "checks/boundary/boundary_test.go", "checks/new/check.go",
		"assets/install.sh", "assets/qualify.sh", "assets/create-users.sh", "assets/launchd/org.macserve.worker.plist", "assets/new.sh",
		"cmd/macserve/main.go", "cmd/macserve/qualify.go", "cmd/macserve/new.go",
		"internal/hostguard/hostguard.go", "internal/deploy/new.go", "internal/qualification/anchor.go", "internal/qualification/new.go",
		"internal/peercred/new.go", "internal/protocol/new.go", "internal/workerclient/new.go", "internal/pfctl/new.go", "internal/launchctlprint/new.go",
		"internal/controller/guards.go", "internal/controller/socket.go", "internal/controller/config.go", "internal/controller/artifacts.go", "internal/controller/new.go",
		"internal/api/api.go", "internal/store/auth.go", "internal/model/new.go", "internal/profiles/new.go",
		"internal/maintenance/evaluate.go", "internal/maintenance/coexistence.go", "internal/maintenance/persistence.go", "internal/maintenance/inspect.go", "internal/maintenance/new.go",
		"internal/worker/simulator.go", "internal/worker/types.go", "internal/worker/execute.go", "internal/worker/new.go",
		"internal/worker/simulator_test.go", "internal/worker/metal_test.go",
		"internal/evidence/artifacts.go", "internal/evidence/new.go",
		"internal/maintenance/maintenance_invariants_test.go", "internal/maintenance/maintenance_test.go",
	}
	for _, file := range pinned {
		if class, err := m.Classify(file); err != nil || class != ClassB {
			t.Errorf("%s: class %q (%v), want B", file, class, err)
		}
	}
	files, err := TrackedFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		for _, prefix := range []string{"assets/", ".github/", "checks/", "cmd/macserve/", "internal/qualification/", "internal/hostguard/"} {
			if strings.HasPrefix(f.Path, prefix) {
				if class, _ := m.Classify(f.Path); class != ClassB {
					t.Errorf("%s: class %q, want B", f.Path, class)
				}
			}
		}
	}
}

// TestBannedImportClassification covers import paths the fixture module
// cannot build (it has no third-party dependencies).
func TestBannedImportClassification(t *testing.T) {
	for _, p := range []string{"syscall", "golang.org/x/sys", "golang.org/x/sys/unix", "golang.org/x/sys/execabs"} {
		if !isSyscallPackage(p) {
			t.Errorf("%s not treated as a syscall package", p)
		}
	}
	for _, p := range []string{"golang.org/x/sysx", "syscallx", "strings"} {
		if isSyscallPackage(p) {
			t.Errorf("%s treated as a syscall package", p)
		}
	}
	if !slices.Contains(bannedImports, "github.com/ebitengine/purego") || !slices.Contains(bannedImports, "plugin") || !slices.Contains(bannedImports, "runtime/debug") || !slices.Contains(bannedImports, "os/user") {
		t.Fatal("banned import list lost an entry")
	}
}

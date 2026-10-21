package qualification

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestAnchorBindingChangesCatchEveryBinding(t *testing.T) {
	anchored := map[string]string{
		"/Library/macserve/bin/macserve":                         "a1",
		"/Library/macserve/config/deploy.env":                    "a2",
		"/Library/LaunchDaemons/org.macserve.worker.plist":       "a3",
		"/Library/macserve/var/broker/reviewed-persistence.json": "a4",
	}
	if got := bindingChanges(anchored, anchored); len(got) != 0 {
		t.Fatalf("unchanged bindings reported %v", got)
	}
	for path := range anchored {
		t.Run("changed "+path, func(t *testing.T) {
			now := map[string]string{}
			for k, v := range anchored {
				now[k] = v
			}
			now[path] = "changed"
			if got := bindingChanges(anchored, now); !slices.Equal(got, []string{path}) {
				t.Fatalf("changed %s reported as %v", path, got)
			}
			delete(now, path)
			if got := bindingChanges(anchored, now); !slices.Equal(got, []string{path}) {
				t.Fatalf("removed %s reported as %v", path, got)
			}
		})
		// A single binding has no other entry to compensate for a skipped one.
		single := map[string]string{path: anchored[path]}
		if got := bindingChanges(single, map[string]string{path: "changed"}); !slices.Equal(got, []string{path}) {
			t.Fatalf("single changed binding %s reported as %v", path, got)
		}
	}
	if got := bindingChanges(anchored, map[string]string{"/Library/macserve/bin/macserve": "a1", "/Library/macserve/config/deploy.env": "a2", "/Library/LaunchDaemons/org.macserve.worker.plist": "a3", "/Library/macserve/var/broker/reviewed-persistence.json": "a4", "/Library/macserve/bin/extra": "x"}); !slices.Equal(got, []string{"/Library/macserve/bin/extra"}) {
		t.Fatalf("added binding reported as %v", got)
	}
}

// The job report is read only through the protected read. Each fixture is
// readable with os.ReadFile, so a plain read would accept it.
func TestJobProbeArtifactsRefuseUnprotectedFiles(t *testing.T) {
	write := func(t *testing.T, dir string) {
		for _, name := range []string{jobLaunchFile, jobProbeFile} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Run("job-owned report", func(t *testing.T) {
		dir := t.TempDir()
		write(t, dir)
		if os.Geteuid() == 0 {
			for _, name := range []string{jobLaunchFile, jobProbeFile} {
				if err := os.Chown(filepath.Join(dir, name), 6202, 20); err != nil {
					t.Fatal(err)
				}
			}
		}
		if _, _, err := readJobProbeArtifacts(dir); err == nil {
			t.Fatal("non-root-owned job report accepted")
		}
	})
	t.Run("writable ancestor", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "session")
		if err := os.Mkdir(dir, 0777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0777); err != nil {
			t.Fatal(err)
		}
		write(t, dir)
		if _, _, err := readJobProbeArtifacts(dir); err == nil {
			t.Fatal("job report under a world-writable directory accepted")
		}
	})
	t.Run("symlinked report", func(t *testing.T) {
		dir := t.TempDir()
		target := t.TempDir()
		write(t, target)
		for _, name := range []string{jobLaunchFile, jobProbeFile} {
			if err := os.Symlink(filepath.Join(target, name), filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
		}
		if _, _, err := readJobProbeArtifacts(dir); err == nil {
			t.Fatal("symlinked job report accepted")
		}
	})
}

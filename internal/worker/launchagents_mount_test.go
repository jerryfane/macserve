package worker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// A nested filesystem under LaunchAgents is contamination; reset removes
// nothing, including inside the mount.
func TestResetLaunchAgentsRefusesNestedMount(t *testing.T) {
	for _, at := range []string{"LaunchAgents", "mounted", "inner"} {
		t.Run(at, func(t *testing.T) {
			home := t.TempDir()
			agents := filepath.Join(home, "Library", "LaunchAgents")
			mounted := filepath.Join(agents, "mounted", "inner")
			if err := os.MkdirAll(mounted, 0700); err != nil {
				t.Fatal(err)
			}
			files := []string{filepath.Join(agents, "job.plist"), filepath.Join(agents, "mounted", "a.plist"), filepath.Join(mounted, "b.plist")}
			for _, f := range files {
				if err := os.WriteFile(f, []byte("data"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			statat := func(fd int, name string, st *unix.Stat_t, flags int) error {
				if err := unix.Fstatat(fd, name, st, flags); err != nil {
					return err
				}
				if name == at {
					st.Dev++
				}
				return nil
			}
			if err := resetLaunchAgentsWithStat(context.Background(), home, statat); !errors.Is(err, ErrContamination) {
				t.Fatalf("nested mount at %s: %v", at, err)
			}
			for _, f := range files {
				if _, err := os.Stat(f); err != nil {
					t.Fatalf("reset removed %s: %v", f, err)
				}
			}
		})
	}
}

func TestResetLaunchAgentsRemovesNestedTree(t *testing.T) {
	home := t.TempDir()
	deep := filepath.Join(home, "Library", "LaunchAgents", "a", "b")
	if err := os.MkdirAll(deep, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deep, "x.plist"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := resetLaunchAgents(context.Background(), home); err != nil {
		t.Fatal(err)
	}
	if err := inspectLaunchAgents(home); err != nil {
		t.Fatalf("entries remain: %v", err)
	}
}

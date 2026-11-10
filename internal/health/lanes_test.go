package health

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLaneOverrideOnlyLowers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lanes.json")
	ok := func() error { return nil }
	read := func() ([]byte, error) { return os.ReadFile(path) }
	if n, _ := LaneOverride(2, false, ok, read); n != 2 {
		t.Fatalf("absent override changed lanes to %d", n)
	}
	for body, want := range map[string][2]int{
		`{"max_concurrent_jobs":1}`:       {2, 1},
		`{"max_concurrent_jobs":2}`:       {3, 2},
		`{"max_concurrent_jobs":3}`:       {2, 2}, // never raises
		`{"max_concurrent_jobs":0}`:       {2, 1},
		`{"max_concurrent_jobs":4}`:       {3, 1},
		`{}`:                              {2, 1},
		`{"max_concurrent_jobs":"2"}`:     {2, 1},
		`{"max_concurrent_jobs":2,"x":1}`: {2, 1},
		`{"max_concurrent_jobs":2} {}`:    {2, 1},
		`not json`:                        {3, 1},
	} {
		if err := os.WriteFile(path, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
		if n, _ := LaneOverride(want[0], true, ok, read); n != want[1] {
			t.Errorf("%s with configured %d: %d lanes, want %d", body, want[0], n, want[1])
		}
	}
	if err := os.WriteFile(path, []byte(`{"max_concurrent_jobs":2}`), 0644); err != nil {
		t.Fatal(err)
	}
	if n, _ := LaneOverride(3, true, func() error { return errors.New("not root-owned") }, read); n != 1 {
		t.Fatalf("unsafe override gave %d lanes, want 1", n)
	}
	if n, _ := LaneOverride(3, true, ok, func() ([]byte, error) { return nil, os.ErrPermission }); n != 1 {
		t.Fatalf("unreadable override gave %d lanes, want 1", n)
	}
}

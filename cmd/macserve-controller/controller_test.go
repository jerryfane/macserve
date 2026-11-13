package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/controllerk/store"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
)

// The controller's store holds 30 unfinished jobs of one principal (six
// herdrup heads of five GitHub runs each) and 100 in total.
func TestControllerStoreQueueLimits(t *testing.T) {
	template := model.Template{ID: "org-ios-sim-build-v1", Version: 1, Kind: model.Build, Owners: []string{"themartianapp"}, Xcode: model.Xcode{Version: "27.0", Build: "27A100"}, DeveloperDir: "/Applications/Example.app/Contents/Developer", DefaultTimeoutSeconds: 1800, MaxTimeoutSeconds: 3600, MemoryLimitMiB: 8192}
	registry, err := profiles.New(nil, []model.Template{template})
	if err != nil {
		t.Fatal(err)
	}
	admission, err := registry.Resolve(model.Request{Repo: "themartianapp/herdrup", SHA: strings.Repeat("a", 40), Kind: template.Kind, Profile: template.ID, Xcode: template.Xcode})
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(filepath.Join(t.TempDir(), "state", "queue.sqlite"), storeOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	now := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	enqueue := func(principal string, n int) error {
		_, _, err := db.Enqueue(ctx, principal, fmt.Sprintf("key-%d", n), admission, now)
		return err
	}
	for n := range 30 {
		if err := enqueue("github:1318951363", n); err != nil {
			t.Fatalf("GitHub job %d refused: %v", n+1, err)
		}
	}
	if err := enqueue("github:1318951363", 30); !errors.Is(err, store.ErrFull) {
		t.Fatalf("31st job of one principal: %v", err)
	}
	for n := range 70 {
		if err := enqueue(fmt.Sprintf("principal-%d", n/30), n); err != nil {
			t.Fatalf("job %d in total refused: %v", 31+n, err)
		}
	}
	if err := enqueue("principal-3", 0); !errors.Is(err, store.ErrFull) {
		t.Fatalf("101st job in total: %v", err)
	}
}

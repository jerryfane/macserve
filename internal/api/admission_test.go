package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/controller"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/store"
)

func TestAuthenticatedRequestsRejectCaseAliasesAtEveryDepth(t *testing.T) {
	f := setup(t)
	encoded, err := json.Marshal(f.request)
	if err != nil {
		t.Fatal(err)
	}
	body := string(encoded)
	for name, bad := range map[string]string{
		"root alias":             strings.Replace(body, `"repo":`, `"REPO":`, 1),
		"root alias duplicate":   strings.Replace(body, `"repo":`, `"REPO":"example-org/other-app","repo":`, 1),
		"nested alias":           strings.Replace(body, `"version":`, `"Version":`, 1),
		"nested alias duplicate": strings.Replace(body, `"version":`, `"VERSION":"unapproved","version":`, 1),
		"escaped nested alias":   strings.Replace(body, `"version":`, `"\u0056ersion":`, 1),
		"unicode nested alias":   strings.Replace(body, `"version":`, `"verſion":`, 1),
		"exact nested duplicate": strings.Replace(body, `"version":`, `"version":"unapproved","version":`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			w := perform(f.handler, http.MethodPost, "/v1/jobs", testToken, name, bad)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("case-ambiguous request accepted: %d %s", w.Code, w.Body.String())
			}
			if _, err := f.db.Lookup(context.Background(), f.owner.ID, name); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("invalid request created work: %v", err)
			}
		})
	}
	job := f.submit(t, "canonical")
	w := perform(f.handler, http.MethodPost, "/v1/jobs/"+job.ID+"/cancel", testToken, "", `{"reason":"stop","REASON":"override"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("ambiguous cancellation: %d %s", w.Code, w.Body.String())
	}
	current, err := f.db.Get(context.Background(), job.ID)
	if err != nil || current.State != model.Queued || current.CancelRequested {
		t.Fatalf("invalid cancellation changed work: %+v %v", current, err)
	}
}

func TestReplayCannotBecomeNewAdmissionWhenRetentionRuns(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	job := f.submit(t, "retention")
	body, err := json.Marshal(f.request)
	if err != nil {
		t.Fatal(err)
	}
	// This hook is reached only when creating fresh work. The old handler
	// looked up the key, skipped readiness, then pruned here before Submit's
	// second lookup, silently recreating work while readiness was false.
	f.options.Now = func() time.Time {
		if _, err := f.db.Cancel(ctx, job.ID, "retired", testTime); err != nil {
			t.Fatal(err)
		}
		if err := f.db.Prune(ctx, testTime.Add(91*24*time.Hour)); err != nil {
			t.Fatal(err)
		}
		return testTime.Add(91 * 24 * time.Hour)
	}
	f.options.Status = func(context.Context) (controller.Status, error) {
		return controller.Status{Gate: controller.GateState{Ready: false}}, nil
	}
	h, err := New(f.options)
	if err != nil {
		t.Fatal(err)
	}
	w := perform(h, http.MethodPost, "/v1/jobs", testToken, "retention", string(body))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), job.ID) {
		t.Fatalf("read-only replay: %d %s", w.Code, w.Body.String())
	}
	retained, err := f.db.Lookup(ctx, f.owner.ID, "retention")
	if err != nil || retained.ID != job.ID || retained.State != model.Queued {
		t.Fatalf("replay changed original admission: %+v %v", retained, err)
	}
	if _, err := f.db.Cancel(ctx, job.ID, "retired", testTime); err != nil {
		t.Fatal(err)
	}
	if err := f.db.Prune(ctx, testTime.Add(91*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	w = perform(h, http.MethodPost, "/v1/jobs", testToken, "retention", string(body))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("pruned key bypassed readiness: %d %s", w.Code, w.Body.String())
	}
	registry, err := profiles.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, replay, err := Submit(ctx, f.db, registry, f.owner, "retention", f.request, testTime.Add(91*24*time.Hour))
	if !errors.Is(err, profiles.ErrUnsupported) || replay {
		t.Fatalf("pruned key bypassed current profiles: replay=%v err=%v", replay, err)
	}
	f.options.Profiles = registry
	f.options.Status = func(context.Context) (controller.Status, error) {
		return controller.Status{Gate: controller.GateState{Ready: true}}, nil
	}
	f.options.Now = func() time.Time { return testTime.Add(91 * 24 * time.Hour) }
	h, err = New(f.options)
	if err != nil {
		t.Fatal(err)
	}
	w = perform(h, http.MethodPost, "/v1/jobs", testToken, "retention", string(body))
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("pruned key bypassed current HTTP profiles: %d %s", w.Code, w.Body.String())
	}
	if _, err := f.db.Lookup(ctx, f.owner.ID, "retention"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("rejected key resurrected work: %v", err)
	}
}

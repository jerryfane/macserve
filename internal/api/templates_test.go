package api

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/store"
)

func TestOwnerWildcardPrincipalSubmitsTemplateJobs(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	template := model.Template{ID: "org-build-v1", Version: 1, Kind: model.Build, Owners: []string{"themartianapp", "jerryfane"}, Xcode: model.Xcode{Version: "27.0", Build: "27A100"}, DeveloperDir: "/Applications/Example.app/Contents/Developer"}
	exact := model.Profile{ID: "build-v1", Version: 1, Repo: "example-org/example-app", Kind: model.Build, Xcode: template.Xcode, DeveloperDir: template.DeveloperDir, WorkDir: ".", Run: model.Command{Executable: "/usr/bin/true"}}
	registry, err := profiles.New([]model.Profile{exact}, []model.Template{template})
	if err != nil {
		t.Fatal(err)
	}
	org := principal(strings.Repeat("1", 64), "org", "TheMartianApp/*", "jobs:submit")
	exactOnly := principal(strings.Repeat("2", 64), "exact", "example-org/example-app", "jobs:submit")
	if err := f.db.ReplacePrincipals(ctx, []store.Principal{f.owner, org, exactOnly}); err != nil {
		t.Fatal(err)
	}
	org, err = f.db.Authenticate(ctx, strings.Repeat("1", 64))
	if err != nil || org.Repositories[0] != "themartianapp/*" {
		t.Fatalf("wildcard not canonical: %+v %v", org, err)
	}
	exactOnly, _ = f.db.Authenticate(ctx, strings.Repeat("2", 64))
	request := func(repo, profile string) model.Request {
		return model.Request{Repo: repo, SHA: strings.Repeat("a", 40), Kind: model.Build, Profile: profile, Xcode: template.Xcode}
	}
	for i, repo := range []string{"themartianapp/new-app", "TheMartianApp/Another"} {
		job, replay, err := Submit(ctx, f.db, registry, org, "key-"+string(rune('a'+i)), request(repo, template.ID), testTime)
		if err != nil || replay || job.Profile.Template == nil || job.ProfileDigest != registry.Digests()[template.ID] {
			t.Fatalf("%s: wildcard principal refused: %+v %v", repo, job, err)
		}
	}
	refusals := []struct {
		principal store.Principal
		request   model.Request
	}{
		{org, request("jerryfane/tool", template.ID)},              // template owner, but not this principal's owner
		{org, request("themartianapp-evil/app", template.ID)},      // owner prefix
		{exactOnly, request("themartianapp/new-app", template.ID)}, // exact principal, other repo
		{exactOnly, request("example-org/other", template.ID)},     // exact principal, same owner, other repo
		{org, request("example-org/example-app", exact.ID)},        // wildcard of another owner
	}
	for i, r := range refusals {
		if _, _, err := Submit(ctx, f.db, registry, r.principal, "refused-"+string(rune('a'+i)), r.request, testTime); !errors.Is(err, ErrForbidden) {
			t.Fatalf("refusal %d: got %v", i, err)
		}
	}
	// Exact-repository principals keep today's behaviour.
	if _, _, err := Submit(ctx, f.db, registry, exactOnly, "exact", request("example-org/example-app", exact.ID), testTime); err != nil {
		t.Fatalf("exact principal refused: %v", err)
	}
	for _, bad := range []string{"*/*", "themartianapp/*/x", "/*", "the_martian/*", "themartianapp/**"} {
		if err := f.db.ReplacePrincipals(ctx, []store.Principal{principal(strings.Repeat("3", 64), "bad", bad, "jobs:submit")}); !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("%q accepted: %v", bad, err)
		}
	}
}

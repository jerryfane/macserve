package onboarding

import (
	"context"
	"slices"
	"strings"
	"testing"
)

func TestCheckInstallations(t *testing.T) {
	f := newFakeGitHub(t)
	api, err := NewAPI(f.options())
	if err != nil {
		t.Fatal(err)
	}
	app := f.app(t)
	detail, err := api.CheckInstallations(context.Background(), app, map[string]int64{"jdoe": 555}, []string{"jdoe/myapp"})
	if err != nil || !strings.Contains(detail, "1 configured") {
		t.Fatalf("%q %v", detail, err)
	}
	if len(f.tokenPerms) != 1 || len(f.tokenPerms[0]) != 1 || f.tokenPerms[0]["metadata"] != "read" {
		t.Errorf("token permissions %v", f.tokenPerms)
	}
	if !slices.Contains(f.calls, "DELETE /installation/token") {
		t.Errorf("token not revoked: %v", f.calls)
	}
	if _, err := api.CheckInstallations(context.Background(), app, map[string]int64{"jdoe": 555}, []string{"jdoe/removed"}); err == nil || !strings.Contains(err.Error(), "no longer grants jdoe/removed") {
		t.Errorf("removed repo: %v", err)
	}
	if _, err := api.CheckInstallations(context.Background(), app, nil, nil); err == nil {
		t.Error("no installation accepted")
	}
	for _, call := range f.calls {
		if strings.Contains(call, fakeToken) {
			t.Errorf("token in path %q", call)
		}
	}
}

package onboarding

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func newTestAPI(t *testing.T, f *fakeGitHub) *API {
	t.Helper()
	api, err := NewAPI(f.options())
	if err != nil {
		t.Fatal(err)
	}
	return api
}

func TestConvertReturnsAppWithoutSecrets(t *testing.T) {
	f := newFakeGitHub(t)
	app, err := newTestAPI(t, f).Convert(context.Background(), "goodcode", Account{Login: "jdoe"})
	if err != nil {
		t.Fatal(err)
	}
	_, pemBytes := appKey(t)
	if app.ID != 77 || app.Slug != "macserve-studio" || string(app.PEM) != string(pemBytes) || app.Key == nil {
		t.Fatalf("%+v", app)
	}
	if app.InstallURL() != "https://github.com/apps/macserve-studio/installations/new" {
		t.Fatal(app.InstallURL())
	}
}

func TestConvertRefusesReplayedOrExpiredCode(t *testing.T) {
	f := newFakeGitHub(t)
	api := newTestAPI(t, f)
	if _, err := api.Convert(context.Background(), "goodcode", Account{Login: "jdoe"}); err != nil {
		t.Fatal(err)
	}
	// Replayed: GitHub converts a code once. Expired or never issued: 404.
	for _, code := range []string{"goodcode", "expiredcode"} {
		if _, err := api.Convert(context.Background(), code, Account{Login: "jdoe"}); !errors.Is(err, ErrCodeRejected) {
			t.Errorf("%s: %v", code, err)
		}
	}
	if _, err := api.Convert(context.Background(), "../app/installations", Account{Login: "jdoe"}); !errors.Is(err, ErrRedirect) {
		t.Error(err)
	}
}

func TestConvertRefusesWrongPermissions(t *testing.T) {
	for name, mutate := range map[string]func(*fakeGitHub){
		"extra":   func(f *fakeGitHub) { f.permissions["administration"] = "write" },
		"missing": func(f *fakeGitHub) { delete(f.permissions, "checks") },
		"weaker":  func(f *fakeGitHub) { f.permissions["checks"] = "read" },
		"wider":   func(f *fakeGitHub) { f.permissions["contents"] = "write" },
		"events":  func(f *fakeGitHub) { f.events = []string{"pull_request"} },
	} {
		f := newFakeGitHub(t)
		mutate(f)
		_, err := newTestAPI(t, f).Convert(context.Background(), "goodcode", Account{Login: "jdoe"})
		var refused *RefusedAppError
		if !errors.As(err, &refused) || !strings.Contains(err.Error(), "https://github.com/settings/apps/macserve-studio/advanced") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestConvertRefusesAppOfAnotherAccount(t *testing.T) {
	for name, owner := range map[string]Owner{
		"other user": {Login: "mallory", ID: 666, Type: "User"},
		"org named":  {Login: "jdoe", ID: 1001, Type: "Organization"},
		"no id":      {Login: "jdoe", Type: "User"},
	} {
		f := newFakeGitHub(t)
		f.owner = owner
		if _, err := newTestAPI(t, f).Convert(context.Background(), "goodcode", Account{Login: "jdoe"}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestInstallationIDConfirmedByJWT(t *testing.T) {
	f := newFakeGitHub(t)
	api := newTestAPI(t, f)
	app := f.app(t)
	got, err := api.Confirm(context.Background(), app, Account{Login: "jdoe"}, 555)
	if err != nil || got.ID != 555 || got.Account.ID != 1001 {
		t.Fatal(got, err)
	}
	// A forged installation_id from the setup redirect: unknown to GitHub,
	// or an installation of another App.
	f.installations[556] = fakeInstallation{AppID: 99, Account: f.owner, Selection: "selected", Permissions: RequiredPermissions()}
	for _, forged := range []int64{0, 1, 556} {
		if _, err := api.Confirm(context.Background(), app, Account{Login: "jdoe"}, forged); !errors.Is(err, ErrNotInstallation) {
			t.Errorf("installation %d: %v", forged, err)
		}
	}
	// The JWT is what GitHub checks: a different key is refused.
	other := app
	other.ID = 78
	if _, err := api.Confirm(context.Background(), other, Account{Login: "jdoe"}, 555); err == nil {
		t.Error("confirmed with the wrong App identity")
	}
}

func TestInstallationForAnotherAccountRefused(t *testing.T) {
	f := newFakeGitHub(t)
	f.installations[557] = fakeInstallation{AppID: 77, Account: Owner{Login: "mallory", ID: 666, Type: "User"}, Selection: "selected", Permissions: RequiredPermissions()}
	f.installations[558] = fakeInstallation{AppID: 77, Account: f.owner, Selection: "all", Permissions: RequiredPermissions()}
	f.installations[559] = fakeInstallation{AppID: 77, Account: f.owner, Selection: "selected", Permissions: map[string]string{"metadata": "read"}}
	api := newTestAPI(t, f)
	for id, want := range map[int64]string{557: `"mallory"`, 558: "all repositories", 559: "permissions"} {
		if _, err := api.Confirm(context.Background(), f.app(t), Account{Login: "jdoe"}, id); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%d: %v", id, err)
		}
	}
}

func TestConfirmInstallationRequiresExactlyThePinnedRepository(t *testing.T) {
	f := newFakeGitHub(t)
	api := newTestAPI(t, f)
	o := ConnectOptions{Account: Account{Login: "jdoe"}, Repository: "jdoe/myapp", RepositoryID: 4242}
	if _, repo, _, err := confirmInstallation(context.Background(), api, f.app(t), o, 555); err != nil || repo.ID != 4242 {
		t.Fatal(repo, err)
	}
	if got := f.tokenPerms[len(f.tokenPerms)-1]; len(got) != 2 || got["metadata"] != "read" || got["contents"] != "read" {
		t.Fatalf("onboarding token permissions %v", got)
	}
	o.RepositoryID = 4243
	if _, _, _, err := confirmInstallation(context.Background(), api, f.app(t), o, 555); err == nil {
		t.Fatal("accepted a repository with another ID")
	}
	o.RepositoryID = 4242
	f.repos = append(f.repos, Repository{ID: 9, FullName: "jdoe/other", Owner: f.owner, DefaultBranch: "main"})
	if _, _, _, err := confirmInstallation(context.Background(), api, f.app(t), o, 555); err == nil {
		t.Fatal("accepted an installation on two repositories")
	}
}

func TestParseAppKeyRefusesNonRSAOrTrailingData(t *testing.T) {
	_, pemBytes := appKey(t)
	for name, data := range map[string][]byte{
		"empty":    nil,
		"trailing": append(append([]byte{}, pemBytes...), []byte("extra")...),
		"two":      append(append([]byte{}, pemBytes...), pemBytes...),
		"garbage":  []byte("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n"),
	} {
		if _, err := ParseAppKey(data); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ParseAppKey(pemBytes); err != nil {
		t.Fatal(err)
	}
}

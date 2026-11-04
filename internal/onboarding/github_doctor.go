package onboarding

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
)

// CheckInstallations is `macserve doctor --live`'s github.app check: the
// App's JWT is accepted, and each installation (by owner login) lists the
// repositories configured for that owner. Tokens are minted read-only and
// are never returned or printed; errors name only repositories and
// installation IDs. Each token is metadata-only and revoked after use.
func (a *API) CheckInstallations(ctx context.Context, app App, installations map[string]int64, repositories []string) (string, error) {
	if len(installations) == 0 {
		return "", errors.New("no GitHub App installation is configured")
	}
	owners := make([]string, 0, len(installations))
	for owner := range installations {
		owners = append(owners, owner)
	}
	sort.Strings(owners)
	listed := 0
	for _, owner := range owners {
		id := installations[owner]
		token, err := a.mintToken(ctx, app, Installation{ID: id}, map[string]string{"metadata": "read"})
		if err != nil {
			return "", fmt.Errorf("the App cannot use installation %d (%s)", id, owner)
		}
		repos, err := a.repositories(ctx, token)
		// The token served only this listing; revoke it (best effort, it
		// expires within the hour anyway).
		_ = a.do(ctx, http.MethodDelete, "/installation/token", token, nil, nil)
		if err != nil {
			return "", fmt.Errorf("cannot list the repositories of installation %d (%s)", id, owner)
		}
		var names []string
		for _, r := range repos {
			names = append(names, strings.ToLower(r.FullName))
		}
		for _, repo := range repositories {
			o, _, _ := strings.Cut(repo, "/")
			if !strings.EqualFold(o, owner) {
				continue
			}
			if !slices.Contains(names, strings.ToLower(repo)) {
				return "", fmt.Errorf("installation %d no longer grants %s", id, repo)
			}
			listed++
		}
	}
	return fmt.Sprintf("App %d is installed; %d installation(s) grant the %d configured repositories", app.ID, len(owners), listed), nil
}

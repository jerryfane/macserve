package onboarding

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
)

// RepoConfigStatus is the .macserve.json state at the default branch head.
// It is read through the contents and trees APIs only: nothing from the
// repository is checked out or executed, and root never runs repository
// tools (docs/install.md).
type RepoConfigStatus struct {
	Commit      string
	Found       bool
	Config      model.RepoConfig
	Invalid     error
	Suggestions []model.RepoConfig
	// Truncated reports a tree too large for one listing; suggestions may
	// then be incomplete.
	Truncated bool
}

// DetectRepoConfig reads .macserve.json at repo's default branch head and
// validates it with profiles.ParseRepoConfig. When it is missing it
// suggests configurations from the tree listing alone: shared schemes
// (xcshareddata/xcschemes/*.xcscheme) of *.xcworkspace and *.xcodeproj
// containers that are not nested in another container.
func (a *API) DetectRepoConfig(ctx context.Context, token string, repo Repository) (RepoConfigStatus, error) {
	commit, tree, err := a.head(ctx, token, repo)
	if err != nil {
		return RepoConfigStatus{}, err
	}
	status := RepoConfigStatus{Commit: commit}
	data, found, err := a.file(ctx, token, repo, commit, profiles.RepoConfigFile, profiles.MaxRepoConfigBytes)
	if found {
		status.Found = true
		if err == nil {
			status.Config, err = profiles.ParseRepoConfig(data)
		}
		status.Invalid = err
		return status, nil
	}
	if err != nil {
		return RepoConfigStatus{}, err
	}
	entries, truncated, err := a.tree(ctx, token, repo, tree)
	if err != nil {
		return RepoConfigStatus{}, err
	}
	status.Truncated = truncated
	status.Suggestions = SuggestRepoConfigs(entries)
	return status, nil
}

func container(p string) bool {
	return strings.HasSuffix(p, ".xcodeproj") || strings.HasSuffix(p, ".xcworkspace")
}

// SuggestRepoConfigs derives candidate .macserve.json values from a tree
// listing. Root-level containers come first, a workspace before a project
// in the same directory, then by path; each candidate passes
// profiles.ValidateRepoConfig.
func SuggestRepoConfigs(entries []TreeEntry) []model.RepoConfig {
	containers := map[string]bool{}
	for _, e := range entries {
		if e.Type == "tree" && container(e.Path) {
			containers[e.Path] = true
		}
	}
	nested := func(p string) bool {
		for dir := path.Dir(p); dir != "." && dir != "/"; dir = path.Dir(dir) {
			if containers[dir] {
				return true
			}
		}
		return false
	}
	schemes := map[string][]string{}
	for _, e := range entries {
		dir, file := path.Split(e.Path)
		if e.Type != "blob" || !strings.HasSuffix(file, ".xcscheme") || !strings.HasSuffix(dir, "/xcshareddata/xcschemes/") {
			continue
		}
		owner := strings.TrimSuffix(dir, "/xcshareddata/xcschemes/")
		if containers[owner] && !nested(owner) {
			schemes[owner] = append(schemes[owner], strings.TrimSuffix(file, ".xcscheme"))
		}
	}
	var paths []string
	for p := range containers {
		if !nested(p) {
			paths = append(paths, p)
		}
	}
	sort.Slice(paths, func(i, j int) bool {
		di, dj := strings.Count(paths[i], "/"), strings.Count(paths[j], "/")
		if di != dj {
			return di < dj
		}
		wi, wj := strings.HasSuffix(paths[i], ".xcworkspace"), strings.HasSuffix(paths[j], ".xcworkspace")
		if path.Dir(paths[i]) == path.Dir(paths[j]) && wi != wj {
			return wi
		}
		return paths[i] < paths[j]
	})
	var out []model.RepoConfig
	for _, p := range paths {
		names := schemes[p]
		if len(names) == 0 && strings.HasSuffix(p, ".xcworkspace") {
			// A workspace usually shares its projects' schemes.
			dir := path.Dir(p)
			for q, s := range schemes {
				if path.Dir(q) == dir && strings.HasSuffix(q, ".xcodeproj") {
					names = append(names, s...)
				}
			}
		}
		sort.Strings(names)
		for _, scheme := range names {
			c := model.RepoConfig{Version: 1, WorkDir: path.Dir(p), Scheme: scheme}
			if strings.HasSuffix(p, ".xcworkspace") {
				c.Workspace = path.Base(p)
			} else {
				c.Project = path.Base(p)
			}
			if profiles.ValidateRepoConfig(c) == nil {
				out = append(out, c)
			}
		}
	}
	return out
}

// WriteRepoConfigSuggestion prints c as a ready .macserve.json and the
// commands that commit it. The App is read-only and cannot commit.
func WriteRepoConfigSuggestion(w io.Writer, c model.RepoConfig, branch string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "In a checkout of the repository on %s, create %s:\n\ncat > %s <<'EOF'\n%s\nEOF\ngit add %s\ngit commit -m \"Add %s for macserve\"\ngit push origin HEAD:%s\n\n",
		branch, profiles.RepoConfigFile, profiles.RepoConfigFile, data, profiles.RepoConfigFile, profiles.RepoConfigFile, shellQuote(branch))
	return err
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

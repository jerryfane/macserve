package githubpull

import (
	"errors"
	"testing"

	"github.com/jerryfane/macserve/internal/model"
)

const archiveTemplate = "org-ios-archive-v1"

func archiveTemplateFor(owners ...string) model.Template {
	t := templateFor(owners...)
	t.ID, t.Kind = archiveTemplate, model.IOSArchive
	return t
}

// A pull request policy can never select an ios_archive template, even one
// whose owners include the repository owner: a release archive is admitted
// only at the default-branch head through the private API.
func TestPolicyCannotSelectArchiveTemplate(t *testing.T) {
	registry := registryOf(t, nil, templateFor("example-org"), archiveTemplateFor("example-org"))
	for name, ids := range map[string][]string{
		"archive only":       {archiveTemplate},
		"archive with build": {testTemplate, archiveTemplate},
	} {
		if _, err := newFixtureWith(t, registry, ids); err == nil || err.Error() != "invalid GitHub profile policy" {
			t.Errorf("%s: policy accepted or wrong error: %v", name, err)
		}
	}
	f, err := newFixtureWith(t, registry, []string{testTemplate})
	if err != nil {
		t.Fatalf("build template refused beside an archive template: %v", err)
	}
	// The poller's recipe path refuses the archive even for a policy that
	// names it, so no pull request is admitted as an archive.
	policy := f.p.policies[testRepo]
	policy.Profiles = append(policy.Profiles, archiveTemplate)
	if _, ok := f.p.recipe(policy, archiveTemplate); ok {
		t.Fatal("recipe selected an archive template")
	}
	if _, err := f.p.admission(policy, f.remote.pull, archiveTemplate); !errors.Is(err, ErrIneligible) {
		t.Fatalf("archive admission: %v", err)
	}
	if _, ok := f.p.recipe(policy, testTemplate); !ok {
		t.Fatal("build template no longer selectable")
	}
}

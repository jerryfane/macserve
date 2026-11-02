package qualification

import (
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/maintenance"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
)

func TestTemplatesAreQualificationRecipes(t *testing.T) {
	template := model.Template{ID: "org-build-v1", Version: 1, Kind: model.Build, Owners: []string{"themartianapp"}, Xcode: model.Xcode{Version: "27.1", Build: "27A9275"}, DeveloperDir: "/Applications/Xcode.app/Contents/Developer", DefaultTimeoutSeconds: 1800, MaxTimeoutSeconds: 3600, MemoryLimitMiB: 32768}
	registry, err := profiles.New(nil, []model.Template{template})
	if err != nil {
		t.Fatal(err)
	}
	c := Challenge{Templates: registry.Templates(), Observation: maintenance.Observation{Profiles: registry.Digests()}}
	recipes := c.recipes()
	if len(recipes) != 1 || recipes[0].ID != template.ID || recipes[0].Template == nil || recipes[0].DeveloperDir != template.DeveloperDir || recipes[0].Xcode != template.Xcode {
		t.Fatalf("template is not a qualification recipe: %+v", recipes)
	}
	pin := SourcePin{Profile: template.ID, Repo: "themartianapp/fixture-app", Commit: strings.Repeat("a", 40)}
	admission, err := pinRequest(recipes[0], pin, 600)
	if err != nil || admission.ProfileDigest != c.Observation.Profiles[template.ID] || admission.Request.Repo != pin.Repo || admission.Profile.Template == nil {
		t.Fatalf("template pin admission %+v %v", admission, err)
	}
	for _, repo := range []string{"", "someone-else/app"} {
		pin.Repo = repo
		if _, err := pinRequest(recipes[0], pin, 600); err == nil {
			t.Fatalf("template pin for %q admitted", repo)
		}
	}
	// Zero templates: the challenge JSON and recipe list are unchanged.
	if (Challenge{}).recipes() != nil {
		t.Fatal("empty challenge grew recipes")
	}
}

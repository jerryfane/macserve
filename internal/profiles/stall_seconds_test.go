package profiles_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
)

// #201: a script template's jobs stall after ten minutes without output
// unless it sets stall_seconds; a test template's jobs only when it sets
// it. stall_seconds lies within 60 to 3600 and loads only on the kinds
// whose run command is watched.
func TestStallSecondsTemplateBounds(t *testing.T) {
	ui, err := loadTemplates(uiTemplate)
	if err != nil {
		t.Fatal(err)
	}
	a, err := ui.Resolve(testRequest(t, model.SimulatorUITest, "iphone-terminal"))
	if err != nil || a.Profile.StallTimeout() != 0 {
		t.Fatalf("UI-test default stall limit %s: %v", a.Profile.StallTimeout(), err)
	}
	ui, err = loadTemplates(withParallel(uiTemplate, `"stall_seconds":900`))
	if err != nil {
		t.Fatal(err)
	}
	a, err = ui.Resolve(testRequest(t, model.SimulatorUITest, "iphone-terminal"))
	if err != nil || a.Profile.StallTimeout() != 15*time.Minute {
		t.Fatalf("UI-test opt-in stall limit %s: %v", a.Profile.StallTimeout(), err)
	}
	script := model.Profile{Kind: model.SimulatorScript, Template: &model.Template{Kind: model.SimulatorScript}}
	if script.StallTimeout() != 10*time.Minute {
		t.Fatalf("script default stall limit %s", script.StallTimeout())
	}
	script.Template.StallSeconds = 120
	if script.StallTimeout() != 2*time.Minute {
		t.Fatalf("script stall limit %s", script.StallTimeout())
	}
	for _, template := range []string{withParallel(scriptTemplate, `"stall_seconds":60`), withParallel(scriptTemplate, `"stall_seconds":3600`), withParallel(unitTemplate, `"stall_seconds":600`)} {
		if _, err := loadTemplates(template); err != nil {
			t.Fatalf("%s: %v", template, err)
		}
	}
	for name, template := range map[string]string{
		"under a minute": withParallel(scriptTemplate, `"stall_seconds":59`),
		"over an hour":   withParallel(scriptTemplate, `"stall_seconds":3601`),
		"negative":       withParallel(scriptTemplate, `"stall_seconds":-1`),
	} {
		if _, err := loadTemplates(template); !errors.Is(err, profiles.ErrInvalid) || !strings.Contains(err.Error(), "stall_seconds must be 60 to 3600") {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for name, template := range map[string]string{
		"build":       strings.Replace(buildTemplate, `"version":1`, `"version":1,"stall_seconds":600`, 1),
		"ios_archive": withParallel(archiveTemplate, `"stall_seconds":600`),
	} {
		if _, err := loadTemplates(template); !errors.Is(err, profiles.ErrInvalid) || !strings.Contains(err.Error(), "may set stall_seconds") {
			t.Fatalf("stall_seconds on a %s template: %v", name, err)
		}
	}
}

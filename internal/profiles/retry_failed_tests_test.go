package profiles_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
)

// retry_failed_tests loads only on a simulator_ui_test template, with
// exactly 2 iterations (one retry) and a well-formed object; beside
// parallel_testing too.
func TestRetryFailedTestsTemplateBounds(t *testing.T) {
	for name, member := range map[string]string{
		"alone":                 `"retry_failed_tests":{"iterations":2}`,
		"with parallel testing": `"retry_failed_tests":{"iterations":2},"parallel_testing":{"workers":2}`,
	} {
		template := strings.Replace(withParallel(uiTemplate, member), `"memory_limit_mib":32768`, `"memory_limit_mib":49152`, 1)
		r, err := loadTemplates(template)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		a, err := r.Resolve(testRequest(t, model.SimulatorUITest, "iphone-terminal"))
		if err != nil || a.Profile.RetryIterations() != 2 {
			t.Fatalf("%s: admitted snapshot retries %d: %v", name, a.Profile.RetryIterations(), err)
		}
	}
	for name, member := range map[string]string{
		"one iteration":      `"retry_failed_tests":{"iterations":1}`,
		"three iterations":   `"retry_failed_tests":{"iterations":3}`,
		"zero iterations":    `"retry_failed_tests":{"iterations":0}`,
		"missing iterations": `"retry_failed_tests":{}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadTemplates(withParallel(uiTemplate, member)); !errors.Is(err, profiles.ErrInvalid) || !strings.Contains(err.Error(), "retry_failed_tests iterations must be 2") {
				t.Fatalf("%s: %v", member, err)
			}
		})
	}
	for name, template := range map[string]string{
		"unknown member": withParallel(uiTemplate, `"retry_failed_tests":{"iterations":2,"relaunch":true}`),
		"not an object":  withParallel(uiTemplate, `"retry_failed_tests":2`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadTemplates(template); !errors.Is(err, profiles.ErrInvalid) {
				t.Fatalf("%s: %v", template, err)
			}
		})
	}
	for name, template := range map[string]string{
		"unit test":   withParallel(unitTemplate, `"retry_failed_tests":{"iterations":2}`),
		"script":      withParallel(scriptTemplate, `"retry_failed_tests":{"iterations":2}`),
		"build":       strings.Replace(buildTemplate, `"version":1`, `"version":1,"retry_failed_tests":{"iterations":2}`, 1),
		"ios_archive": withParallel(archiveTemplate, `"retry_failed_tests":{"iterations":2}`),
	} {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(template, `"retry_failed_tests"`) {
				t.Fatalf("fixture lacks the field: %s", template)
			}
			if _, err := loadTemplates(template); !errors.Is(err, profiles.ErrInvalid) || !strings.Contains(err.Error(), "only simulator_ui_test templates may set retry_failed_tests") {
				t.Fatalf("retry_failed_tests on a %s template: %v", name, err)
			}
		})
	}
}

// The opt-in is part of the template digest only when set: absent (or
// null) keeps the template's digest, so existing receipts and
// qualifications stand; set, the admitted snapshot binds it and re-admits
// as itself.
func TestRetryFailedTestsTemplateDigest(t *testing.T) {
	plain := templatesFile(t, uiTemplate).Digests()["org-ios-sim-uitest-v1"]
	null := templatesFile(t, withParallel(uiTemplate, `"retry_failed_tests":null`)).Digests()["org-ios-sim-uitest-v1"]
	retry := templatesFile(t, withParallel(uiTemplate, `"retry_failed_tests":{"iterations":2}`))
	digest := retry.Digests()["org-ios-sim-uitest-v1"]
	if null != plain || digest == plain {
		t.Fatalf("digests: plain %s, null %s, retry %s", plain, null, digest)
	}
	a, err := retry.Resolve(testRequest(t, model.SimulatorUITest, "iphone-terminal"))
	if err != nil || a.ProfileDigest != digest || member(t, *a.Profile.Template, "retry_failed_tests") != `{"iterations":2}` {
		t.Fatalf("admitted snapshot: %+v %s %v", a.Profile.Template, a.ProfileDigest, err)
	}
	again, err := profiles.ForSnapshot(a.Profile)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := again.Resolve(a.Request); err != nil || b.ProfileDigest != digest || b.Profile.RetryIterations() != 2 {
		t.Fatalf("re-admitted snapshot: %+v %v", b.Profile, err)
	}
	p, err := templatesFile(t, uiTemplate).Resolve(testRequest(t, model.SimulatorUITest, "iphone-terminal"))
	if err != nil || p.Profile.RetryIterations() != 0 {
		t.Fatalf("plain template retries: %+v %v", p.Profile, err)
	}
}

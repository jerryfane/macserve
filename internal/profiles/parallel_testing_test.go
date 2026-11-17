package profiles_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
)

// withParallel adds members (e.g. a parallel_testing opt-in) before a
// template's memory_limit_mib.
func withParallel(template, members string) string {
	return strings.Replace(template, `"memory_limit_mib"`, members+`,"memory_limit_mib"`, 1)
}

// parallel_testing loads only on a simulator_ui_test template with 1 to 4
// workers and a well-formed object.
func TestParallelTestingTemplateBounds(t *testing.T) {
	for _, workers := range []string{"1", "4"} {
		template := strings.Replace(withParallel(uiTemplate, `"parallel_testing":{"workers":`+workers+`}`), `"memory_limit_mib":32768`, `"memory_limit_mib":49152`, 1)
		if _, err := loadTemplates(template); err != nil {
			t.Fatalf("%s workers: %v", workers, err)
		}
	}
	for name, member := range map[string]string{
		"zero workers":     `"parallel_testing":{"workers":0}`,
		"five workers":     `"parallel_testing":{"workers":5}`,
		"negative workers": `"parallel_testing":{"workers":-1}`,
		"missing workers":  `"parallel_testing":{}`,
	} {
		t.Run(name, func(t *testing.T) {
			template := strings.Replace(withParallel(uiTemplate, member), `"memory_limit_mib":32768`, `"memory_limit_mib":65536`, 1)
			if _, err := loadTemplates(template); !errors.Is(err, profiles.ErrInvalid) || !strings.Contains(err.Error(), "parallel_testing workers must be 1 to 4") {
				t.Fatalf("%s: %v", member, err)
			}
		})
	}
	for name, template := range map[string]string{
		"unknown member": withParallel(uiTemplate, `"parallel_testing":{"workers":2,"destinations":2}`),
		"not an object":  withParallel(uiTemplate, `"parallel_testing":2`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadTemplates(template); !errors.Is(err, profiles.ErrInvalid) {
				t.Fatalf("%s: %v", template, err)
			}
		})
	}
	for name, template := range map[string]string{
		"unit test":   withParallel(unitTemplate, `"parallel_testing":{"workers":2}`),
		"script":      withParallel(scriptTemplate, `"parallel_testing":{"workers":2}`),
		"build":       strings.Replace(buildTemplate, `"version":1`, `"version":1,"parallel_testing":{"workers":2}`, 1),
		"ios_archive": withParallel(archiveTemplate, `"parallel_testing":{"workers":2}`),
	} {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(template, `"parallel_testing"`) {
				t.Fatalf("fixture lacks the field: %s", template)
			}
			if _, err := loadTemplates(template); !errors.Is(err, profiles.ErrInvalid) || !strings.Contains(err.Error(), "only simulator_ui_test templates may set parallel_testing") {
				t.Fatalf("parallel_testing on a %s template: %v", name, err)
			}
		})
	}
}

// A parallel-testing template's memory budget covers its clones: omitted, it
// is the default budget plus 4096 MiB per worker. An explicit budget loads
// from 8192 MiB plus 4096 MiB per worker (the measured UI-test peak of 5209
// MiB with headroom, and an allowance per clone) and refuses below that. A
// budget that lets six jobs fit the controller's cap, 20480 MiB for two
// workers, loads.
func TestParallelTestingTemplateMemoryBudget(t *testing.T) {
	omitted := strings.Replace(withParallel(uiTemplate, `"parallel_testing":{"workers":2}`), `,"memory_limit_mib":32768`, ``, 1)
	r := templatesFile(t, omitted)
	const want = 32768 + 2*4096
	if got := r.Templates()[0].MemoryLimitMiB; got != want {
		t.Fatalf("defaulted budget %d, want %d", got, want)
	}
	a, err := r.Resolve(testRequest(t, model.SimulatorUITest, "iphone-terminal"))
	if err != nil || a.Profile.MemoryLimitMiB != want || member(t, *a.Profile.Template, "parallel_testing") != `{"workers":2}` {
		t.Fatalf("admitted snapshot: %+v %v", a.Profile, err)
	}
	budget := func(workers, mib int) string {
		return strings.Replace(withParallel(uiTemplate, fmt.Sprintf(`"parallel_testing":{"workers":%d}`, workers)), `"memory_limit_mib":32768`, fmt.Sprintf(`"memory_limit_mib":%d`, mib), 1)
	}
	for workers := 1; workers <= 4; workers++ {
		floor := 8192 + workers*4096
		r, err := loadTemplates(budget(workers, floor))
		if err != nil || r.Templates()[0].MemoryLimitMiB != floor {
			t.Fatalf("%d workers at the %d MiB floor: %v", workers, floor, err)
		}
		if _, err := loadTemplates(budget(workers, floor-1)); !errors.Is(err, profiles.ErrInvalid) || !strings.Contains(err.Error(), fmt.Sprintf("memory_limit_mib must be at least %d for %d workers", floor, workers)) {
			t.Fatalf("%d workers below the floor: %v", workers, err)
		}
	}
	if _, err := loadTemplates(budget(2, 20480)); err != nil {
		t.Fatalf("20480 MiB for two workers: %v", err)
	}
}

// The opt-in is part of the template digest, so a receipt names the recipe
// that ran: absent (or null) keeps the template's digest, each worker count
// has its own, and the admitted snapshot binds it and re-admits as itself.
func TestParallelTestingTemplateDigest(t *testing.T) {
	budget := func(template string) string {
		return strings.Replace(template, `"memory_limit_mib":32768`, `"memory_limit_mib":65536`, 1)
	}
	plain := templatesFile(t, budget(uiTemplate)).Digests()["org-ios-sim-uitest-v1"]
	null := templatesFile(t, budget(withParallel(uiTemplate, `"parallel_testing":null`))).Digests()["org-ios-sim-uitest-v1"]
	two := templatesFile(t, budget(withParallel(uiTemplate, `"parallel_testing":{"workers":2}`)))
	three := templatesFile(t, budget(withParallel(uiTemplate, `"parallel_testing":{"workers":3}`))).Digests()["org-ios-sim-uitest-v1"]
	digest := two.Digests()["org-ios-sim-uitest-v1"]
	if null != plain || digest == plain || three == plain || three == digest {
		t.Fatalf("digests: plain %s, null %s, two %s, three %s", plain, null, digest, three)
	}
	a, err := two.Resolve(testRequest(t, model.SimulatorUITest, "iphone-terminal"))
	if err != nil || a.ProfileDigest != digest || member(t, *a.Profile.Template, "parallel_testing") != `{"workers":2}` {
		t.Fatalf("admitted snapshot: %+v %s %v", a.Profile.Template, a.ProfileDigest, err)
	}
	again, err := profiles.ForSnapshot(a.Profile)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := again.Resolve(a.Request); err != nil || b.ProfileDigest != digest || member(t, *b.Profile.Template, "parallel_testing") != `{"workers":2}` {
		t.Fatalf("re-admitted snapshot: %+v %v", b.Profile, err)
	}
}

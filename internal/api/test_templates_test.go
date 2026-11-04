package api

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/store"
)

// viaJSON round-trips v through its JSON object form, applying change on the
// way; the test-template fields are reached only by their JSON spelling.
func viaJSON[T any](t *testing.T, v any, change func(map[string]any)) T {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatal(err)
	}
	if change != nil {
		change(object)
	}
	if data, err = json.Marshal(object); err != nil {
		t.Fatal(err)
	}
	var out T
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func jsonMember(t *testing.T, v any, key string) any {
	return viaJSON[map[string]any](t, v, nil)[key]
}

// Capabilities list a test template's simulator pins, first (the default)
// first; a build template lists none.
func TestCapabilitiesListTestTemplateSimulators(t *testing.T) {
	f := setup(t)
	iPhone := model.Simulator{Runtime: "com.apple.CoreSimulator.SimRuntime.iOS-27-0", RuntimeBuild: "24A434", DeviceType: "com.apple.CoreSimulator.SimDeviceType.iPhone-18-Pro"}
	iPad := model.Simulator{Runtime: iPhone.Runtime, RuntimeBuild: iPhone.RuntimeBuild, DeviceType: "com.apple.CoreSimulator.SimDeviceType.iPad-Pro-13-inch-M5-12GB"}
	base := model.Template{Version: 1, Owners: []string{"themartianapp"}, Xcode: model.Xcode{Version: "27.0", Build: "27A100"}, DeveloperDir: "/Applications/Example.app/Contents/Developer"}
	ui, build := base, base
	ui.ID, ui.Kind, ui.Simulators = "org-ios-sim-uitest-v1", model.SimulatorUITest, []model.Simulator{iPhone, iPad}
	build.ID, build.Kind = "org-build-v1", model.Build
	registry, err := profiles.New(nil, []model.Template{ui, build})
	if err != nil {
		t.Fatal(err)
	}
	org := principal(strings.Repeat("1", 64), "org", "themartianapp/*", "jobs:read")
	if err := f.db.ReplacePrincipals(context.Background(), []store.Principal{f.owner, org}); err != nil {
		t.Fatal(err)
	}
	f.options.Profiles = registry
	h, err := New(f.options)
	if err != nil {
		t.Fatal(err)
	}
	w := perform(h, "GET", "/v1/capabilities", strings.Repeat("1", 64), "", "")
	var body struct {
		Templates []struct {
			ID         string             `json:"id"`
			Kind       model.Kind         `json:"kind"`
			Simulators *[]model.Simulator `json:"simulators"`
		} `json:"templates"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); w.Code != 200 || err != nil {
		t.Fatalf("capabilities: %d %s %v", w.Code, w.Body.String(), err)
	}
	listed := map[string]*[]model.Simulator{}
	for _, item := range body.Templates {
		listed[item.ID] = item.Simulators
	}
	if got := listed[ui.ID]; len(listed) != 2 || got == nil || len(*got) != 2 || (*got)[0] != iPhone || (*got)[1] != iPad {
		t.Fatalf("test template simulators not listed: %s", w.Body.String())
	}
	if got, ok := listed[build.ID]; !ok || got != nil {
		t.Fatalf("build template listed simulators: %s", w.Body.String())
	}
}

func TestSubmitTestTemplateJobPinsSimulatorAndShard(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	iPhone := model.Simulator{Runtime: "com.apple.CoreSimulator.SimRuntime.iOS-27-0", RuntimeBuild: "24A434", DeviceType: "com.apple.CoreSimulator.SimDeviceType.iPhone-18-Pro"}
	iPad := model.Simulator{Runtime: iPhone.Runtime, RuntimeBuild: iPhone.RuntimeBuild, DeviceType: "com.apple.CoreSimulator.SimDeviceType.iPad-Pro-13-inch-M5-12GB"}
	template := viaJSON[model.Template](t, map[string]any{"id": "org-ios-sim-uitest-v1", "version": 1, "kind": model.SimulatorUITest, "owners": []string{"themartianapp"}, "xcode": model.Xcode{Version: "27.0", Build: "27A100"}, "developer_dir": "/Applications/Example.app/Contents/Developer", "simulators": []model.Simulator{iPhone, iPad}}, nil)
	registry, err := profiles.New(nil, []model.Template{template})
	if err != nil {
		t.Fatal(err)
	}
	org := principal(strings.Repeat("1", 64), "org", "themartianapp/*", "jobs:submit")
	if err := f.db.ReplacePrincipals(ctx, []store.Principal{f.owner, org}); err != nil {
		t.Fatal(err)
	}
	if org, err = f.db.Authenticate(ctx, strings.Repeat("1", 64)); err != nil {
		t.Fatal(err)
	}
	request := viaJSON[model.Request](t, map[string]any{"repo": "themartianapp/herdrup", "sha": strings.Repeat("a", 40), "kind": model.SimulatorUITest, "profile": template.ID, "xcode": template.Xcode, "shard": "iphone-terminal"}, nil)
	job, replay, err := Submit(ctx, f.db, registry, org, "shard-1", request, testTime)
	if err != nil || replay {
		t.Fatalf("test template job refused: %v", err)
	}
	if job.Request.Simulator == nil || *job.Request.Simulator != iPhone || job.Profile.Simulator == nil || *job.Profile.Simulator != iPhone || jsonMember(t, job.Request, "shard") != "iphone-terminal" || jsonMember(t, job.Profile, "shard") != "iphone-terminal" || job.Request.TimeoutSeconds != 2400 || job.ProfileDigest != registry.Digests()[template.ID] {
		t.Fatalf("admitted job %+v", job)
	}
	// Replaying the same request, with the simulator still omitted, is a replay.
	again, replay, err := Submit(ctx, f.db, registry, org, "shard-1", request, testTime)
	if err != nil || !replay || again.ID != job.ID {
		t.Fatalf("replay: %+v %v %v", again, replay, err)
	}
	// So is naming the pin it resolved to; another shard or device conflicts.
	named := request
	named.Simulator = &iPhone
	if again, replay, err := Submit(ctx, f.db, registry, org, "shard-1", named, testTime); err != nil || !replay || again.ID != job.ID {
		t.Fatalf("replay with the admitted simulator: %v %v", replay, err)
	}
	for name, changed := range map[string]model.Request{
		"shard":     viaJSON[model.Request](t, request, func(m map[string]any) { m["shard"] = "iphone-chrome" }),
		"simulator": viaJSON[model.Request](t, request, func(m map[string]any) { m["simulator"] = iPad }),
	} {
		if _, _, err := Submit(ctx, f.db, registry, org, "shard-1", changed, testTime); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("replay with another %s: %v", name, err)
		}
	}
	// The second pin is its own job.
	other := request
	other.Simulator = &iPad
	if job, _, err := Submit(ctx, f.db, registry, org, "shard-2", other, testTime); err != nil || *job.Profile.Simulator != iPad {
		t.Fatalf("listed simulator: %+v %v", job, err)
	}

	// The store refuses template snapshots that admission would not produce.
	admission, err := registry.Resolve(request)
	if err != nil {
		t.Fatal(err)
	}
	unlisted := iPhone
	unlisted.RuntimeBuild = "24A435"
	forged := map[string]func(request, profile, template map[string]any){
		"unlisted simulator": func(request, profile, _ map[string]any) {
			request["simulator"], profile["simulator"] = unlisted, unlisted
		},
		"no shard":       func(request, profile, _ map[string]any) { delete(request, "shard"); delete(profile, "shard") },
		"snapshot shard": func(_, profile, _ map[string]any) { profile["shard"] = "iphone-chrome" },
		"no simulator":   func(request, profile, _ map[string]any) { delete(request, "simulator"); delete(profile, "simulator") },
		"required tests": func(_, profile, _ map[string]any) { profile["required_tests"] = []string{"HerdrUITests/GramTests"} },
		"build with a shard": func(request, profile, template map[string]any) {
			request["kind"], profile["kind"], template["kind"] = model.Build, model.Build, model.Build
			delete(request, "simulator")
			delete(profile, "simulator")
			delete(template, "simulators")
		},
	}
	for name, change := range forged {
		changed := viaJSON[model.Admission](t, admission, func(m map[string]any) {
			profile := m["profile"].(map[string]any)
			change(m["request"].(map[string]any), profile, profile["template"].(map[string]any))
		})
		digest, err := changed.Profile.SnapshotDigest()
		if err != nil {
			t.Fatal(err)
		}
		changed.ProfileDigest = digest
		if _, _, err := f.db.Enqueue(ctx, org.ID, "forged-"+name, changed, testTime); !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("%s: store accepted %v", name, err)
		}
	}
}

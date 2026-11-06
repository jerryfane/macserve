package store

import (
	"context"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
)

// Enqueue re-checks a Flutter template admission: the request must name the
// pinned Flutter version exactly, and no other recipe's request may name one.
func TestEnqueueFlutterTemplateJobRequiresPinnedVersion(t *testing.T) {
	ctx := context.Background()
	s, _ := newStore(t, Options{})
	pin := model.FlutterPin{Version: "3.41.9", SDKSHA256: strings.Repeat("a", 64), RubySHA256: strings.Repeat("b", 64), CocoaPodsVersion: "1.16.2", GemsSHA256: strings.Repeat("c", 64)}
	flutter := model.Template{ID: "org-flutter-build-v1", Version: 1, Kind: model.Build, Owners: []string{"example-org"}, Xcode: model.Xcode{Version: "27.0", Build: "27A100"}, DeveloperDir: "/Applications/ExampleToolchain.app/Contents/Developer", MemoryLimitMiB: 512, Flutter: &pin}
	native := flutter
	native.ID, native.Flutter = "org-build-v1", nil
	registry, err := profiles.New(nil, []model.Template{flutter, native})
	if err != nil {
		t.Fatal(err)
	}
	request := model.Request{Repo: "example-org/example-app", SHA: strings.Repeat("a", 40), Kind: model.Build, Profile: flutter.ID, Xcode: flutter.Xcode, Flutter: &model.FlutterRequest{Version: "3.41.9"}}
	admission, err := registry.Resolve(request)
	if err != nil {
		t.Fatal(err)
	}
	job, _, err := s.Enqueue(ctx, "principal", "flutter", admission, testNow)
	if err != nil || job.Request.Flutter == nil || job.Request.Flutter.Version != "3.41.9" || job.Profile.Template.Flutter == nil || *job.Profile.Template.Flutter != pin {
		t.Fatalf("flutter job: %+v %v", job, err)
	}
	for name, edit := range map[string]func(*model.Admission){
		"version mismatch": func(a *model.Admission) { a.Request.Flutter = &model.FlutterRequest{Version: "3.41.8"} },
		"version missing":  func(a *model.Admission) { a.Request.Flutter = nil },
	} {
		mismatched := admission
		edit(&mismatched)
		_, _, err = s.Enqueue(ctx, "principal", name, mismatched, testNow)
		requireError(t, err, ErrInvalid)
	}
	request.Profile, request.Flutter = native.ID, nil
	plain, err := registry.Resolve(request)
	if err != nil {
		t.Fatal(err)
	}
	plain.Request.Flutter = &model.FlutterRequest{Version: "3.41.9"}
	_, _, err = s.Enqueue(ctx, "principal", "native-with-flutter", plain, testNow)
	requireError(t, err, ErrInvalid)
	profile := admissionFixture()
	profile.Request.Flutter = &model.FlutterRequest{Version: "3.41.9"}
	setDigest(&profile)
	_, _, err = s.Enqueue(ctx, "principal", "profile-with-flutter", profile, testNow)
	requireError(t, err, ErrInvalid)
}

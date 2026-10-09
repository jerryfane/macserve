package receipt

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/jerryfane/macserve/internal/model"
)

func TestSmallSuccessKeepsRecipeAndCommandsInPrivateManifest(t *testing.T) {
	options, job, result, expected := fixture(t, model.UnitTest)
	const private = "private-recipe-and-argv-marker"
	job.Profile.Run.Args = append(job.Profile.Run.Args, private)
	profile, err := json.Marshal(job.Profile)
	if err != nil {
		t.Fatal(err)
	}
	job.ProfileDigest = hashBytes(profile)
	expected.ProfileDigest = job.ProfileDigest
	result.Commands[0].Args = job.Profile.Run.Args
	signer, raw, core := sealFixture(t, options, job, result)
	if core.Details != nil || core.Manifest == nil || bytes.Contains(raw, []byte(private)) {
		t.Fatal("small public receipt exposed private execution details")
	}
	if err := ValidateSuccess(core, expected); err != nil {
		t.Fatal(err)
	}
	if _, err := PublicDigest(raw); err != nil {
		t.Fatal(err)
	}
	manifest, err := signer.Manifest(context.Background(), job.ID, core.Manifest.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest) >= MaxReceiptBytes || int64(len(manifest)) != core.Manifest.SizeBytes || hashBytes(manifest) != core.Manifest.SHA256 {
		t.Fatal("small manifest bytes do not match authenticated commitment")
	}
	var full Payload
	if err := strictDecode(manifest, &full); err != nil {
		t.Fatal(err)
	}
	if full.Details == nil {
		t.Fatal("private full manifest omitted execution details")
	}
	gotDetails, err := canonicalValue(full.Details)
	if err != nil {
		t.Fatal(err)
	}
	wantDetails, err := canonicalValue(Details{Profile: job.Profile, Result: result})
	if err != nil || !bytes.Equal(gotDetails, wantDetails) {
		t.Fatal("private full manifest changed recipe or execution records")
	}
	full.Details = nil
	full.Manifest = core.Manifest
	if !reflect.DeepEqual(full, core) {
		t.Fatal("public core changed full-manifest identities or evidence")
	}
	// The previous full-envelope format remains verifiable but is never public-safe.
	var legacy Payload
	if err := strictDecode(manifest, &legacy); err != nil {
		t.Fatal(err)
	}
	legacyRaw, err := signer.envelope(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PublicDigest(legacyRaw); err == nil {
		t.Fatal("legacy full receipt accepted for public publication")
	}
}

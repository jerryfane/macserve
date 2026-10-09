package qualification

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/jerryfane/macserve/internal/controller"
)

func TestReviewStrictJSONRejectsFoldedAliasesBeforeDecoding(t *testing.T) {
	for name, raw := range map[string]string{
		"report field":         `{"schema":1,"Schema":2}`,
		"nested success":       `{"results":[{"success":false,"Success":true}]}`,
		"nested long s":        `{"results":[{"success":false,"\u017fuccess":true}]}`,
		"escaped ASCII":        `{"results":[{"success":false,"\u0053uccess":true}]}`,
		"nested result arrays": `{"results":[],"RESULTS":[{"success":true}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			before := Report{Schema: 7, Role: "owner"}
			after := before
			if err := decode([]byte(raw), &after); err == nil {
				t.Fatal("ambiguous report accepted")
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatal("ambiguous report modified destination before rejection")
			}
		})
	}
}

func TestReviewStrictJSONUsesUnicodeSimpleFold(t *testing.T) {
	for name, raw := range map[string]string{
		"Kelvin sign":    `{"key":1,"\u212aey":2}`,
		"sigma variants": `{"nested":[{"\u03c3":1,"\u03c2":2}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			var value map[string]any
			if err := decode([]byte(raw), &value); err == nil {
				t.Fatal("Unicode simple-fold aliases accepted")
			}
		})
	}
	// Folding is scoped to each object and does not use full Unicode case
	// conversion: dotted/dotless i and multi-rune expansions remain distinct.
	raw := []byte(`{"i":1,"\u0130":2,"\u0131":3,"ss":4,"\u00df":5,"items":[{"key":1},{"KEY":2}]}`)
	var got map[string]any
	if err := decode(raw, &got); err != nil {
		t.Fatal(err)
	}
	var want map[string]any
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("unambiguous keys or values changed")
	}
}

func TestReviewPolicyConfigRejectsAliasesInsteadOfReorderingTheirMeaning(t *testing.T) {
	for name, raw := range map[string]string{
		"policy alias":              `{"policy_sha256":"old","Policy_SHA256":"other"}`,
		"policy Unicode alias":      `{"policy_sha256":"old","policy_\u017fha256":"other"}`,
		"noncanonical policy alone": `{"Policy_SHA256":"old","job_uid":502}`,
		"job UID alias":             `{"policy_sha256":"old","job_uid":502,"Job_UID":503}`,
		"socket Unicode alias":      `{"policy_sha256":"old","socket":"/service/a","soc\u212aet":"/service/b"}`,
		"nested controller alias":   `{"policy_sha256":"old","receipt":{"key_id":"a","Key_ID":"b"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			updated, err := policyConfig([]byte(raw), "new")
			if err == nil || updated != nil {
				t.Fatal("ambiguous or noncanonical policy input produced staged bytes")
			}
		})
	}
}

func TestReviewPolicyConfigPreservesControllerMeaningWithUniqueCaseVariants(t *testing.T) {
	raw := []byte(`{"policy_sha256":"old","Job_UID":502,"Owner_UID":501,"soc\u212aet":"/service/run/job.sock","Allowed_Networks":["192.0.2.0/24"],"Receipt":{"Key_ID":"reviewed"}}`)
	var before controller.Config
	if err := json.Unmarshal(raw, &before); err != nil {
		t.Fatal(err)
	}
	updated, err := policyConfig(raw, "new")
	if err != nil {
		t.Fatal(err)
	}
	var after controller.Config
	if err := json.Unmarshal(updated, &after); err != nil {
		t.Fatal(err)
	}
	before.PolicySHA256 = "new"
	if !reflect.DeepEqual(before, after) {
		t.Fatal("policy update reinterpreted an unrelated controller field")
	}
}

func TestReviewRootProbeRefusesBeforeSessionAndOutputAccess(t *testing.T) {
	for _, ids := range []struct {
		name      string
		uid, euid int
	}{
		{"real root", 0, 501},
		{"effective root", 501, 0},
		{"both root", 0, 0},
	} {
		t.Run(ids.name, func(t *testing.T) {
			dir := t.TempDir()
			session := filepath.Join(dir, "missing-session")
			existing := filepath.Join(dir, "existing")
			original := []byte("preserve output bytes")
			if err := os.WriteFile(existing, original, 0600); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(dir, "output-link")
			if err := os.Symlink(existing, link); err != nil {
				t.Fatal(err)
			}
			newOutput := filepath.Join(dir, "new-output")
			for _, out := range []string{newOutput, existing, link, filepath.Join(existing, "not-a-directory"), ""} {
				err := probe(context.Background(), session, "job", out, ids.uid, ids.euid)
				if !errors.Is(err, errRootProbe) {
					t.Fatalf("root refusal must precede missing session or output errors: %v", err)
				}
			}
			if _, err := os.Lstat(newOutput); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("root probe created refusal output: %v", err)
			}
			got, err := os.ReadFile(existing)
			if err != nil || string(got) != string(original) {
				t.Fatalf("root probe changed existing output: %q, %v", got, err)
			}
			if target, err := os.Readlink(link); err != nil || target != existing {
				t.Fatalf("root probe changed output symlink: %q, %v", target, err)
			}
		})
	}
}

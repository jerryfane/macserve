package receipt

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/model"
)

// withRetry is s with its first case passing on retry: a failed first
// attempt is recorded before it, as -retry-tests-on-failure records it.
func withRetry(t *testing.T, s evidence.Summary) evidence.Summary {
	t.Helper()
	first := s.Cases[0]
	if first.Outcome != "passed" || first.Attempt != 1 {
		t.Fatalf("fixture's first case %+v", first)
	}
	failed := first
	failed.Outcome, failed.Failures = "failed", []string{"flaky"}
	first.Attempt = 2
	s.Cases = append([]evidence.TestCase{failed, first}, s.Cases[1:]...)
	for i := range s.Cases[2:] {
		if s.Cases[i+2].ID == first.ID {
			t.Fatalf("fixture repeats %q", first.ID)
		}
	}
	if err := evidence.MarkRetries(s.Cases, 2); err != nil || !s.Cases[1].Retried || !s.Cases[0].Superseded {
		t.Fatalf("retry marks: %v %+v", err, s.Cases[:2])
	}
	s.Tests++
	s.Superseded++
	s.Retried++
	s.DurationSeconds += failed.DurationSeconds
	return s
}

func retryTemplate(template *model.Template) {
	if err := json.Unmarshal([]byte(`{"retry_failed_tests":{"iterations":2}}`), template); err != nil {
		panic(err)
	}
}

// A retry job's receipt records the retried tests, binds the template's
// opt-in, and validates only when the template enables retries.
func TestRetryReceiptValidates(t *testing.T) {
	_, _, _, plain := testTemplateFixture(t, model.SimulatorUITest)
	options, job, result, expected := testTemplateFixtureWith(t, model.SimulatorUITest, retryTemplate)
	if expected.ProfileDigest == plain.ProfileDigest {
		t.Fatal("retry_failed_tests left the template digest unchanged")
	}
	if job.Profile.RetryIterations() != 2 {
		t.Fatalf("snapshot retries %d", job.Profile.RetryIterations())
	}
	retried := withRetry(t, *result.Summary)
	result.Summary = &retried
	expected.RetryIterations = 2
	signer, _, p := sealFixture(t, options, job, result)
	full := fullPayload(t, signer, p)
	for form, payload := range map[string]Payload{"compact": p, "full": full} {
		if err := ValidateSuccess(payload, expected); err != nil {
			t.Fatalf("%s: %v", form, err)
		}
		tests := payload.Tests
		if tests.RetryIterations != 2 || tests.Retried != 1 || tests.Superseded != 1 || tests.Failed != 0 || !slices.Equal(tests.RetriedTests, []string{retried.Cases[1].ID}) {
			t.Fatalf("%s test evidence %+v", form, tests)
		}
	}
	unpinned := expected
	unpinned.RetryIterations = 0
	if err := ValidateSuccess(p, unpinned); !errors.Is(err, ErrInvalid) {
		t.Fatalf("retry receipt matched an expectation without retries: %v", err)
	}
}

// Validation recomputes the retry verdict from the recorded attempts: a pass
// on retry claimed without its failing attempt, on a case that failed every
// attempt, or by a job whose template does not enable retries is refused,
// even when the payload's test record is rebuilt to match the forgery.
func TestRetryReceiptRefusesForgedClaims(t *testing.T) {
	options, job, result, expected := testTemplateFixtureWith(t, model.SimulatorUITest, retryTemplate)
	retried := withRetry(t, *result.Summary)
	result.Summary = &retried
	expected.RetryIterations = 2
	signer, _, p := sealFixture(t, options, job, result)
	base := fullPayload(t, signer, p)
	if err := ValidateSuccess(base, expected); err != nil {
		t.Fatal(err)
	}
	forge := func(edit func(*evidence.Summary)) Payload {
		var f Payload
		raw, err := json.Marshal(base)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &f); err != nil {
			t.Fatal(err)
		}
		edit(f.Details.Result.Summary)
		f.Tests = testEvidence(f.Request.Kind, base.Tests.Required, base.Tests.RetryIterations, f.Details.Result.Summary)
		return f
	}
	for name, edit := range map[string]func(*evidence.Summary){
		"no failing attempt": func(s *evidence.Summary) {
			s.DurationSeconds -= s.Cases[0].DurationSeconds
			s.Cases = s.Cases[1:]
			s.Tests--
			s.Superseded--
		},
		"failing last attempt": func(s *evidence.Summary) {
			s.Cases[1].Outcome, s.Cases[1].Failures = "failed", []string{"still failing"}
			s.Passed--
			s.Superseded++
			s.Cases[1].Superseded = false
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := ValidateSuccess(forge(edit), expected)
			if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "test retries") {
				t.Fatalf("forged retry accepted: %v", err)
			}
		})
	}

	// The same attempts on a template without retries.
	options, job, result, expected = testTemplateFixture(t, model.SimulatorUITest)
	signer, _, p = sealFixture(t, options, job, result)
	plain := fullPayload(t, signer, p)
	plain.Details.Result.Summary = &retried
	plain.Tests = testEvidence(plain.Request.Kind, plain.Tests.Required, 0, &retried)
	if err := ValidateSuccess(plain, expected); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "test retries") {
		t.Fatalf("retry claim without the template field accepted: %v", err)
	}
	plain.Tests.RetryIterations = 2
	expected.RetryIterations = 2
	if err := ValidateSuccess(plain, expected); !errors.Is(err, ErrInvalid) {
		t.Fatalf("retry claim with a forged opt-in accepted: %v", err)
	}
}

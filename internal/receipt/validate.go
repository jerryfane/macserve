package receipt

import (
	"encoding/json"
	"fmt"
	"math"
	"path"
	"reflect"
	"slices"
	"strings"

	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/model"
)

func sameSimulator(a, b *model.Simulator) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}
func sameStrings(a, b []string) bool { return slices.Equal(a, b) }
func expectedFor(p Payload) Expected {
	return Expected{RepositoryID: p.Repository.ID, Repo: p.Request.Repo, SHA: p.Request.SHA, Profile: p.Request.Profile, ProfileDigest: p.ProfileDigest, Kind: p.Request.Kind, Xcode: p.Request.Xcode, Simulator: p.Request.Simulator, RequiredTests: p.Tests.Required}
}

// ValidateSuccess must only be called on the Payload returned by Verify. A
// signature authenticates evidence; it does not by itself establish success.
func ValidateSuccess(p Payload, e Expected) error {
	if e.RepositoryID <= 0 || e.Repo == "" || !validSHA(e.SHA) || e.Profile == "" || !validDigest(e.ProfileDigest) || e.Xcode.Version == "" || e.Xcode.Build == "" {
		return fmt.Errorf("%w: incomplete expected policy", ErrInvalid)
	}
	if p.Repository.ID != e.RepositoryID || p.Repository.Name != e.Repo || p.Request.Repo != e.Repo || p.Request.SHA != e.SHA || p.Source.Commit != e.SHA || p.Request.Profile != e.Profile || p.ProfileDigest != e.ProfileDigest || p.Request.Kind != e.Kind || p.Request.Xcode != e.Xcode || !sameSimulator(p.Request.Simulator, e.Simulator) || !sameStrings(p.Tests.Required, e.RequiredTests) {
		return fmt.Errorf("%w: expected policy mismatch", ErrInvalid)
	}
	if p.State != model.Succeeded || !p.Complete || len(p.Missing) != 0 {
		return fmt.Errorf("%w: evidence does not prove success", ErrInvalid)
	}
	if missing := incomplete(p); len(missing) != 0 {
		return fmt.Errorf("%w: %s", ErrInvalid, strings.Join(missing, "; "))
	}
	return nil
}

func incomplete(p Payload) []string {
	missing := []string{}
	require := func(ok bool, field string) {
		if !ok && !slices.Contains(missing, field) {
			missing = append(missing, field)
		}
	}
	require(p.Schema == 1 && validJobID(p.JobID) && p.AttemptID != "" && p.AttemptID == p.Approval.AttemptID && validDigest(p.InputDigest), "receipt identity")
	require(p.Service.ID != "" && p.Service.HostID != "" && p.Service.Version != "" && validDigest(p.Service.BinarySHA256), "service identity")
	require(p.Repository.ID > 0 && p.Repository.Name == p.Request.Repo && p.Request.Repo != "" && p.Approval.Intake != "" && p.Approval.Identity != "", "repository approval")
	request, requestErr := json.Marshal(p.Request)
	require(requestErr == nil && hashBytes(request) == p.RequestDigest, "request digest")
	require(validSHA(p.Request.SHA) && p.Source.Commit == p.Request.SHA && validSHA(p.Source.Tree) && validDigest(p.Source.SHA256) && p.Source.SizeBytes > 0, "source export")
	require(p.Request.Profile != "" && p.ProfileVersion > 0 && validDigest(p.ProfileDigest), "recipe identity")
	require(p.Request.Kind == model.Build || p.Request.Kind == model.UnitTest || p.Request.Kind == model.SimulatorUITest, "job kind")
	require(p.ExitCode != nil && *p.ExitCode == 0 && p.Signal == "", "successful exit")
	require(!p.CreatedAt.IsZero() && !p.StartedAt.IsZero() && !p.FinishedAt.IsZero() && !p.SealedAt.IsZero() && !p.StartedAt.Before(p.CreatedAt) && !p.FinishedAt.Before(p.StartedAt) && !p.SealedAt.Before(p.FinishedAt) && p.Deadline != nil && !p.Deadline.Before(p.StartedAt) && p.WorkerEpoch != "", "execution timing")
	// Final evidence extraction and cleanup may finish after the execution deadline.
	require(p.Resources.TimeoutSeconds > 0 && p.Resources.TimeoutSeconds == p.Request.TimeoutSeconds && p.Resources.MemoryLimitMiB > 0 && p.Resources.PeakMemoryMiB >= 0 && p.Resources.CleanupRequired && p.Resources.CleanupOK, "resource and cleanup policy")
	o := p.Observation
	require(p.Request.Xcode.Version != "" && p.Request.Xcode.Build != "" && o.Xcode == p.Request.Xcode && o.SDKVersion != "" && o.SDKBuild != "" && o.SwiftVersion != "" && o.OSVersion != "" && o.OSBuild != "" && o.Architecture == "arm64", "toolchain observation")
	if sim := p.Request.Simulator; sim != nil {
		identifier := sim.Runtime[strings.LastIndex(sim.Runtime, ".")+1:]
		_, version, _ := strings.Cut(identifier, "-")
		require(sim.Runtime != "" && sim.RuntimeBuild != "" && sim.DeviceType != "" && o.RuntimeBuild == sim.RuntimeBuild && o.RuntimeVersion == strings.ReplaceAll(version, "-", ".") && o.DeviceUDID != "", "simulator observation")
	} else {
		require(p.Request.Kind != model.SimulatorUITest, "simulator pin")
	}
	require(!p.LogsTruncated && validLogs(p.Logs), "raw logs")
	require(p.CommandCount > 0 && p.ArtifactCount >= len(p.Logs) && validDigest(p.Digests.Commands) && validDigest(p.Digests.Artifacts) && validDigest(p.Digests.Generated) && validDigest(p.Digests.Lockfiles) && validDigest(p.Digests.TestCases), "evidence digests")
	t := p.Tests
	if p.Request.Kind == model.Build {
		require(t.Status == "tests_not_run" && t.Tests == 0 && t.Passed == 0 && t.Failed == 0 && t.Skipped == 0 && t.ExpectedFailures == 0 && len(t.Required) == 0 && len(t.ExecutedRequired) == 0, "build-only test scope")
	} else {
		require(t.Status == "parsed" && t.ParserVersion == "xcresult-tests-0.4.0" && t.Tests > 0 && t.Passed >= 0 && t.Failed == 0 && t.Skipped >= 0 && t.ExpectedFailures >= 0 && t.Passed+t.ExpectedFailures > 0 && t.Tests == t.Passed+t.Failed+t.Skipped+t.ExpectedFailures && validDigest(t.XCResultSHA256) && sameStrings(t.Required, t.ExecutedRequired), "parsed tests and required scope")
		seen := map[string]bool{}
		for _, name := range t.Required {
			require(name != "" && !seen[name], "required test identity")
			seen[name] = true
		}
	}
	require((p.Details == nil) != (p.Manifest == nil), "full or compact evidence")
	if p.Manifest != nil {
		require(validDigest(p.Manifest.SHA256) && p.Manifest.SizeBytes > 0 && p.Manifest.SizeBytes <= maxManifestBytes && p.Manifest.URL == manifestURL(p.JobID, p.Manifest.SHA256), "full manifest reference")
	}
	if p.Details != nil {
		validateDetails(p, require)
	}
	return missing
}

func validArtifact(a evidence.Artifact) bool {
	return a.ID != "" && a.Name != "" && path.IsAbs(a.Name) == false && path.Clean(a.Name) == a.Name && a.Name != "." && a.Name != ".." && !strings.HasPrefix(a.Name, "../") && a.SizeBytes >= 0 && validDigest(a.SHA256) && a.MediaType != "" && !a.ExpiresAt.IsZero()
}
func validLogs(logs []evidence.Artifact) bool {
	if len(logs) != 2 {
		return false
	}
	found := map[string]bool{}
	for _, a := range logs {
		if !validArtifact(a) || found[a.Name] {
			return false
		}
		found[a.Name] = true
	}
	return found["evidence/stdout.log"] && found["evidence/stderr.log"]
}
func requiredExecuted(c evidence.TestCase, name string) bool {
	return !c.Container && (c.Outcome == "passed" || c.Outcome == "expected-failure") && (c.ID == name || c.Name == name || c.Suite == name || strings.HasPrefix(c.ID, name+"/") || strings.HasPrefix(c.Suite, name+"/"))
}
func testEvidence(kind model.Kind, required []string, s *evidence.Summary) TestEvidence {
	t := TestEvidence{Status: "missing", Required: append([]string(nil), required...)}
	if kind == model.Build {
		t.Status = "tests_not_run"
		return t
	}
	if s == nil {
		return t
	}
	t.Status = s.ParseStatus
	t.ParserVersion = s.ParserVersion
	t.Tests = s.Tests
	t.Passed = s.Passed
	t.Failed = s.Failed
	t.Skipped = s.Skipped
	t.ExpectedFailures = s.ExpectedFailures
	t.XCResultSHA256 = s.XCResultSHA256
	for _, name := range required {
		for _, c := range s.Cases {
			if name != "" && requiredExecuted(c, name) {
				t.ExecutedRequired = append(t.ExecutedRequired, name)
				break
			}
		}
	}
	return t
}
func validateDetails(p Payload, require func(bool, string)) {
	d := p.Details
	r := d.Result
	profile := d.Profile
	raw, err := json.Marshal(profile)
	require(err == nil && hashBytes(raw) == p.ProfileDigest && profile.ID == p.Request.Profile && profile.Version == p.ProfileVersion && profile.Repo == p.Request.Repo && profile.Kind == p.Request.Kind && profile.Xcode == p.Request.Xcode && sameSimulator(profile.Simulator, p.Request.Simulator) && sameStrings(profile.RequiredTests, p.Tests.Required) && profile.MemoryLimitMiB == p.Resources.MemoryLimitMiB, "recipe manifest")
	require(r.State == p.State && r.Source == p.Source && r.StartedAt.Equal(p.StartedAt) && r.FinishedAt.Equal(p.FinishedAt) && r.CleanupOK == p.Resources.CleanupOK && reflect.DeepEqual(r.ExitCode, p.ExitCode) && r.Signal == p.Signal && r.Reason == p.Reason && r.LogsTruncated == p.LogsTruncated && r.PeakMemoryMiB == p.Resources.PeakMemoryMiB && observed(r.Observation) == p.Observation, "execution manifest")
	require(len(r.Commands) == p.CommandCount && len(r.Artifacts) == p.ArtifactCount, "manifest counts")
	for _, item := range []struct {
		value  any
		digest string
	}{{r.Commands, p.Digests.Commands}, {r.Artifacts, p.Digests.Artifacts}, {manifestMap(r.Observation.GeneratedDigests), p.Digests.Generated}, {manifestMap(r.Observation.LockfileDigests), p.Digests.Lockfiles}, {cases(r.Summary), p.Digests.TestCases}} {
		digest, err := valueDigest(item.value)
		require(err == nil && digest == item.digest, "manifest digest")
	}
	ran := false
	for _, c := range r.Commands {
		require(c.Executable != "" && !c.StartedAt.IsZero() && !c.FinishedAt.Before(c.StartedAt) && !c.StartedAt.Before(p.StartedAt) && !c.FinishedAt.After(p.FinishedAt), "command record")
		if c.Executable == profile.Run.Executable && c.ExitCode == 0 && c.Signal == "" {
			ran = true
		}
	}
	require(ran, "executed recipe")
	names := map[string]evidence.Artifact{}
	ids := map[string]bool{}
	for _, a := range r.Artifacts {
		_, exists := names[a.Name]
		require(validArtifact(a) && !exists && !ids[a.ID], "artifact manifest")
		names[a.Name] = a
		ids[a.ID] = true
	}
	for _, log := range p.Logs {
		require(names[log.Name] == log, "log manifest")
	}
	for _, rule := range profile.Artifacts {
		if !rule.Required {
			continue
		}
		found := false
		for name := range names {
			match, _ := path.Match(rule.Path, name)
			directory, _ := path.Match(rule.Path, strings.TrimSuffix(name, ".tar.gz"))
			found = found || match || directory
		}
		require(found, "required artifact")
	}
	require(len(r.Observation.GeneratedDigests) == len(profile.GeneratedFiles), "generated file count")
	for _, f := range profile.GeneratedFiles {
		require(r.Observation.GeneratedDigests[f.Path] == hashBytes([]byte(f.Content)), "generated file digest")
	}
	for name, digest := range r.Observation.LockfileDigests {
		require(name != "" && validDigest(digest), "lockfile digest")
	}
	require(reflect.DeepEqual(testEvidence(p.Request.Kind, profile.RequiredTests, r.Summary), p.Tests), "test predicate")
	if p.Request.Kind == model.Build {
		require(r.Summary == nil, "build tests not run")
		return
	}
	s := r.Summary
	if s == nil {
		require(false, "test summary")
		return
	}
	archive, found := names["results.xcresult.tar.gz"]
	_, testsFound := names["evidence/tests.json"]
	require(found && testsFound && archive.SHA256 == s.XCResultSHA256, "test artifacts")
	require(s.SchemaVersion == 1 && sameStrings(s.RequiredTests, profile.RequiredTests) && len(s.Cases) == s.Tests, "test schema")
	passed, failed, skipped, expected := 0, 0, 0, 0
	duration := 0.0
	attempts := map[string]int{}
	for _, c := range s.Cases {
		require(c.ID != "" && c.Name != "" && c.Attempt > 0 && c.DurationSeconds >= 0 && !math.IsNaN(c.DurationSeconds) && !math.IsInf(c.DurationSeconds, 0), "test case")
		require(!c.Container, "aggregate test diagnostic")
		attempts[c.ID]++
		require(c.Attempt == attempts[c.ID], "test attempt")
		duration += c.DurationSeconds
		switch c.Outcome {
		case "passed":
			passed++
			require(len(c.Failures) == 0, "passing test failures")
		case "failed":
			failed++
		case "skipped":
			skipped++
		case "expected-failure":
			expected++
		default:
			require(false, "test outcome")
		}
	}
	require(passed == s.Passed && failed == s.Failed && skipped == s.Skipped && expected == s.ExpectedFailures && duration == s.DurationSeconds, "test counts")
}
func cases(s *evidence.Summary) []evidence.TestCase {
	if s == nil {
		return nil
	}
	return s.Cases
}

// Empty omitempty maps disappear in the full JSON manifest. Commit to the
// same absence before and after serialization rather than to Go allocation.
func manifestMap(value map[string]string) map[string]string {
	if len(value) == 0 {
		return nil
	}
	return value
}

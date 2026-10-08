package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path"
	"strings"
	"time"

	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/store"
	"github.com/jerryfane/macserve/internal/worker"
)

func completionDigest(result worker.Result) (string, error) {
	bytes, err := json.Marshal(result)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(bytes)
	return hex.EncodeToString(digest[:]), nil
}

func (c *Controller) complete(ctx context.Context, job model.Job, result worker.Result) error {
	if result.State != model.Succeeded && result.State != model.Failed && result.State != model.Cancelled && result.State != model.TimedOut || len(result.Reason) > 4096 {
		return store.ErrInvalid
	}
	digest, err := completionDigest(result)
	if err != nil {
		return err
	}
	c.evidenceMu.Lock()
	defer c.evidenceMu.Unlock()
	job, err = c.options.Store.Get(ctx, job.ID)
	if err != nil {
		return err
	}
	if job.State.Terminal() {
		if len(job.Result) == 0 {
			return store.ErrLease
		}
		var prior Completion
		if err := json.Unmarshal(job.Result, &prior); err != nil {
			return err
		}
		if prior.InputDigest != digest {
			return store.ErrConflict
		}
		return nil
	}
	c.mu.Lock()
	if c.active == nil || c.active.job.ID != job.ID || !c.active.offered {
		c.mu.Unlock()
		return store.ErrLease
	}
	source := c.active.source.Source
	c.mu.Unlock()
	normalized, err := c.verifyResult(ctx, job, result, source)
	if err != nil {
		return err
	}
	// Source bytes are controller-only and no longer needed once all evidence is
	// copied. Failure to reclaim them cannot silently unlock more disk-consuming work.
	if err := c.options.Source.Remove(job.ID); err != nil {
		normalized.CleanupOK = false
		normalized.State = model.Failed
		normalized.Reason = "controller source cleanup failed"
	}
	for range 2 {
		c.mu.Lock()
		current, err := c.options.Store.Get(ctx, job.ID)
		if err == nil && current.State.Terminal() {
			err = store.ErrLease
		}
		if err == nil && current.State != model.Finalizing {
			err = c.options.Store.Transition(ctx, job.ID, job.LeaseToken, current.State, model.Finalizing, "", c.options.Now())
		}
		c.mu.Unlock()
		if err != nil {
			return err
		}
		normalizeCancellation(&normalized, current, c.options.Now())
		completion := Completion{InputDigest: digest, Result: normalized}
		if c.options.Seal != nil {
			receipt, err := c.options.Seal(ctx, current, normalized)
			if err != nil {
				return err
			}
			if len(receipt) > 0 && !json.Valid(receipt) {
				return errors.New("seal returned invalid receipt JSON")
			}
			completion.Receipt = receipt
		}
		encoded, err := json.Marshal(completion)
		if err != nil {
			return err
		}
		c.mu.Lock()
		err = c.options.Store.Finish(ctx, job.ID, job.LeaseToken, normalized.State, encoded, normalized.CleanupOK, normalized.Reason, c.options.Now())
		if err == nil && c.active != nil && c.active.job.ID == job.ID {
			c.active.cancel()
			c.active = nil
			c.workerIdle = false
			if !normalized.CleanupOK {
				c.epoch = ""
			}
		}
		c.mu.Unlock()
		if err == nil {
			return nil
		}
		// The API may persist cancellation while the seal hook is running. Store's
		// transactional predicate wins; never retain a success receipt in that race.
		if !errors.Is(err, store.ErrTransition) || normalized.State != model.Succeeded {
			return err
		}
	}
	return store.ErrTransition
}

func normalizeCancellation(result *worker.Result, job model.Job, now time.Time) {
	if !result.CleanupOK {
		result.State = model.Failed
		if result.Reason == "" {
			result.Reason = "worker cleanup was not confirmed"
		}
		return
	}
	if job.Deadline != nil && !now.Before(*job.Deadline) {
		result.State = model.TimedOut
		result.Reason = "job deadline exceeded"
	} else if job.CancelRequested {
		result.State = model.Cancelled
		result.Reason = "cancellation requested"
	}
}

func (c *Controller) verifyResult(ctx context.Context, job model.Job, result worker.Result, source worker.Source) (worker.Result, error) {
	suppliedSuccess := result.State == model.Succeeded
	result.Summary = nil
	var problems []string
	reject := func(reason string) { problems = append(problems, reason) }
	if result.Source != source || result.Source.Commit != job.Request.SHA {
		reject("source descriptor mismatch")
	}
	if result.StartedAt.IsZero() || result.FinishedAt.IsZero() || result.FinishedAt.Before(result.StartedAt) || result.StartedAt.Before(*job.StartedAt) || result.FinishedAt.After(c.options.Now().Add(time.Minute)) {
		reject("invalid execution timestamps")
	}
	manifest, err := c.uploaded(job.ID)
	if err != nil {
		return result, err
	}
	uploadedByName := make(map[string]evidence.Artifact, len(manifest))
	for _, artifact := range manifest {
		uploadedByName[artifact.Name] = artifact
	}
	if len(result.Artifacts) > maxArtifacts {
		return result, evidence.ErrArtifactLimit
	}
	names := make(map[string]evidence.Artifact, len(result.Artifacts))
	var total int64
	verified := make([]evidence.Artifact, 0, len(result.Artifacts))
	for _, artifact := range result.Artifacts {
		if !validArtifact(artifact) {
			reject("invalid artifact manifest")
			continue
		}
		if _, exists := names[artifact.Name]; exists {
			reject("duplicate artifact name")
			continue
		}
		total += artifact.SizeBytes
		if total > maxArtifactBytes {
			return result, evidence.ErrArtifactLimit
		}
		if uploaded, found := uploadedByName[artifact.Name]; !found || uploaded != artifact {
			reject("artifact not uploaded")
			continue
		}
		file, err := c.openArtifact(job.ID, artifact.ID)
		if err != nil {
			reject("artifact bytes unavailable")
			continue
		}
		err = verifyBytes(file, artifact.SizeBytes, artifact.SHA256)
		file.Close()
		if err != nil {
			reject("artifact bytes do not match manifest")
			continue
		}
		names[artifact.Name] = artifact
		verified = append(verified, artifactExpiry(artifact, c.options.Now()))
	}
	result.Artifacts = verified
	truncated, err := c.options.Store.LogsTruncated(ctx, job.ID)
	if err != nil {
		return result, err
	}
	result.LogsTruncated = result.LogsTruncated || truncated
	if result.LogsTruncated {
		reject("log evidence truncated")
	}
	if job.Request.Kind != model.Build {
		tests, hasTests := names["evidence/tests.json"]
		archive, hasArchive := names["results.xcresult.tar.gz"]
		if !hasTests || !hasArchive {
			reject("test evidence missing")
		} else if tests.SizeBytes > 32<<20 {
			reject("test JSON exceeds parser limit")
		} else {
			file, err := c.openArtifact(job.ID, tests.ID)
			if err != nil {
				return result, err
			}
			raw, readErr := io.ReadAll(io.LimitReader(file, (32<<20)+1))
			file.Close()
			summary, parseErr := evidence.ParseTests(raw, job.Profile.RequiredTests)
			summary.XCResultSHA256 = archive.SHA256
			result.Summary = &summary
			if readErr != nil || parseErr != nil || summary.ParseStatus != "parsed" || summary.Tests == 0 || summary.Failed != 0 {
				reject("test evidence did not prove success")
			}
		}
	}
	if suppliedSuccess {
		if result.ExitCode == nil || *result.ExitCode != 0 || result.Signal != "" || !result.CleanupOK {
			reject("exit status or cleanup did not prove success")
		}
		if err := verifyObservation(job, result.Observation); err != nil {
			reject(err.Error())
		}
		for _, name := range []string{"evidence/stdout.log", "evidence/stderr.log"} {
			if _, ok := names[name]; !ok {
				reject("raw log evidence missing")
			}
		}
		for _, rule := range job.Profile.Artifacts {
			if !rule.Required {
				continue
			}
			found := false
			for name := range names {
				match, _ := path.Match(rule.Path, name)
				directoryMatch, _ := path.Match(rule.Path, strings.TrimSuffix(name, ".tar.gz"))
				if match || directoryMatch {
					found = true
					break
				}
			}
			if !found {
				reject("required profile artifact missing")
			}
		}
	}
	if !result.CleanupOK {
		result.State = model.Failed
		result.Reason = "worker cleanup was not confirmed"
	} else if suppliedSuccess && len(problems) > 0 {
		result.State = model.Failed
		result.Reason = strings.Join(problems, "; ")
		if len(result.Reason) > 4096 {
			result.Reason = result.Reason[:4096]
		}
	}
	return result, nil
}

func verifyObservation(job model.Job, o worker.Observation) error {
	if o.Xcode != job.Profile.Xcode || o.Architecture != "arm64" || o.SDKVersion == "" || o.SDKBuild == "" || o.SwiftVersion == "" || o.OSVersion == "" || o.OSBuild == "" {
		return errors.New("toolchain observation does not match approved pins")
	}
	if simulator := job.Profile.Simulator; simulator != nil {
		identifier := simulator.Runtime[strings.LastIndex(simulator.Runtime, ".")+1:]
		_, version, _ := strings.Cut(identifier, "-")
		if o.RuntimeBuild != simulator.RuntimeBuild || o.RuntimeVersion != strings.ReplaceAll(version, "-", ".") || o.DeviceUDID == "" {
			return errors.New("simulator observation does not match approved pins")
		}
	}
	if len(o.GeneratedDigests) != len(job.Profile.GeneratedFiles) {
		return errors.New("generated file digest manifest mismatch")
	}
	for _, generated := range job.Profile.GeneratedFiles {
		digest := sha256.Sum256([]byte(generated.Content))
		if o.GeneratedDigests[generated.Path] != hex.EncodeToString(digest[:]) {
			return errors.New("generated file digest mismatch")
		}
	}
	return nil
}

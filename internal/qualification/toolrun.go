package qualification

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"time"

	"github.com/jerryfane/macserve/internal/hostguard"
	"github.com/jerryfane/macserve/internal/maintenance"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/worker"
	"github.com/jerryfane/macserve/internal/workerclient"
)

// Tool evidence (v0.1.13) replaces the owner-attested tool_profiles artifact.
// Root runs every enabled profile's real recipe through the production worker
// engine (admission, workspace, launchctl asuser + _job-exec, taskpolicy,
// cleanup, quarantine) on root-protected source archives pinned by hash. The
// only input is the session ID; the binary, recipes, sources and credential
// are all root-protected and bound to the challenge.

const (
	sourcesPinsPath  = "/Library/macserve/config/qualification-sources.json"
	sourcesDir       = "/Library/macserve/qualification-sources"
	toolEvidenceFile = "tool-evidence.json"
	toolReserve      = 15 * time.Minute
)

var (
	sha40 = regexp.MustCompile(`^[0-9a-f]{40}$`)
	sha64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type SourcePins struct {
	Schema  int         `json:"schema"`
	Sources []SourcePin `json:"sources"`
}

// SourcePin pins one profile's source: a git archive stored root-owned at
// sourcesDir/<sha256>.tar.
type SourcePin struct {
	Profile   string `json:"profile"`
	Commit    string `json:"commit"`
	Tree      string `json:"tree"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

type ToolRun struct {
	Profile       string        `json:"profile"`
	ProfileDigest string        `json:"profile_digest"`
	Result        worker.Result `json:"result"`
	Error         string        `json:"error,omitempty"`
}

type ToolEvidence struct {
	Schema          int       `json:"schema"`
	Session         string    `json:"session"`
	ChallengeSHA256 string    `json:"challenge_sha256"`
	SourcesSHA256   string    `json:"sources_sha256"`
	Started         time.Time `json:"started"`
	Finished        time.Time `json:"finished"`
	Runs            []ToolRun `json:"runs"`
}

// loadSourcePins reads the protected pins and requires one pin per profile.
func loadSourcePins(list []model.Profile) (SourcePins, string, error) {
	var pins SourcePins
	b, err := protectedRead(sourcesPinsPath)
	if err != nil {
		return pins, "", err
	}
	if err = decode(b, &pins); err != nil {
		return pins, "", err
	}
	if pins.Schema != 1 {
		return pins, "", errors.New("unsupported qualification source pins")
	}
	for _, p := range list {
		pin, ok := sourcePin(pins, p.ID)
		if !ok || !sha40.MatchString(pin.Commit) || !sha40.MatchString(pin.Tree) || !sha64.MatchString(pin.SHA256) || pin.SizeBytes <= 0 {
			return pins, "", fmt.Errorf("qualification source pin missing or invalid for profile %s", p.ID)
		}
	}
	return pins, digest(b), nil
}

func sourcePin(pins SourcePins, profile string) (SourcePin, bool) {
	for _, pin := range pins.Sources {
		if pin.Profile == profile {
			return pin, true
		}
	}
	return SourcePin{}, false
}

type discardSink struct{}

func (discardSink) Log(string, string) error { return nil }
func (discardSink) Stage(model.State) error  { return nil }

// RunToolEvidence is root-only; its only input is the session ID. The broker
// must be stopped (exclusive worker lock). One run per session.
func RunToolEvidence(ctx context.Context, id string) error {
	if err := rootOnly(); err != nil {
		return err
	}
	dir, err := SessionDirectory(id)
	if err != nil {
		return err
	}
	_, envRaw, err := installedDeployment()
	if err != nil {
		return err
	}
	unlock, err := sessionLock(dir)
	if err != nil {
		return err
	}
	defer unlock()
	c, raw, err := loadChallenge(dir)
	if err != nil {
		return err
	}
	if err = fresh(c, time.Now().UTC()); err != nil {
		return err
	}
	if c.EnvironmentSHA256 != digest(envRaw) {
		return errors.New("installed deployment environment differs from the session challenge")
	}
	if _, err := os.Lstat(filepath.Join(dir, "candidate.json")); !errors.Is(err, os.ErrNotExist) {
		return errors.New("session already collected; begin a new session")
	}
	if len(c.Profiles) == 0 {
		return errors.New("no enabled profiles: tool evidence is not applicable")
	}
	pins, pinsDigest, err := loadSourcePins(c.Profiles)
	if err != nil {
		return err
	}
	if c.SourcesSHA256 == "" || pinsDigest != c.SourcesSHA256 {
		return errors.New("qualification source pins differ from the session challenge")
	}
	mc, err := maintenance.LoadConfig(maintenancePath)
	if err != nil {
		return err
	}
	if err = hostguard.Worker(mc.WorkerConfig); err != nil {
		return err
	}
	wc, err := workerclient.LoadConfig(mc.WorkerConfig)
	if err != nil {
		return err
	}
	engine, err := worker.New(wc.EngineOptions())
	if err != nil {
		return fmt.Errorf("stop the broker before tool evidence: %w", err)
	}
	defer engine.Close()
	if err = engine.Recover(ctx); err != nil {
		return err
	}
	evidence := ToolEvidence{Schema: schema, Session: id, ChallengeSHA256: digest(raw), SourcesSHA256: pinsDigest, Started: time.Now().UTC()}
	if err = saveJSON(filepath.Join(dir, "tool-evidence-attempt.json"), evidence, 0600); err != nil {
		return fmt.Errorf("one tool evidence run per session; begin a new session: %w", err)
	}
	list := slices.Clone(c.Profiles)
	slices.SortFunc(list, func(a, b model.Profile) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	var failures []error
	for i, p := range list {
		pin, _ := sourcePin(pins, p.ID)
		run, err := runProfile(ctx, engine, c, p, pin, i)
		if err != nil {
			run.Error = err.Error()
			failures = append(failures, fmt.Errorf("%s: %w", p.ID, err))
		} else if run.Result.State != model.Succeeded {
			failures = append(failures, fmt.Errorf("%s: %s %s", p.ID, run.Result.State, run.Result.Reason))
		}
		evidence.Runs = append(evidence.Runs, run)
	}
	evidence.Finished = time.Now().UTC()
	return errors.Join(append(failures, saveJSON(filepath.Join(dir, toolEvidenceFile), evidence, 0600))...)
}

func runProfile(ctx context.Context, engine *worker.Engine, c Challenge, p model.Profile, pin SourcePin, index int) (ToolRun, error) {
	run := ToolRun{Profile: p.ID}
	deadline := c.Expires.Add(-toolReserve)
	remaining := time.Until(deadline)
	if remaining < 5*time.Minute {
		return run, errors.New("not enough challenge lifetime left for a recipe run; begin a new session")
	}
	timeout := min(time.Duration(p.DefaultTimeoutSeconds)*time.Second, remaining)
	registry, err := profiles.New([]model.Profile{p})
	if err != nil {
		return run, err
	}
	admission, err := registry.Resolve(model.Request{Repo: p.Repo, SHA: pin.Commit, Kind: p.Kind, Profile: p.ID, Xcode: p.Xcode, Simulator: p.Simulator, TimeoutSeconds: int(timeout / time.Second)})
	if err != nil {
		return run, err
	}
	run.ProfileDigest = admission.ProfileDigest
	if admission.ProfileDigest != c.Observation.Profiles[p.ID] {
		return run, errors.New("profile digest differs from the session observation")
	}
	request, err := json.Marshal(admission.Request)
	if err != nil {
		return run, err
	}
	requestDigest := sha256.Sum256(request)
	token := make([]byte, 16)
	if _, err = rand.Read(token); err != nil {
		return run, err
	}
	now := time.Now().UTC()
	job := model.Job{ID: fmt.Sprintf("qualify-%s-%d", c.ID[:16], index), Principal: "qualification", Request: admission.Request, Profile: admission.Profile, ProfileDigest: admission.ProfileDigest, RequestDigest: hex.EncodeToString(requestDigest[:]), State: model.Preparing, CreatedAt: now, UpdatedAt: now, Deadline: &deadline, WorkerEpoch: "qualify-" + c.ID[:16], LeaseToken: hex.EncodeToString(token)}
	archive := filepath.Join(sourcesDir, pin.SHA256+".tar")
	if err = hostguard.RootConfig(archive); err != nil {
		return run, err
	}
	f, err := os.Open(archive)
	if err != nil {
		return run, err
	}
	defer f.Close()
	result, err := engine.Execute(ctx, job, worker.Source{Commit: pin.Commit, Tree: pin.Tree, SHA256: pin.SHA256, SizeBytes: pin.SizeBytes}, f, discardSink{})
	run.Result = result
	return run, errors.Join(err, engine.RemoveExport(job.ID))
}

// toolEvidencePasses checks the root-written evidence for every profile.
func toolEvidencePasses(dir string, c Challenge, raw []byte) ([]byte, bool, string) {
	b, err := protectedRead(filepath.Join(dir, toolEvidenceFile))
	if err != nil {
		return nil, false, "root tool evidence missing: run the tool evidence verb before collect"
	}
	var t ToolEvidence
	if err = decode(b, &t); err != nil {
		return b, false, "tool evidence is not a valid document"
	}
	if t.Schema != schema || t.Session != filepath.Base(dir) || t.ChallengeSHA256 != digest(raw) || t.SourcesSHA256 != c.SourcesSHA256 || t.Started.Before(c.Created) || t.Finished.Before(t.Started) || t.Finished.After(c.Expires) || len(t.Runs) != len(c.Profiles) {
		return b, false, "tool evidence does not bind this session"
	}
	for _, p := range c.Profiles {
		ok := false
		for _, run := range t.Runs {
			if run.Profile == p.ID && run.Error == "" && run.ProfileDigest == c.Observation.Profiles[p.ID] && run.Result.State == model.Succeeded && run.Result.CleanupOK && run.Result.Observation.Xcode == p.Xcode {
				ok = true
			}
		}
		if !ok {
			return b, false, "recipe run failed or missing for profile " + p.ID
		}
	}
	return b, true, "root-run production recipes succeeded for every enabled profile on pinned sources"
}

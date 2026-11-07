package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jerryfane/macserve/internal/controllerconfig"
	"github.com/jerryfane/macserve/internal/controllerk/controller"
	"github.com/jerryfane/macserve/internal/controllerk/githubpull"
	"github.com/jerryfane/macserve/internal/controllerk/store"
	"github.com/jerryfane/macserve/internal/githubapi"
	"github.com/jerryfane/macserve/internal/keyholder"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/receipt"
	"github.com/jerryfane/macserve/internal/worker"
)

type integrations struct {
	keyholder *keyholder.Client
	app       *githubapi.Client
	poller    *githubpull.Poller
	db        *store.Store
}

// newIntegrations connects the controller to the keyholder, which holds the
// receipt and GitHub App keys: the controller never opens either key file.
// Its GitHub client is brokered (installation tokens minted per repository
// by the keyholder), and every receipt is signed by the keyholder after it
// verifies the root worker's build seal.
func newIntegrations(ctx context.Context, config controllerconfig.Config, db *store.Store, registry *profiles.Registry) (*integrations, error) {
	if err := db.InitializeGitHub(ctx); err != nil {
		return nil, err
	}
	for _, profile := range registry.List() {
		if config.Receipt.Repositories[profile.Repo] <= 0 {
			return nil, errors.New("every profile requires a pinned numeric repository ID")
		}
	}
	for _, template := range registry.Templates() {
		for _, owner := range template.Owners {
			if !slices.Contains(config.Receipt.Owners, owner) {
				return nil, errors.New("every template owner requires a receipt owners entry")
			}
		}
	}
	if config.Keyholder == nil {
		return nil, errors.New("controller configuration lacks the keyholder section")
	}
	keys, err := receipt.ParsePublicKeys(config.Receipt.VerificationKeys)
	if err != nil {
		return nil, err
	}
	if _, ok := keys[config.Receipt.KeyID]; !ok {
		return nil, errors.New("receipt key ID has no pinned verification key")
	}
	service := &integrations{db: db, keyholder: &keyholder.Client{Socket: config.Keyholder.Socket, KeyholderUID: config.Keyholder.UID}}
	if cfg := config.GitHub; cfg != nil {
		service.app, err = githubapi.NewBrokered(githubapi.BrokeredOptions{AppID: cfg.AppID, Tokens: service.keyholder.Token, Repositories: config.Receipt.Repositories, Owners: config.Receipt.Owners})
		if err != nil {
			return nil, err
		}
		service.poller, err = githubpull.New(githubpull.Options{Store: db, Profiles: registry, Client: service.app, Policies: cfg.Policies, PollInterval: time.Duration(cfg.PollSeconds) * time.Second,
			VerifyReceipt: func(job model.Job, raw json.RawMessage) error {
				payload, err := receipt.Verify(raw, keys)
				if err != nil {
					return err
				}
				expected, err := receiptExpectation(config.Receipt.Repositories, job)
				if err != nil {
					return err
				}
				return receipt.ValidateSuccess(payload, expected)
			},
		})
		if err != nil {
			return nil, err
		}
	}
	return service, nil
}

// approval is the job's admission approval the receipt states: its GitHub
// intake approval, or the private API principal.
func (s *integrations) approval(ctx context.Context, job model.Job) (receipt.Approval, error) {
	_, err := s.db.GitHubByJob(ctx, job.ID)
	if err == nil {
		if s.poller == nil {
			return receipt.Approval{}, errors.New("GitHub admission policy is unavailable")
		}
		return s.poller.Approval(ctx, job)
	}
	if !errors.Is(err, store.ErrNotFound) || strings.HasPrefix(job.Principal, "github:") {
		return receipt.Approval{}, errors.New("job admission provenance is unavailable")
	}
	return receipt.Approval{Intake: "private_api", Identity: job.Principal, AttemptID: job.ID}, nil
}

// seal asks the keyholder for the job's receipt.
func (s *integrations) seal(ctx context.Context, job model.Job, result worker.Result, sealing controller.Sealing) (json.RawMessage, error) {
	approval, err := s.approval(ctx, job)
	if err != nil {
		return nil, err
	}
	raw, err := s.keyholder.Seal(ctx, keyholder.SealRequest{Job: job, Worker: sealing.Worker, Result: result, Seal: sealing.Seal, Approval: approval})
	return raw, receiptError(err)
}

// receiptError marks the keyholder's reasoned refusal as definitive, so
// completion records an unsuccessful result instead of retrying; transport
// and other failures stay retryable.
func receiptError(err error) error {
	var refused *keyholder.RefusalError
	if errors.As(err, &refused) {
		return fmt.Errorf("%w: %s", controller.ErrReceiptRefused, refused.Reason)
	}
	return err
}

func (s *integrations) beforeDispatch(ctx context.Context, job model.Job) error {
	_, err := s.db.GitHubByJob(ctx, job.ID)
	if errors.Is(err, store.ErrNotFound) && !strings.HasPrefix(job.Principal, "github:") {
		return nil
	}
	if err != nil {
		return err
	}
	if s.poller == nil {
		return errors.New("GitHub dispatch policy is unavailable")
	}
	return s.poller.BeforeDispatch(ctx, job)
}

func (s *integrations) pruneReceipts(ctx context.Context) error {
	return s.keyholder.Prune(ctx, func(id string) (bool, error) {
		_, err := s.db.Get(ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			return false, nil
		}
		return err == nil, err
	})
}

// receiptExpectation is the policy a completed job's receipt must match. A
// template test job's admitted snapshot has no required tests: they are its
// shard's selectors, derived from the repository recipe its completion
// recorded, exactly as the signer sealed them.
func receiptExpectation(repositories map[string]int64, job model.Job) (receipt.Expected, error) {
	var completion controller.Completion
	if err := json.Unmarshal(job.Result, &completion); err != nil {
		return receipt.Expected{}, fmt.Errorf("job %s completion: %w", job.ID, err)
	}
	profile, err := profiles.Effective(job.Profile, completion.Result.Observation.Recipe)
	if err != nil {
		return receipt.Expected{}, err
	}
	return receipt.Expected{RepositoryID: repositories[job.Request.Repo], Repo: job.Request.Repo, SHA: job.Request.SHA, Profile: job.Request.Profile, ProfileDigest: job.ProfileDigest, Kind: job.Request.Kind, Xcode: job.Request.Xcode, Simulator: job.Request.Simulator, RequiredTests: profile.RequiredTests, Release: job.Request.Release}, nil
}

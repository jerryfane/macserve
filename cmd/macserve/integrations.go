package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/jerryfane/macserve/internal/controller"
	"github.com/jerryfane/macserve/internal/githubapi"
	"github.com/jerryfane/macserve/internal/githubpull"
	"github.com/jerryfane/macserve/internal/hostguard"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/receipt"
	"github.com/jerryfane/macserve/internal/store"
)

type integrations struct {
	signer *receipt.Signer
	app    *githubapi.Client
	poller *githubpull.Poller
	db     *store.Store
}

func privateKeyBytes(path string) ([]byte, error) {
	if err := hostguard.PrivateFile(path); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 64<<10 {
		return nil, errors.New("private key exceeds size limit")
	}
	return data, nil
}

func newIntegrations(ctx context.Context, config controller.Config, db *store.Store, registry *profiles.Registry) (*integrations, error) {
	if err := db.InitializeGitHub(ctx); err != nil {
		return nil, err
	}
	for _, profile := range registry.List() {
		if config.Receipt.Repositories[profile.Repo] <= 0 {
			return nil, errors.New("every profile requires a pinned numeric repository ID")
		}
	}
	data, err := privateKeyBytes(config.Receipt.PrivateKeyFile)
	if err != nil {
		return nil, err
	}
	key, err := receipt.ParsePrivateKey(data)
	if err != nil {
		return nil, err
	}
	keys, err := publicKeys(config.Receipt.VerificationKeys)
	if err != nil {
		return nil, err
	}
	public := key.Public().(ed25519.PublicKey)
	if prior, ok := keys[config.Receipt.KeyID]; ok && !public.Equal(prior) {
		return nil, errors.New("receipt key ID contradicts pinned verification key")
	}
	keys[config.Receipt.KeyID] = public
	binary, err := os.Executable()
	if err != nil {
		return nil, err
	}
	f, err := os.Open(binary)
	if err != nil {
		return nil, err
	}
	hash := sha256.New()
	_, hashErr := io.Copy(hash, f)
	err = errors.Join(hashErr, f.Close())
	if err != nil {
		return nil, err
	}
	version := "development"
	if info, ok := debug.ReadBuildInfo(); ok {
		if info.Main.Version != "" && info.Main.Version != "(devel)" {
			version = info.Main.Version
		}
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				version += "+" + setting.Value
			}
			if setting.Key == "vcs.modified" && setting.Value == "true" {
				version += ".modified"
			}
		}
	}
	service := &integrations{db: db}
	service.signer, err = receipt.NewSigner(receipt.Options{
		Root: filepath.Join(config.Root, "receipts"), KeyID: config.Receipt.KeyID, PrivateKey: key,
		Service: receipt.ServiceIdentity{ID: config.Receipt.ServiceID, HostID: config.Receipt.HostID, Version: version, BinarySHA256: hex.EncodeToString(hash.Sum(nil))},
		Repository: func(_ context.Context, job model.Job) (receipt.Repository, error) {
			id := config.Receipt.Repositories[job.Request.Repo]
			if id <= 0 {
				return receipt.Repository{}, errors.New("receipt repository identity is not pinned")
			}
			return receipt.Repository{ID: id, Name: job.Request.Repo}, nil
		},
		Approval: func(ctx context.Context, job model.Job) (receipt.Approval, error) {
			_, err := db.GitHubByJob(ctx, job.ID)
			if err == nil {
				if service.poller == nil {
					return receipt.Approval{}, errors.New("GitHub admission policy is unavailable")
				}
				return service.poller.Approval(ctx, job)
			}
			if !errors.Is(err, store.ErrNotFound) || strings.HasPrefix(job.Principal, "github:") {
				return receipt.Approval{}, errors.New("job admission provenance is unavailable")
			}
			return receipt.Approval{Intake: "private_api", Identity: job.Principal, AttemptID: job.ID}, nil
		},
	})
	if err != nil {
		return nil, err
	}
	complete := false
	defer func() {
		if !complete {
			service.signer.Close()
		}
	}()
	if cfg := config.GitHub; cfg != nil {
		data, err := privateKeyBytes(cfg.PrivateKeyFile)
		if err != nil {
			return nil, err
		}
		block, rest := pem.Decode(data)
		if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
			return nil, errors.New("invalid GitHub App private key PEM")
		}
		var key *rsa.PrivateKey
		if block.Type == "RSA PRIVATE KEY" {
			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		} else if block.Type == "PRIVATE KEY" {
			var parsed any
			parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			key, _ = parsed.(*rsa.PrivateKey)
		}
		if err != nil || key == nil {
			return nil, errors.New("GitHub App key must be an RSA private key")
		}
		service.app, err = githubapi.NewApp(githubapi.AppOptions{AppID: cfg.AppID, InstallationID: cfg.InstallationID, PrivateKey: key, Repositories: config.Receipt.Repositories})
		if err != nil {
			return nil, err
		}
		service.poller, err = githubpull.New(githubpull.Options{Store: db, Profiles: registry, Client: service.app, Policies: cfg.Policies, PollInterval: time.Duration(cfg.PollSeconds) * time.Second,
			VerifyReceipt: func(job model.Job, raw json.RawMessage) error {
				payload, err := receipt.Verify(raw, keys)
				if err != nil {
					return err
				}
				return receipt.ValidateSuccess(payload, receipt.Expected{RepositoryID: config.Receipt.Repositories[job.Request.Repo], Repo: job.Request.Repo, SHA: job.Request.SHA, Profile: job.Request.Profile, ProfileDigest: job.ProfileDigest, Kind: job.Request.Kind, Xcode: job.Request.Xcode, Simulator: job.Request.Simulator, RequiredTests: job.Profile.RequiredTests})
			},
		})
		if err != nil {
			return nil, err
		}
	}
	complete = true
	return service, nil
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
	return s.signer.Prune(ctx, func(id string) (bool, error) {
		_, err := s.db.Get(ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			return false, nil
		}
		return err == nil, err
	})
}

func publicKeys(encoded map[string]string) (map[string]ed25519.PublicKey, error) {
	keys := make(map[string]ed25519.PublicKey, len(encoded)+1)
	for id, text := range encoded {
		key, err := base64.StdEncoding.Strict().DecodeString(text)
		if id == "" || err != nil || len(key) != ed25519.PublicKeySize {
			return nil, errors.New("invalid pinned Ed25519 public key")
		}
		keys[id] = ed25519.PublicKey(key)
	}
	return keys, nil
}

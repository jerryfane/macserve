package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"syscall"

	"github.com/jerryfane/macserve/internal/controllerconfig"
	"github.com/jerryfane/macserve/internal/daemonlog"
	"github.com/jerryfane/macserve/internal/githubapi"
	"github.com/jerryfane/macserve/internal/hostguard"
	"github.com/jerryfane/macserve/internal/keyholder"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/receipt"
)

// runKeyholder serves token and receipt requests from the controller as
// _macserve_key, the only account that can read the receipt and GitHub App
// keys.
func runKeyholder(args []string, stdout, stderr io.Writer) int {
	stderr = daemonlog.Stderr(stderr)
	path, done, status := parseConfigArgs("keyholder", args, stdout, stderr)
	if done {
		return status
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "macserve keyholder: %v\n", err)
		return 1
	}
	config, err := keyholder.LoadConfig(path)
	if err != nil {
		return fail(err)
	}
	if err := hostguard.Keyholder(path, hostguard.KeyholderIdentity{KeyholderUID: config.KeyholderUID, KeyholderGID: config.KeyholderGID, RPCGID: config.RPCGID, JobUID: config.JobUID, JobGID: config.JobGID, ControllerUID: config.ControllerUID, StateDir: config.StateDir, SocketDir: filepath.Dir(config.Socket)}); err != nil {
		return fail(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	engine, err := newKeyholderEngine(ctx, config)
	if err != nil {
		return fail(err)
	}
	defer engine.Close()
	listener, err := keyholder.Listen(config.Socket, config.RPCGID)
	if err != nil {
		return fail(err)
	}
	server := &keyholder.Server{Engine: engine, ControllerUID: config.ControllerUID, Logger: log.New(stderr, "", 0)}
	if err := server.Serve(ctx, listener); err != nil && !errors.Is(err, context.Canceled) {
		return fail(err)
	}
	return 0
}

// newKeyholderEngine loads the root-owned controller configuration for the
// key paths, service identity and repository policy, reads both keys from
// the keyholder's own private secrets directory, and builds the receipt
// signer and the GitHub App client only it holds.
func newKeyholderEngine(ctx context.Context, config keyholder.Config) (*keyholder.Engine, error) {
	if err := hostguard.RootConfig(config.ControllerConfig); err != nil {
		return nil, err
	}
	cc, err := controllerconfig.LoadConfig(config.ControllerConfig)
	if err != nil {
		return nil, err
	}
	if cc.Keyholder == nil || cc.Keyholder.UID != config.KeyholderUID || cc.Keyholder.Socket != config.Socket {
		return nil, errors.New("controller configuration does not name this keyholder")
	}
	secrets := config.SecretsDir()
	if cc.Receipt.PrivateKeyFile != filepath.Join(secrets, keyholder.ReceiptKeyName) {
		return nil, fmt.Errorf("receipt key must be %s", filepath.Join(secrets, keyholder.ReceiptKeyName))
	}
	data, err := hostguard.ReadPrivateKey(cc.Receipt.PrivateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("receipt key: %w", err)
	}
	key, err := receipt.ParsePrivateKey(data)
	clear(data)
	if err != nil {
		return nil, err
	}
	pins, err := receipt.ParsePublicKeys(cc.Receipt.VerificationKeys)
	if err != nil {
		return nil, err
	}
	if pinned, ok := pins[cc.Receipt.KeyID]; ok && !key.Public().(ed25519.PublicKey).Equal(pinned) {
		return nil, errors.New("receipt key ID contradicts pinned verification key")
	}
	sealKeys, err := config.SealPublicKeys()
	if err != nil {
		return nil, err
	}
	var app *githubapi.Client
	if g := cc.GitHub; g != nil {
		if g.PrivateKeyFile != filepath.Join(secrets, keyholder.AppKeyName) {
			return nil, fmt.Errorf("GitHub App key must be %s", filepath.Join(secrets, keyholder.AppKeyName))
		}
		appKey, err := readAppKey(g.PrivateKeyFile)
		if err != nil {
			return nil, err
		}
		app, err = githubapi.NewApp(githubapi.AppOptions{AppID: g.AppID, InstallationID: g.InstallationID, Installations: g.Installations, PrivateKey: appKey, Repositories: cc.Receipt.Repositories, Owners: cc.Receipt.Owners})
		if err != nil {
			return nil, err
		}
	}
	service, err := serviceIdentity(cc.Receipt)
	if err != nil {
		return nil, err
	}
	signer, err := receipt.NewSigner(receipt.Options{
		Root: config.ReceiptsDir(), KeyID: cc.Receipt.KeyID, PrivateKey: key, Service: service,
		Repository: func(ctx context.Context, job model.Job) (receipt.Repository, error) {
			if id := cc.Receipt.Repositories[job.Request.Repo]; id > 0 {
				return receipt.Repository{ID: id, Name: job.Request.Repo}, nil
			}
			owner, _, _ := strings.Cut(job.Request.Repo, "/")
			if app == nil || !slices.Contains(cc.Receipt.Owners, owner) {
				return receipt.Repository{}, errors.New("receipt repository identity is not pinned")
			}
			// Owner-approved repositories: the ID verified from this
			// keyholder's own installation token reply.
			id, ok := app.RepositoryID(job.Request.Repo)
			if !ok {
				repository, err := app.Repository(ctx, job.Request.Repo)
				if err != nil {
					return receipt.Repository{}, errors.New("receipt repository identity is unavailable")
				}
				id = repository.ID
			}
			return receipt.Repository{ID: id, Name: job.Request.Repo}, nil
		},
		Approval: keyholder.ApprovalFromContext,
	})
	if err != nil {
		return nil, err
	}
	options := keyholder.Options{
		Signer: signer, SealKeys: sealKeys,
		Policy: keyholder.Policy{Repositories: cc.Receipt.Repositories, Owners: cc.Receipt.Owners},
		ReleaseScope: func() (keyholder.ReleaseScope, error) {
			if err := hostguard.RootConfig(config.ReleaseScopeFile); err != nil {
				return keyholder.ReleaseScope{}, err
			}
			return keyholder.LoadReleaseScope(config.ReleaseScopeFile)
		},
		ReleaseDir: config.ReleaseDir(),
	}
	if app != nil {
		options.GitHub = app
	}
	engine, err := keyholder.NewEngine(options)
	if err != nil {
		signer.Close()
		return nil, err
	}
	return engine, nil
}

func readAppKey(path string) (*rsa.PrivateKey, error) {
	data, err := hostguard.ReadPrivateKey(path)
	if err != nil {
		return nil, fmt.Errorf("GitHub App key: %w", err)
	}
	defer clear(data)
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
	return key, nil
}

// serviceIdentity is the receipt service identity: the configured service
// and host IDs, and the version and SHA-256 of the running binary (the root
// macserve binary that runs the keyholder).
func serviceIdentity(r controllerconfig.ReceiptConfig) (receipt.ServiceIdentity, error) {
	binary, err := os.Executable()
	if err != nil {
		return receipt.ServiceIdentity{}, err
	}
	f, err := os.Open(binary)
	if err != nil {
		return receipt.ServiceIdentity{}, err
	}
	hash := sha256.New()
	_, hashErr := io.Copy(hash, f)
	if err := errors.Join(hashErr, f.Close()); err != nil {
		return receipt.ServiceIdentity{}, err
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
	return receipt.ServiceIdentity{ID: r.ServiceID, HostID: r.HostID, Version: version, BinarySHA256: hex.EncodeToString(hash.Sum(nil))}, nil
}

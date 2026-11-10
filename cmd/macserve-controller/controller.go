package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jerryfane/macserve/internal/controllerconfig"
	"github.com/jerryfane/macserve/internal/controllerk/api"
	"github.com/jerryfane/macserve/internal/controllerk/controller"
	"github.com/jerryfane/macserve/internal/controllerk/store"
	"github.com/jerryfane/macserve/internal/daemonlog"
	"github.com/jerryfane/macserve/internal/health"
	"github.com/jerryfane/macserve/internal/hostguard"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/source"
)

func runController(path string, stderr io.Writer) int {
	stderr = daemonlog.Stderr(stderr)
	if err := hostguard.Controller(path); err != nil {
		fmt.Fprintf(stderr, "macserve controller: %v\n", err)
		return 1
	}
	config, err := controllerconfig.LoadConfig(path)
	if err != nil {
		fmt.Fprintf(stderr, "macserve controller: %v\n", err)
		return 1
	}
	if config.JobUID == uint32(os.Geteuid()) || config.OwnerUID == uint32(os.Geteuid()) {
		fmt.Fprintln(stderr, "macserve controller: owner, job and controller UIDs must differ")
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := serveController(ctx, config); err != nil {
		fmt.Fprintf(stderr, "macserve controller: %v\n", err)
		return 1
	}
	return 0
}
func serveController(parent context.Context, config controllerconfig.Config) error {
	if err := hostguard.RootConfig(config.ProfilesFile); err != nil {
		return err
	}
	if err := hostguard.RootConfig(config.TLSCertificate); err != nil {
		return err
	}
	if err := hostguard.PrivateFile(config.TLSKey); err != nil {
		return err
	}
	registry, err := profiles.Load(config.ProfilesFile)
	if err != nil {
		return err
	}
	// Health must qualify every configured profile and template digest.
	qualified := registry.Digests()
	certificate, err := tls.LoadX509KeyPair(config.TLSCertificate, config.TLSKey)
	if err != nil {
		return err
	}
	guard, err := health.NewGuard(health.GuardOptions{Root: config.Root, HealthFile: config.HealthFile, PauseFile: config.PauseFile, JobUID: config.JobUID, OwnerUID: config.OwnerUID, Profiles: qualified})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(config.Root, 0700); err != nil {
		return err
	}
	if err := hostguard.PrivateDirectory(config.Root); err != nil {
		return err
	}
	db, err := store.Open(filepath.Join(config.Root, "state", "queue.sqlite"), store.Options{})
	if err != nil {
		return err
	}
	defer db.Close()
	integrations, err := newIntegrations(parent, config, db, registry)
	if err != nil {
		return err
	}
	sourceOptions := source.Options{Root: filepath.Join(config.Root, "source")}
	if integrations.app != nil {
		sourceOptions.Token = integrations.app.SourceToken
	}
	exporter, err := source.New(sourceOptions)
	if err != nil {
		return err
	}
	defer exporter.Close()
	controllerOptions := controller.Options{Root: config.Root, Socket: config.Socket, BrokerUID: 0, Store: db, Source: exporter, Gate: guard.Check, BeforeDispatch: integrations.beforeDispatch, Seal: integrations.seal, PruneReceipts: integrations.pruneReceipts}
	signerKey, err := signerOptions(config, &controllerOptions)
	if err != nil {
		return err
	}
	runtime, err := controller.New(controllerOptions)
	if err != nil {
		return err
	}
	defer runtime.Close()
	if err := db.ReplacePrincipals(parent, config.Principals); err != nil {
		return err
	}
	apiOptions := api.Options{Store: db, Profiles: registry, Status: runtime.Status, Artifact: runtime.Artifact, Receipt: runtime.Receipt, ReceiptManifest: integrations.keyholder.Manifest, ServiceVersion: buildVersion().Version}
	// Only the GitHub App resolves the default-branch head an ios_archive
	// job must build; without one, archive admission is refused.
	if integrations.app != nil {
		apiOptions.BranchHeads = integrations.app
	}
	if signerKey != nil {
		apiOptions.Sign, apiOptions.SignerKey = runtime.Sign, signerKey
	}
	handler, err := api.New(apiOptions)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", config.Listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10, BaseContext: func(net.Listener) context.Context { return ctx }}
	secure := tls.NewListener(listener, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, NextProtos: []string{"http/1.1"}})
	workerDone, httpDone := make(chan error, 1), make(chan error, 1)
	go func() { workerDone <- runtime.Run(ctx) }()
	go func() { httpDone <- server.Serve(secure) }()
	var pollDone chan error
	if integrations.poller != nil {
		pollDone = make(chan error, 1)
		go func() { pollDone <- integrations.poller.Run(ctx) }()
	}
	var runErr error
	workerStopped, httpStopped, pollStopped := false, false, false
	select {
	case <-parent.Done():
	case runErr = <-workerDone:
		workerStopped = true
	case runErr = <-httpDone:
		httpStopped = true
	case runErr = <-pollDone:
		pollStopped = true
	}
	cancel()
	shutdown, stop := context.WithTimeout(context.Background(), 10*time.Second)
	shutdownErr := server.Shutdown(shutdown)
	stop()
	if shutdownErr != nil {
		server.Close()
	}
	if !workerStopped {
		runErr = errors.Join(runErr, <-workerDone)
	}
	if !httpStopped {
		err := <-httpDone
		if !errors.Is(err, http.ErrServerClosed) {
			runErr = errors.Join(runErr, err)
		}
	}
	if pollDone != nil && !pollStopped {
		runErr = errors.Join(runErr, <-pollDone)
	}
	if errors.Is(runErr, context.Canceled) && parent.Err() != nil {
		return shutdownErr
	}
	if errors.Is(runErr, http.ErrServerClosed) {
		return shutdownErr
	}
	return errors.Join(runErr, shutdownErr)
}

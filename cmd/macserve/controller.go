package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/jerryfane/macserve/internal/api"
	"github.com/jerryfane/macserve/internal/controller"
	"github.com/jerryfane/macserve/internal/hostguard"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/source"
	"github.com/jerryfane/macserve/internal/store"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func runController(args []string, stdout, stderr io.Writer) int {
	path, done, status := parseConfigArgs("controller", args, stdout, stderr)
	if done {
		return status
	}
	if err := hostguard.Controller(path); err != nil {
		fmt.Fprintf(stderr, "macserve controller: %v\n", err)
		return 1
	}
	config, err := controller.LoadConfig(path)
	if err != nil {
		fmt.Fprintf(stderr, "macserve controller: %v\n", err)
		return 1
	}
	if config.WorkerUID == uint32(os.Geteuid()) || config.OwnerUID == uint32(os.Geteuid()) {
		fmt.Fprintln(stderr, "macserve controller: owner, worker and controller UIDs must differ")
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
func serveController(parent context.Context, config controller.Config) error {
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
	qualified := make(map[string]string)
	for _, p := range registry.List() {
		a, err := registry.Resolve(model.Request{Repo: p.Repo, SHA: strings.Repeat("0", 40), Kind: p.Kind, Profile: p.ID, Xcode: p.Xcode, Simulator: p.Simulator})
		if err != nil {
			return err
		}
		qualified[p.ID] = a.ProfileDigest
	}
	certificate, err := tls.LoadX509KeyPair(config.TLSCertificate, config.TLSKey)
	if err != nil {
		return err
	}
	guard, err := controller.NewGuard(controller.GuardOptions{Root: config.Root, HealthFile: config.HealthFile, PolicySHA256: config.PolicySHA256, PauseFile: config.PauseFile, WorkerUID: config.WorkerUID, OwnerUID: config.OwnerUID, Profiles: qualified})
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
	exporter, err := source.New(source.Options{Root: filepath.Join(config.Root, "source")})
	if err != nil {
		return err
	}
	defer exporter.Close()
	runtime, err := controller.New(controller.Options{Root: config.Root, Socket: config.Socket, WorkerUID: config.WorkerUID, Store: db, Source: exporter, Gate: guard.Check})
	if err != nil {
		return err
	}
	defer runtime.Close()
	if err := db.ReplacePrincipals(parent, config.Principals); err != nil {
		return err
	}
	handler, err := api.New(api.Options{Store: db, Profiles: registry, Status: runtime.Status, Artifact: runtime.Artifact, Receipt: runtime.Receipt})
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
	var runErr error
	workerStopped, httpStopped := false, false
	select {
	case <-parent.Done():
	case runErr = <-workerDone:
		workerStopped = true
	case runErr = <-httpDone:
		httpStopped = true
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
	if errors.Is(runErr, context.Canceled) && parent.Err() != nil {
		return shutdownErr
	}
	if errors.Is(runErr, http.ErrServerClosed) {
		return shutdownErr
	}
	return errors.Join(runErr, shutdownErr)
}

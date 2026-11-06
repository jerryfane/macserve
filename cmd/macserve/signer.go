package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jerryfane/macserve/internal/hostguard"
	"github.com/jerryfane/macserve/internal/signer"
)

// runSigner serves signing requests from the controller as _macserve_sign.
func runSigner(args []string, stdout, stderr io.Writer) int {
	path, done, status := parseConfigArgs("signer", args, stdout, stderr)
	if done {
		return status
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "macserve signer: %v\n", err)
		return 1
	}
	config, err := signer.LoadConfig(path)
	if err != nil {
		return fail(err)
	}
	if err := hostguard.Signer(path, signerIdentity(config)); err != nil {
		return fail(err)
	}
	if err := hostguard.RootConfig(config.PolicyFile); err != nil {
		return fail(fmt.Errorf("signer policy: %w", err))
	}
	policy, err := signer.LoadPolicy(config.PolicyFile)
	if err != nil {
		return fail(err)
	}
	key, err := signer.ReadKey(config.KeyFile)
	if err != nil {
		return fail(fmt.Errorf("signer receipt key: %w", err))
	}
	secret, err := signer.ReadSecret(config.KeychainSecretFile)
	if err != nil {
		return fail(err)
	}
	receiptKeys, err := config.ReceiptPublicKeys()
	if err != nil {
		return fail(err)
	}
	engine, err := signer.NewEngine(signer.Options{
		Config: config, Policy: policy, Tools: signer.ExecTools{Home: config.StateDir},
		PrivateKey: key, ReceiptKeys: receiptKeys, KeychainSecret: secret,
		CheckProfileFile: hostguard.RootConfig,
	})
	if err != nil {
		return fail(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ready, cancel := context.WithTimeout(ctx, time.Minute)
	err = engine.Ready(ready)
	cancel()
	if err != nil {
		return fail(err)
	}
	listener, err := signer.Listen(config.Socket, config.RPCGID)
	if err != nil {
		return fail(err)
	}
	server := &signer.Server{Engine: engine, ControllerUID: config.ControllerUID, Logger: log.New(stderr, "", log.LstdFlags)}
	if err := server.Serve(ctx, listener); err != nil && !errors.Is(err, context.Canceled) {
		return fail(err)
	}
	return 0
}

// runSignerInit creates the signer receipt key, keychain secret and empty
// keychain where absent and prints the controller's signer key pin.
func runSignerInit(args []string, stdout, stderr io.Writer) int {
	path, done, status := parseConfigArgs("signer-init", args, stdout, stderr)
	if done {
		return status
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "macserve signer-init: %v\n", err)
		return 1
	}
	config, err := signer.LoadConfig(path)
	if err != nil {
		return fail(err)
	}
	if err := hostguard.Signer(path, signerIdentity(config)); err != nil {
		return fail(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	result, err := signer.Init(ctx, config, signer.ExecTools{Home: config.StateDir})
	if err != nil {
		return fail(err)
	}
	line, err := json.Marshal(result)
	if err != nil {
		return fail(err)
	}
	fmt.Fprintln(stdout, string(line))
	return 0
}

func signerIdentity(c signer.Config) hostguard.SignerIdentity {
	return hostguard.SignerIdentity{SignerUID: c.SignerUID, SignerGID: c.SignerGID, RPCGID: c.RPCGID, JobUID: c.JobUID, JobGID: c.JobGID, ControllerUID: c.ControllerUID, StateDir: c.StateDir, SocketDir: filepath.Dir(c.Socket)}
}

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jerryfane/macserve/internal/githubapi"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/receipt"
	"github.com/jerryfane/macserve/internal/waiter"
)

type waitPins struct {
	RepositoryID     int64             `json:"repository_id"`
	AppID            int64             `json:"app_id"`
	Request          model.Request     `json:"request"`
	ProfileDigest    string            `json:"profile_digest"`
	RequiredTests    []string          `json:"required_tests"`
	VerificationKeys map[string]string `json:"verification_keys"`
}

func runWait(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("wait", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var pinsPath, sha, requestID, mode string
	var pr int
	var timeout time.Duration
	flags.StringVar(&pinsPath, "pins", "", "trusted JSON policy and out-of-band verification keys")
	flags.StringVar(&sha, "sha", "", "exact PR head SHA (never the synthetic merge SHA)")
	flags.IntVar(&pr, "pr", 0, "pull request number")
	flags.StringVar(&requestID, "request", "", "actions:<run-id>:<run-attempt>")
	flags.StringVar(&mode, "mode", "ensure", "ensure or bounded explicit rerun")
	flags.DurationVar(&timeout, "timeout", 90*time.Minute, "wait deadline; does not cancel shared Mac work")
	flags.Usage = func() {
		fmt.Fprintln(flags.Output(), "Usage: macserve wait --pins FILE --pr N --sha HEAD --request actions:RUN:ATTEMPT\nAuthentication: GITHUB_TOKEN environment only. No checkout or Mac credentials.")
		flags.PrintDefaults()
	}
	for _, arg := range args {
		if arg == "--help" || arg == "-h" {
			flags.SetOutput(stdout)
			break
		}
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 || pinsPath == "" || sha == "" || pr <= 0 || requestID == "" || timeout <= 0 {
		flags.Usage()
		return 2
	}
	fail := func(err error) int { fmt.Fprintf(stderr, "macserve wait: %v\n", err); return 1 }
	f, err := os.Open(pinsPath)
	if err != nil {
		return fail(err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return fail(err)
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		f.Close()
		return fail(errors.New("pins must be a bounded regular JSON file"))
	}
	var pins waitPins
	decoder := json.NewDecoder(io.LimitReader(f, (1<<20)+1))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&pins)
	if err == nil && decoder.Decode(new(any)) != io.EOF {
		err = errors.New("trailing pins JSON")
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return fail(err)
	}
	if pins.Request.SHA != "" && pins.Request.SHA != sha {
		return fail(errors.New("requested SHA contradicts pinned SHA"))
	}
	keys, err := publicKeys(pins.VerificationKeys)
	if err != nil {
		return fail(err)
	}
	client, err := githubapi.NewToken(os.Getenv("GITHUB_TOKEN"), githubapi.HTTPOptions{})
	if err != nil {
		return fail(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	result, err := waiter.Run(ctx, waiter.Options{Client: client, Repo: pins.Request.Repo, RepositoryID: pins.RepositoryID, PullRequest: pr, Profile: pins.Request.Profile, RequestID: requestID, Mode: mode, AppID: pins.AppID, Timeout: timeout, Keys: keys,
		Expected: receipt.Expected{RepositoryID: pins.RepositoryID, Repo: pins.Request.Repo, SHA: sha, Profile: pins.Request.Profile, ProfileDigest: pins.ProfileDigest, Kind: pins.Request.Kind, Xcode: pins.Request.Xcode, Simulator: pins.Request.Simulator, RequiredTests: pins.RequiredTests},
	})
	if err != nil {
		return fail(err)
	}
	// Only verified values may reach Actions command files. Reject line injection
	// even if a remote check's display URL violates GitHub's normal wire contract.
	checkURL, err := url.Parse(result.CheckURL)
	if err != nil || checkURL.Scheme != "https" || checkURL.Host != "github.com" || checkURL.User != nil || strings.ContainsAny(result.CheckURL, "\r\n\x00") {
		return fail(errors.New("invalid verified check URL"))
	}
	output := fmt.Sprintf("job_id=%s\ncheck_url=%s\nreceipt_digest=%s\n", result.JobID, result.CheckURL, result.ReceiptDigest)
	if err := appendActionsFile("GITHUB_OUTPUT", output); err != nil {
		return fail(err)
	}
	summary := fmt.Sprintf("## Verified Mac evidence\n\nJob `%s`; receipt `%s`.\n\nTests: %s; %d passed, %d failed, %d skipped, %d expected failures.\n", result.JobID, result.ReceiptDigest, result.Tests.Status, result.Tests.Passed, result.Tests.Failed, result.Tests.Skipped, result.Tests.ExpectedFailures)
	if err := appendActionsFile("GITHUB_STEP_SUMMARY", summary); err != nil {
		return fail(err)
	}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		return fail(err)
	}
	return 0
}

func appendActionsFile(variable, text string) error {
	path := os.Getenv(variable)
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	_, err = io.WriteString(f, text)
	return errors.Join(err, f.Close())
}

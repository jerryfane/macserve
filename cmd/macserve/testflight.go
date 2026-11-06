package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jerryfane/macserve/internal/testflight"
)

func runTestflightUpload(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("testflight-upload", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var o testflight.Options
	var out string
	var timeout time.Duration
	flags.StringVar(&o.API, "api", "", "macserve API base URL that authenticates this agent, e.g. http://127.0.0.1:7700/<role>/macserve-builds")
	flags.StringVar(&o.JobID, "job", "", "signed ios_archive job ID")
	flags.StringVar(&o.KeyringRole, "keyring-role", "", "keyring role whose appstoreconnect service signs the JWTs")
	flags.StringVar(&o.AppID, "app-id", "", "numeric App Store Connect app ID")
	flags.StringVar(&o.Keyring, "keyring", "http://127.0.0.1:7700", "keyring relay base URL")
	flags.StringVar(&o.ASC, "asc", "https://api.appstoreconnect.apple.com", "App Store Connect API base URL")
	flags.DurationVar(&timeout, "timeout", 2*time.Hour, "deadline for verification, upload and processing")
	flags.StringVar(&out, "out", "", "write the evidence JSON to this new file")
	flags.Usage = func() {
		fmt.Fprintln(flags.Output(), "Usage: macserve testflight-upload --api URL --job ID --keyring-role ROLE --app-id ID [--out FILE]\nVerifies the job's signer receipt and App.ipa, then uploads it with keyring-signed App Store Connect JWTs.\nNo Apple key is read or held; nothing is sent to macserve but reads.")
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
	if flags.NArg() != 0 || o.API == "" || o.JobID == "" || o.KeyringRole == "" || o.AppID == "" || timeout <= 0 {
		flags.Usage()
		return 2
	}
	fail := func(err error) int { fmt.Fprintf(stderr, "macserve testflight-upload: %v\n", err); return 1 }
	// Refuse an existing --out before any upload, so evidence is never lost.
	var evidenceFile *os.File
	if out != "" {
		f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return fail(err)
		}
		evidenceFile = f
	}
	o.Log = stderr
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ev, runErr := testflight.Run(ctx, o)
	// The evidence file is written also on failure: it records how far the
	// run got, including a build upload ID to resume.
	if evidenceFile != nil {
		encoded, err := json.MarshalIndent(ev, "", "  ")
		if err == nil {
			_, err = evidenceFile.Write(append(encoded, '\n'))
		}
		if err = errors.Join(err, evidenceFile.Close()); err != nil {
			return fail(errors.Join(runErr, err))
		}
	}
	summary := fmt.Sprintf("job_id=%s\nbundle_id=%s\nbuild_name=%s\nbuild_number=%s\nipa_sha256=%s\nipa_size=%d\nsigner_receipt_sha256=%s\napp_id=%s\nbuild_upload_id=%s\nresumed=%t\nfinal_state=%s\n",
		ev.JobID, ev.BundleID, ev.BuildName, ev.BuildNumber, ev.IPASHA256, ev.IPASize, ev.SignerReceiptSHA256, ev.AppID, ev.BuildUploadID, ev.Resumed, ev.FinalState)
	if _, err := io.WriteString(stdout, summary); err != nil {
		return fail(errors.Join(runErr, err))
	}
	if runErr != nil {
		return fail(runErr)
	}
	return 0
}

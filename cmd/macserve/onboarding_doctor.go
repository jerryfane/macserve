package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/jerryfane/macserve/internal/controllerconfig"
	"github.com/jerryfane/macserve/internal/doctor"
	"github.com/jerryfane/macserve/internal/githubapi"
	"github.com/jerryfane/macserve/internal/hostguard"
	"github.com/jerryfane/macserve/internal/onboarding"
	"github.com/jerryfane/macserve/internal/setup"
)

func runDoctor(args []string, stdout, stderr io.Writer) int {
	return doctorDispatch([]string{doctor.Mode(args)}, args, stdout, stderr)
}

// doctorDispatch runs the doctor mode words[0]. checks/readonly proves it
// for the mode "check": everything here except the live clause.
func doctorDispatch(words, args []string, stdout, stderr io.Writer) int {
	switch words[0] {
	case doctor.ModeLive:
		return runDoctorLive(args, stdout, stderr)
	}
	return runDoctorWith(doctor.SystemProbe(), args, stdout, stderr)
}

// runDoctorWith parses the doctor flags and runs the checks against probe;
// tests pass a fake host. Exit 0: nothing failed; 1: a check failed;
// 2: usage.
func runDoctorWith(probe doctor.Probe, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var asJSON, live bool
	var o doctor.Options
	flags.BoolVar(&asJSON, "json", false, "")
	flags.BoolVar(&live, "live", false, "")
	flags.StringVar(&o.ReleaseSHA256, "sha256", "", "")
	flags.StringVar(&o.SHA256Sums, "sha256sums", "", "")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, doctorHelp)
			return 0
		}
		fmt.Fprintf(stderr, "macserve doctor: %v\n", err)
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "macserve doctor: unexpected arguments; see macserve doctor --help")
		return 2
	}
	if live != (probe.FDA != nil) {
		fmt.Fprintln(stderr, "macserve doctor: spell the live mode exactly --live, as its own argument")
		return 2
	}
	if o.ReleaseSHA256 != "" && !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(o.ReleaseSHA256) {
		fmt.Fprintln(stderr, "macserve doctor: --sha256 needs 64 lowercase hexadecimal characters")
		return 2
	}
	if o.ReleaseSHA256 != "" && o.SHA256Sums != "" {
		fmt.Fprintln(stderr, "macserve doctor: give --sha256 or --sha256sums, not both")
		return 2
	}
	report := doctor.Run(context.Background(), probe, o)
	if err := doctor.Write(stdout, report, asJSON); err != nil {
		fmt.Fprintf(stderr, "macserve doctor: %v\n", err)
		return 2
	}
	return report.ExitCode()
}

// runDoctorLive adds the two checks with effects: the transient launchd
// Full Disk Access job and the GitHub App calls. It needs root.
func runDoctorLive(args []string, stdout, stderr io.Writer) int {
	if os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "macserve doctor: --live needs sudo: it starts a transient launchd job and reads the GitHub App key")
		return 2
	}
	probe := doctor.SystemProbe()
	probe.FDA = setup.CheckFDA
	probe.GitHub = liveGitHub
	return runDoctorWith(probe, args, stdout, stderr)
}

// liveGitHub checks the configured App against GitHub. The key and tokens
// are never printed.
func liveGitHub(ctx context.Context) (string, error) {
	data, err := readSmallFile(doctor.Root+"/config/controller.json", 1<<20)
	if err != nil {
		return "", errors.New("cannot read controller.json")
	}
	var config controllerconfig.Config
	if err := json.Unmarshal(data, &config); err != nil {
		return "", errors.New("invalid controller.json")
	}
	gh := config.GitHub
	if gh == nil || gh.AppID <= 0 {
		return "", errors.New("no GitHub App is connected")
	}
	if config.Keyholder == nil {
		return "", errors.New("controller.json has no keyholder section")
	}
	pem, err := hostguard.ReadOwnedPrivateKey(gh.PrivateKeyFile, config.Keyholder.UID)
	if err != nil {
		return "", errors.New("cannot read the GitHub App key")
	}
	key, err := onboarding.ParseAppKey(pem)
	if err != nil {
		return "", errors.New("the GitHub App key is invalid")
	}
	installations := gh.Installations
	if len(installations) == 0 && gh.InstallationID > 0 {
		installations = map[string]int64{}
		for _, p := range gh.Policies {
			owner, _, _ := strings.Cut(p.Repository, "/")
			installations[owner] = gh.InstallationID
		}
	}
	var repos []string
	for _, p := range gh.Policies {
		repos = append(repos, p.Repository)
	}
	api, err := onboarding.NewAPI(githubapi.HTTPOptions{})
	if err != nil {
		return "", err
	}
	return api.CheckInstallations(ctx, onboarding.App{ID: gh.AppID, Key: key}, installations, repos)
}

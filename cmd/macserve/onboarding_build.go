package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jerryfane/macserve/internal/deploy"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/onboarding"
)

// Build exit codes beyond 0 (succeeded, receipt verified), 1 (error or
// the job did not succeed) and 2 (usage).
const buildInterrupted = 3

func runBuild(args []string, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runBuildWith(ctx, buildHost{
		readFile: readSmallFile,
		token:    keychainToken,
		local:    onboarding.LocalRepo,
		cwd:      os.Getwd,
	}, args, stdout, stderr)
}

// buildHost is what `macserve build` reads from this Mac; tests fake it.
type buildHost struct {
	readFile func(path string, max int64) ([]byte, error)
	token    func(ctx context.Context) (string, error)
	local    func(dir string) (repo, sha string, config []byte, err error)
	cwd      func() (string, error)
	// configure lets tests replace the HTTP client and the poll sleep.
	configure func(*onboarding.Build)
}

func runBuildWith(ctx context.Context, host buildHost, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("build", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var r onboarding.BuildRequest
	var follow string
	var noFollow bool
	flags.StringVar(&r.Repo, "repo", "", "")
	flags.StringVar(&r.SHA, "sha", "", "")
	flags.StringVar(&r.Profile, "profile", "", "")
	flags.StringVar(&follow, "follow", "", "")
	flags.BoolVar(&noFollow, "no-follow", false, "")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, buildHelp)
			return 0
		}
		fmt.Fprintf(stderr, "macserve build: %v\n", err)
		return 2
	}
	if flags.NArg() != 0 || follow != "" && (noFollow || r.Repo != "" || r.SHA != "" || r.Profile != "") {
		fmt.Fprintln(stderr, "macserve build: unexpected arguments; see macserve build --help")
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "macserve build: %v\n", err)
		return 1
	}
	b, err := newBuildClient(host, stdout)
	if err != nil {
		return fail(err)
	}
	id := follow
	var sent *model.Request
	if id == "" {
		if r.Repo == "" || r.SHA == "" {
			dir, err := host.cwd()
			if err != nil {
				return fail(err)
			}
			repo, sha, config, err := host.local(dir)
			if err != nil {
				return fail(err)
			}
			if r.Repo == "" {
				r.Repo = repo
			}
			if r.SHA == "" {
				r.SHA = sha
				fmt.Fprintln(stdout, "Building HEAD "+sha+"; macserve fetches it from GitHub, so push it first.")
			}
			r.RepoConfig = config
		}
		if r.Repo == "" {
			return fail(errors.New("cannot tell the GitHub repository from remote \"origin\"; pass --repo OWNER/NAME"))
		}
		var request model.Request
		if id, request, err = b.Submit(ctx, r); err != nil {
			return fail(err)
		}
		sent = &request
		if noFollow {
			fmt.Fprintf(stdout, "Follow it with: macserve build --follow %s\n", id)
			return 0
		}
	}
	res, err := b.Follow(ctx, id, sent)
	if errors.Is(err, onboarding.ErrInterrupted) {
		fmt.Fprintf(stderr, "macserve build: %v; follow it again with: macserve build --follow %s\n", err, id)
		return buildInterrupted
	}
	if err != nil {
		return fail(err)
	}
	switch {
	case res.Succeeded():
		fmt.Fprintf(stdout, "✓ job %s succeeded; its signed receipt verifies against this Mac's deployment pins and matches the submitted job.\n", res.ID)
		return 0
	case res.Receipt && res.State == model.Succeeded:
		fmt.Fprintf(stdout, "✗ job %s: its signed receipt is not a complete success (exit code %s).\n", res.ID, exitText(res.ExitCode))
	case res.ExitCode != nil:
		fmt.Fprintf(stdout, "✗ job %s %s (exit code %d).\n", res.ID, res.State, *res.ExitCode)
	default:
		fmt.Fprintf(stdout, "✗ job %s %s.\n", res.ID, res.State)
	}
	return 1
}

// newBuildClient reads the API address from deploy.env and the pins from
// deployment-pins.json; both are public.
func newBuildClient(host buildHost, stdout io.Writer) (*onboarding.Build, error) {
	envData, err := host.readFile(deploy.Prefix+"/config/deploy.env", deploy.MaxEnvironment)
	if err != nil {
		return nil, errors.New("macserve is not installed on this Mac (no deploy.env)")
	}
	env, err := deploy.ParseEnvironment(envData)
	if err != nil {
		return nil, errors.New("invalid deploy.env")
	}
	ip, err := netip.ParseAddr(env.TailnetIP)
	if err != nil {
		return nil, errors.New("invalid TAILNET_IP in deploy.env")
	}
	pinData, err := host.readFile(deploy.Prefix+"/config/deployment-pins.json", 64<<10)
	if err != nil {
		return nil, errors.New("cannot read deployment-pins.json")
	}
	var pins onboarding.Pins
	if err := json.Unmarshal(pinData, &pins); err != nil {
		return nil, errors.New("invalid deployment-pins.json")
	}
	b := &onboarding.Build{
		Endpoint: "https://" + netip.AddrPortFrom(ip, env.Port).String(),
		Pins:     pins,
		Token:    host.token,
		Out:      stdout,
		Poll:     2 * time.Second,
	}
	if host.configure != nil {
		host.configure(b)
	}
	return b, nil
}

func exitText(code *int) string {
	if code == nil {
		return "none"
	}
	return strconv.Itoa(*code)
}

// keychainArgs finds the item setup's saveKeychainToken adds (PR #73):
// service keychainService, account the owner's username.
func keychainArgs(account string) []string {
	return []string{"find-generic-password", "-a", account, "-s", keychainService, "-w"}
}

// keychainToken reads the API token from the invoking user's login
// keychain with security(1). Its output is the token only; stderr is
// discarded so nothing about the item is shown.
func keychainToken(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/security", keychainArgs(u.Username)...)
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	cmd.Dir = "/"
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", errors.New("keychain item not found")
	}
	return strings.TrimSpace(out.String()), nil
}

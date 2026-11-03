package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"

	"github.com/jerryfane/macserve/internal/deploy"
	"github.com/jerryfane/macserve/internal/githubapi"
	"github.com/jerryfane/macserve/internal/onboarding"
)

// connectGitHubHost, connectGitHubIn and connectGitHubHTTP are test seams.
// They are function literals or zero values: checks/readonly walks every
// package initialiser, so none reads process state at init.
var (
	connectGitHubHost = func() onboarding.Host {
		return onboarding.Host{Root: deploy.Prefix, EUID: os.Geteuid(), SudoUID: os.Getenv("SUDO_UID"), ConsoleUID: onboarding.SystemConsoleUID}
	}
	connectGitHubIn   = func() io.Reader { return os.Stdin }
	connectGitHubHTTP githubapi.HTTPOptions
)

const connectGitHubHelp = `Usage: macserve connect-github --profile ID [--profile ID…]
                              [--repository OWNER/NAME] [--author LOGIN] [--org]

Creates a private GitHub App from a manifest (metadata, contents and pull
requests read; checks write; no webhook, no events), installs it on the one
repository you select, confirms the installation by authenticating as the
App (the installation_id in GitHub's redirect is not trusted), installs the
App key controller-owned 0600 in /Library/macserve/var/controller/secrets
without overwriting any existing key, and adds the github section to
controller.json. It then reads .macserve.json at the default branch through
the GitHub API (no repository code runs) and suggests one if it is missing.

Run it with sudo from your own login at this Mac, after deploy-install and
before qualification: it refuses a root shell without SUDO_UID, a SUDO_UID
that is not the console user and deploy.env owner, an existing App key or
github section, and an approved qualification. It prints a 127.0.0.1
address to open; it never opens a browser itself. A browser on another
device can reach it through ssh -L, or you paste the address GitHub
redirected to back into the terminal.

  --profile ID
          Profile in profiles.json that pull requests run (repeatable,
          required). Its recipe must build this repository, and the App
          must be installed on only this repository. Temporary until
          PR-policy templates (O7): policies cannot name templates yet, so
          an all-repositories installation is refused.
  --repository OWNER/NAME
          Repository pinned in controller.json receipt.repositories
          (default: the only pin).
  --author LOGIN
          GitHub user whose pull requests are built (default: the
          repository owner; required with --org).
  --org   The repository owner is an organization: the App is registered
          under it and needs an organization owner to create it.

Exit status: 0 connected, 1 refused or failed, 2 usage.
`

type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

func runConnectGitHub(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("connect-github", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var repository, author string
	var org bool
	var profileIDs stringList
	flags.StringVar(&repository, "repository", "", "")
	flags.StringVar(&author, "author", "", "")
	flags.BoolVar(&org, "org", false, "")
	flags.Var(&profileIDs, "profile", "")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, connectGitHubHelp)
			return 0
		}
		fmt.Fprintf(stderr, "macserve connect-github: %v\n", err)
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "macserve connect-github: unexpected arguments; see macserve connect-github --help")
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintln(stderr, "macserve connect-github:", err)
		return 1
	}
	prepared, err := onboarding.Prepare(connectGitHubHost())
	if err != nil {
		return fail(err)
	}
	repo, repoID, err := prepared.Repository(strings.ToLower(repository))
	if err != nil {
		return fail(err)
	}
	ownerLogin, _, _ := strings.Cut(repo, "/")
	if author == "" {
		if org {
			fmt.Fprintln(stderr, "macserve connect-github: --org needs --author YOUR-LOGIN, the account whose pull requests are built")
			return 2
		}
		author = ownerLogin
	}
	author = strings.ToLower(author)
	scope, err := onboarding.PolicyScope(prepared.Profiles, repo, profileIDs)
	if err != nil {
		return fail(err)
	}
	listener, err := onboarding.Listen()
	if err != nil {
		return fail(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	hostname, _ := os.Hostname()
	confirmed, status, err := onboarding.Connect(ctx, onboarding.ConnectOptions{
		Account: onboarding.Account{Login: ownerLogin, Org: org}, AppName: onboarding.AppName(hostname),
		Repository: repo, RepositoryID: repoID, Author: author, Scope: scope,
		Listener: listener, In: connectGitHubIn(), Out: stdout, HTTP: connectGitHubHTTP,
		Install: func(c onboarding.Confirmed) error {
			enrollment := onboarding.Enrollment{
				AppID: c.App.ID, InstallationID: c.Installation.ID, Repository: repo, RepositoryID: repoID,
				AuthorIDs: []int64{c.Author.ID}, BaseBranches: []string{c.Repository.DefaultBranch},
				Profiles: profileIDs,
			}
			return prepared.Config.WriteGitHub(enrollment, prepared.Key, c.App.PEM)
		},
	})
	if err != nil {
		return fail(err)
	}
	fmt.Fprintf(stdout, "Connected: App %d, installation %d on %s; pull requests by %s (ID %d) to %s run %s.\nThe App key is %s (controller-owned, 0600); controller.json has the github section.\n",
		confirmed.App.ID, confirmed.Installation.ID, repo, confirmed.Author.Login, confirmed.Author.ID, confirmed.Repository.DefaultBranch, strings.Join(profileIDs, ", "), prepared.Key.Path())
	if status == nil || !status.Found || status.Invalid != nil {
		fmt.Fprintln(stdout, "Template builds of this repository need a valid .macserve.json on its default branch; commit one before the first template build.")
	}
	return 0
}

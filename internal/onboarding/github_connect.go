package onboarding

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jerryfane/macserve/internal/githubapi"
)

// FlowTimeout bounds each wait for the browser: GitHub requires the whole
// manifest flow to finish within one hour.
const FlowTimeout = time.Hour

// ConnectOptions configures one connect-github run.
type ConnectOptions struct {
	Account Account
	AppName string
	// Repository and RepositoryID are the receipt pin the App must be
	// installed on, alone.
	Repository   string
	RepositoryID int64
	// Author is the login whose pull requests are trusted.
	Author string
	// Listener is the loopback listener the flow serves; Connect closes it.
	Listener net.Listener
	// In carries pasted redirect addresses and Enter; Out the instructions.
	In   io.Reader
	Out  io.Writer
	HTTP githubapi.HTTPOptions
	// Install receives the App key and identities only after every GitHub
	// check passed; it installs the key and writes the configuration.
	Install func(Confirmed) error
}

// Confirmed is the App, its confirmed installation, the one repository and
// the trusted author.
type Confirmed struct {
	App          App
	Installation Installation
	Repository   Repository
	Author       Owner
}

// Connect runs the manifest flow, confirms the installation, hands the
// result to Install and then checks .macserve.json. Nothing is written
// before Install; a refused App keeps no key.
func Connect(ctx context.Context, o ConnectOptions) (Confirmed, *RepoConfigStatus, error) {
	defer o.Listener.Close()
	addr, ok := o.Listener.Addr().(*net.TCPAddr)
	if !ok || !addr.IP.IsLoopback() || addr.IP.To4() == nil {
		return Confirmed{}, nil, errors.New("the manifest flow listens on 127.0.0.1 only")
	}
	if !githubapi.ValidOwner(o.Author) {
		return Confirmed{}, nil, errors.New("invalid trusted author login")
	}
	api, err := NewAPI(o.HTTP)
	if err != nil {
		return Confirmed{}, nil, err
	}
	flow, err := NewFlow(o.Account, o.AppName, addr.Port)
	if err != nil {
		return Confirmed{}, nil, err
	}
	server := &http.Server{Handler: flow.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go server.Serve(o.Listener)
	defer server.Close()
	lines := readLines(o.In)
	out := o.Out

	fmt.Fprintf(out, "Open this address in a browser signed in to GitHub as %s:\n\n  %s\n\n", o.Account.Login, flow.StartURL())
	fmt.Fprintf(out, "It sends the App manifest to GitHub; confirm the name and click Create GitHub App.\n")
	fmt.Fprintf(out, "Browser on another device: forward the port first (ssh -L %d:127.0.0.1:%d <this Mac>) and open the same address there. If GitHub's redirect to 127.0.0.1 does not load, copy the full address from the browser's address bar and paste it here.\n\n", addr.Port, addr.Port)

	code, err := waitCode(ctx, flow, lines, out)
	if err != nil {
		return Confirmed{}, nil, err
	}
	app, err := api.Convert(ctx, code, o.Account)
	if err != nil {
		return Confirmed{}, nil, err
	}
	fmt.Fprintf(out, "GitHub App %s created (App ID %d).\n\nInstall it on %s only:\n\n  %s\n\nChoose “Only select repositories”, select %s, and click Install.\n\n", app.Slug, app.ID, o.Repository, app.InstallURL(), o.Repository)

	// From here on the App exists on GitHub; every failure says how to
	// remove it so a re-run starts clean.
	created := func(err error) error {
		return fmt.Errorf("%w; GitHub App %s was created but not connected: delete it at %s before running connect-github again", err, app.Slug, app.SettingsURL(o.Account))
	}
	confirmed := Confirmed{App: app}
	var token string
	confirmed.Installation, confirmed.Repository, token, err = waitInstallation(ctx, api, app, o, flow, lines)
	if err != nil {
		return Confirmed{}, nil, created(err)
	}
	if confirmed.Author, err = api.user(ctx, token, o.Author); err != nil {
		return Confirmed{}, nil, created(err)
	}
	// Mint a token exactly as the controller does (internal/githubapi), so
	// the installation is proven to grant the controller's permissions on
	// the pinned repository ID before anything is written.
	client, err := githubapi.NewApp(githubapi.AppOptions{AppID: app.ID, InstallationID: confirmed.Installation.ID, PrivateKey: app.Key, Repositories: map[string]int64{o.Repository: o.RepositoryID}, HTTP: o.HTTP})
	if err != nil {
		return Confirmed{}, nil, created(err)
	}
	if repo, err := client.Repository(ctx, o.Repository); err != nil || repo.ID != o.RepositoryID {
		return Confirmed{}, nil, created(fmt.Errorf("the controller's GitHub client cannot use the installation on %s: %v", o.Repository, err))
	}
	if err := o.Install(confirmed); err != nil {
		return Confirmed{}, nil, created(err)
	}
	status := repoConfigLoop(ctx, api, token, confirmed.Repository, lines, out)
	return confirmed, status, nil
}

// readLines delivers terminal lines until EOF, then closes the channel.
func readLines(in io.Reader) <-chan string {
	lines := make(chan string)
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(in)
		scanner.Buffer(make([]byte, 4096), 4096)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
	}()
	return lines
}

func waitCode(ctx context.Context, flow *Flow, lines <-chan string, out io.Writer) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, FlowTimeout)
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("waiting for GitHub to create the App: %w", ctx.Err())
		case code := <-flow.Codes():
			return code, nil
		case line, ok := <-lines:
			if !ok {
				lines = nil
				continue
			}
			if strings.TrimSpace(line) == "" {
				continue
			}
			installation, err := flow.AcceptPasted(line)
			switch {
			case err != nil:
				fmt.Fprintf(out, "Not accepted: %v\n", err)
			case installation:
				fmt.Fprintln(out, "That is an installation address; create the App first.")
			}
		}
	}
}

func waitInstallation(ctx context.Context, api *API, app App, o ConnectOptions, flow *Flow, lines <-chan string) (Installation, Repository, string, error) {
	ctx, cancel := context.WithTimeout(ctx, FlowTimeout)
	defer cancel()
	for {
		var candidate int64
		select {
		case <-ctx.Done():
			return Installation{}, Repository{}, "", fmt.Errorf("waiting for the App installation: %w", ctx.Err())
		case candidate = <-flow.Installations():
		case line, ok := <-lines:
			if !ok {
				lines = nil
				continue
			}
			if strings.TrimSpace(line) == "" {
				continue
			}
			if installation, err := flow.AcceptPasted(line); err != nil || !installation {
				fmt.Fprintln(o.Out, "Not accepted: paste the address GitHub opened after Install (…/installed?installation_id=…).")
			}
			continue
		}
		installation, repo, token, err := confirmInstallation(ctx, api, app, o, candidate)
		if err != nil {
			fmt.Fprintf(o.Out, "Installation not accepted: %v\nCorrect the installation on GitHub (Configure); GitHub returns here afterwards.\n", err)
			continue
		}
		return installation, repo, token, nil
	}
}

func confirmInstallation(ctx context.Context, api *API, app App, o ConnectOptions, candidate int64) (Installation, Repository, string, error) {
	installation, err := api.Confirm(ctx, app, o.Account, candidate)
	if err != nil {
		return Installation{}, Repository{}, "", err
	}
	token, err := api.readToken(ctx, app, installation)
	if err != nil {
		return Installation{}, Repository{}, "", err
	}
	repos, err := api.repositories(ctx, token)
	if err != nil {
		return Installation{}, Repository{}, "", err
	}
	if len(repos) != 1 || repos[0].ID != o.RepositoryID || !strings.EqualFold(repos[0].FullName, o.Repository) {
		return Installation{}, Repository{}, "", fmt.Errorf("the installation must select exactly %s (repository ID %d)", o.Repository, o.RepositoryID)
	}
	return installation, repos[0], token, nil
}

func repoConfigLoop(ctx context.Context, api *API, token string, repo Repository, lines <-chan string, out io.Writer) *RepoConfigStatus {
	for {
		status, err := api.DetectRepoConfig(ctx, token, repo)
		if err != nil {
			fmt.Fprintf(out, "Could not read .macserve.json from %s: %v\n", repo.FullName, err)
			return nil
		}
		switch {
		case status.Found && status.Invalid == nil:
			fmt.Fprintf(out, "%s has a valid .macserve.json at %s.\n", repo.FullName, status.Commit)
			return &status
		case status.Found:
			fmt.Fprintf(out, "%s at %s is not valid: %v\n", ".macserve.json", status.Commit, status.Invalid)
		case len(status.Suggestions) > 0:
			_ = WriteRepoConfigSuggestion(out, status.Suggestions[0], repo.DefaultBranch)
			if len(status.Suggestions) > 1 {
				fmt.Fprintf(out, "Other shared schemes found: %d more; edit scheme, project or workspace if the first is not the app.\n", len(status.Suggestions)-1)
			}
		default:
			fmt.Fprintln(out, "No .macserve.json and no shared Xcode scheme were found. In Xcode, mark the app's scheme Shared (Product > Scheme > Manage Schemes), commit it, and write .macserve.json as described in docs/install.md.")
		}
		if status.Truncated {
			fmt.Fprintln(out, "The repository tree was too large to list completely.")
		}
		fmt.Fprintf(out, "Press Enter after pushing to %s to check again, or type skip: ", repo.DefaultBranch)
		select {
		case <-ctx.Done():
			return &status
		case line, ok := <-lines:
			if !ok || strings.TrimSpace(line) == "skip" {
				fmt.Fprintln(out)
				return &status
			}
		}
	}
}

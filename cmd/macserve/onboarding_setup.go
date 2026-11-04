package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/jerryfane/macserve/internal/deploy"
	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/setup"
	"github.com/jerryfane/macserve/internal/setup/plan"
)

// setupSession is the wizard's connection to the root helper.
type setupSession interface {
	Call(setup.Request) (setup.Response, error)
	Close() error
}

// setupWizard is `macserve setup` without --plan. It runs as the owner
// and never under sudo; privileged steps go to the one root helper it
// starts. Every field that touches the host is injected.
type setupWizard struct {
	probe plan.Probe
	in    *bufio.Reader
	out   io.Writer
	// root is deploy.Prefix.
	root string
	// self is this binary's resolved path.
	self string
	// start runs `sudo path _setup-root --sha256 digest` and connects to it.
	start func(path, digest string) (setupSession, error)
	// open runs /usr/bin/open as the owner with fixed arguments.
	open  func(args ...string) error
	sleep func(time.Duration)
	// loginPoll and loginWait pace the job-login detection.
	loginPoll, loginWait time.Duration
	// home is the owner's home directory (owner canary and owner files).
	home string
	// keychain stores the one-time API token in the owner's login
	// keychain (decision D11).
	keychain func(token string) error
	// canary and probe are the owner-home control and the owner probe of
	// a qualification session (qualification.Canary owner-home and
	// qualification.Probe owner), run in this process as the owner.
	homeControl func(ctx context.Context, sessionDir, out string) error
	ownerReport func(ctx context.Context, sessionDir, out string) error
	// canaryLead lets the owner-home control take its first read before
	// the job probe.
	canaryLead time.Duration
	// restart restarts the Mac (kind: setup.RestartAuth, RestartUnlock or
	// RestartPlain) through sudo on the owner's terminal.
	restart func(kind string) error
	// healthWait bounds the wait for valid health before owner.pause is
	// removed.
	healthWait time.Duration
}

func runSetupApply(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("setup", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	choices := plan.DefaultChoices()
	var planOnly bool
	var sha, sums string
	flags.BoolVar(&planOnly, "plan", false, "")
	flags.StringVar(&choices.Repository, "repository", "", "")
	flags.StringVar(&choices.JobRealName, "job-real-name", choices.JobRealName, "")
	flags.StringVar(&sha, "sha256", "", "")
	flags.StringVar(&sums, "sha256sums", "", "")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, setupHelp)
			return 0
		}
		fmt.Fprintf(stderr, "macserve setup: %v\n", err)
		return 2
	}
	if flags.NArg() != 0 || planOnly {
		fmt.Fprintln(stderr, "macserve setup: unexpected arguments; see macserve setup --help")
		return 2
	}
	if sha != "" && !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(sha) {
		fmt.Fprintln(stderr, "macserve setup: --sha256 needs 64 lowercase hexadecimal characters")
		return 2
	}
	if sha != "" && sums != "" {
		fmt.Fprintln(stderr, "macserve setup: give --sha256 or --sha256sums, not both")
		return 2
	}
	if sums != "" {
		data, err := readSmallFile(sums, 64<<10)
		if err == nil {
			sha, err = setup.ReleaseDigest(data, setup.ReleaseAsset)
		}
		if err != nil {
			fmt.Fprintln(stderr, "macserve setup: --sha256sums:", err)
			return 2
		}
	}
	self, err := os.Executable()
	if err == nil {
		self, err = filepath.EvalSymlinks(self)
	}
	if err != nil {
		fmt.Fprintln(stderr, "macserve setup:", err)
		return 1
	}
	w := &setupWizard{
		probe: plan.SystemProbe(), in: bufio.NewReader(os.Stdin), out: stdout, root: deploy.Prefix, self: self,
		open: func(args ...string) error {
			cmd := exec.Command("/usr/bin/open", args...)
			cmd.Env, cmd.Dir = []string{setup.FixedPath}, "/"
			return cmd.Run()
		},
		sleep: time.Sleep, loginPoll: 5 * time.Second, loginWait: 30 * time.Minute,
		keychain: saveKeychainToken, homeControl: runOwnerHomeControl, ownerReport: runOwnerProbe, canaryLead: 3 * time.Second,
		restart: restartMac, healthWait: 10 * time.Minute,
	}
	if w.home, err = ownerHome(); err != nil {
		fmt.Fprintln(stderr, "macserve setup:", err)
		return 1
	}
	w.start = func(path, digest string) (setupSession, error) { return startRootHelper(path, digest, false, stderr) }
	return w.run(choices, sha, stderr)
}

func (w *setupWizard) say(format string, args ...any) { fmt.Fprintf(w.out, format+"\n", args...) }

// ask prints prompt and returns the trimmed answer; io errors are "q".
func (w *setupWizard) ask(prompt string) string {
	fmt.Fprint(w.out, prompt)
	line, err := w.in.ReadString('\n')
	if err != nil && line == "" {
		return "q"
	}
	return strings.TrimSpace(line)
}

// errStopped is a resumable stop the owner chose.
var errStopped = errors.New("stopped")

func (w *setupWizard) run(choices plan.Choices, sha string, stderr io.Writer) int {
	fail := func(err error) int {
		fmt.Fprintln(stderr, "macserve setup:", err)
		return 1
	}
	if w.probe.Elevated() {
		fmt.Fprintln(stderr, "macserve setup: run it as yourself, not with sudo; qualification refuses owner evidence gathered under sudo, and setup asks for your password once when it needs it.")
		return 2
	}
	helper, digest, err := helperIdentity(w.root, w.self, sha)
	if err != nil {
		fmt.Fprintln(stderr, "macserve setup:", err)
		return 2
	}
	var env []byte
	if _, err := os.Lstat(w.root); errors.Is(err, fs.ErrNotExist) {
		if choices.Repository == "" {
			fmt.Fprintln(stderr, "macserve setup: --repository OWNER/NAME:ID is required before install (numeric ID: gh api repos/OWNER/NAME --jq .id)")
			return 2
		}
		result := plan.Preflight(context.Background(), w.probe, choices)
		if err := plan.WritePlan(w.out, result); err != nil {
			return fail(err)
		}
		if !result.Ready() {
			return 1
		}
		env = result.Environment
		if w.ask("\nType yes to install macserve on this Mac as shown (sudo asks for your password once): ") != "yes" {
			w.say("Nothing was changed.")
			return 0
		}
	} else if err != nil {
		return fail(err)
	}
	session, err := w.start(helper, digest)
	if err != nil {
		return fail(err)
	}
	defer session.Close()
	for {
		resp, err := session.Call(setup.Request{Verb: setup.VerbStatus})
		if err != nil {
			return fail(err)
		}
		l, err := resp.DecodedLedger()
		if err != nil {
			return fail(err)
		}
		step := setup.StepPreflight
		if l != nil {
			next, done, err := l.Next()
			if err != nil {
				return fail(fmt.Errorf("%w. Nothing more is changed; reconcile by hand (docs/install.md) before running setup again", err))
			}
			if done {
				w.say("Setup is complete.")
				return 0
			}
			step = next.Step
		}
		switch step {
		case setup.StepPreflight:
			if env == nil {
				return fail(errors.New("preflight is not recorded and " + w.root + " exists; macserve setup does not change an existing installation"))
			}
			_, err = w.call(session, setup.Request{Verb: setup.VerbPreflight, Env: string(env)})
		case setup.StepInstall:
			err = w.install(session)
		case setup.StepGitHub:
			err = w.github(session)
		case setup.StepTools:
			w.say("\nXcode system steps (as root): accept the license, run first launch, download the Metal toolchain. This can take a while.")
			_, err = w.call(session, setup.Request{Verb: setup.VerbTools})
		case setup.StepOwnerActions:
			err = w.ownerActions(session)
		case setup.StepRound1, setup.StepRound2:
			err = w.round(session, step)
		case setup.StepReboot:
			err = w.reboot(session)
		case setup.StepApproveAndStart:
			err = w.approve(session)
		case setup.StepFirstBuild:
			return w.finish()
		}
		if errors.Is(err, errRestarting) {
			return 0
		}
		if errors.Is(err, errStopped) {
			w.say("Stopped. Run macserve setup again to continue from here.")
			return 0
		}
		if err != nil {
			return fail(err)
		}
	}
}

// call is one helper request; a response error is an error.
func (w *setupWizard) call(s setupSession, r setup.Request) (setup.Response, error) {
	return s.Call(r)
}

func (w *setupWizard) install(s setupSession) error {
	w.say("\nInstall (as root, through deploy-install): creates the controller and build accounts, /Library/macserve, TLS and receipt keys and three launchd services, all disabled, with owner.pause set.")
	w.say("sysadminctl asks for the build account's password: choose one and keep it; you log in to that account later.")
	resp, err := w.call(s, setup.Request{Verb: setup.VerbInstall})
	if resp.Token != "" {
		if kerr := w.saveToken(resp.Token); kerr != nil {
			err = errors.Join(err, kerr)
		}
		resp.Token = ""
	}
	if err != nil {
		return err
	}
	w.say("Installed.")
	return nil
}

func (w *setupWizard) installedEnv() (deploy.Environment, error) {
	return deploy.LoadEnvironment(filepath.Join(w.root, "config", "deploy.env"))
}

// github detects connect-github; until it is done it prints the exact
// commands (temporary until O5/O7, when setup does this itself).
func (w *setupWizard) github(s setupSession) error {
	for {
		resp, err := w.call(s, setup.Request{Verb: setup.VerbGitHub})
		if err != nil {
			return err
		}
		if resp.Done {
			w.say("GitHub App connected.")
			return nil
		}
		text, err := w.githubCommands()
		if err != nil {
			return err
		}
		w.say("%s", text)
		if w.ask("Press Enter when connect-github has finished (q to stop): ") == "q" {
			return errStopped
		}
	}
}

func (w *setupWizard) githubCommands() (string, error) {
	e, err := w.installedEnv()
	if err != nil {
		return "", err
	}
	var repo string
	for name := range e.Repositories {
		if repo == "" || name < repo {
			repo = name
		}
	}
	profilesPath := filepath.Join(w.root, "config", "profiles.json")
	registry, err := profiles.Load(profilesPath)
	if err != nil {
		return "", fmt.Errorf("profiles.json: %w", err)
	}
	var b strings.Builder
	b.WriteString("\nGitHub (temporary until O5/O7: setup will do this itself). In this or another terminal, run:\n")
	id := ""
	for _, p := range registry.List() {
		if p.Repo == repo && p.Template == nil {
			id = p.ID
			break
		}
	}
	if id == "" {
		p, err := w.suggestProfile(e, repo)
		if err != nil {
			return "", err
		}
		id = p.ID
		existing := registry.List()
		if len(existing) != 0 || len(registry.Templates()) != 0 {
			return "", fmt.Errorf("profiles.json already has other entries; add a build profile for %s by hand, then run: sudo %s/bin/macserve connect-github --profile ID --repository %s", repo, w.root, repo)
		}
		data, err := json.MarshalIndent(struct {
			Profiles []model.Profile `json:"profiles"`
		}{[]model.Profile{p}}, "", "  ")
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "\n1. The build profile for %s (replace YOUR_SCHEME with the Xcode scheme to build):\n\n", repo)
		fmt.Fprintf(&b, "sudo /usr/bin/tee %s >/dev/null <<'JSON'\n%s\nJSON\n", profilesPath, data)
		b.WriteString("\n2. Connect the GitHub App:\n\n")
	} else {
		fmt.Fprintf(&b, "\nConnect the GitHub App (profile %s is in profiles.json):\n\n", id)
	}
	fmt.Fprintf(&b, "sudo %s/bin/macserve connect-github --profile %s --repository %s\n", w.root, id, repo)
	return b.String(), nil
}

var xcodeVersionLine = regexp.MustCompile(`^Xcode ([0-9]+\.[0-9]+(?:\.[0-9]+)?)\nBuild version ([0-9A-Za-z]+)\n?$`)

// suggestProfile is a per-repository build profile with the installed
// developer directory's Xcode pins. It is checked with the profiles
// validator before it is printed.
func (w *setupWizard) suggestProfile(e deploy.Environment, repo string) (model.Profile, error) {
	out, err := w.probe.Run(context.Background(), []string{e.DeveloperDir + "/usr/bin/xcodebuild", "-version"})
	if err != nil {
		return model.Profile{}, fmt.Errorf("xcodebuild -version: %w", err)
	}
	m := xcodeVersionLine.FindStringSubmatch(strings.TrimSpace(out) + "\n")
	if m == nil {
		return model.Profile{}, fmt.Errorf("unexpected xcodebuild -version output %q", out)
	}
	_, name, _ := strings.Cut(repo, "/")
	id := strings.Trim(regexp.MustCompile(`[^A-Za-z0-9.-]+`).ReplaceAllString(strings.ToLower(name), "-"), "-.") + "-build-v1"
	p := model.Profile{
		ID: id, Version: 1, Repo: repo, Kind: model.Build, Xcode: model.Xcode{Version: m[1], Build: m[2]},
		DeveloperDir: e.DeveloperDir, WorkDir: ".",
		Run: model.Command{Executable: "/usr/bin/xcrun", Args: []string{
			"xcodebuild", "-scheme", "YOUR_SCHEME", "-configuration", "Debug", "-sdk", "iphonesimulator", "-destination", "generic/platform=iOS Simulator",
			"-derivedDataPath", "${DERIVED_DATA}", "CODE_SIGNING_ALLOWED=NO", "build",
		}},
		DefaultTimeoutSeconds: 1800, MaxTimeoutSeconds: 3600, MemoryLimitMiB: 32768,
	}
	if _, err := profiles.New([]model.Profile{p}, nil); err != nil {
		return model.Profile{}, fmt.Errorf("suggested profile: %w", err)
	}
	return p, nil
}

// ownerActions guides Full Disk Access and the one build-account login,
// and records the step when the helper detects both.
func (w *setupWizard) ownerActions(s setupSession) error {
	binary := filepath.Join(w.root, "bin", "macserve")
	for {
		resp, err := w.call(s, setup.Request{Verb: setup.VerbFDACheck})
		if err != nil {
			return err
		}
		if resp.Done {
			w.say("Full Disk Access: granted in launchd context.")
			break
		}
		_ = w.open("x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")
		_ = w.open("-R", binary)
		w.say("\nFull Disk Access: System Settings > Privacy & Security > Full Disk Access is open, and Finder shows %s.", binary)
		w.say("Click +, choose %s (in the file dialog press Command-Shift-G and paste the path), and turn it on. macserve's services need it to inspect the build account's files.", binary)
		if w.ask("Press Enter to check again (q to stop): ") == "q" {
			return errStopped
		}
	}
	if err := w.waitJobLogin(s, "once"); err != nil {
		return err
	}
	resp, err := w.call(s, setup.Request{Verb: setup.VerbOwnerActions})
	if err != nil {
		return err
	}
	if !resp.Done {
		w.say("Owner actions not complete yet: %s.", resp.Detail)
		return nil
	}
	w.say("Owner actions recorded.")
	return nil
}

// waitJobLogin polls the build account's GUI session and the console
// until the build account is logged in in the background and the owner
// (or the login window) holds the screen; it explains how once.
func (w *setupWizard) waitJobLogin(s setupSession, when string) error {
	e, err := w.installedEnv()
	if err != nil {
		return err
	}
	shown := false
	deadline := time.Now().Add(w.loginWait)
	for {
		resp, err := w.call(s, setup.Request{Verb: setup.VerbJobLogin})
		if err != nil {
			return err
		}
		if resp.Done {
			return nil
		}
		if !shown {
			w.say("\nLog in to the build account %s, then come back:", when)
			w.say("  1. Control Center > your name > %q (or Apple menu > Lock Screen and choose it), and log in with the password you chose at install.", e.JobRealName)
			w.say("  2. When its desktop appears, Control Center > %q > Switch User..., and log back in to your own account.", e.JobRealName)
			w.say("  Do not open or type anything in the build account. Setup notices both steps on its own.")
			shown = true
		}
		if time.Now().After(deadline) {
			w.say("Not detected yet: %s.", resp.Detail)
			return errStopped
		}
		w.sleep(w.loginPoll)
	}
}

func readSmallFile(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err == nil && int64(len(data)) > max {
		err = errors.New("file too large")
	}
	return data, err
}

// helperIdentity picks the binary sudo runs as the root helper and the
// digest it is started with; the helper re-hashes itself and refuses a
// mismatch.
//   - After install it is the root-owned root/bin/macserve. Its digest
//     identifies it; the helper requires that digest to be the one install
//     recorded. A given --sha256 must match too.
//   - Before install it is this binary, which the owner downloaded. Its
//     digest is never taken from the file itself: want must come from the
//     release (--sha256 or --sha256sums), and this binary must match it
//     before sudo is asked for.
func helperIdentity(root, self, want string) (string, string, error) {
	installed := filepath.Join(root, "bin", "macserve")
	if info, err := os.Lstat(installed); err == nil {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !info.Mode().IsRegular() || !ok || st.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
			return "", "", fmt.Errorf("%s is not a root-owned binary; macserve setup does not run it", installed)
		}
		digest, err := fileDigest(installed)
		if err != nil {
			return "", "", err
		}
		if want != "" && digest != want {
			return "", "", fmt.Errorf("%s has SHA-256 %s, not the one you gave; nothing was changed", installed, digest)
		}
		return installed, digest, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", "", err
	}
	if want == "" {
		return "", "", fmt.Errorf("before install, give the release digest of this binary: --sha256sums SHA256SUMS (from the same release; verify it first with gh attestation verify %s --repo jerryfane/macserve) or --sha256 HEX", setup.ReleaseAsset)
	}
	digest, err := fileDigest(self)
	if err != nil {
		return "", "", err
	}
	if digest != want {
		return "", "", fmt.Errorf("%s has SHA-256 %s, not the release digest %s; nothing was changed", self, digest, want)
	}
	return self, digest, nil
}

// startRootHelper starts the one root helper, sudo path _setup-root
// [--upgrade] --sha256 digest, and connects to it.
func startRootHelper(path, digest string, upgrade bool, stderr io.Writer) (setupSession, error) {
	argv := []string{path, "_setup-root", "--sha256", digest}
	if upgrade {
		argv = []string{path, "_setup-root", "--upgrade", "--sha256", digest}
	}
	cmd := exec.Command("/usr/bin/sudo", argv...)
	cmd.Env, cmd.Dir = []string{setup.FixedPath, "LANG=C"}, "/"
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	deadline := time.Now().Add(10 * time.Minute)
	for {
		select {
		case err := <-exited:
			return nil, fmt.Errorf("the root helper exited (%v); nothing more was changed", err)
		default:
		}
		if c, err := setup.Dial(setup.SocketDir, 0); err == nil {
			return &helperSession{Client: c, exited: exited}, nil
		} else if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			return nil, fmt.Errorf("cannot reach the root helper: %w", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// helperSession waits for the helper to exit when it is closed.
type helperSession struct {
	*setup.Client
	exited chan error
}

func (s *helperSession) Close() error {
	err := s.Client.Close()
	select {
	case <-s.exited:
	case <-time.After(10 * time.Second):
	}
	return err
}

func fileDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, 256<<20+1)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func runSetupRoot(args []string, stdout, stderr io.Writer) int {
	return setup.RunRoot(args, stdout, stderr)
}

func runFDACheck(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "Usage: macserve _fda-check")
		return 2
	}
	return setup.FDACheck(stdout, os.Getppid(), func(path string) (io.Closer, error) { return os.Open(path) })
}

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/jerryfane/macserve/internal/qualification"
	"github.com/jerryfane/macserve/internal/setup"
)

// The wizard's part of qualification and approve-and-start (design §3.2
// steps 6-9). The owner canary, the owner-home control and the owner probe
// run here, as the owner and never under sudo; everything else is a helper
// verb.

// errRestarting: the Mac is restarting; setup resumes after the restart.
var errRestarting = errors.New("restarting")

// keychainService is the owner's login keychain item of the API token.
const keychainService = "macserve API token"

// apiToken is deploy-install's token: 256 random bits in hex.
var apiToken = regexp.MustCompile(`^[0-9a-f]{64}$`)

// saveToken puts the one-time API token into the owner's login keychain.
// It is never printed, unless the keychain refuses it and the owner asks
// for it once (decision D11: "never printed unless asked").
func (w *setupWizard) saveToken(token string) error {
	if !apiToken.MatchString(token) {
		return errors.New("deploy-install returned an API token of an unexpected form; it was not stored or shown")
	}
	err := w.keychain(token)
	if err == nil {
		w.say("Your API token is saved in your login keychain as %q.", keychainService)
		return nil
	}
	w.say("Your login keychain did not accept the API token (%v). It exists only now: it is not stored anywhere else.", err)
	if w.ask(`Type "show" to display it once so you can save it yourself (anything else discards it): `) == "show" {
		fmt.Fprintln(w.out, token)
		return nil
	}
	return errors.New("the API token was discarded; a new one needs a reviewed credential rotation (docs/configuration.md)")
}

// round runs one qualification round: job login detected, review
// confirmed, session begun, owner-home control started, root job probe,
// owner probe, tool evidence and collection.
func (w *setupWizard) round(s setupSession, step setup.Step) error {
	n := strings.TrimPrefix(string(step), "round-")
	when := "again after the restart"
	if step == setup.StepRound1 {
		when = "(it may still be logged in from before)"
	}
	if err := w.waitJobLogin(s, when); err != nil {
		return err
	}
	w.say("\nQualification round %s.", n)
	resp, err := w.call(s, setup.Request{Verb: setup.VerbRoundPrepare})
	if err != nil {
		return err
	}
	session := resp.Session
	switch {
	case resp.Review != nil:
		if err := w.confirmReview(resp.Review); err != nil {
			return err
		}
		if err := w.ensureCanary(); err != nil {
			return err
		}
		w.say("Resetting the build account's baseline and beginning the round (about a minute) ...")
		if resp, err = w.call(s, setup.Request{Verb: setup.VerbRoundBegin, SHA256: resp.Review.Digest}); err != nil {
			return err
		}
		session = resp.Session
	case session != "":
		w.say("Continuing qualification session %s.", session)
	default:
		w.say("Not ready: %s.", resp.Detail)
		return errStopped
	}
	if err := w.ownerSide(s, session); err != nil {
		return err
	}
	w.say("Tool evidence: building your repository as the build account, then collecting the round (about 10 minutes) ...")
	resp, err = w.call(s, setup.Request{Verb: setup.VerbRoundCollect})
	if err != nil {
		return err
	}
	if !resp.Done {
		for _, item := range resp.Items {
			w.say("  ✗ %s", item)
		}
		return fmt.Errorf("round %s did not pass; nothing was approved. Fix the items above, then run macserve setup again to begin a new round", n)
	}
	passed := 0
	for _, status := range resp.Categories {
		if status == "pass" {
			passed++
		}
	}
	w.say("Round %s: %d/%d categories passed.", n, passed, len(resp.Categories))
	if step == setup.StepRound1 {
		w.say(`"reboot" passes in round 2, after a restart.`)
	}
	return nil
}

// confirmReview shows the build account's login items and agents and the
// baseline proposal. An empty list is accepted without a question
// (decision D6); anything listed needs the typed word accept. The baseline
// needs y.
func (w *setupWizard) confirmReview(r *setup.RoundReview) error {
	if len(r.Persistence) == 0 {
		w.say("  Build account has 0 third-party login items or agents ✓")
	} else {
		w.say("  The build account has these third-party login items or agents:")
		for _, item := range r.Persistence {
			w.say("    %s", item)
		}
		if r.Accept && w.ask(`  Each one runs in the build account with every build. Type "accept" to trust them, anything else stops: `) != "accept" {
			return errStopped
		}
	}
	w.say("  Build-session processes: %d, all Apple system programs (SIP-protected, root-owned, not shells or Terminal):", r.Processes)
	w.say("    %s", strings.Join(r.Executables, ", "))
	if a := w.ask("  Use this as the baseline? [y/N] "); a != "y" && a != "Y" {
		return errStopped
	}
	return nil
}

// ensureCanary creates the nonsecret owner-home canary (mode 0644) once.
func (w *setupWizard) ensureCanary() error {
	path := setup.OwnerCanary(w.home)
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o644 {
			return fmt.Errorf("%s exists but is not a regular file with mode 0644; remove it and run macserve setup again", path)
		}
		return nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	_, err = io.WriteString(f, setup.OwnerCanaryContent)
	return errors.Join(err, f.Chmod(0o644), f.Sync(), f.Close())
}

// ownerSide runs the owner-home control around the root job probe and
// the owner probe; their files go to setup.OwnerFiles.
func (w *setupWizard) ownerSide(s setupSession, session string) error {
	dir, report, receipts := setup.OwnerFiles(w.home, session)
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return err
	}
	// Files of an interrupted attempt in this session are the owner's own
	// and not evidence yet: start again.
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}
	sessionDir := filepath.Join(w.root, "var", "qualification", session)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	control := make(chan error, 1)
	go func() { control <- w.homeControl(ctx, sessionDir, receipts) }()
	w.sleep(w.canaryLead)
	select {
	case err := <-control:
		return fmt.Errorf("owner-home control: %w", errors.Join(err, errors.New("it ended before the probes")))
	default:
	}
	w.say("Job probe (as the build account, in the background) ...")
	_, err := w.call(s, setup.Request{Verb: setup.VerbRoundJobProbe})
	if err == nil {
		w.say("Owner probe (as you) ...")
		err = w.ownerReport(context.Background(), sessionDir, report)
	}
	cancel()
	if cerr := <-control; cerr != nil {
		err = errors.Join(err, fmt.Errorf("owner-home control: %w", cerr))
	}
	return err
}

// reboot prints how to restart and the after-boot steps, and restarts on
// a typed y; after the restart the helper records the new boot.
func (w *setupWizard) reboot(s setupSession) error {
	resp, err := w.call(s, setup.Request{Verb: setup.VerbReboot})
	if err != nil {
		return err
	}
	if resp.Done {
		w.say("\nThe Mac restarted; continuing.")
		return nil
	}
	if len(resp.Items) != 1 {
		return errors.New("the setup helper did not say how to restart")
	}
	kind := resp.Items[0]
	w.say("\nRestart (about 5 minutes). Qualification needs a round on a new boot.")
	switch kind {
	case setup.RestartAuth:
		w.say("FileVault is on: fdesetup asks for your password now, not after the restart; macserve never sees it.")
	case setup.RestartUnlock:
		w.say("FileVault is on and this Mac cannot restart with authentication: unlock the disk at this Mac after the restart.")
	}
	w.say("%s", resp.Detail)
	if a := w.ask("Restart now? [y/N] "); a != "y" && a != "Y" {
		w.say("Restart when you are ready (Apple menu > Restart), then follow the steps above.")
		return errStopped
	}
	if err := w.restart(kind); err != nil {
		return fmt.Errorf("restart: %w", err)
	}
	w.say("Restarting.")
	return errRestarting
}

// approve shows the summary and records the typed approval; the helper
// approves, checks the activation anchor and starts the services. Then,
// in this run only, it waits for valid health and removes owner.pause
// (decision D15).
func (w *setupWizard) approve(s setupSession) error {
	resp, err := w.call(s, setup.Request{Verb: setup.VerbSummary})
	if err != nil {
		return err
	}
	summary := resp.Detail
	w.say("\n%s", summary)
	if w.ask(`Type "approve" to record your approval and start macserve (anything else stops): `) != "approve" {
		return errStopped
	}
	sum := sha256.Sum256([]byte(summary))
	resp, err = w.call(s, setup.Request{Verb: setup.VerbApprove, SHA256: hex.EncodeToString(sum[:])})
	if err != nil {
		for _, line := range resp.Items {
			w.say("  %s", line)
		}
		return err
	}
	w.say("✓ approved, activation anchor written, services started: %s.", strings.Join(resp.Items, ", "))
	return w.releasePause(s)
}

// releasePause waits for valid health and has the helper remove
// owner.pause. The helper serves it once, right after it started the
// services; on timeout owner.pause stays for the owner to remove.
func (w *setupWizard) releasePause(s setupSession) error {
	w.say("\nWaiting for valid health before macserve accepts builds ...")
	deadline := time.Now().Add(w.healthWait)
	for {
		resp, err := w.call(s, setup.Request{Verb: setup.VerbReleasePause})
		if err != nil {
			return err
		}
		if resp.Done {
			w.say("✓ %s; macserve accepts builds. Your API token is in your login keychain as %q.", resp.Detail, keychainService)
			return nil
		}
		if time.Now().After(deadline) {
			slices.Sort(resp.Items)
			w.say("Health is not valid yet (%s); owner.pause stays.", strings.Join(resp.Items, ", "))
			w.say("%s", pauseByHand)
			return nil
		}
		w.sleep(w.loginPoll)
	}
}

// pauseByHand is how the owner removes owner.pause when setup did not.
const pauseByHand = "setup removes owner.pause only right after it starts the services, never later. Once GET /v1/admin/state reports health valid with only the owner marker blocking, remove it yourself: sudo rm /Library/macserve/config/owner.pause (docs/install.md)."

// finish is setup at the first build, which this release does not run.
// It never removes owner.pause: a pause set after the start is the
// owner's.
func (w *setupWizard) finish() int {
	w.say("\nmacserve is approved and its services are started. The first build through setup is not in this release; see docs/install.md to start one.")
	w.say("If owner.pause is still present: %s", pauseByHand)
	return 0
}

// ownerHome is the invoking user's home directory.
func ownerHome() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(u.HomeDir) || u.HomeDir == "/" {
		return "", errors.New("your home directory is unavailable")
	}
	return u.HomeDir, nil
}

// saveKeychainToken runs security as the owner and passes the command on
// its standard input, so the token is never in an argument list.
func saveKeychainToken(token string) error {
	u, err := user.Current()
	if err != nil {
		return err
	}
	if !regexp.MustCompile(`^[a-z_][a-z0-9_]{0,31}$`).MatchString(u.Username) {
		return errors.New("unexpected account name")
	}
	cmd := exec.Command("/usr/bin/security", "-i")
	cmd.Env, cmd.Dir = []string{setup.FixedPath, "HOME=" + u.HomeDir}, "/"
	cmd.Stdin = strings.NewReader(fmt.Sprintf("add-generic-password -U -a %s -s %q -w %s\n", u.Username, keychainService, token))
	out, err := cmd.CombinedOutput()
	if err == nil && len(strings.TrimSpace(string(out))) > 0 {
		err = errors.New(strings.TrimSpace(string(out)))
	}
	return err
}

// runOwnerHomeControl is `qualify canary --transport owner-home` until ctx
// ends.
func runOwnerHomeControl(ctx context.Context, sessionDir, out string) error {
	return qualification.Canary(ctx, sessionDir, "", "owner-home", out, 90*time.Minute)
}

// runOwnerProbe is `qualify probe --role owner`.
func runOwnerProbe(ctx context.Context, sessionDir, out string) error {
	return qualification.Probe(ctx, sessionDir, "owner", out)
}

// restartMac restarts through sudo on the owner's terminal: fdesetup
// authrestart prompts for the FileVault password itself.
func restartMac(kind string) error {
	argv := []string{"/sbin/shutdown", "-r", "now"}
	if kind == setup.RestartAuth {
		argv = []string{"/usr/bin/fdesetup", "authrestart"}
	}
	cmd := exec.Command("/usr/bin/sudo", argv...)
	cmd.Env, cmd.Dir = []string{setup.FixedPath, "LANG=C"}, "/"
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

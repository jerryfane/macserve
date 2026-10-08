package source

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// gitCommand deliberately does not inherit the controller environment. In
// particular config injection, proxies, alternate objects, tracing, askpass,
// executable overrides and credential helpers cannot cross this boundary.
func gitCommand(ctx context.Context, dir string, authentication []string, args ...string) *exec.Cmd {
	command := exec.CommandContext(ctx, "/usr/bin/git", args...)
	command.Dir = dir
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	command.Env = []string{
		"PATH=/usr/bin:/bin", "HOME=" + dir, "XDG_CONFIG_HOME=" + dir, "TMPDIR=" + dir,
		"LANG=C", "LC_ALL=C", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=/usr/bin/false",
		"GIT_NO_REPLACE_OBJECTS=1", "GIT_ATTR_NOSYSTEM=1", "GIT_OPTIONAL_LOCKS=0",
	}
	config := []string{
		"credential.helper", "", "credential.interactive", "false",
		"core.hooksPath", "/dev/null", "core.attributesFile", "/dev/null",
		"protocol.allow", "never", "protocol.https.allow", "always",
		"http.followRedirects", "false", "http.sslVerify", "true",
		"fetch.recurseSubmodules", "false", "submodule.recurse", "false",
		"fetch.fsckObjects", "true", "transfer.fsckObjects", "true",
		"gc.auto", "0", "maintenance.auto", "false", "fetch.unpackLimit", "0",
	}
	config = append(config, authentication...)
	command.Env = append(command.Env, "GIT_CONFIG_COUNT="+strconv.Itoa(len(config)/2))
	for i := 0; i < len(config); i += 2 {
		command.Env = append(command.Env, "GIT_CONFIG_KEY_"+strconv.Itoa(i/2)+"="+config[i], "GIT_CONFIG_VALUE_"+strconv.Itoa(i/2)+"="+config[i+1])
	}
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.WaitDelay = time.Second
	return command
}

func runGit(ctx context.Context, dir string, authentication []string, args ...string) error {
	return sourceError("git", gitCommand(ctx, dir, authentication, args...).Run())
}

func gitOutput(ctx context.Context, dir string, args ...string) ([]byte, error) {
	var output bytes.Buffer
	command := gitCommand(ctx, dir, nil, args...)
	command.Stdout = &boundedWriter{writer: &output, remaining: 8192}
	if err := command.Run(); err != nil {
		return nil, sourceError("git inspection", err)
	}
	return output.Bytes(), nil
}

func fetch(ctx context.Context, dir, repo, sha, token string, limit int64) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	url := "https://github.com/" + repo + ".git"
	var authentication []string
	if token != "" {
		credential := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))
		authentication = []string{"http." + url + ".extraHeader", "Authorization: Basic " + credential}
	}
	command := gitCommand(ctx, dir, authentication, "--git-dir=repo.git", "fetch", "--depth=1", "--no-tags", "--no-recurse-submodules", "--no-write-fetch-head", "--no-auto-maintenance", url, sha)
	if err := command.Start(); err != nil {
		return sourceError("fetch", err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			if err != nil {
				return sourceError("fetch", err)
			}
			return stageBudget(dir, limit)
		case <-ticker.C:
			if err := stageBudget(dir, limit); err != nil {
				cancel()
				<-done
				return err
			}
		case <-ctx.Done():
			cancel()
			<-done
			return ctx.Err()
		}
	}
}

// Fetch is monitored separately from the strict uncompressed archive limit:
// even a server streaming an oversized pack is stopped before export begins.
func stageBudget(dir string, limit int64) error {
	var size int64
	entries := 0
	return filepath.WalkDir(dir, func(_ string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		entries++
		if entries > 100000 {
			return errors.New("source staging entry limit exceeded")
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return errors.New("unexpected source staging file")
		}
		info, err := entry.Info()
		if err != nil {
			// Git atomically renames temporary pack files during fetch.
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if info.Size() > limit-size {
			return errors.New("source staging exceeds byte limit")
		}
		size += info.Size()
		return nil
	})
}

func inspectCommit(ctx context.Context, dir, sha string) (string, error) {
	kind, err := gitOutput(ctx, dir, "--git-dir=repo.git", "cat-file", "-t", sha)
	if err != nil {
		return "", err
	}
	if string(kind) != "commit\n" {
		return "", errors.New("source SHA is not a commit")
	}
	commit, err := gitOutput(ctx, dir, "--git-dir=repo.git", "rev-parse", "--verify", sha+"^{commit}")
	if err != nil {
		return "", err
	}
	if string(commit) != sha+"\n" {
		return "", errors.New("source commit mismatch")
	}
	tree, err := gitOutput(ctx, dir, "--git-dir=repo.git", "rev-parse", "--verify", sha+"^{tree}")
	if err != nil {
		return "", err
	}
	identity := strings.TrimSuffix(string(tree), "\n")
	if !shaPattern.MatchString(identity) {
		return "", errors.New("invalid source tree identity")
	}
	return identity, nil
}

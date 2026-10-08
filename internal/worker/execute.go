package worker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jerryfane/macserve/internal/evidence"
	"github.com/jerryfane/macserve/internal/hostguard"
	"github.com/jerryfane/macserve/internal/model"
	"golang.org/x/sys/unix"
)

const maxLogBytes = 256 << 20

type execution struct {
	engine         *Engine
	job            model.Job
	result         *Result
	manifest       manifest
	workspace      string
	root           *os.Root
	sink           Sink
	evidenceRoot   *os.Root
	ranRecipe      bool
	stdout, stderr *logWriter
	cancel         context.CancelFunc
	logs           *logState
}

type logState struct {
	mu        sync.Mutex
	size      int64
	err       error
	truncated bool
}
type logWriter struct {
	state  *logState
	file   *os.File
	stream string
	sink   Sink
	cancel context.CancelFunc
}

func (w *logWriter) Write(data []byte) (int, error) {
	w.state.mu.Lock()
	defer w.state.mu.Unlock()
	if w.state.err != nil {
		return 0, w.state.err
	}
	if int64(len(data)) > maxLogBytes-w.state.size {
		w.state.truncated = true
		w.state.err = errors.New("raw log limit exceeded")
		w.cancel()
		return 0, w.state.err
	}
	n, err := w.file.Write(data)
	w.state.size += int64(n)
	if err == nil && w.sink != nil {
		for offset := 0; offset < n; {
			end := min(offset+32<<10, n)
			if err = w.sink.Log(w.stream, string(data[offset:end])); err != nil {
				break
			}
			offset = end
		}
	}
	if err != nil {
		w.state.err = err
		w.cancel()
	}
	return n, err
}

type boundedBuffer struct {
	bytes.Buffer
	max int
	err error
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	if len(p) > b.max-b.Len() {
		b.err = errors.New("command output limit exceeded")
		return 0, b.err
	}
	return b.Buffer.Write(p)
}

func (e *Engine) Execute(parent context.Context, job model.Job, source Source, archive io.Reader, sink Sink) (result Result, returned error) {
	result = Result{State: model.Failed, Source: source, StartedAt: e.options.Now()}
	if !e.mu.TryLock() {
		return result, ErrBusy
	}
	defer e.mu.Unlock()
	if e.closed {
		return result, ErrClosed
	}
	e.recording = &result
	defer func() { e.recording = nil }()
	job, err := validateJob(job, source)
	if err != nil {
		return result, err
	}
	if _, native := e.options.Runner.(*nativeRunner); native {
		if err := hostguard.ToolchainDirectory(job.Profile.DeveloperDir, e.options.JobUID); err != nil {
			return result, err
		}
	}
	names, err := e.registryNames()
	if err != nil {
		return result, err
	}
	if len(names) > 0 {
		return result, ErrRecovery
	}
	if err := e.admission(parent); err != nil {
		return result, err
	}
	if _, err := e.exports.Lstat(job.ID); !os.IsNotExist(err) {
		return result, errors.New("job export already exists or is inaccessible")
	}
	if _, err := e.workspaces.Lstat(job.ID); !os.IsNotExist(err) {
		return result, errors.New("job workspace already exists or is inaccessible")
	}
	deadline := time.Now().Add(time.Duration(job.Request.TimeoutSeconds) * time.Second)
	if job.Deadline != nil && job.Deadline.Before(deadline) {
		deadline = *job.Deadline
	}
	ctx, deadlineCancel := context.WithDeadline(parent, deadline)
	defer deadlineCancel()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	x := &execution{engine: e, job: job, result: &result, workspace: filepath.Join(e.options.WorkspaceRoot, job.ID), sink: sink, cancel: cancel, logs: &logState{}, manifest: manifest{JobID: job.ID, DeveloperDir: job.Profile.DeveloperDir}}
	if err := e.saveManifest(x.manifest); err != nil {
		return result, err
	}
	defer func() {
		finalCtx, finalCancel := context.WithTimeout(context.Background(), e.options.CleanupTimeout)
		defer finalCancel()
		if sink != nil {
			returned = errors.Join(returned, sink.Stage(model.Finalizing))
		}
		// Stop simulators and all escaped/orphan job-UID writers before running
		// the pinned extractor. A second UID barrier follows that subprocess.
		quietErr := e.stopWriters(finalCtx, &x.manifest)
		returned = errors.Join(returned, quietErr)
		var evidenceErr error
		if quietErr == nil && x.root != nil {
			evidenceErr = e.workspacePass(finalCtx, job.ID, false, false)
			returned = errors.Join(returned, evidenceErr)
		}
		if quietErr == nil && evidenceErr == nil && x.root != nil {
			returned = errors.Join(returned, x.checkLockfiles(finalCtx))
			if x.ranRecipe && job.Request.Kind != model.Build {
				returned = errors.Join(returned, x.testEvidence(finalCtx))
			}
		}
		if x.stdout != nil {
			returned = errors.Join(returned, x.stdout.file.Close(), x.stderr.file.Close())
		}
		x.logs.mu.Lock()
		result.LogsTruncated = x.logs.truncated
		returned = errors.Join(returned, x.logs.err)
		x.logs.mu.Unlock()
		if x.root != nil {
			if quietErr == nil && evidenceErr == nil {
				returned = errors.Join(returned, x.collect(finalCtx))
			}
			returned = errors.Join(returned, x.root.Close())
		}
		if x.evidenceRoot != nil {
			returned = errors.Join(returned, x.evidenceRoot.Close())
		}
		quietErr = errors.Join(quietErr, e.options.Runner.Quiesce(finalCtx))
		if quietErr == nil {
			if inspector, ok := e.options.Runner.(interface{ Admission(context.Context) error }); ok {
				quietErr = inspector.Admission(finalCtx)
			}
		}
		var cleanupErr error
		if quietErr == nil {
			cleanupErr = e.cleanup(finalCtx, &x.manifest)
		}
		returned = e.quarantine(errors.Join(returned, quietErr, cleanupErr))
		result.CleanupOK = quietErr == nil && cleanupErr == nil && !errors.Is(returned, ErrContamination)
		switch {
		case parent.Err() == context.Canceled || job.CancelRequested:
			result.State = model.Cancelled
		case errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(returned, context.DeadlineExceeded):
			result.State = model.TimedOut
		case returned != nil:
			result.State = model.Failed
		default:
			result.State = model.Succeeded
		}
		if returned != nil {
			result.Reason = returned.Error()
		}
		result.FinishedAt = e.options.Now()
	}()
	preflightCtx, preflightCancel := context.WithTimeout(context.Background(), e.options.CleanupTimeout)
	preflightErr := e.options.Runner.Quiesce(preflightCtx)
	preflightCancel()
	if preflightErr != nil {
		return result, e.quarantine(preflightErr)
	}
	if job.CancelRequested {
		return result, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if err := e.workspaces.Mkdir(job.ID, 0700); err != nil {
		return result, err
	}
	x.root, err = e.workspaces.OpenRoot(job.ID)
	if err != nil {
		return result, err
	}
	for _, dir := range []string{"checkout", "home", "tmp", "caches", "derived-data"} {
		if err := x.root.Mkdir(dir, 0700); err != nil {
			return result, err
		}
	}
	if err := e.root.MkdirAll("evidence/"+job.ID+"/evidence", 0700); err != nil {
		return result, err
	}
	x.evidenceRoot, err = e.root.OpenRoot("evidence/" + job.ID)
	if err != nil {
		return result, err
	}
	stdout, err := x.evidenceRoot.OpenFile("evidence/stdout.log", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return result, err
	}
	stderr, err := x.evidenceRoot.OpenFile("evidence/stderr.log", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		stdout.Close()
		return result, err
	}
	x.stdout = &logWriter{state: x.logs, file: stdout, stream: "stdout", sink: sink, cancel: cancel}
	x.stderr = &logWriter{state: x.logs, file: stderr, stream: "stderr", sink: sink, cancel: cancel}
	prepareCtx, prepareCancel := context.WithTimeout(ctx, 10*time.Minute)
	checkout, err := x.root.OpenRoot("checkout")
	if err != nil {
		prepareCancel()
		return result, err
	}
	err = extractSource(prepareCtx, checkout, archive, source, e.options.MaxWorkspaceBytes)
	closeErr := checkout.Close()
	if err = errors.Join(err, closeErr); err != nil {
		prepareCancel()
		return result, err
	}
	result.Observation.LockfileDigests, err = lockfiles(prepareCtx, x.root, uint32(os.Geteuid()))
	if err != nil {
		prepareCancel()
		return result, err
	}
	// Application-level monitoring can overshoot between samples. Stage-boundary
	// checks supplement the low-frequency scan without hammering DerivedData.
	monitorCtx, stopMonitor := context.WithCancel(ctx)
	monitorDone := make(chan struct{})
	diskFailure := make(chan error, 1)
	go func() {
		defer close(monitorDone)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-monitorCtx.Done():
				return
			case <-ticker.C:
				if err := workspaceBudget(x.root, e.options.MaxWorkspaceBytes); err != nil {
					diskFailure <- err
					cancel()
					return
				}
			}
		}
	}()
	defer func() {
		stopMonitor()
		<-monitorDone
		select {
		case err := <-diskFailure:
			returned = errors.Join(returned, err)
		default:
		}
		returned = errors.Join(returned, workspaceBudget(x.root, e.options.MaxWorkspaceBytes))
	}()
	err = x.prepare(prepareCtx)
	prepareCancel()
	if err != nil {
		return result, err
	}
	if err := x.checkLockfiles(ctx); err != nil {
		return result, err
	}
	if sink != nil {
		if err := sink.Stage(model.Running); err != nil {
			cancel()
			return result, err
		}
	}
	x.ranRecipe = true
	returned = x.recipe(ctx, job.Profile.Run)
	return result, returned
}

func (x *execution) prepare(ctx context.Context) error {
	x.result.Observation.GeneratedDigests = make(map[string]string, len(x.job.Profile.GeneratedFiles))
	for _, generated := range x.job.Profile.GeneratedFiles {
		name := "checkout/" + generated.Path
		if !safeRelative(generated.Path) {
			return errors.New("unsafe generated file path")
		}
		size := int64(len(generated.Content))
		if size > x.engine.options.MaxWorkspaceBytes {
			return errors.New("generated file exceeds workspace budget")
		}
		if err := workspaceBudget(x.root, x.engine.options.MaxWorkspaceBytes-size); err != nil {
			return err
		}
		if err := x.root.MkdirAll(path.Dir(name), 0700); err != nil {
			return err
		}
		file, err := x.root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return fmt.Errorf("generated file would overwrite source or another generated file: %w", err)
		}
		_, writeErr := io.WriteString(file, generated.Content)
		closeErr := file.Close()
		if err := errors.Join(writeErr, closeErr); err != nil {
			return err
		}
		digest := sha256.Sum256([]byte(generated.Content))
		x.result.Observation.GeneratedDigests[generated.Path] = hex.EncodeToString(digest[:])
	}
	if err := x.engine.workspacePass(ctx, x.job.ID, true, false); err != nil {
		return err
	}
	if err := x.observe(ctx); err != nil {
		return err
	}
	if err := x.simulator(ctx); err != nil {
		return err
	}
	for _, command := range x.job.Profile.Prepare {
		if err := x.recipe(ctx, command); err != nil {
			return err
		}
		if err := workspaceBudget(x.root, x.engine.options.MaxWorkspaceBytes); err != nil {
			return err
		}
	}
	return workspaceBudget(x.root, x.engine.options.MaxWorkspaceBytes)
}

func (x *execution) invoke(ctx context.Context, command Command, stdout, stderr io.Writer) (ProcessResult, error) {
	if err := ctx.Err(); err != nil {
		return ProcessResult{}, err
	}
	result, err := x.engine.run(ctx, command, stdout, stderr)
	if !result.CleanupOK {
		err = errors.Join(err, errors.New("process cleanup was not confirmed"))
	}
	if result.ExitCode != 0 || result.Signal != "" {
		err = errors.Join(err, fmt.Errorf("command failed: exit %d signal %s", result.ExitCode, result.Signal))
	}
	return result, x.engine.quarantine(err)
}

func (x *execution) command(executable string, args []string) Command {
	return Command{Executable: executable, Args: args, Dir: x.workspace, Env: environment(x.workspace, x.job.Profile.DeveloperDir), MemoryLimitMiB: x.job.Profile.MemoryLimitMiB}
}

func (x *execution) capture(ctx context.Context, executable string, args ...string) ([]byte, error) {
	output := &boundedBuffer{max: evidence.MaxTestsBytes}
	_, err := x.invoke(ctx, x.command(executable, args), io.MultiWriter(output, x.stdout), x.stderr)
	return output.Bytes(), errors.Join(err, output.err)
}

func (x *execution) recipe(ctx context.Context, recipe model.Command) error {
	replacement := strings.NewReplacer("${CHECKOUT}", filepath.Join(x.workspace, "checkout"), "${WORKSPACE}", x.workspace, "${DERIVED_DATA}", filepath.Join(x.workspace, "derived-data"), "${RESULT_BUNDLE}", filepath.Join(x.workspace, "results.xcresult"), "${SIMULATOR_ID}", x.manifest.DeviceUDID, "${JOB_ID}", x.job.ID, "${DEVELOPER_DIR}", x.job.Profile.DeveloperDir)
	args := make([]string, len(recipe.Args))
	for i, arg := range recipe.Args {
		args[i] = replacement.Replace(arg)
	}
	executable := recipe.Executable
	if filepath.Base(executable) == "xcode-select" {
		return errors.New("xcode-select is forbidden")
	}
	isXcode := filepath.Base(executable) == "xcodebuild"
	if filepath.Base(executable) == "xcrun" {
		for _, arg := range args {
			if arg == "xcodebuild" {
				isXcode = true
				break
			}
			if arg == "xcode-select" {
				return errors.New("xcode-select is forbidden")
			}
		}
	}
	if isXcode {
		filtered := make([]string, 0, len(args)+8)
		testing := x.job.Request.Kind != model.Build
		for i := 0; i < len(args); i++ {
			arg := args[i]
			if arg == "test" || arg == "test-without-building" {
				testing = true
			}
			if arg == "-allowProvisioningUpdates" || arg == "-allowProvisioningDeviceRegistration" || strings.HasPrefix(arg, "-download") {
				return errors.New("Xcode profile or platform fetching is forbidden")
			}
			if arg == "-jobs" || arg == "-parallel-testing-enabled" || arg == "-maximum-concurrent-test-simulator-destinations" {
				if i+1 == len(args) {
					return errors.New("missing Xcode option value")
				}
				i++
				continue
			}
			if strings.HasPrefix(arg, "-jobs=") || strings.HasPrefix(arg, "-parallel-testing-enabled=") || strings.HasPrefix(arg, "-maximum-concurrent-test-simulator-destinations=") || strings.HasPrefix(arg, "CODE_SIGNING_ALLOWED=") {
				continue
			}
			filtered = append(filtered, arg)
		}
		args = append(filtered, "-jobs", "4", "CODE_SIGNING_ALLOWED=NO")
		if testing {
			args = append(args, "-parallel-testing-enabled", "NO", "-maximum-concurrent-test-simulator-destinations", "1")
		}
	}
	work := path.Join("checkout", x.job.Profile.WorkDir)
	if err := noSymlinkPath(x.root, work); err != nil {
		return err
	}
	info, err := x.root.Stat(work)
	if err != nil || !info.IsDir() {
		return errors.New("recipe working directory does not exist")
	}
	command := x.command(executable, args)
	command.Dir = filepath.Join(x.workspace, filepath.FromSlash(work))
	outcome, err := x.invoke(ctx, command, x.stdout, x.stderr)
	x.result.ExitCode = &outcome.ExitCode
	x.result.Signal = outcome.Signal
	return err
}

func noSymlinkPath(root *os.Root, name string) error {
	components := strings.Split(name, "/")
	for i := range components {
		info, err := root.Lstat(strings.Join(components[:i+1], "/"))
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("symlink in worker path")
		}
	}
	return nil
}

func workspaceBudget(root *os.Root, limit int64) error {
	var total int64
	entries := 0
	return fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			if name != "." && os.IsNotExist(err) {
				return nil
			}
			return err
		}
		entries++
		if entries > maxArchiveEntries {
			return errors.New("workspace entry limit exceeded")
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if !info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
			return errors.New("special file in workspace")
		}
		total += info.Size()
		if total > limit {
			return errors.New("workspace disk budget exceeded")
		}
		return nil
	})
}

func lockfiles(ctx context.Context, root *os.Root, owner uint32) (map[string]string, error) {
	digests := make(map[string]string)
	err := fs.WalkDir(root.FS(), "checkout", func(name string, entry fs.DirEntry, err error) error {
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		switch entry.Name() {
		case "Package.resolved", "Podfile.lock", "Cartfile.resolved", "Gemfile.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Cargo.lock", "go.sum":
		default:
			return nil
		}
		if !entry.Type().IsRegular() {
			return errors.New("dependency lockfile is not regular")
		}
		if err := noSymlinkPath(root, name); err != nil {
			return err
		}
		file, err := root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if err != nil {
			return err
		}
		var stat unix.Stat_t
		if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
			file.Close()
			return err
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != owner || stat.Nlink != 1 || stat.Size > 16<<20 {
			file.Close()
			return errors.New("dependency lockfile has unsafe ownership, links, type or size")
		}
		h := sha256.New()
		n, copyErr := io.Copy(h, io.LimitReader(&contextReader{ctx: ctx, reader: file}, (16<<20)+1))
		if n > 16<<20 {
			copyErr = errors.New("dependency lockfile grew beyond limit")
		}
		closeErr := file.Close()
		if err := errors.Join(copyErr, closeErr); err != nil {
			return err
		}
		digests[strings.TrimPrefix(name, "checkout/")] = hex.EncodeToString(h.Sum(nil))
		return nil
	})
	return digests, err
}

func (x *execution) checkLockfiles(ctx context.Context) error {
	owner := x.engine.options.JobUID
	if _, native := x.engine.options.Runner.(*nativeRunner); !native {
		owner = uint32(os.Geteuid())
	}
	after, err := lockfiles(ctx, x.root, owner)
	for name, digest := range x.result.Observation.LockfileDigests {
		if after[name] != digest {
			err = errors.Join(err, fmt.Errorf("tracked dependency lockfile mutated: %s", name))
		}
	}
	for name, digest := range after {
		if _, exists := x.result.Observation.LockfileDigests[name]; !exists {
			x.result.Observation.LockfileDigests[name] = digest
		}
	}
	return err
}

func (x *execution) testEvidence(ctx context.Context) error {
	tool := filepath.Join(x.job.Profile.DeveloperDir, "usr/bin/xcresulttool")
	if _, native := x.engine.options.Runner.(*nativeRunner); native {
		if err := hostguard.ToolchainExecutable(tool, x.engine.options.JobUID); err != nil {
			return err
		}
	}
	raw, commandErr := x.capture(ctx, tool, "get", "test-results", "tests", "--schema-version", "0.4.0", "--path", filepath.Join(x.workspace, "results.xcresult"), "--compact")
	// Extraction can load hostile bundle contents; its descendants are subject
	// to the same full-UID barrier before parsing or sealing anything.
	if err := x.engine.stopWriters(ctx, &x.manifest); err != nil {
		return errors.Join(commandErr, err)
	}
	if commandErr != nil {
		return commandErr
	}
	writeErr := x.writeEvidence("tests.json", raw)
	summary, parseErr := evidence.ParseTests(raw, x.job.Profile.RequiredTests)
	x.result.Summary = &summary
	var failed error
	if summary.Failed > 0 {
		failed = errors.New("test evidence contains failed tests")
	}
	return errors.Join(writeErr, parseErr, failed)
}

func (x *execution) writeEvidence(name string, data []byte) error {
	file, err := x.evidenceRoot.OpenFile("evidence/"+name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	return errors.Join(writeErr, file.Close())
}

func (x *execution) collect(ctx context.Context) error {
	if err := x.engine.options.Runner.Quiesce(ctx); err != nil {
		return x.engine.quarantine(err)
	}
	if err := x.engine.workspacePass(ctx, x.job.ID, false, false); err != nil {
		return err
	}
	dest := filepath.Join(x.engine.options.ExportRoot, x.job.ID)
	remaining := x.engine.options.MaxArtifactBytes
	var failures []error
	collect := func(source string, rules []model.ArtifactRule) {
		if remaining <= 0 {
			failures = append(failures, errors.New("artifact budget exhausted"))
			return
		}
		artifacts, err := evidence.Collect(ctx, source, rules, dest, evidence.Limits{MaxTotalBytes: remaining, MaxFileBytes: remaining, MaxEntries: maxArchiveEntries}, x.engine.options.Now())
		if err != nil {
			failures = append(failures, err)
			return
		}
		for _, artifact := range artifacts {
			remaining -= artifact.SizeBytes
		}
		x.result.Artifacts = append(x.result.Artifacts, artifacts...)
	}
	// Preserve raw logs even when required test or profile evidence is missing.
	protectedEvidence := filepath.Join(x.engine.options.Root, "evidence", x.job.ID)
	collect(protectedEvidence, []model.ArtifactRule{{Path: "evidence/stdout.log", Required: true}, {Path: "evidence/stderr.log", Required: true}})
	if x.result.Summary != nil {
		collect(x.workspace, []model.ArtifactRule{{Path: "results.xcresult", Required: true}})
		for _, artifact := range x.result.Artifacts {
			if artifact.Name == "results.xcresult.tar.gz" {
				x.result.Summary.XCResultSHA256 = artifact.SHA256
			}
		}
		if x.result.Summary.XCResultSHA256 == "" {
			failures = append(failures, errors.New("xcresult archive digest missing"))
		}
		normalized, err := json.Marshal(x.result.Summary)
		failures = append(failures, err, x.writeEvidence("summary.json", normalized))
		junit, err := evidence.JUnit(*x.result.Summary)
		failures = append(failures, err, x.writeEvidence("junit.xml", junit))
		collect(protectedEvidence, []model.ArtifactRule{{Path: "evidence/tests.json", Required: true}, {Path: "evidence/summary.json", Required: true}, {Path: "evidence/junit.xml", Required: true}})
	}
	// Artifact rules are workspace-relative, including explicit checkout/... paths.
	if len(x.job.Profile.Artifacts) > 0 {
		collect(x.workspace, x.job.Profile.Artifacts)
	}
	if len(x.result.Artifacts) > 0 {
		data, err := json.Marshal(exportManifest{Artifacts: x.result.Artifacts})
		failures = append(failures, err)
		if err == nil {
			failures = append(failures, durableFile(x.engine.exports, x.job.ID+"/manifest.json", data))
		}
	}
	return errors.Join(failures...)
}

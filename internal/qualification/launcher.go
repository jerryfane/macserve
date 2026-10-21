package qualification

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"syscall"
	"time"

	"github.com/jerryfane/macserve/internal/deploy"
	"github.com/jerryfane/macserve/internal/hostguard"
)

// The background job probe (v0.1.13). The administrator's fixed verb runs
//
//	/bin/launchctl asuser JOB_UID /Library/macserve/bin/macserve _qualify-job-probe SESSION_ID
//
// launchctl asuser adopts the job's existing GUI bootstrap namespace and audit
// session without changing credentials, exactly as the broker launches jobs.
// The root launcher then spawns the production drop path
//
//	macserve _job-exec JOB_UID JOB_GID / macserve _qualify-job-probe-child SESSION_ID
//
// (setgroups([]), setgid, setuid, then taskpolicy -b) and captures the child's
// report from a pipe into root-owned session files. Collect reads only those
// files, so the report's provenance is the launcher itself: no job-account
// process and no owner-account process can supply or replace it.

var sessionIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

const (
	sessionParent        = "/Library/macserve/var/qualification"
	installedHelper      = "/Library/macserve/bin/macserve"
	installedEnvironment = "/Library/macserve/config/deploy.env"
	jobProbeFile         = "job-probe.json"
	jobLaunchFile        = "job-launch.json"
	jobAttemptFile       = "job-probe-attempt.json"
	maxJobReport         = maxArtifact
)

// SessionDirectory maps an administrator session ID to its fixed protected
// session directory.
func SessionDirectory(id string) (string, error) {
	if !sessionIDPattern.MatchString(id) {
		return "", errors.New("session ID must match ^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
	}
	return filepath.Join(sessionParent, id), nil
}

// JobProbeLaunch is the root launcher's record of one job probe.
type JobProbeLaunch struct {
	Schema               int       `json:"schema"`
	Session              string    `json:"session"`
	ChallengeSHA256      string    `json:"challenge_sha256"`
	LauncherSHA256       string    `json:"launcher_sha256"`
	LauncherAuditUID     uint32    `json:"launcher_audit_uid"`
	LauncherAuditSession int32     `json:"launcher_audit_session"`
	ConsoleUID           uint32    `json:"console_uid"`
	Started              time.Time `json:"started"`
	Finished             time.Time `json:"finished"`
	ExitStatus           int       `json:"exit_status"`
	ReportSHA256         string    `json:"report_sha256,omitempty"`
	Diagnostics          string    `json:"diagnostics,omitempty"`
	Error                string    `json:"error,omitempty"`
}

func fileDigest(path string) (string, error) {
	if err := hostguard.RootConfig(path); err != nil {
		return "", err
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func sudoInvocation() bool {
	for _, key := range []string{"SUDO_UID", "SUDO_USER", "SUDO_COMMAND"} {
		if os.Getenv(key) != "" {
			return true
		}
	}
	return false
}

func installedDeployment() (deploy.Environment, []byte, error) {
	raw, err := protectedRead(installedEnvironment)
	if err != nil {
		return deploy.Environment{}, nil, err
	}
	env, err := deploy.ParseEnvironment(raw)
	return env, raw, err
}

// launcherContext verifies that this root process runs inside the job's GUI
// audit session (launchctl asuser JOB_UID), from the installed executable,
// with an admissible console. Every failure is a refusal with no host change.
func launcherContext(env deploy.Environment) (launch JobProbeLaunch, err error) {
	if err = rootOnly(); err != nil {
		return launch, err
	}
	if sudoInvocation() {
		return launch, errors.New("the job probe launcher refuses sudo invocations; it runs only from the fixed administrator verb")
	}
	self, err := os.Executable()
	if err == nil {
		self, err = filepath.EvalSymlinks(self)
	}
	if err != nil || self != installedHelper {
		return launch, fmt.Errorf("job probe launcher must be the installed %s", installedHelper)
	}
	if launch.LauncherSHA256, err = fileDigest(installedHelper); err != nil {
		return launch, err
	}
	if launch.LauncherAuditUID, launch.LauncherAuditSession, err = processAudit(); err != nil {
		return launch, fmt.Errorf("audit session unavailable: %w", err)
	}
	if launch.LauncherAuditUID != env.JobUID {
		return launch, fmt.Errorf("launcher audit user %d is not the job account %d: run as /bin/launchctl asuser %d %s _qualify-job-probe SESSION_ID with the job GUI logged in", launch.LauncherAuditUID, env.JobUID, env.JobUID, installedHelper)
	}
	if launch.ConsoleUID, err = hostguard.ConsoleUID(); err != nil {
		return launch, err
	}
	if err = hostguard.ConsoleAdmissible(launch.ConsoleUID, env.OwnerUID); err != nil {
		return launch, err
	}
	return launch, nil
}

// LaunchJobProbe is the root launcher. Its only input is the session ID.
// One attempt per session; a failed or refused attempt needs a new session.
func LaunchJobProbe(ctx context.Context, id string) error {
	if err := rootOnly(); err != nil {
		return err
	}
	dir, err := SessionDirectory(id)
	if err != nil {
		return err
	}
	env, envRaw, err := installedDeployment()
	if err != nil {
		return err
	}
	unlock, err := sessionLock(dir)
	if err != nil {
		return err
	}
	defer unlock()
	c, raw, err := loadChallenge(dir)
	if err != nil {
		return err
	}
	if err = fresh(c, time.Now().UTC()); err != nil {
		return err
	}
	if c.EnvironmentSHA256 != digest(envRaw) {
		return errors.New("installed deployment environment differs from the session challenge")
	}
	if _, err := os.Lstat(filepath.Join(dir, "candidate.json")); !errors.Is(err, os.ErrNotExist) {
		return errors.New("session already collected; begin a new session")
	}
	launch, err := launcherContext(env)
	launch.Schema, launch.Session, launch.ChallengeSHA256, launch.Started = schema, id, digest(raw), time.Now().UTC()
	if err != nil {
		return err
	}
	if err = saveJSON(filepath.Join(dir, jobAttemptFile), launch, 0600); err != nil {
		return fmt.Errorf("one job probe per session; begin a new session: %w", err)
	}
	report, runErr := runJobProbeChild(ctx, c, env, id, &launch)
	launch.Finished = time.Now().UTC()
	if runErr != nil {
		launch.Error = runErr.Error()
	}
	var saveErr error
	if report != nil {
		launch.ReportSHA256 = digest(report)
		saveErr = saveNew(filepath.Join(dir, jobProbeFile), report, 0600)
	}
	return errors.Join(runErr, saveErr, saveJSON(filepath.Join(dir, jobLaunchFile), launch, 0600))
}

// runJobProbeChild returns the child's report bytes when they decode as a
// report for this challenge, with any refusal or failed rows as the error.
func runJobProbeChild(ctx context.Context, c Challenge, env deploy.Environment, id string, launch *JobProbeLaunch) ([]byte, error) {
	ctx, cancel := context.WithDeadline(ctx, c.Expires)
	defer cancel()
	jobUID, jobGID := strconv.FormatUint(uint64(env.JobUID), 10), strconv.FormatUint(uint64(env.JobGID), 10)
	home := "/Users/" + env.JobUser
	cmd := exec.CommandContext(ctx, installedHelper, "_job-exec", jobUID, jobGID, "/", installedHelper, "_qualify-job-probe-child", id)
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C", "HOME=" + home, "USER=" + env.JobUser, "LOGNAME=" + env.JobUser}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 5 * time.Second
	out := &boundedOutput{limit: maxJobReport}
	diag := &boundedOutput{limit: 16 << 10}
	cmd.Stdout, cmd.Stderr = out, diag
	runErr := cmd.Run()
	launch.Diagnostics = diag.String()
	if cmd.ProcessState != nil {
		launch.ExitStatus = cmd.ProcessState.ExitCode()
	} else {
		launch.ExitStatus = -1
	}
	var r Report
	if err := decode(out.Bytes(), &r); err != nil {
		return nil, errors.Join(runErr, fmt.Errorf("job probe produced no valid report: %w", err))
	}
	if err := checkReportBinding(r, c, launch.ChallengeSHA256, "job"); err != nil {
		return nil, errors.Join(runErr, err)
	}
	report := slices.Clone(out.Bytes())
	if r.Refusal != "" {
		return report, fmt.Errorf("job probe refused: %s", r.Refusal)
	}
	if runErr != nil {
		return report, fmt.Errorf("job probe: %w", runErr)
	}
	return report, nil
}

// RunJobProbeChild runs as the job account after the production credential
// drop and writes the report to stdout. Run any other way, its output is never
// evidence: Collect reads only the launcher's root-owned capture.
func RunJobProbeChild(ctx context.Context, id string, stdout io.Writer) error {
	if os.Getuid() == 0 || os.Geteuid() == 0 {
		return errRootProbe
	}
	dir, err := SessionDirectory(id)
	if err != nil {
		return err
	}
	c, raw, err := loadChallenge(dir)
	if err != nil {
		return err
	}
	r, probeErr := probeReport(ctx, c, raw, "job")
	b, err := json.Marshal(r)
	if err != nil {
		return errors.Join(probeErr, err)
	}
	_, err = stdout.Write(b)
	return errors.Join(probeErr, err)
}

// loadJobProbe returns the launcher-captured job report and its launch record
// after binding them to the challenge and the installed launcher.
func loadJobProbe(dir string, c Challenge, raw []byte) ([]byte, []byte, Report, error) {
	var r Report
	lb, err := protectedRead(filepath.Join(dir, jobLaunchFile))
	if err != nil {
		return nil, nil, r, fmt.Errorf("root-captured job probe launch record required (run the job probe launcher first): %w", err)
	}
	var launch JobProbeLaunch
	if err = decode(lb, &launch); err != nil {
		return nil, nil, r, err
	}
	jb, err := protectedRead(filepath.Join(dir, jobProbeFile))
	if err != nil {
		return nil, nil, r, fmt.Errorf("root-captured job probe report required: %w", err)
	}
	launcher, err := fileDigest(installedHelper)
	if err != nil {
		return nil, nil, r, err
	}
	if launch.Schema != schema || launch.Session != filepath.Base(dir) || launch.ChallengeSHA256 != digest(raw) || launch.ReportSHA256 != digest(jb) || launch.LauncherSHA256 != launcher || launch.LauncherAuditUID != c.Environment.JobUID || hostguard.ConsoleAdmissible(launch.ConsoleUID, c.Environment.OwnerUID) != nil || launch.Started.Before(c.Created) || launch.Finished.Before(launch.Started) || launch.Finished.After(c.Expires) {
		return nil, nil, r, errors.New("job probe launch record does not bind this session, report and installed launcher")
	}
	if err = decode(jb, &r); err != nil {
		return nil, nil, r, err
	}
	return jb, lb, r, nil
}

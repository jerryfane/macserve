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
	Schema               int    `json:"schema"`
	Session              string `json:"session"`
	ChallengeSHA256      string `json:"challenge_sha256"`
	LauncherSHA256       string `json:"launcher_sha256"`
	LauncherAuditUID     uint32 `json:"launcher_audit_uid"`
	LauncherAuditSession int32  `json:"launcher_audit_session"`
	// Provenance is how the launcher proved it runs in the job GUI session
	// (provenanceAuditUser or provenanceGUISession); GUISession is root's
	// measurement of that session.
	Provenance   string     `json:"provenance"`
	GUISession   guiSession `json:"gui_session"`
	ConsoleUID   uint32     `json:"console_uid"`
	Started      time.Time  `json:"started"`
	Finished     time.Time  `json:"finished"`
	ExitStatus   int        `json:"exit_status"`
	ReportSHA256 string     `json:"report_sha256,omitempty"`
	Diagnostics  string     `json:"diagnostics,omitempty"`
	Error        string     `json:"error,omitempty"`
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
func launcherContext(ctx context.Context, env deploy.Environment) (launch JobProbeLaunch, err error) {
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
	// The GUI session is measured even when the audit user already matches,
	// so the launch record always shows both facts.
	launch.GUISession, _ = measureGUISession(ctx, env.JobUID)
	if launch.Provenance, err = launcherProvenance(launch.LauncherAuditUID, launch.LauncherAuditSession, env.JobUID, launch.GUISession.ASID); err != nil {
		return launch, err
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
	launch, err := launcherContext(ctx, env)
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
	if launch.Schema != schema || launch.Session != filepath.Base(dir) || launch.ChallengeSHA256 != digest(raw) || launch.ReportSHA256 != digest(jb) || launch.LauncherSHA256 != launcher || !launchProvenanceValid(launch, c.Environment.JobUID) || hostguard.ConsoleAdmissible(launch.ConsoleUID, c.Environment.OwnerUID) != nil || launch.Started.Before(c.Created) || launch.Finished.Before(launch.Started) || launch.Finished.After(c.Expires) {
		return nil, nil, r, errors.New("job probe launch record does not bind this session, report and installed launcher")
	}
	if err = decode(jb, &r); err != nil {
		return nil, nil, r, err
	}
	// The child inherits the launcher's audit identity through _job-exec;
	// a report from any other session is not this launch's child.
	if r.AuditUID != launch.LauncherAuditUID || r.AuditSession != launch.LauncherAuditSession {
		return nil, nil, r, errors.New("job report audit identity differs from the verified launcher")
	}
	return jb, lb, r, nil
}

// launchProvenanceValid re-derives the recorded provenance decision.
func launchProvenanceValid(l JobProbeLaunch, jobUID uint32) bool {
	p, err := launcherProvenance(l.LauncherAuditUID, l.LauncherAuditSession, jobUID, l.GUISession.ASID)
	return err == nil && p == l.Provenance
}

// SelfTestReport is the read-only host check of the launcher context.
type SelfTestReport struct {
	Root                 bool       `json:"root"`
	Sudo                 bool       `json:"sudo_environment"`
	Executable           string     `json:"executable"`
	InstalledExecutable  bool       `json:"installed_executable"`
	LauncherAuditUID     uint32     `json:"launcher_audit_uid"`
	LauncherAuditSession int32      `json:"launcher_audit_session"`
	GUISession           guiSession `json:"gui_session"`
	ConsoleUID           uint32     `json:"console_uid"`
	Provenance           string     `json:"provenance,omitempty"`
	Child                *SelfTest  `json:"child,omitempty"`
	ChildError           string     `json:"child_error,omitempty"`
	WouldAccept          bool       `json:"would_accept"`
	Refusals             []string   `json:"refusals,omitempty"`
}

// SelfTest is what the job child observes after the production drop.
type SelfTest struct {
	UID          int    `json:"uid"`
	GID          int    `json:"gid"`
	Groups       []int  `json:"groups"`
	AuditUID     uint32 `json:"audit_uid"`
	AuditSession int32  `json:"audit_session"`
	ConsoleUID   uint32 `json:"console_uid"`
	Error        string `json:"error,omitempty"`
}

// JobProbeSelfTest runs every launcher check and the production credential
// drop without a session. It reads installed configuration only, writes no
// file and prints one JSON report. It fails when the real launcher would
// refuse.
func JobProbeSelfTest(ctx context.Context, stdout io.Writer) error {
	var t SelfTestReport
	refuse := func(format string, args ...any) { t.Refusals = append(t.Refusals, fmt.Sprintf(format, args...)) }
	t.Root = os.Getuid() == 0 && os.Geteuid() == 0
	if !t.Root {
		refuse("not root")
	}
	t.Sudo = sudoInvocation()
	if t.Sudo {
		refuse("SUDO_* environment present")
	}
	if self, err := os.Executable(); err == nil {
		if self, err = filepath.EvalSymlinks(self); err == nil {
			t.Executable = self
		}
	}
	t.InstalledExecutable = t.Executable == installedHelper
	if !t.InstalledExecutable {
		refuse("not the installed %s", installedHelper)
	}
	env, _, err := installedDeployment()
	if err != nil {
		refuse("deployment environment: %v", err)
	} else {
		var auditErr error
		if t.LauncherAuditUID, t.LauncherAuditSession, auditErr = processAudit(); auditErr != nil {
			refuse("audit session: %v", auditErr)
		}
		var sessionErr error
		if t.GUISession, sessionErr = measureGUISession(ctx, env.JobUID); sessionErr != nil {
			refuse("job GUI session: %v", sessionErr)
		}
		if auditErr == nil {
			if t.Provenance, err = launcherProvenance(t.LauncherAuditUID, t.LauncherAuditSession, env.JobUID, t.GUISession.ASID); err != nil {
				refuse("%v", err)
			}
		}
		if t.ConsoleUID, err = hostguard.ConsoleUID(); err != nil {
			refuse("console: %v", err)
		} else if err = hostguard.ConsoleAdmissible(t.ConsoleUID, env.OwnerUID); err != nil {
			refuse("%v", err)
		}
		if t.Root && t.InstalledExecutable {
			t.Child, err = runSelfTestChild(ctx, env)
			if err != nil {
				t.ChildError = err.Error()
				refuse("job child: %v", err)
			} else if t.Child.UID != int(env.JobUID) || t.Child.GID != int(env.JobGID) || !slices.Equal(t.Child.Groups, []int{int(env.JobGID)}) || t.Child.AuditUID != t.LauncherAuditUID || t.Child.AuditSession != t.LauncherAuditSession {
				refuse("job child credential or audit identity is not the production one")
			}
		}
	}
	t.WouldAccept = len(t.Refusals) == 0
	b, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	if _, err = stdout.Write(append(b, '\n')); err != nil {
		return err
	}
	if !t.WouldAccept {
		return errors.New("self-test: the job probe launcher would refuse; see refusals")
	}
	return nil
}

func runSelfTestChild(ctx context.Context, env deploy.Environment) (*SelfTest, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	jobUID, jobGID := strconv.FormatUint(uint64(env.JobUID), 10), strconv.FormatUint(uint64(env.JobGID), 10)
	cmd := exec.CommandContext(ctx, installedHelper, "_job-exec", jobUID, jobGID, "/", installedHelper, "_qualify-job-probe-child", "--self-test")
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 5 * time.Second
	out := &boundedOutput{limit: 64 << 10}
	diag := &boundedOutput{limit: 16 << 10}
	cmd.Stdout, cmd.Stderr = out, diag
	runErr := cmd.Run()
	var child SelfTest
	if err := decode(out.Bytes(), &child); err != nil {
		return nil, errors.Join(runErr, fmt.Errorf("no child report: %w %s", err, diag.String()))
	}
	if child.Error != "" {
		return &child, errors.New(child.Error)
	}
	return &child, runErr
}

// JobProbeChildSelfTest reports the job child's own credential and audit
// identity. It reads nothing protected and writes only stdout.
func JobProbeChildSelfTest(stdout io.Writer) error {
	t := SelfTest{UID: os.Getuid(), GID: os.Getgid()}
	var errs []error
	var err error
	if t.Groups, err = processGroups(); err != nil {
		errs = append(errs, err)
	}
	if t.AuditUID, t.AuditSession, err = processAudit(); err != nil {
		errs = append(errs, err)
	}
	if t.ConsoleUID, err = hostguard.ConsoleUID(); err != nil {
		errs = append(errs, err)
	}
	if os.Geteuid() == 0 {
		errs = append(errs, errRootProbe)
	}
	if err = errors.Join(errs...); err != nil {
		t.Error = err.Error()
	}
	b, merr := json.Marshal(t)
	if merr != nil {
		return merr
	}
	_, werr := stdout.Write(b)
	return errors.Join(err, werr)
}

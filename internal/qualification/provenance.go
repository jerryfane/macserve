package qualification

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/jerryfane/macserve/internal/worker"
)

// Launcher provenance. `launchctl asuser UID` adopts "the Mach bootstrap
// namespace, exception server and security audit session" of the user's
// bootstrap without changing credentials (launchctl(1), asuser). In XNU,
// joining a session replaces the process's whole audit info pointer with the
// session's (audit_session_join_internal sets cr_audit.as_aia_p, which holds
// ai_auid and ai_asid; bsd/security/audit/audit_session.c), so the expected
// result is audit user = job UID and audit session = the job GUI session.
// Because that is first exercised as root on the host, the launcher accepts
// either fact and nothing else:
//
//   - audit user == job UID, or
//   - audit session == the job GUI login session, measured by root from the
//     job's own loginwindow (auditon A_GETPINFO_ADDR) and/or launchd's record
//     of gui/JOB ("security context" asid); when both are available they must
//     agree.
//
// A plain sudo or root SSH launch keeps the administrator's audit user (501)
// and session, so it matches neither.

const (
	provenanceAuditUser  = "audit-user"
	provenanceGUISession = "gui-session"
)

// guiSession is root's measurement of the job GUI login's audit session.
type guiSession struct {
	ASID        int32  `json:"asid,omitempty"`
	Loginwindow int    `json:"loginwindow_pid,omitempty"`
	KernelASID  int32  `json:"kernel_asid,omitempty"`
	KernelError string `json:"kernel_error,omitempty"`
	LaunchdASID int32  `json:"launchd_asid,omitempty"`
	LaunchdErr  string `json:"launchd_error,omitempty"`
}

// combineSessionASID applies the agreement rule to the two measurements.
func combineSessionASID(kernel, launchd int32) (int32, error) {
	switch {
	case kernel > 0 && launchd > 0 && kernel != launchd:
		return 0, fmt.Errorf("job GUI audit session measurements disagree (loginwindow %d, launchd %d)", kernel, launchd)
	case kernel > 0:
		return kernel, nil
	case launchd > 0:
		return launchd, nil
	}
	return 0, errors.New("job GUI audit session unavailable from both the job loginwindow and launchd")
}

// parseSecurityContextASID reads the asid of the root-level "security context"
// dictionary of `launchctl print gui/UID`, requiring its uid to equal uid.
func parseSecurityContextASID(text string, uid uint32) (int32, error) {
	scanner := bufio.NewScanner(strings.NewReader(text))
	in, found := false, false
	var asid int32
	var ctxUID int64 = -1
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case line == "\tsecurity context = {":
			if found || in {
				return 0, errors.New("duplicate security context")
			}
			in = true
		case in && line == "\t}":
			in, found = false, true
		case in && strings.HasPrefix(line, "\t\tasid = "):
			n, err := strconv.ParseInt(strings.TrimPrefix(line, "\t\tasid = "), 10, 32)
			if err != nil || n <= 0 || asid != 0 {
				return 0, errors.New("invalid security context asid")
			}
			asid = int32(n)
		case in && strings.HasPrefix(line, "\t\tuid = "):
			n, err := strconv.ParseInt(strings.TrimPrefix(line, "\t\tuid = "), 10, 64)
			if err != nil || ctxUID != -1 {
				return 0, errors.New("invalid security context uid")
			}
			ctxUID = n
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	if !found || asid == 0 || ctxUID != int64(uid) {
		return 0, errors.New("launchd security context for the job GUI domain unavailable")
	}
	return asid, nil
}

// measureGUISession is root-only and read-only.
func measureGUISession(ctx context.Context, jobUID uint32) (guiSession, error) {
	var s guiSession
	if pids, err := worker.JobLoginwindows(ctx, jobUID); err != nil {
		s.KernelError = err.Error()
	} else if len(pids) != 1 {
		s.KernelError = fmt.Sprintf("expected one job loginwindow, found %d", len(pids))
	} else {
		s.Loginwindow = pids[0]
		if auid, asid, err := processAuditOf(pids[0]); err != nil {
			s.KernelError = "auditon(A_GETPINFO_ADDR): " + err.Error()
		} else if auid != jobUID || asid <= 0 {
			s.KernelError = fmt.Sprintf("job loginwindow audit user %d session %d is not a job login session", auid, asid)
		} else {
			s.KernelASID = asid
		}
	}
	text, diag, err := command(ctx, "", "/bin/launchctl", "print", "gui/"+strconv.FormatUint(uint64(jobUID), 10))
	if err != nil {
		s.LaunchdErr = fmt.Sprintf("%v %s", err, diag)
	} else if s.LaunchdASID, err = parseSecurityContextASID(text, jobUID); err != nil {
		s.LaunchdErr = err.Error()
	}
	s.ASID, err = combineSessionASID(s.KernelASID, s.LaunchdASID)
	return s, err
}

// launcherProvenance decides whether a root process with this audit identity
// runs in the job's GUI session. It never accepts the default session.
func launcherProvenance(auid uint32, asid int32, jobUID uint32, session int32) (string, error) {
	if auid == jobUID {
		return provenanceAuditUser, nil
	}
	if asid > 0 && session > 0 && asid == session {
		return provenanceGUISession, nil
	}
	return "", fmt.Errorf("launcher audit user %d / session %d is neither the job account %d nor the job GUI session %d: run /bin/launchctl asuser %d /Library/macserve/bin/macserve _qualify-job-probe SESSION_ID with the job GUI logged in", auid, asid, jobUID, session, jobUID)
}

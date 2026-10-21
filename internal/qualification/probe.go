package qualification

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jerryfane/macserve/internal/hostguard"
)

type boundedOutput struct {
	bytes.Buffer
	limit int
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		n, _ := b.Buffer.Write(p[:b.limit-b.Len()])
		return n, errors.New("probe output limit exceeded")
	}
	return b.Buffer.Write(p)
}

// commandTimeout bounds each probe tool command. The job probe runs under
// taskpolicy -b (background CPU and I/O), so it allows more than an
// interactive shell would need.
const commandTimeout = 30 * time.Second

func command(ctx context.Context, developer, exe string, args ...string) (string, string, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C", "DEVELOPER_DIR=" + developer}
	cmd.WaitDelay = time.Second
	if developer != "" {
		account, e := user.LookupId(strconv.Itoa(os.Getuid()))
		if e != nil {
			return "", "", e
		}
		if os.Getuid() == 0 || account.HomeDir != "/Users/"+account.Username {
			return "", "", errors.New("native tools require the actual job account home")
		}
		temporary := filepath.Join(account.HomeDir, ".macserve-qualification")
		if e = os.Mkdir(temporary, 0700); e != nil && !os.IsExist(e) {
			return "", "", e
		}
		if e = hostguard.PrivateDirectory(temporary); e != nil {
			return "", "", e
		}
		cmd.Env = append(cmd.Env, "HOME="+account.HomeDir, "USER="+account.Username, "LOGNAME="+account.Username, "CFFIXED_USER_HOME="+account.HomeDir, "TMPDIR="+temporary, "TMP="+temporary, "TEMP="+temporary)
	}
	out := boundedOutput{limit: 1 << 20}
	diag := boundedOutput{limit: 8192}
	cmd.Stdout = &out
	cmd.Stderr = &diag
	e := cmd.Run()
	return out.String(), diag.String(), e
}

// Probe context modes recorded in reports.
const (
	// jobProbeMode: the job probe, reached only as root launchctl asuser JOB
	// into the job's existing GUI bootstrap and audit session, then the
	// production _job-exec credential drop (no supplementary groups,
	// taskpolicy -b). The report counts only when the root launcher captured it.
	jobProbeMode = "asuser-background"
	// ownerProbeMode: the owner's own account, typically over SSH.
	ownerProbeMode = "owner"
)

type probeIdentity struct {
	groups       []int
	console      uint32
	auditUID     uint32
	auditSession int32
}

func processGroups() ([]int, error) {
	groups, e := os.Getgroups()
	if e != nil {
		return nil, e
	}
	groups = append(groups, os.Getgid())
	slices.Sort(groups)
	return slices.Compact(groups), nil
}

func actualIdentity(ctx context.Context, c Challenge, role string) (probeIdentity, error) {
	var id probeIdentity
	uid := c.Environment.JobUID
	name := c.Environment.JobUser
	if role == "owner" {
		uid = c.Environment.OwnerUID
		name = c.Environment.OwnerUser
	} else if role != "job" {
		return id, errors.New("role must be job or owner")
	}
	if runtime.GOOS != "darwin" || os.Getuid() != int(uid) || os.Geteuid() != int(uid) || os.Getgid() != os.Getegid() {
		return id, errors.New("run as the approved actual account, not root impersonation")
	}
	// sudo/su wrappers are not a substitute for the reviewed contexts.
	for _, key := range []string{"SUDO_UID", "SUDO_USER", "SUDO_COMMAND"} {
		if os.Getenv(key) != "" {
			return id, errors.New("sudo impersonation is not qualification")
		}
	}
	account, e := user.LookupId(strconv.Itoa(int(uid)))
	if e != nil {
		return id, e
	}
	if account.Username != name || account.Gid != strconv.Itoa(os.Getgid()) {
		return id, errors.New("actual account name/primary group differs from reviewed identity")
	}
	if id.groups, e = processGroups(); e != nil {
		return id, e
	}
	if role == "job" {
		if e := hostguard.JobLoginListable(ctx, name); e != nil {
			return id, e
		}
		// The production credential: primary group only, exactly what
		// _job-exec leaves after setgroups([]), setgid, setuid. Full
		// memberships could hide a group deny ACE that production would meet.
		if os.Getgid() != int(c.Environment.JobGID) || !slices.Equal(id.groups, []int{int(c.Environment.JobGID)}) {
			return id, fmt.Errorf("job probe groups %v are not the production credential [%d]; it runs only through the root background launcher", id.groups, c.Environment.JobGID)
		}
	} else {
		wanted, e := account.GroupIds()
		if e != nil {
			return id, e
		}
		expected := []int{}
		for _, s := range append(wanted, account.Gid) {
			n, e := strconv.Atoi(s)
			if e != nil {
				return id, e
			}
			expected = append(expected, n)
		}
		slices.Sort(expected)
		if !slices.Equal(slices.Compact(expected), id.groups) {
			return id, errors.New("process does not have the account's full current memberships")
		}
	}
	if id.console, e = hostguard.ConsoleUID(); e != nil {
		return id, e
	}
	// The qualified arrangement: the owner in the foreground, or the login
	// window after the owner chose Switch User. Never a foreground job session.
	if e = hostguard.ConsoleAdmissible(id.console, c.Environment.OwnerUID); e != nil {
		return id, e
	}
	if id.auditUID, id.auditSession, e = processAudit(); e != nil {
		return id, fmt.Errorf("audit session unavailable: %w", e)
	}
	if role == "job" && id.auditUID != uid {
		return id, fmt.Errorf("job probe audit user %d is not the job account %d: launchctl asuser did not join the job's GUI audit session", id.auditUID, uid)
	}
	_, diag, e := command(ctx, "", "/bin/launchctl", "print", "gui/"+strconv.Itoa(int(uid)))
	if e != nil {
		return id, fmt.Errorf("existing GUI domain required: %v %s", e, diag)
	}
	return id, nil
}
func tcpProbe(ctx context.Context, target string) (bool, string) {
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, e := d.DialContext(ctx, "tcp", target)
	if e != nil {
		return false, e.Error()
	}
	conn.Close()
	return true, "TCP connected"
}
func udpProbe(ctx context.Context, target string, p Packet) (bool, string) {
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, e := d.DialContext(ctx, "udp", target)
	if e != nil {
		return false, e.Error()
	}
	defer conn.Close()
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		conn.Close()
		close(closed)
	})
	defer func() {
		if !stop() {
			<-closed
		}
	}()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	b, _ := json.Marshal(p)
	if _, e = conn.Write(b); e != nil {
		return false, e.Error()
	}
	reply := make([]byte, 2048)
	n, e := conn.Read(reply)
	if e != nil {
		return false, e.Error()
	}
	return bytes.Equal(reply[:n], b), fmt.Sprintf("UDP nonce echo bytes=%d", n)
}
func probeRead(p string, list bool) error {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if (list && !info.IsDir()) || (!list && !info.Mode().IsRegular()) {
		return errors.New("probe target is not the expected regular file or directory")
	}
	if list {
		_, err = f.Readdirnames(1)
	} else {
		var b [1]byte
		_, err = f.Read(b[:])
	}
	return err
}
func deniedRead(p string, list bool) (bool, string) {
	err := probeRead(p, list)
	return errors.Is(err, os.ErrPermission), fmt.Sprintf("access error=%v (only EACCES/EPERM counts)", err)
}
func readable(p string, list bool) (bool, string) {
	err := probeRead(p, list)
	return err == nil || err == io.EOF, fmt.Sprintf("control error=%v", err)
}
func ownerCanaryRead(path string) OwnerCanaryControl {
	ok, detail := readable(path, false)
	return OwnerCanaryControl{Path: path, At: time.Now().UTC(), Readable: ok, Detail: detail}
}

// networkMatrix retains serial evidence order while bounding in-flight work.
// Transport functions own their per-probe deadlines; all workers are joined.
func networkMatrix(ctx context.Context, c Challenge, challengeDigest, role string, tcp func(context.Context, string) (bool, string), udp func(context.Context, string, Packet) (bool, string)) ([]Result, error) {
	results := make([]Result, 0, 3*len(c.TCP)+3*len(c.UDP)+len(c.Allow))
	for _, target := range c.TCP {
		for attempt := 1; attempt <= 3; attempt++ {
			results = append(results, Result{Category: "network_reachability", Target: target, Attempt: attempt, Detail: "TCP: "})
		}
	}
	for _, target := range c.UDP {
		for attempt := 1; attempt <= 3; attempt++ {
			nonce, err := randomID()
			if err != nil {
				return nil, err
			}
			results = append(results, Result{Category: "network_reachability", Target: target, Attempt: attempt, Detail: "UDP: ", Nonce: nonce})
		}
	}
	for _, target := range c.Allow {
		results = append(results, Result{Category: "network_reachability", Target: target, Attempt: 1, Detail: "authorized TCP endpoint: "})
	}
	jobs := make(chan int)
	var workers sync.WaitGroup
	for range min(16, len(results)) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				row := &results[index]
				if err := ctx.Err(); err != nil {
					row.Detail += err.Error()
					continue
				}
				var detail string
				if row.Nonce != "" {
					row.Success, detail = udp(ctx, row.Target, Packet{challengeDigest, role, row.Attempt, row.Nonce})
				} else {
					row.Success, detail = tcp(ctx, row.Target)
				}
				row.Detail += detail
			}
		}()
	}
	for index := range results {
		jobs <- index
	}
	close(jobs)
	workers.Wait()
	return results, nil
}

var errRootProbe = errors.New("qualification probes must not run with real or effective UID 0")

var errJobProbeLauncher = errors.New("job probes run only through the root background launcher (launchctl asuser JOB_UID macserve _qualify-job-probe SESSION_ID); a probe run in the job account is not qualification evidence")

func Probe(ctx context.Context, dir, role, out string) error {
	return probe(ctx, dir, role, out, os.Getuid(), os.Geteuid())
}

func probe(ctx context.Context, dir, role, out string, uid, euid int) error {
	// Refuse before inspecting the protected session or touching caller paths,
	// including refusal evidence. Only actual non-root accounts may probe.
	if uid == 0 || euid == 0 {
		return errRootProbe
	}
	if role == "job" {
		return errJobProbeLauncher
	}
	c, raw, e := loadChallenge(dir)
	if e != nil {
		return e
	}
	r, e := probeReport(ctx, c, raw, role)
	if saveErr := saveJSON(out, r, 0600); saveErr != nil {
		return errors.Join(e, saveErr)
	}
	if e != nil {
		return e
	}
	return fresh(c, r.Finished)
}

// probeReport always returns a complete report, including refusal evidence;
// the error reports a refusal or a failed non-network row.
func probeReport(ctx context.Context, c Challenge, raw []byte, role string) (Report, error) {
	ctx, cancel := context.WithDeadline(ctx, c.Expires)
	defer cancel()
	mode := ownerProbeMode
	if role == "job" {
		mode = jobProbeMode
	}
	r := Report{Schema: schema, ChallengeSHA256: digest(raw), Role: role, UID: os.Getuid(), Started: time.Now().UTC(), Mode: mode}
	id, e := actualIdentity(ctx, c, role)
	r.ConsoleUID, r.AuditUID, r.AuditSession = id.console, id.auditUID, id.auditSession
	if e != nil {
		r.Refusal = e.Error()
		r.Finished = time.Now().UTC()
		return r, e
	}
	r.Groups = id.groups
	remaining := 1 << 20
	add := func(category, target string, attempt int, ok bool, detail, nonce string) {
		if len(detail) > remaining {
			detail = detail[:remaining] + "\nDiagnostic budget exhausted; this row cannot pass."
			ok = false
		}
		remaining -= min(remaining, len(detail))
		r.Results = append(r.Results, Result{category, target, attempt, ok, detail, nonce})
	}
	network, err := networkMatrix(ctx, c, digest(raw), role, tcpProbe, udpProbe)
	if err != nil {
		return r, err
	}
	for _, row := range network {
		add(row.Category, row.Target, row.Attempt, row.Success, row.Detail, row.Nonce)
	}
	if role == "job" {
		d := net.Dialer{Timeout: 2 * time.Second}
		conn, err := d.DialContext(ctx, "unix", c.Socket)
		if err == nil {
			conn.Close()
		}
		add("unix_socket_boundary", c.Socket, 1, errors.Is(err, os.ErrPermission), fmt.Sprintf("unix connect error=%v", err), "")
		for _, p := range c.PrivatePaths {
			fi, err := os.Lstat(p)
			isDir := err == nil && fi.IsDir()
			ok, detail := deniedRead(p, isDir)
			add("unix_socket_boundary", p, 1, ok, detail, "")
		}
	}
	for _, p := range homeTargets(c) {
		list := p != c.OwnerCanary
		var ok bool
		var detail string
		if role == "job" {
			ok, detail = deniedRead(p, list)
		} else {
			ok, detail = readable(p, list)
		}
		add("owner_home_denial", p, 1, ok, detail, "")
	}
	if role == "job" {
		developerDirs := []string{c.Environment.DeveloperDir}
		for _, p := range c.Profiles {
			developerDirs = append(developerDirs, p.DeveloperDir)
		}
		slices.Sort(developerDirs)
		developerDirs = slices.Compact(developerDirs)
		for _, developer := range developerDirs {
			err := hostguard.ToolchainDirectory(developer, c.Environment.JobUID)
			if err != nil {
				add("tool_profiles", developer, 1, false, err.Error(), "")
				continue
			}
			exe := filepath.Join(developer, "usr/bin/xcodebuild")
			err = hostguard.ToolchainExecutable(exe, c.Environment.JobUID)
			if err != nil {
				add("tool_profiles", developer, 1, false, err.Error(), "")
				continue
			}
			text, diag, err := command(ctx, developer, exe, "-version")
			ok := err == nil && strings.HasPrefix(text, "Xcode ") && strings.Contains(text, "\nBuild version ")
			for _, p := range c.Profiles {
				if p.DeveloperDir == developer {
					ok = ok && text == "Xcode "+p.Xcode.Version+"\nBuild version "+p.Xcode.Build+"\n"
				}
			}
			detail := fmt.Sprintf("stdout:\n%sstderr:\n%serror: %v; enabled profiles: %d; inspection is NOT recipe/UI execution", text, diag, err, len(c.Profiles))
			extraOK, extra := inspectTools(ctx, c, developer)
			ok = ok && extraOK
			detail += "\n" + extra
			add("tool_profiles", developer, 1, ok, detail, "")
		}
	}
	r.Finished = time.Now().UTC()
	for _, row := range r.Results {
		if !row.Success && row.Category != "network_reachability" {
			return r, errors.New("one or more probes failed; complete report preserved")
		}
	}
	return r, nil
}

// Canary is an explicitly approved, bounded nonce echo receiver. TCP mode only
// accepts/closes sockets; neither transport forwards requests to service APIs.
func Canary(ctx context.Context, dir, listen, transport, out string, duration time.Duration) error {
	c, raw, e := loadChallenge(dir)
	if e != nil {
		return e
	}
	if _, e = actualIdentity(ctx, c, "owner"); e != nil {
		return e
	}
	if duration < time.Second || duration > lifetime {
		return errors.New("duration must be 1s..2h")
	}
	if transport == "owner-home" {
		if listen != "" {
			return errors.New("owner-home controls do not accept a network listener")
		}
		r := Receipts{Schema: schema, ChallengeSHA256: digest(raw), UID: os.Getuid(), Started: time.Now().UTC()}
		r.OwnerBefore = ownerCanaryRead(c.OwnerCanary)
		end := minTime(time.Now().Add(duration), c.Expires)
		controlCtx, cancel := context.WithDeadline(ctx, end)
		defer cancel()
		<-controlCtx.Done()
		r.OwnerAfter = ownerCanaryRead(c.OwnerCanary)
		r.Finished = time.Now().UTC()
		return saveJSON(out, r, 0600)
	}
	targets, e := endpoints(listen)
	if e != nil {
		return e
	}
	approved := c.UDP
	if transport == "tcp" {
		approved = c.TCP
	} else if transport != "udp" {
		return errors.New("transport must be tcp or udp")
	}
	for _, p := range targets {
		if !slices.Contains(approved, p) {
			return fmt.Errorf("unreviewed canary endpoint %s", p)
		}
	}
	// One independent receipt document per endpoint permits strict coverage and
	// avoids combining a working receiver with an absent target.
	end := time.Now().Add(duration)
	if c.Expires.Before(end) {
		end = c.Expires
	}
	ctx, cancel := context.WithDeadline(ctx, end)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var first error
	listeners := []io.Closer{}
	defer func() {
		cancel()
		for _, l := range listeners {
			l.Close()
		}
		wg.Wait()
	}()
	for index, target := range targets {
		r := Receipts{Schema: schema, ChallengeSHA256: digest(raw), UID: os.Getuid(), Listen: target, Started: time.Now().UTC()}
		var udp *net.UDPConn
		var tcp net.Listener
		if transport == "udp" {
			a, err := net.ResolveUDPAddr("udp", target)
			if err != nil {
				return err
			}
			udp, e = net.ListenUDP("udp", a)
			if e != nil {
				return e
			}
			listeners = append(listeners, udp)
		} else {
			tcp, e = net.Listen("tcp", target)
			if e != nil {
				return e
			}
			listeners = append(listeners, tcp)
		}
		wg.Add(1)
		go func(index int, r Receipts, udp *net.UDPConn, tcp net.Listener) {
			defer wg.Done()
			if udp != nil {
				receiveUDP(ctx, udp, &r)
			} else {
				go func() { <-ctx.Done(); tcp.Close() }()
				for ctx.Err() == nil {
					conn, err := tcp.Accept()
					if err != nil {
						if ctx.Err() == nil {
							r.Error = err.Error()
						}
						break
					}
					if len(r.Packets) >= 4096 {
						conn.Close()
						r.Error = "receipt limit exceeded"
						break
					}
					r.Packets = append(r.Packets, Received{At: time.Now().UTC(), Peer: conn.RemoteAddr().String()})
					conn.Close()
				}
			}
			r.Finished = time.Now().UTC()
			path := out
			if len(targets) > 1 {
				path = out + "." + strconv.Itoa(index+1) + ".json"
			}
			err := saveJSON(path, r, 0600)
			if r.Error != "" {
				err = errors.Join(err, errors.New(r.Error))
			}
			mu.Lock()
			if first == nil {
				first = err
			}
			mu.Unlock()
		}(index, r, udp, tcp)
	}
	wg.Wait()
	return first
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

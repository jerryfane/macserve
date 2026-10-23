//go:build macserve_realhost && darwin

package worker

// Real-host end-to-end harness (v0.1.16). It runs the production engine
// (New -> Recover -> Execute for every enabled profile of
// /Library/macserve/config/profiles.json, with the pinned qualification
// archives) on the Mac Studio as the owner account, in a temporary root under
// /tmp. Approved deviations, all logged:
//
//	credential drop: job commands are exec'd as the harness user (taskpolicy
//	    wrapper and environment unchanged); nothing runs as root.
//	H1  signals are a dry run: every SIGTERM/SIGKILL target is logged with its
//	    kernel facts and classified, never sent. A SIGKILLed instance is
//	    filtered from later samples ("virtual death"); SIGTERM is ignored.
//	H2  toolchain policy is judged for the dedicated job UID 6202
//	    (realhostToolchainUID): the owner is an administrator.
//	H3  the GUI baseline is an in-memory snapshot of the owner's processes and
//	    launchd domain environment at harness start (realhostBaseline).
//	H4  persistence inspection (LaunchAgents, crontab, login items, BTM) is
//	    skipped; the console check stays.
//	H5  the memory monitor counts only the harness's job descendants; the RSS
//	    production would see is sampled every second (rss.jsonl).
//	H6  the engine's own inspection commands (launchctl, ps, plutil, getconf),
//	    root processes in production, are direct children of the harness here
//	    and are excluded from the job census.
//	H7  descendants of fixed foreign roots, named by PID and executable before
//	    the run (MACSERVE_RH_FOREIGN), are excluded from the census.
//
// Everything else is production code: budget walks, census classification of
// real processes, Recover/admission, quiesce decisions, cleanup walks and
// evidence collection.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jerryfane/macserve/internal/model"
	"github.com/jerryfane/macserve/internal/profiles"
	"golang.org/x/sys/unix"
)

const (
	rhProductionJobUID = 6202
	rhMemoryLimitMiB   = 32768
	rhProfilesPath     = "/Library/macserve/config/profiles.json"
	rhPinsPath         = "/Library/macserve/config/qualification-sources.json"
	rhSourcesDir       = "/Library/macserve/qualification-sources"
)

var rhHelperExes = map[string]bool{"/bin/launchctl": true, "/bin/ps": true, "/usr/bin/plutil": true, "/usr/bin/getconf": true}

type rhIdentity struct {
	PID   int    `json:"pid"`
	Start string `json:"start"`
}

type rhRow struct {
	pid, ppid, pgid, uid int
	start, comm          string
	zombie               bool
}

// rhProc is a uid process first seen after the baseline snapshot (or excluded
// from it). Class: descendant (the harness's job processes), helper (H6),
// foreign (H7), launchd (PPID 1 at first sight), other (any other parent),
// pending (a harness child not yet exec'd).
type rhProc struct {
	rhIdentity
	PPID      int       `json:"ppid"`
	PGID      int       `json:"pgid"`
	Exe       string    `json:"exe"`
	Comm      string    `json:"comm"`
	Class     string    `json:"class"`
	ParentExe string    `json:"parent_exe,omitempty"`
	First     time.Time `json:"first"`
	Phase     string    `json:"phase"`
}

type rhHarness struct {
	t       *testing.T
	out     string
	self    int
	selfExe string
	uid     int
	agents  agentInspector
	env     LaunchdEnvironment

	mu           sync.Mutex
	phase        string
	baseline     map[rhIdentity]bool
	baselineExe  map[int]string
	audited      []ProcessIdentity
	procs        map[rhIdentity]*rhProc
	livePID      map[int]rhIdentity
	jobGroups    map[int]bool
	foreignRoots map[int]string
	dead         map[rhIdentity]string
	excluded     map[rhIdentity]bool
	signalled    map[rhIdentity]bool
	abort        error
	cancel       context.CancelFunc
	files        map[string]*os.File

	wg  sync.WaitGroup
	sem chan struct{}
}

// rhAgents is nativeAgents without the job credential switch (not root).
type rhAgents struct{ nativeAgents }

func (rhAgents) xpcEnvironment(ctx context.Context, uid int) (map[string]string, error) {
	account, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return nil, err
	}
	out, _, err := inspectCommand(ctx, nil, "/usr/bin/getconf", "DARWIN_USER_TEMP_DIR")
	if err != nil {
		return nil, err
	}
	tmp := strings.TrimSuffix(out, "\n")
	if !strings.HasPrefix(tmp, "/var/folders/") || !strings.HasSuffix(tmp, "/T/") || filepath.Clean(tmp)+"/" != tmp || !filepath.IsAbs(account.HomeDir) {
		return nil, errors.New("job temporary directory or home unavailable")
	}
	return map[string]string{"HOME": account.HomeDir, "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "TMPDIR": tmp}, nil
}

func rhSnapshot() ([]rhRow, error) {
	kinfo, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, err
	}
	rows := make([]rhRow, 0, len(kinfo))
	for i := range kinfo {
		p := kinfo[i].Proc
		comm := string(p.P_comm[:])
		if n := strings.IndexByte(comm, 0); n >= 0 {
			comm = comm[:n]
		}
		rows = append(rows, rhRow{pid: int(p.P_pid), ppid: int(kinfo[i].Eproc.Ppid), pgid: int(kinfo[i].Eproc.Pgid), uid: int(kinfo[i].Eproc.Ucred.Uid), start: startToken(&p), comm: comm, zombie: p.P_stat == 5})
	}
	return rows, nil
}

func rhExe(pid int) string {
	facts, err := (nativeAgents{}).kernel(pid)
	if err != nil {
		return ""
	}
	return facts.executable
}

func (h *rhHarness) log(name string, v any) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.logLocked(name, v)
}

func (h *rhHarness) logLocked(name string, v any) {
	f := h.files[name]
	if f == nil {
		var err error
		f, err = os.OpenFile(filepath.Join(h.out, name), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			h.t.Errorf("log %s: %v", name, err)
			return
		}
		h.files[name] = f
	}
	b, _ := json.Marshal(v)
	f.Write(append(b, '\n'))
}

func (h *rhHarness) setPhase(phase string) {
	h.mu.Lock()
	h.phase = phase
	h.mu.Unlock()
	h.log("phases.jsonl", map[string]any{"t": time.Now().UTC(), "phase": phase})
}

// observe classifies every uid process not yet known. Caller holds h.mu.
func (h *rhHarness) observe(rows []rhRow) {
	byPID := make(map[int]rhRow, len(rows))
	for _, r := range rows {
		byPID[r.pid] = r
	}
	h.livePID = make(map[int]rhIdentity)
	for _, r := range rows {
		if r.uid != h.uid || r.zombie {
			continue
		}
		id := rhIdentity{r.pid, r.start}
		h.livePID[r.pid] = id
		if h.baseline[id] {
			continue
		}
		if p := h.procs[id]; p != nil && p.Class != "pending" {
			continue
		}
		p := &rhProc{rhIdentity: id, PPID: r.ppid, PGID: r.pgid, Comm: r.comm, First: time.Now().UTC(), Phase: h.phase}
		p.Exe = rhExe(r.pid)
		parent, parentLive := byPID[r.ppid]
		parentProc := h.procs[rhIdentity{parent.pid, parent.start}]
		switch {
		case r.ppid == h.self && p.Exe == h.selfExe:
			p.Class = "pending"
		case r.ppid == h.self && rhHelperExes[p.Exe]:
			p.Class = "helper"
		case r.ppid == h.self:
			p.Class = "descendant"
			h.jobGroups[r.pgid] = true
		case parentLive && parentProc != nil && parentProc.Class == "descendant":
			p.Class = "descendant"
		case r.pgid != 0 && h.jobGroups[r.pgid]:
			p.Class = "descendant"
		case h.foreignAncestry(r, byPID):
			p.Class = "foreign"
		case r.ppid == 1:
			p.Class = "launchd"
		default:
			p.Class = "other"
		}
		if parentLive {
			if exe, ok := h.baselineExe[r.ppid]; ok {
				p.ParentExe = exe
			} else if parentProc != nil {
				p.ParentExe = parentProc.Exe
			}
		}
		h.procs[id] = p
		if p.Class != "pending" {
			h.logLocked("procs.jsonl", p)
		}
	}
	if h.abort == nil {
		for _, r := range rows {
			if r.comm != "xcodebuild" && r.comm != "launchd_sim" || r.zombie {
				continue
			}
			if p := h.procs[rhIdentity{r.pid, r.start}]; r.uid == h.uid && p != nil && p.Class == "descendant" {
				continue
			}
			h.abort = fmt.Errorf("foreign %s pid %d uid %d (ppid %d) during %s", r.comm, r.pid, r.uid, r.ppid, h.phase)
			h.logLocked("abort.jsonl", map[string]any{"t": time.Now().UTC(), "reason": h.abort.Error()})
			if h.cancel != nil {
				h.cancel()
			}
		}
	}
}

// foreignAncestry reports whether a fixed foreign root (PID and start) or a
// process already classified foreign is an ancestor of r, walking parents of
// any UID (sandboxd-pf-helper starts the job-UID container CLI through a root
// sudo). Caller holds h.mu.
func (h *rhHarness) foreignAncestry(r rhRow, byPID map[int]rhRow) bool {
	for depth := 0; depth < 64 && r.ppid > 1 && r.ppid != h.self; depth++ {
		parent, ok := byPID[r.ppid]
		if !ok {
			return false
		}
		if start, root := h.foreignRoots[parent.pid]; root && start == parent.start {
			return true
		}
		if p := h.procs[rhIdentity{parent.pid, parent.start}]; p != nil && p.Class == "foreign" {
			return true
		}
		r = parent
	}
	return false
}

// jobSample is the census sampler: the production kernel snapshot without
// virtually dead instances (H1), harness inspection helpers (H6) and
// processes descending from the fixed foreign roots (H7).
func (h *rhHarness) jobSample(ctx context.Context) ([]processSample, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rows, err := rhSnapshot()
	if err != nil {
		return nil, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.observe(rows)
	samples := make([]processSample, 0, len(rows))
	for _, r := range rows {
		id := rhIdentity{r.pid, r.start}
		if r.uid == h.uid && !r.zombie {
			if _, dead := h.dead[id]; dead {
				continue
			}
			if p := h.procs[id]; p != nil && (p.Class == "helper" || p.Class == "foreign" || p.Class == "pending") {
				if !h.excluded[id] {
					h.excluded[id] = true
					h.logLocked("excluded.jsonl", map[string]any{"t": time.Now().UTC(), "phase": h.phase, "proc": p})
				}
				continue
			}
		}
		samples = append(samples, processSample{pid: r.pid, group: r.pgid, uid: r.uid, zombie: r.zombie, start: r.start})
	}
	return samples, ctx.Err()
}

// memorySample is H5: the production ps sample, restricted to the harness's
// live job descendants.
func (h *rhHarness) memorySample(ctx context.Context) ([]processSample, error) {
	rows, err := sampleProcessesAs(ctx, nil)
	if err != nil {
		return nil, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	out := rows[:0]
	for _, r := range rows {
		id, live := h.livePID[r.pid]
		if p := h.procs[id]; live && p != nil && p.Class == "descendant" {
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		// parseProcesses never returns an empty snapshot; an idle moment is
		// one zero-RSS row of the harness user.
		out = append(out, processSample{pid: h.self, uid: -1})
	}
	return out, nil
}

// dryRun is H1: log and classify, never signal.
func (h *rhHarness) dryRun(ctx context.Context, p processSample, sig syscall.Signal) error {
	id := rhIdentity{p.pid, p.start}
	facts, factsErr := (nativeAgents{}).kernel(p.pid)
	h.mu.Lock()
	class := "unknown"
	if h.baseline[id] {
		class = "baseline"
	} else if c := h.procs[id]; c != nil {
		class = c.Class
	}
	if sig == syscall.SIGKILL {
		h.dead[id] = class
	}
	first := !h.signalled[id]
	h.signalled[id] = true
	record := map[string]any{"t": time.Now().UTC(), "phase": h.phase, "signal": sig.String(), "pid": p.pid, "start": p.start, "tracker_class": class, "first": first}
	if factsErr == nil {
		record["exe"], record["ppid"], record["live_start"] = facts.executable, facts.ppid, facts.start
	} else {
		record["facts_error"] = factsErr.Error()
	}
	h.logLocked("signals.jsonl", record)
	h.mu.Unlock()
	if first {
		h.wg.Add(1)
		go h.classify(p, class)
	}
	return nil
}

// classify records the production rule's verdict for a signalled instance:
// Apple-defined or developer-tool launch (with its launchd target) or
// residual (with each rule's refusal).
func (h *rhHarness) classify(p processSample, class string) {
	defer h.wg.Done()
	h.sem <- struct{}{}
	defer func() { <-h.sem }()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	record := map[string]any{"t": time.Now().UTC(), "pid": p.pid, "start": p.start, "tracker_class": class}
	rows, err := rhSnapshot()
	if err != nil {
		record["error"] = err.Error()
		h.log("classified.jsonl", record)
		return
	}
	h.mu.Lock()
	var candidates []processSample
	for _, r := range rows {
		id := rhIdentity{r.pid, r.start}
		c := h.procs[id]
		if r.uid != h.uid || r.zombie || h.baseline[id] || c == nil || c.Class == "helper" || c.Class == "foreign" || c.Class == "pending" || r.pid == p.pid {
			continue
		}
		candidates = append(candidates, processSample{pid: r.pid, group: r.pgid, uid: r.uid, start: r.start})
	}
	present := make(map[int]bool)
	for _, r := range rows {
		if h.baseline[rhIdentity{r.pid, r.start}] {
			present[r.pid] = true
		}
	}
	var audited []int
	for _, a := range h.audited {
		if present[a.PID] && a.Service.Domain != "" {
			audited = append(audited, a.PID)
		}
	}
	h.mu.Unlock()
	candidates = append(candidates, p)
	residual, tolerated, refused := toleratedLaunches(ctx, h.agents, h.uid, h.env, audited, candidates)
	switch {
	case slices.ContainsFunc(tolerated, func(t processSample) bool { return t.pid == p.pid && t.start == p.start }):
		hints := newServiceHints(h.agents, h.uid, nil)
		if target, err := appleLaunch(ctx, h.agents, h.uid, h.env, hints, p); err == nil {
			record["verdict"], record["target"] = "tolerated-apple", target
		} else {
			owners := audited
			for _, t := range tolerated {
				owners = append(owners, t.pid)
			}
			target, err := developerToolLaunch(ctx, h.agents, h.uid, h.env, hints, owners, p)
			record["verdict"], record["target"] = "tolerated-developer-tool", target
			if err != nil {
				record["target_error"] = err.Error()
			}
		}
	case slices.ContainsFunc(residual, func(r processSample) bool { return r.pid == p.pid }):
		record["verdict"] = "residual"
		if r, ok := refused[p.pid]; ok {
			record["target"] = r.target
			if r.apple != nil {
				record["apple"] = r.apple.Error()
			}
			if r.developerTool != nil {
				record["developer_tool"] = r.developerTool.Error()
			}
		}
	default:
		record["verdict"] = "unclassified"
	}
	h.log("classified.jsonl", record)
}

func rhDevStack(exe string) bool {
	return strings.HasPrefix(exe, "/Library/Developer/") || strings.HasPrefix(exe, "/Applications/Xcode.app/") || exe == "/usr/libexec/fskit_agent"
}

// rss samples every second what production would charge the job UID: the
// harness's job descendants, every other new census process (launchd and
// other classes, alive or virtually dead) and the owner's pre-existing
// developer-tool stack, which the job account would start itself.
func (h *rhHarness) rss(ctx context.Context, done chan<- map[string]any) {
	peak := map[string]any{"total_mib": int64(0)}
	var peakDesc, peakNew, peakTotal int64
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			done <- map[string]any{"peak_descendants_mib": peakDesc, "peak_new_census_mib": peakNew, "peak_total_mib": peakTotal, "at_peak": peak}
			return
		case <-ticker.C:
		}
		rows, err := sampleProcessesAs(ctx, nil)
		if err != nil {
			continue
		}
		var desc, fresh, stack int64
		type contributor struct {
			PID   int    `json:"pid"`
			Exe   string `json:"exe"`
			Class string `json:"class"`
			MiB   int64  `json:"mib"`
		}
		var top []contributor
		h.mu.Lock()
		phase := h.phase
		for _, r := range rows {
			if r.uid != h.uid || r.zombie {
				continue
			}
			id, live := h.livePID[r.pid]
			if !live {
				continue
			}
			mib := r.rssKiB / 1024
			if h.baseline[id] {
				if exe := h.baselineExe[r.pid]; rhDevStack(exe) {
					stack += r.rssKiB
					top = append(top, contributor{r.pid, exe, "baseline-devstack", mib})
				}
				continue
			}
			p := h.procs[id]
			if p == nil {
				continue
			}
			switch p.Class {
			case "descendant":
				desc += r.rssKiB
			case "launchd", "other":
				fresh += r.rssKiB
			default:
				continue
			}
			top = append(top, contributor{r.pid, p.Exe, p.Class, mib})
		}
		h.mu.Unlock()
		sort.Slice(top, func(i, j int) bool { return top[i].MiB > top[j].MiB })
		if len(top) > 12 {
			top = top[:12]
		}
		total := (desc + fresh + stack) / 1024
		rec := map[string]any{"t": time.Now().UTC(), "phase": phase, "descendants_mib": desc / 1024, "new_census_mib": fresh / 1024, "baseline_devstack_mib": stack / 1024, "total_mib": total, "top": top}
		h.log("rss.jsonl", rec)
		peakDesc, peakNew = max(peakDesc, desc/1024), max(peakNew, fresh/1024)
		if total > peakTotal {
			peakTotal, peak = total, rec
		}
	}
}

func (h *rhHarness) tracker(ctx context.Context) {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		rows, err := rhSnapshot()
		if err != nil {
			continue
		}
		h.mu.Lock()
		h.observe(rows)
		h.mu.Unlock()
	}
}

func rhForeignRoots(t *testing.T, rows []rhRow) map[int]string {
	roots := make(map[int]string)
	spec := os.Getenv("MACSERVE_RH_FOREIGN")
	if spec == "" {
		return roots
	}
	for _, item := range strings.Split(spec, ",") {
		pidText, exe, ok := strings.Cut(item, ":")
		pid, err := strconv.Atoi(pidText)
		if !ok || err != nil {
			t.Fatalf("invalid foreign root %q", item)
		}
		i := slices.IndexFunc(rows, func(r rhRow) bool { return r.pid == pid })
		if i < 0 || rhExe(pid) != exe {
			t.Fatalf("foreign root %d is not %s at harness start (exe %q)", pid, exe, rhExe(pid))
		}
		roots[pid] = rows[i].start
	}
	return roots
}

type rhPin struct {
	Profile   string `json:"profile"`
	Commit    string `json:"commit"`
	Tree      string `json:"tree"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

func TestRealHostEndToEnd(t *testing.T) {
	out := os.Getenv("MACSERVE_RH_OUT")
	if out == "" {
		t.Skip("MACSERVE_RH_OUT unset")
	}
	if os.Geteuid() == 0 {
		t.Fatal("the harness runs as the owner, never as root")
	}
	selfExe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	h := &rhHarness{t: t, out: out, self: os.Getpid(), selfExe: selfExe, uid: os.Getuid(), agents: rhAgents{}, baseline: map[rhIdentity]bool{}, baselineExe: map[int]string{}, procs: map[rhIdentity]*rhProc{}, livePID: map[int]rhIdentity{}, jobGroups: map[int]bool{}, dead: map[rhIdentity]string{}, excluded: map[rhIdentity]bool{}, signalled: map[rhIdentity]bool{}, files: map[string]*os.File{}, sem: make(chan struct{}, 2)}
	defer func() {
		for _, f := range h.files {
			f.Close()
		}
	}()
	rows, err := rhSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if (r.comm == "xcodebuild" || r.comm == "launchd_sim") && !r.zombie {
			h.log("abort.jsonl", map[string]any{"t": time.Now().UTC(), "reason": "foreign " + r.comm + " before start", "pid": r.pid, "uid": r.uid})
			t.Fatalf("ABORT: foreign %s pid %d uid %d is running", r.comm, r.pid, r.uid)
		}
	}
	if os.Getenv("MACSERVE_RH_MODE") == "measure" {
		rhMeasure(t, h, rows)
		return
	}

	// H3 baseline: every owner process present now, except descendants of
	// the fixed foreign roots (H7), which are excluded from the census.
	h.setPhase("baseline")
	h.foreignRoots = rhForeignRoots(t, rows)
	h.mu.Lock()
	byPID := make(map[int]rhRow)
	for _, r := range rows {
		byPID[r.pid] = r
	}
	foreignAncestor := func(r rhRow) bool {
		for depth := 0; depth < 64 && r.ppid > 1; depth++ {
			parent, ok := byPID[r.ppid]
			if !ok {
				return false
			}
			if h.foreignRoots[parent.pid] == parent.start {
				return true
			}
			r = parent
		}
		return false
	}
	var processes []ProcessIdentity
	for _, r := range rows {
		if r.uid != h.uid || r.zombie {
			continue
		}
		id := rhIdentity{r.pid, r.start}
		if foreignAncestor(r) {
			p := &rhProc{rhIdentity: id, PPID: r.ppid, PGID: r.pgid, Comm: r.comm, Exe: rhExe(r.pid), Class: "foreign", First: time.Now().UTC(), Phase: "baseline"}
			h.procs[id] = p
			h.logLocked("procs.jsonl", p)
			continue
		}
		h.baseline[id] = true
		h.baselineExe[r.pid] = rhExe(r.pid)
		processes = append(processes, ProcessIdentity{PID: r.pid, Start: r.start})
	}
	h.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.mu.Lock()
	h.cancel = cancel
	h.mu.Unlock()
	trackCtx, stopTracking := context.WithCancel(context.Background())
	go h.tracker(trackCtx)
	rssDone := make(chan map[string]any, 1)
	rssCtx, stopRSS := context.WithCancel(context.Background())
	go h.rss(rssCtx, rssDone)

	boot, err := bootIdentity()
	if err != nil {
		t.Fatal(err)
	}
	env, err := launchdEnvironment(ctx, h.agents, h.uid)
	if err != nil {
		t.Fatal(err)
	}
	h.env = *env
	baseline := describeServices(ctx, h.agents, h.uid, GUIBaseline{JobUID: uint32(h.uid), Boot: boot, Processes: processes, PersistenceSHA256: "realhost-harness", Launchd: env})
	if err := validateBaseline(baseline, uint32(h.uid), boot); err != nil {
		t.Fatalf("harness baseline: %v", err)
	}
	h.mu.Lock()
	h.audited = baseline.Processes
	h.mu.Unlock()
	described := 0
	for _, p := range baseline.Processes {
		if p.Service.Domain != "" {
			described++
		}
	}
	h.log("baseline.json", map[string]any{"t": time.Now().UTC(), "processes": len(baseline.Processes), "launchd_described": described, "foreign_roots": h.foreignRoots, "boot": boot, "gui_env": env.GUI, "user_env": env.User})
	realhostBaseline = &baseline
	realhostToolchainUID = rhProductionJobUID
	defer func() { realhostBaseline, realhostToolchainUID = nil, 0 }()

	// Engine: the production wiring (nativeRunnerFor) with the deviations.
	tmp, err := os.MkdirTemp("/tmp", "v0116-rh.")
	if err != nil {
		t.Fatal(err)
	}
	tmp, err = filepath.EvalSymlinks(tmp)
	if err != nil {
		t.Fatal(err)
	}
	account, err := user.LookupId(strconv.Itoa(h.uid))
	if err != nil {
		t.Fatal(err)
	}
	gid, _ := strconv.Atoi(account.Gid)
	options := Options{Root: filepath.Join(tmp, "broker"), ExportRoot: filepath.Join(tmp, "exports"), WorkspaceRoot: filepath.Join(tmp, "workspaces"), JobUID: uint32(h.uid), JobGID: uint32(gid), OwnerUID: uint32(h.uid), HelperPath: "/nonexistent/macserve-helper", CleanupTimeout: 2 * time.Minute}
	runner := nativeRunnerFor(options)
	runner.command = func(command Command) *exec.Cmd {
		executable, argv := backgroundCommand(command.Executable, command.Args)
		return exec.Command(executable, argv...)
	}
	runner.launchDir = ""
	runner.sample = h.memorySample
	runner.persistence = func(context.Context) error {
		h.log("deviations.jsonl", map[string]any{"t": time.Now().UTC(), "deviation": "H4", "skipped": "persistence inspection"})
		return nil
	}
	runner.scope.sample = h.jobSample
	runner.scope.agents = h.agents
	runner.scope.signal = h.dryRun
	runner.signalProcess = h.dryRun
	options.Runner = runner
	engine, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	if control := os.Getenv("MACSERVE_RH_CONTROL"); control != "" {
		if err := os.WriteFile(control, []byte(options.WorkspaceRoot), 0600); err != nil {
			t.Fatal(err)
		}
	}

	registry, err := profiles.Load(rhProfilesPath)
	if err != nil {
		t.Fatal(err)
	}
	var pins struct {
		Sources []rhPin `json:"sources"`
	}
	data, err := os.ReadFile(rhPinsPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &pins); err != nil {
		t.Fatal(err)
	}
	list := registry.List()
	slices.SortFunc(list, func(a, b model.Profile) int { return strings.Compare(a.ID, b.ID) })
	runID := make([]byte, 8)
	rand.Read(runID)
	type runRecord struct {
		Profile  string  `json:"profile"`
		JobID    string  `json:"job_id"`
		Recover  string  `json:"recover_error,omitempty"`
		Error    string  `json:"error,omitempty"`
		Result   *Result `json:"result,omitempty"`
		Duration string  `json:"duration"`
	}
	var runs []runRecord
	for i, p := range list {
		run := runRecord{Profile: p.ID, JobID: fmt.Sprintf("realhost-%s-%d", hex.EncodeToString(runID), i)}
		begun := time.Now()
		pin := pins.Sources[slices.IndexFunc(pins.Sources, func(s rhPin) bool { return s.Profile == p.ID })]
		h.setPhase("recover:" + p.ID)
		if err := engine.Recover(ctx); err != nil {
			run.Recover = err.Error()
		}
		single, err := profiles.New([]model.Profile{p})
		if err != nil {
			t.Fatal(err)
		}
		admission, err := single.Resolve(model.Request{Repo: p.Repo, SHA: pin.Commit, Kind: p.Kind, Profile: p.ID, Xcode: p.Xcode, Simulator: p.Simulator, TimeoutSeconds: p.DefaultTimeoutSeconds})
		if err != nil {
			t.Fatal(err)
		}
		request, _ := json.Marshal(admission.Request)
		digest := sha256.Sum256(request)
		token := make([]byte, 16)
		rand.Read(token)
		now := time.Now().UTC()
		job := model.Job{ID: run.JobID, Principal: "realhost", Request: admission.Request, Profile: admission.Profile, ProfileDigest: admission.ProfileDigest, RequestDigest: hex.EncodeToString(digest[:]), State: model.Preparing, CreatedAt: now, UpdatedAt: now, WorkerEpoch: "realhost-" + hex.EncodeToString(runID), LeaseToken: hex.EncodeToString(token)}
		archive, err := os.Open(filepath.Join(rhSourcesDir, pin.SHA256+".tar"))
		if err != nil {
			t.Fatal(err)
		}
		h.setPhase("execute:" + p.ID)
		result, err := engine.Execute(ctx, job, Source{Commit: pin.Commit, Tree: pin.Tree, SHA256: pin.SHA256, SizeBytes: pin.SizeBytes}, archive, nil)
		archive.Close()
		run.Result = &result
		if err != nil {
			run.Error = err.Error()
		}
		run.Duration = time.Since(begun).Round(time.Second).String()
		exportDir := filepath.Join(options.ExportRoot, job.ID)
		if _, statErr := os.Stat(exportDir); statErr == nil {
			copyCmd := exec.Command("/bin/cp", "-R", exportDir, filepath.Join(out, "exports-"+p.ID))
			if output, err := copyCmd.CombinedOutput(); err != nil {
				t.Logf("copy export: %v %s", err, output)
			}
		}
		engine.RemoveExport(job.ID)
		runs = append(runs, run)
		h.log("runs.jsonl", run)
		t.Logf("%s: state=%s reason=%q err=%v duration=%s", p.ID, result.State, result.Reason, err, run.Duration)
		h.mu.Lock()
		aborted := h.abort
		h.mu.Unlock()
		if aborted != nil {
			break
		}
	}
	h.setPhase("final")
	if control := os.Getenv("MACSERVE_RH_CONTROL"); control != "" {
		os.WriteFile(control, nil, 0600)
	}
	engine.Close()
	h.wg.Wait()
	stopTracking()
	stopRSS()
	rssPeak := <-rssDone

	// Accounting of every signalled instance.
	verdicts := map[string]string{}
	if data, err := os.ReadFile(filepath.Join(out, "classified.jsonl")); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			var c struct {
				PID     int    `json:"pid"`
				Start   string `json:"start"`
				Verdict string `json:"verdict"`
			}
			if json.Unmarshal([]byte(line), &c) == nil {
				verdicts[strconv.Itoa(c.PID)+"@"+c.Start] = c.Verdict
			}
		}
	}
	rows, _ = rhSnapshot()
	alive := map[rhIdentity]bool{}
	for _, r := range rows {
		alive[rhIdentity{r.pid, r.start}] = !r.zombie
	}
	type rhAccount struct {
		PID      int    `json:"pid"`
		Start    string `json:"start"`
		Exe      string `json:"exe"`
		Tracker  string `json:"tracker_class"`
		Verdict  string `json:"production_verdict"`
		Outcome  string `json:"outcome"`
		Survives bool   `json:"still_running_at_end"`
	}
	var accounting []rhAccount
	failures := 0
	h.mu.Lock()
	for id := range h.signalled {
		a := rhAccount{PID: id.PID, Start: id.Start, Verdict: verdicts[strconv.Itoa(id.PID)+"@"+id.Start], Survives: alive[id]}
		if p := h.procs[id]; p != nil {
			a.Exe, a.Tracker = p.Exe, p.Class
		} else if h.baseline[id] {
			a.Tracker, a.Exe = "baseline", h.baselineExe[id.PID]
		}
		switch {
		case a.Tracker == "descendant":
			a.Outcome = "harness descendant"
		case strings.HasPrefix(a.Verdict, "tolerated-"):
			a.Outcome = "tolerated launch"
		default:
			a.Outcome = "FAILURE"
			failures++
		}
		accounting = append(accounting, a)
	}
	sort.Slice(accounting, func(i, j int) bool { return accounting[i].PID < accounting[j].PID })
	excludedByClass := map[string]int{}
	for id := range h.excluded {
		if p := h.procs[id]; p != nil {
			excludedByClass[p.Class]++
		}
	}
	aborted := h.abort
	h.mu.Unlock()

	// Temporary root: delete unless something is mounted inside it.
	var mounts []string
	if n, err := unix.Getfsstat(nil, unix.MNT_NOWAIT); err == nil {
		buf := make([]unix.Statfs_t, n+8)
		if n, err = unix.Getfsstat(buf, unix.MNT_NOWAIT); err == nil {
			for _, s := range buf[:n] {
				on := unix.ByteSliceToString(s.Mntonname[:])
				if on == tmp || strings.HasPrefix(on, tmp+"/") {
					mounts = append(mounts, on+" ("+unix.ByteSliceToString(s.Fstypename[:])+")")
				}
			}
		}
	}
	removed := false
	if len(mounts) == 0 {
		removed = os.RemoveAll(tmp) == nil
	}
	summary := map[string]any{"runs": runs, "signals": accounting, "signal_failures": failures, "excluded_by_class": excludedByClass, "rss": rssPeak, "memory_limit_mib": rhMemoryLimitMiB, "rss_risk_over_70pct": rssPeak["peak_total_mib"].(int64) > rhMemoryLimitMiB*7/10, "mounts_in_temp_root": mounts, "temp_root": tmp, "temp_root_removed": removed}
	if aborted != nil {
		summary["abort"] = aborted.Error()
	}
	h.log("summary.json", summary)
	if aborted != nil {
		t.Fatalf("ABORT: %v", aborted)
	}
	for _, run := range runs {
		if run.Result == nil || run.Result.State != model.Succeeded {
			t.Errorf("%s did not succeed: recover=%q error=%q", run.Profile, run.Recover, run.Error)
		}
	}
	if len(runs) != len(list) {
		t.Errorf("ran %d of %d profiles", len(runs), len(list))
	}
	if failures != 0 {
		t.Errorf("%d signal targets are neither harness descendants nor tolerated launches", failures)
	}
}

// rhMeasure watches the owner account for 60 s before a run and records the
// parent (PID and executable) of every new process the harness did not start.
func rhMeasure(t *testing.T, h *rhHarness, rows []rhRow) {
	known := map[rhIdentity]bool{}
	for _, r := range rows {
		known[rhIdentity{r.pid, r.start}] = true
	}
	parents := map[string]int{}
	until := time.Now().Add(60 * time.Second)
	for time.Now().Before(until) {
		time.Sleep(50 * time.Millisecond)
		now, err := rhSnapshot()
		if err != nil {
			continue
		}
		byPID := map[int]rhRow{}
		for _, r := range now {
			byPID[r.pid] = r
		}
		for _, r := range now {
			id := rhIdentity{r.pid, r.start}
			if known[id] || r.uid != h.uid || r.ppid == h.self {
				continue
			}
			known[id] = true
			parent := byPID[r.ppid]
			key := strconv.Itoa(r.ppid) + ":" + rhExe(r.ppid)
			parents[key]++
			h.log("measure.jsonl", map[string]any{"t": time.Now().UTC(), "pid": r.pid, "comm": r.comm, "exe": rhExe(r.pid), "ppid": r.ppid, "parent_uid": parent.uid, "parent_exe": rhExe(r.ppid)})
		}
	}
	h.log("measure-parents.json", parents)
	t.Logf("new-process parents in 60 s: %v", parents)
}

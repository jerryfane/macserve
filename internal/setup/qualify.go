package setup

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jerryfane/macserve/internal/deploy"
	"github.com/jerryfane/macserve/internal/qualification"
	"github.com/jerryfane/macserve/internal/worker"
)

// Guided qualification (design §3.2 steps 6-8). The owner-side pieces (the
// owner canary, the owner-home control and the owner probe) run in the
// wizard as the owner; everything here runs in the root helper and only
// calls the existing qualification and worker APIs (Qualifier), unchanged.
//
// One round:
//
//	round-prepare  job login detected; persistence review; baseline proposal
//	(owner confirms both in the wizard; it creates the owner canary)
//	round-begin    accept persistence, worker reset to the proposal,
//	               tool-evidence source pins, qualify begin
//	(wizard starts the owner-home control)
//	round-job-probe launchctl asuser JOB_UID macserve _qualify-job-probe ID
//	(wizard runs the owner probe and stops the owner-home control)
//	round-collect  tool evidence, qualify collect; the round is recorded
//	               when its categories pass
//
// The round's progress is kept root-only beside the ledger (roundState),
// so setup resumes after each part: a begun session that is still fresh
// continues with the probes; any later interruption, a failed category or
// a new boot starts a new session (sessions are append-only evidence).

// Qualifier is the existing qualification and worker APIs that the rounds
// and approve-and-start call, with no change to their logic.
// SystemQualifier calls them; tests fake every method.
type Qualifier interface {
	// ReviewPersistence is worker.ReviewPersistence: it writes the job
	// account's login items and agents to a new candidate file.
	ReviewPersistence(ctx context.Context, candidate string) (string, error)
	// AcceptPersistence is worker.AcceptPersistence.
	AcceptPersistence(ctx context.Context, candidate, reviewedSHA256 string) error
	// PersistenceDigest is worker.PersistenceDigest of the reviewed
	// authority; fs.ErrNotExist when none was accepted yet.
	PersistenceDigest() (string, error)
	// ResetBaseline is worker.ResetGUIBaseline (`worker-reset --pids`).
	ResetBaseline(ctx context.Context, pids []int) error
	// CheckBaseline is worker.CheckBaselinePolicy on the saved baseline.
	CheckBaseline(ctx context.Context) error
	// JobProcesses lists the job UID's processes with kernel facts.
	JobProcesses(jobUID uint32) ([]JobProcess, error)
	// Source exports repo at its default branch head with internal/source
	// and the App's contents token, and stores the archive as dir/<sha256>.tar.
	Source(ctx context.Context, repo, dir string) (worker.Source, error)
	// Begin, ToolEvidence, Collect, Approve and ActivationCheck are the
	// qualification functions of the same names (RunToolEvidence).
	Begin(ctx context.Context, o qualification.BeginOptions) error
	ToolEvidence(ctx context.Context, session string) error
	Collect(ctx context.Context, dir, owner, receipts string) error
	Approve(ctx context.Context, dir string) error
	ActivationCheck(ctx context.Context) error
	// Health is the controller readiness gate's blockers (controller.Guard).
	Health(ctx context.Context) ([]string, error)
}

// JobProcess is one process of the job UID. Restricted is nil when
// Executable is a SIP-restricted (SF_RESTRICTED), root-owned regular file
// without group or other write.
type JobProcess struct {
	PID        int
	Start      string
	Executable string
	Zombie     bool
	Restricted error
}

// RoundReview is what the owner confirms before a round: the job
// account's third-party login items and agents (Accept: they differ from
// the accepted list, which round-begin replaces) and the proposed GUI
// baseline, grouped by executable name. Digest binds both.
type RoundReview struct {
	Persistence []string `json:"persistence"`
	Accept      bool     `json:"accept"`
	Processes   int      `json:"processes"`
	Executables []string `json:"executables"`
	Digest      string   `json:"digest"`
}

// Round phases.
const (
	phaseReviewed = "reviewed"
	phaseBegun    = "begun"
	phaseProbed   = "probed"
	phaseDone     = "done"
)

// sessionFresh is how long a begun session may continue after an
// interruption: the challenge lives two hours and tool evidence needs its
// own share of it.
const sessionFresh = 75 * time.Minute

// proposedProcess is one process of the proposed baseline.
type proposedProcess struct {
	PID        int    `json:"pid"`
	Start      string `json:"start"`
	Executable string `json:"executable"`
}

// roundState is the root-only progress of one round in one boot.
type roundState struct {
	Round       Step              `json:"round"`
	Boot        Boot              `json:"boot"`
	Phase       string            `json:"phase"`
	Candidate   string            `json:"candidate,omitempty"`
	Accept      bool              `json:"accept,omitempty"`
	Persistence []string          `json:"persistence,omitempty"`
	Baseline    []proposedProcess `json:"baseline,omitempty"`
	Review      string            `json:"review,omitempty"`
	Session     string            `json:"session,omitempty"`
	Begun       *time.Time        `json:"begun,omitempty"`
}

// OwnerCanaryName is the nonsecret owner-home canary in the owner's home
// (docs/install.md): mode 0644, so the job is denied by the home boundary.
const (
	OwnerCanaryName    = "macserve-boundary-canary.txt"
	OwnerCanaryContent = "macserve owner boundary canary\n"
	ownerFilesDir      = ".macserve-setup"
)

// OwnerCanary is the owner canary path in home.
func OwnerCanary(home string) string { return filepath.Join(home, OwnerCanaryName) }

// OwnerFiles are the owner-written files of a session: the directory, the
// owner probe report and the owner-home control receipt. The wizard writes
// them as the owner; collect reads them. No path crosses the socket: both
// sides derive them from the owner's home and the session ID.
func OwnerFiles(home, session string) (dir, report, receipts string) {
	dir = filepath.Join(home, ownerFilesDir, session)
	return dir, filepath.Join(dir, "owner-probe.json"), filepath.Join(dir, "owner-home-receipts.json")
}

// sessionDir is qualification.SessionDirectory under h.Root.
func (h *Helper) sessionDir(id string) string {
	return filepath.Join(h.Root, "var", "qualification", id)
}

func (h *Helper) roundPath(round Step) string {
	return filepath.Join(h.Store.Ledger, string(round)+".json")
}

func (h *Helper) candidatePath(round Step) string {
	return filepath.Join(h.Store.Ledger, string(round)+"-persistence-candidate.json")
}

// readRound returns the saved state of round, or a zero state.
func (h *Helper) readRound(round Step) (roundState, []byte, error) {
	var st roundState
	data, err := h.Store.readPrivate(h.roundPath(round), 1<<20)
	if errors.Is(err, fs.ErrNotExist) {
		return st, nil, nil
	}
	if err != nil {
		return st, nil, err
	}
	if err := json.Unmarshal(data, &st); err != nil || st.Round != round {
		return roundState{}, nil, fmt.Errorf("%s: invalid round state", h.roundPath(round))
	}
	return st, data, nil
}

// currentRound is the state of round in boot; a state of another boot is
// discarded (its session cannot continue).
func (h *Helper) currentRound(round Step, boot Boot) (roundState, error) {
	st, _, err := h.readRound(round)
	if err != nil || !st.Boot.same(boot) {
		return roundState{Round: round, Boot: boot}, err
	}
	return st, nil
}

func (h *Helper) saveRound(st roundState) ([]byte, error) {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	return data, h.Store.writePrivate(h.roundPath(st.Round), data)
}

// runningRound requires round to be running in the current boot and
// returns the boot and the round's state.
func (h *Helper) runningRound(l *Ledger, round Step) (Boot, roundState, error) {
	boot, err := h.Boot()
	if err != nil {
		return boot, roundState{}, fmt.Errorf("boot identity: %w", err)
	}
	if r := l.record(round); r.Status != StatusRunning || !r.Boot.same(boot) {
		return boot, roundState{}, fmt.Errorf("%s is not running in this boot; run macserve setup again to prepare it", round)
	}
	st, err := h.currentRound(round, boot)
	return boot, st, err
}

// roundReady requires what every round needs: the installed deploy.env,
// the owner or the login window at the console with the build account
// logged in in the background, and macserve's services disabled and not
// loaded (the broker was never started).
func (h *Helper) roundReady(ctx context.Context, l *Ledger) (deploy.Environment, error) {
	e, _, err := h.installedEnv(l)
	if err != nil {
		return e, err
	}
	if ok, detail := h.checkJobLogin(e.JobUID, e.OwnerUID); !ok {
		return e, errors.New(detail)
	}
	return e, h.servicesDisabled(ctx)
}

// roundPrepare begins round (in the ledger) and returns the review, or
// the round's begun session if it is still fresh.
func (h *Helper) roundPrepare(l *Ledger, loc LedgerLocation, round Step) (Response, error) {
	ctx := context.Background()
	e, _, err := h.installedEnv(l)
	if err != nil {
		return Response{}, err
	}
	if ok, detail := h.checkJobLogin(e.JobUID, e.OwnerUID); !ok {
		return Response{Detail: detail}, nil
	}
	if err := baselineEligible(l); err != nil {
		return Response{}, err
	}
	if _, err := h.roundReady(ctx, l); err != nil {
		return Response{}, err
	}
	boot, err := h.begin(l, loc, round)
	if err != nil {
		return Response{}, err
	}
	st, err := h.currentRound(round, boot)
	if err != nil {
		return Response{}, err
	}
	if st.Phase == phaseBegun && st.Begun != nil && h.Now().Before(st.Begun.Add(sessionFresh)) {
		return Response{Session: st.Session}, nil
	}
	st = roundState{Round: round, Boot: boot, Phase: phaseReviewed}
	if st.Candidate, st.Persistence, st.Accept, err = h.reviewPersistence(ctx, round); err != nil {
		return Response{}, err
	}
	if st.Baseline, err = h.proposeBaseline(e.JobUID); err != nil {
		return Response{}, err
	}
	review := st.review()
	st.Review = review.Digest
	if _, err := h.saveRound(st); err != nil {
		return Response{}, err
	}
	return Response{Review: &review}, nil
}

// review is what the owner sees; its digest binds the candidate digest,
// whether it replaces the accepted list, and the exact proposal.
func (st roundState) review() RoundReview {
	r := RoundReview{Persistence: st.Persistence, Accept: st.Accept, Processes: len(st.Baseline)}
	if r.Persistence == nil {
		r.Persistence = []string{}
	}
	counts := map[string]int{}
	for _, p := range st.Baseline {
		counts[filepath.Base(p.Executable)]++
	}
	for _, name := range slices.Sorted(maps.Keys(counts)) {
		if counts[name] > 1 {
			name += " (" + strconv.Itoa(counts[name]) + ")"
		}
		r.Executables = append(r.Executables, name)
	}
	bound, _ := json.Marshal(struct {
		Candidate string            `json:"candidate"`
		Accept    bool              `json:"accept"`
		Baseline  []proposedProcess `json:"baseline"`
	}{st.Candidate, st.Accept, st.Baseline})
	r.Digest = digestHex(bound)
	return r
}

// baselineEligible is decision D5: the baseline is proposed only for a
// build account this ledger created (install done here) whose services
// setup never started (approve-and-start not begun). roundReady checks
// that the services are disabled and not loaded.
func baselineEligible(l *Ledger) error {
	if l.record(StepInstall).Status != StatusDone || l.record(StepApproveAndStart).Status != StatusPending || l.Approval != nil {
		return errors.New("the process baseline is proposed only for a build account this setup created and whose services it never started")
	}
	return nil
}

// reviewPersistence runs worker-persistence inspect into a new root-only
// candidate and lists its third-party items. Accept reports that the
// candidate differs from the accepted list (or none was accepted).
func (h *Helper) reviewPersistence(ctx context.Context, round Step) (string, []string, bool, error) {
	path := h.candidatePath(round)
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", nil, false, err
	}
	digest, err := h.Qualify.ReviewPersistence(ctx, path)
	if err != nil {
		return "", nil, false, fmt.Errorf("the build account's login items and agents cannot be accepted (%v); nothing was changed. Review them as docs/install.md describes", err)
	}
	data, err := h.Store.readPrivate(path, 1<<20)
	if err != nil {
		return "", nil, false, err
	}
	if digestHex(data) != digest {
		return "", nil, false, errors.New("the persistence candidate changed after inspection")
	}
	var m worker.PersistenceManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return "", nil, false, fmt.Errorf("persistence candidate: %w", err)
	}
	if len(m.Problems) != 0 {
		return "", nil, false, fmt.Errorf("the build account has unresolved login items or agents: %s", strings.Join(m.Problems, "; "))
	}
	current, err := h.Qualify.PersistenceDigest()
	accept := err != nil || current != digest
	return digest, persistenceItems(m), accept, nil
}

// persistenceItems lists the candidate's third-party registered code and
// any registration without code (decision D6: an empty list is accepted
// without a question).
func persistenceItems(m worker.PersistenceManifest) []string {
	items := []string{}
	for _, id := range slices.Sorted(maps.Keys(m.Code)) {
		c := m.Code[id]
		items = append(items, fmt.Sprintf("%s: %s, team %s, signed %s, at %s", id, c.Identifier, c.Team, c.Requirement, c.Path))
	}
	if extra := len(m.Census.Records) - len(m.Code); extra > 0 {
		items = append(items, fmt.Sprintf("%d background item record(s) without registered code", extra))
	}
	return items
}

// codeRunners and codeRunnerDirs are the shells, interpreters and Terminal
// the baseline executable policy refuses (internal/worker/baseline_policy.go,
// the rule begin, collect and approve enforce). The proposal applies the
// same rule up front so a refused process is reported before any reset;
// after the reset worker.CheckBaselinePolicy checks the saved baseline.
var (
	codeRunners = []string{
		"/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
		"/System/Applications/Utilities/Script Editor.app/Contents/MacOS/Script Editor",
		"/System/Applications/Automator.app/Contents/MacOS/Automator",
		"/System/Library/Frameworks/JavaScriptCore.framework/Versions/A/Helpers/jsc",
	}
	codeRunnerDirs = []string{"/bin/", "/sbin/", "/usr/bin/"}
)

func codeRunner(path string) bool {
	if slices.Contains(codeRunners, path) {
		return true
	}
	for _, dir := range codeRunnerDirs {
		if strings.HasPrefix(path, dir) {
			return true
		}
	}
	return false
}

// proposeBaseline proposes every job-UID process, and refuses unless each
// runs a SIP-restricted, root-owned, non-writable executable that is not a
// shell, interpreter or Terminal (decision D5).
func (h *Helper) proposeBaseline(jobUID uint32) ([]proposedProcess, error) {
	procs, err := h.Qualify.JobProcesses(jobUID)
	if err != nil {
		return nil, fmt.Errorf("the build account's processes: %w", err)
	}
	var proposal []proposedProcess
	var refused []string
	for _, p := range procs {
		switch {
		case p.Zombie:
			refused = append(refused, fmt.Sprintf("PID %d is a zombie", p.PID))
		case p.Executable == "":
			refused = append(refused, fmt.Sprintf("PID %d: executable unavailable", p.PID))
		case codeRunner(p.Executable):
			refused = append(refused, fmt.Sprintf("PID %d runs %s: shells, interpreters and Terminal are not trusted baseline processes", p.PID, p.Executable))
		case p.Restricted != nil:
			refused = append(refused, fmt.Sprintf("PID %d runs %s: %v", p.PID, p.Executable, p.Restricted))
		default:
			proposal = append(proposal, proposedProcess{PID: p.PID, Start: p.Start, Executable: p.Executable})
		}
	}
	if len(refused) > 0 {
		return nil, fmt.Errorf("the build account runs processes the baseline rule does not admit; nothing was changed. Log out of the build account, log in again without opening anything, use Switch User, then run macserve setup again: %s", strings.Join(refused, "; "))
	}
	if len(proposal) == 0 {
		return nil, errors.New("the build account has no processes; log in to it at the login window first")
	}
	slices.SortFunc(proposal, func(a, b proposedProcess) int { return a.PID - b.PID })
	return proposal, nil
}

// roundBegin applies the review the owner confirmed (digest) and begins
// the qualification session.
func (h *Helper) roundBegin(l *Ledger, loc LedgerLocation, round Step, digest string) (Response, error) {
	ctx := context.Background()
	_, st, err := h.runningRound(l, round)
	if err != nil {
		return Response{}, err
	}
	if st.Phase != phaseReviewed || st.Review != digest {
		return Response{}, errors.New("this is not the review you confirmed; run macserve setup again to review")
	}
	e, err := h.roundReady(ctx, l)
	if err != nil {
		return Response{}, err
	}
	live, err := h.proposeBaseline(e.JobUID)
	if err != nil {
		return Response{}, err
	}
	if !slices.Equal(live, st.Baseline) {
		return Response{}, errors.New("the build account's processes changed since you confirmed them; nothing was changed. Run macserve setup again to review")
	}
	canary := OwnerCanary(h.Owner.Home)
	if err := h.checkOwnerCanary(canary); err != nil {
		return Response{}, err
	}
	var previous string
	if round == StepRound2 {
		prev, _, err := h.readRound(StepRound1)
		if err != nil || prev.Phase != phaseDone || prev.Session == "" {
			return Response{}, errors.Join(errors.New("round 1's session is not recorded"), err)
		}
		previous = h.sessionDir(prev.Session)
	}
	if st.Accept {
		if err := h.Qualify.AcceptPersistence(ctx, h.candidatePath(round), st.Candidate); err != nil {
			return Response{}, fmt.Errorf("accept the reviewed login items and agents: %w", err)
		}
	}
	pids := make([]int, len(live))
	for i, p := range live {
		pids[i] = p.PID
	}
	if err := h.Qualify.ResetBaseline(ctx, pids); err != nil {
		return Response{}, fmt.Errorf("worker-reset: %w", err)
	}
	if err := h.Qualify.CheckBaseline(ctx); err != nil {
		return Response{}, fmt.Errorf("the reset baseline: %w", err)
	}
	if err := h.pinSources(ctx, e); err != nil {
		return Response{}, err
	}
	id, err := newSessionID(round)
	if err != nil {
		return Response{}, err
	}
	opts := qualification.BeginOptions{Environment: h.configPath("deploy.env"), Session: h.sessionDir(id), OwnerCanary: canary, Previous: previous}
	if err := h.Qualify.Begin(ctx, opts); err != nil {
		return Response{}, fmt.Errorf("qualify begin: %w", err)
	}
	now := h.Now().UTC()
	st.Phase, st.Session, st.Begun = phaseBegun, id, &now
	if _, err := h.saveRound(st); err != nil {
		return Response{}, err
	}
	return Response{Session: id}, nil
}

func newSessionID(round Step) (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "setup-" + string(round) + "-" + hex.EncodeToString(b[:]), nil
}

// checkOwnerCanary requires the canary the wizard created: a regular
// owner-owned single-link file of mode 0644 in the owner's home.
func (h *Helper) checkOwnerCanary(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("owner canary: %w", err)
	}
	uid, _, nlink, ok := statOwner(info)
	if !ok || !info.Mode().IsRegular() || uid != h.Owner.UID || info.Mode().Perm() != 0o644 || nlink != 1 {
		return fmt.Errorf("%s must be your own regular file with mode 0644", path)
	}
	return nil
}

// pinSources writes qualification-sources.json when the registry has
// recipes: one archive per repository, from internal/source at the
// default branch head (decision D8), stored root-owned as
// qualification-sources/<sha256>.tar. Existing pins are kept, so round 2
// and a retried round run the same source. A template is pinned to the
// repository chosen at preflight.
func (h *Helper) pinSources(ctx context.Context, e deploy.Environment) error {
	pinsPath := h.configPath("qualification-sources.json")
	if _, err := os.Lstat(pinsPath); err == nil {
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	registry, err := h.registry()
	if err != nil {
		return err
	}
	chosen := ""
	for repo := range e.Repositories {
		chosen = repo
	}
	pins := qualification.SourcePins{Schema: 1}
	archives := map[string]worker.Source{}
	dir := filepath.Join(h.Root, "qualification-sources")
	pin := func(profile, repo string, template bool) error {
		if repo == "" {
			return fmt.Errorf("template %s needs the repository chosen at preflight", profile)
		}
		src, ok := archives[repo]
		if !ok {
			if err := h.Store.ensureDir(dir, 0o755); err != nil {
				return err
			}
			var err error
			if src, err = h.Qualify.Source(ctx, repo, dir); err != nil {
				return fmt.Errorf("tool-evidence source of %s: %w", repo, err)
			}
			if len(src.Commit) != 40 || len(src.Tree) != 40 || !sha256Hex.MatchString(src.SHA256) || src.SizeBytes <= 0 {
				return fmt.Errorf("tool-evidence source of %s: invalid archive identity", repo)
			}
			archives[repo] = src
		}
		p := qualification.SourcePin{Profile: profile, Commit: src.Commit, Tree: src.Tree, SHA256: src.SHA256, SizeBytes: src.SizeBytes}
		if template {
			p.Repo = repo
		}
		pins.Sources = append(pins.Sources, p)
		return nil
	}
	for _, p := range registry.List() {
		if err := pin(p.ID, p.Repo, false); err != nil {
			return err
		}
	}
	for _, t := range registry.Templates() {
		if len(e.Repositories) != 1 {
			return fmt.Errorf("template %s needs exactly one repository pinned at preflight", t.ID)
		}
		if err := pin(t.ID, chosen, true); err != nil {
			return err
		}
	}
	if len(pins.Sources) == 0 {
		return nil
	}
	data, err := json.MarshalIndent(pins, "", "  ")
	if err != nil {
		return err
	}
	return h.Store.writeFile(pinsPath, append(data, '\n'), 0o644)
}

// roundJobProbe runs the root background job probe in the build account's
// GUI session. An attempt consumes the session.
func (h *Helper) roundJobProbe(l *Ledger, round Step) (Response, error) {
	ctx := context.Background()
	_, st, err := h.runningRound(l, round)
	if err != nil {
		return Response{}, err
	}
	if st.Phase != phaseBegun {
		return Response{}, errors.New("the qualification session is not begun; run macserve setup again")
	}
	e, err := h.roundReady(ctx, l)
	if err != nil {
		return Response{}, err
	}
	st.Phase = phaseProbed
	if _, err := h.saveRound(st); err != nil {
		return Response{}, err
	}
	argv := []string{"/bin/launchctl", "asuser", strconv.FormatUint(uint64(e.JobUID), 10), filepath.Join(h.Root, "bin", "macserve"), "_qualify-job-probe", st.Session}
	if err := h.Exec(ctx, Cmd{Argv: argv, Env: []string{FixedPath}, Timeout: 10 * time.Minute}); err != nil {
		return Response{}, fmt.Errorf("job probe: %w", err)
	}
	return Response{Done: true}, nil
}

// roundCollect runs tool evidence (when the registry has recipes) and
// collect, and records the round when its categories pass: every category
// passes, except reboot in round 1. Otherwise the session is spent and
// the next attempt begins a new one.
func (h *Helper) roundCollect(l *Ledger, loc LedgerLocation, round Step) (Response, error) {
	ctx := context.Background()
	boot, st, err := h.runningRound(l, round)
	if err != nil {
		return Response{}, err
	}
	if st.Phase != phaseProbed {
		return Response{}, errors.New("the job probe has not run in this session; run macserve setup again")
	}
	spend := func(cause error) (Response, error) {
		st.Phase = ""
		_, serr := h.saveRound(st)
		return Response{}, errors.Join(cause, serr)
	}
	registry, err := h.registry()
	if err != nil {
		return spend(err)
	}
	var items []string
	if len(registry.List())+len(registry.Templates()) > 0 {
		if err := h.servicesDisabled(ctx); err != nil {
			return spend(err)
		}
		if err := h.Qualify.ToolEvidence(ctx, st.Session); err != nil {
			items = append(items, "tool evidence: "+err.Error())
		}
	}
	_, report, receipts := OwnerFiles(h.Owner.Home, st.Session)
	dir := h.sessionDir(st.Session)
	if err := h.Qualify.Collect(ctx, dir, report, receipts); err != nil {
		return spend(fmt.Errorf("qualify collect: %w", err))
	}
	raw, err := h.Store.readPrivate(filepath.Join(dir, "candidate.json"), 4<<20)
	if err != nil {
		return spend(err)
	}
	var candidate qualification.Candidate
	if err := json.Unmarshal(raw, &candidate); err != nil {
		return spend(fmt.Errorf("candidate.json: %w", err))
	}
	categories := map[string]string{}
	for name, c := range candidate.Categories {
		categories[name] = c.Status
		if !categoryPasses(round, name, c.Status) {
			items = append(items, name+": "+c.Status+" ("+c.Reason+")")
		}
	}
	if len(categories) == 0 {
		items = append(items, "candidate.json has no categories")
	}
	slices.Sort(items)
	if len(items) > 0 {
		resp, err := spend(nil)
		resp.Categories, resp.Items = categories, items
		return resp, err
	}
	st.Phase = phaseDone
	state, err := h.saveRound(st)
	if err != nil {
		return Response{}, err
	}
	inputs := map[string]string{"candidate.json": digestHex(raw), "round-state": digestHex(state)}
	if pins, err := h.readConfig("qualification-sources.json", 1<<20); err == nil {
		inputs["qualification-sources.json"] = digestHex(pins)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return Response{}, err
	}
	if err := h.complete(l, loc, round, boot, inputs); err != nil {
		return Response{}, err
	}
	return Response{Done: true, Categories: categories}, nil
}

// categoryPasses: pass, or informational network reachability; reboot
// stays pending until the round on the next boot.
func categoryPasses(round Step, name, status string) bool {
	switch {
	case status == "pass", status == "not enforced in phase 1":
		return true
	case round == StepRound1 && name == "reboot" && status == "pending":
		return true
	}
	return false
}

// Restart kinds the reboot step returns in Items.
const (
	// RestartAuth: FileVault is on and supports an authenticated restart
	// (fdesetup authrestart asks for the password before the restart).
	RestartAuth = "authrestart"
	// RestartUnlock: FileVault is on without authenticated restart; the
	// disk is unlocked at the Mac after the restart.
	RestartUnlock = "restart-unlock"
	// RestartPlain: FileVault is off.
	RestartPlain = "restart"
)

// AfterBoot is what the owner does after the restart; setup prints it
// before the restart and again on every run until the restart is seen.
const AfterBoot = `After the restart:
  1. Log in to the build account at the login window, wait for its desktop and open nothing.
  2. Use Switch User to come back to your own account.
  3. Open Terminal and run macserve setup again.`

// reboot begins the reboot step and returns how to restart; once the boot
// identity changed (kern.boottime and kern.bootsessionuuid) it completes
// the step.
func (h *Helper) reboot(l *Ledger, loc LedgerLocation) (Response, error) {
	boot, err := h.Boot()
	if err != nil {
		return Response{}, fmt.Errorf("boot identity: %w", err)
	}
	r := l.record(StepReboot)
	if r.Status == StatusRunning && r.Boot.differs(boot) {
		if err := h.complete(l, loc, StepReboot, boot, nil); err != nil {
			return Response{}, err
		}
		return Response{Done: true, Detail: "the Mac restarted"}, nil
	}
	if r.Status == StatusPending {
		if _, err := h.begin(l, loc, StepReboot); err != nil {
			return Response{}, err
		}
	}
	kind, err := h.restartKind(context.Background())
	if err != nil {
		return Response{}, err
	}
	return Response{Detail: AfterBoot, Items: []string{kind}}, nil
}

func (h *Helper) restartKind(ctx context.Context) (string, error) {
	fdesetup := func(arg string) (string, error) {
		out, status, err := h.Output(ctx, Cmd{Argv: []string{"/usr/bin/fdesetup", arg}, Env: []string{FixedPath}, Timeout: 30 * time.Second})
		if err == nil && status != 0 {
			err = fmt.Errorf("exit status %d", status)
		}
		first, _, _ := strings.Cut(string(out), "\n")
		return strings.TrimSpace(first), err
	}
	status, err := fdesetup("status")
	if err != nil {
		return "", fmt.Errorf("fdesetup status: %w", err)
	}
	switch status {
	case "FileVault is Off.":
		return RestartPlain, nil
	case "FileVault is On.":
		if ar, err := fdesetup("supportsauthrestart"); err == nil && ar == "true" {
			return RestartAuth, nil
		}
		return RestartUnlock, nil
	}
	return "", fmt.Errorf("unexpected FileVault status %q", status)
}

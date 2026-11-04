package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jerryfane/macserve/internal/controller"
	"github.com/jerryfane/macserve/internal/profiles"
	"github.com/jerryfane/macserve/internal/qualification"
)

// Approve-and-start (design §3.2 step 9). The owner reads one summary in
// the wizard and types approve; the helper then records the approval,
// runs qualify approve and activation-check and starts the services with
// the checks of the private admin wrapper (setup_qualification.py
// approve_start, disabled_services, start_labels): owner.pause and the
// profiles unchanged before, during and after; no enabled launchd
// override and nothing already loaded; enable then bootstrap, one label at
// a time; a partial start fails the ledger and prints, never runs, the
// recovery commands. owner.pause is removed afterwards, as a separate
// logged action, once health is valid (decision D15).

// serviceLabels are macserve's three launchd services, in start order.
var serviceLabels = []string{"org.macserve.worker", "org.macserve.maintenance", "org.macserve.controller"}

func (h *Helper) daemonPlist(label string) string {
	return filepath.Join(h.Store.Top, "Library", "LaunchDaemons", label+".plist")
}

func (h *Helper) registry() (*profiles.Registry, error) {
	if _, err := h.readConfig("profiles.json", 1<<20); err != nil {
		return nil, err
	}
	return profiles.Load(h.configPath("profiles.json"))
}

// launchctlOutput runs launchctl and returns its output and exit status.
func (h *Helper) launchctlOutput(ctx context.Context, args ...string) ([]byte, int, error) {
	out, status, err := h.Output(ctx, launchctl(args...))
	if err != nil {
		return nil, 0, fmt.Errorf("launchctl %s: %w", strings.Join(args, " "), err)
	}
	return out, status, nil
}

// launchctlOK runs launchctl and requires exit status 0.
func (h *Helper) launchctlOK(ctx context.Context, args ...string) error {
	_, status, err := h.launchctlOutput(ctx, args...)
	if err == nil && status != 0 {
		err = fmt.Errorf("launchctl %s: exit status %d", strings.Join(args, " "), status)
	}
	return err
}

var (
	disabledEntry = `"([^"\\\x00-\x1f\x7f]+)"\s*=>\s*(true|false|enabled|disabled)`
	disabledAll   = regexp.MustCompile(`^\s*disabled services = \{((?:\s*` + disabledEntry + `\s*)*)\s*\}\s*$`)
	disabledOne   = regexp.MustCompile(disabledEntry)
)

// parseDisabled parses `launchctl print-disabled system`: label to
// disabled. Anything else, or a label listed twice, is refused.
func parseDisabled(text string) (map[string]bool, error) {
	m := disabledAll.FindStringSubmatch(text)
	if m == nil {
		return nil, errors.New("launchd disabled state unreadable")
	}
	states := map[string]bool{}
	for _, e := range disabledOne.FindAllStringSubmatch(m[1], -1) {
		if _, dup := states[e[1]]; dup {
			return nil, errors.New("duplicate launchd disabled override")
		}
		states[e[1]] = e[2] == "true" || e[2] == "disabled"
	}
	return states, nil
}

// servicesDisabled requires each own service as deploy-install left it:
// the plist names the label with Disabled true and RunAtLoad false, no
// enabled (or unknown) launchd override, and not loaded.
func (h *Helper) servicesDisabled(ctx context.Context) error {
	out, status, err := h.launchctlOutput(ctx, "print-disabled", "system")
	if err != nil {
		return err
	}
	if status != 0 {
		return fmt.Errorf("launchctl print-disabled system: exit status %d", status)
	}
	overrides, err := parseDisabled(string(out))
	if err != nil {
		return err
	}
	for _, label := range serviceLabels {
		if err := h.checkDisabledPlist(label); err != nil {
			return err
		}
		if disabled, ok := overrides[label]; ok && !disabled {
			return fmt.Errorf("own service has an enabled launchd override: %s", label)
		}
		_, status, err := h.launchctlOutput(ctx, "print", "system/"+label)
		if err != nil {
			return err
		}
		switch status {
		case 0:
			return fmt.Errorf("own service is already loaded; no automatic repair: %s", label)
		case 113:
		default:
			return fmt.Errorf("launchctl print system/%s: exit status %d", label, status)
		}
	}
	return nil
}

// checkDisabledPlist reads the installed plist (root-owned, not group or
// other writable) and checks its top-level Label, Disabled and RunAtLoad.
func (h *Helper) checkDisabledPlist(label string) error {
	path := h.daemonPlist(label)
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	uid, _, nlink, ok := statOwner(info)
	if !ok || !info.Mode().IsRegular() || uid != h.Store.RootUID || info.Mode().Perm()&0o022 != 0 || nlink != 1 || info.Size() > 64<<10 {
		return fmt.Errorf("%s must be a root-owned single-link regular file", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	keys, err := plistTop(data)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if keys["Label"] != label || keys["Disabled"] != "true" || keys["RunAtLoad"] != "false" {
		return fmt.Errorf("expected reviewed disabled own service plist: %s", label)
	}
	return nil
}

// plistTop returns the string and boolean values of an XML plist's
// top-level dictionary; other values are skipped. A key listed twice is
// refused.
func plistTop(data []byte) (map[string]string, error) {
	d := xml.NewDecoder(bytes.NewReader(data))
	d.Strict = true
	keys := map[string]string{}
	var stack []string
	key := ""
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if len(stack) < 2 {
				if t.Name.Local != []string{"plist", "dict"}[len(stack)] {
					return nil, errors.New("not a plist dictionary")
				}
				stack = append(stack, t.Name.Local)
				continue
			}
			if len(stack) > 2 {
				stack = append(stack, t.Name.Local)
				continue
			}
			// A member of the top-level dictionary: DecodeElement and Skip
			// consume it through its end element.
			var value string
			switch {
			case t.Name.Local == "key":
				if err := d.DecodeElement(&value, &t); err != nil {
					return nil, err
				}
				if _, dup := keys[value]; dup || key != "" {
					return nil, errors.New("duplicate or dangling plist key")
				}
				key = value
				continue
			case key == "":
				return nil, errors.New("plist value without key")
			case t.Name.Local == "string":
				if err := d.DecodeElement(&value, &t); err != nil {
					return nil, err
				}
			default:
				if err := d.Skip(); err != nil {
					return nil, err
				}
				if t.Name.Local == "true" || t.Name.Local == "false" {
					value = t.Name.Local
				}
			}
			keys[key], key = value, ""
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, errors.New("unbalanced plist")
			}
			stack = stack[:len(stack)-1]
		}
	}
	if key != "" || len(stack) != 0 || len(keys) == 0 {
		return nil, errors.New("incomplete plist dictionary")
	}
	return keys, nil
}

// pauseBinding is the state of owner.pause and profiles.json, which the
// controller must read from their fixed paths: owner.pause absent, or its
// digest, device, inode and modification time; and the profiles digest.
// The summary shows it, the approval records it and the start compares
// it before, during and after, in every run.
func (h *Helper) pauseBinding() (string, error) {
	c, err := controller.LoadConfig(h.configPath("controller.json"))
	if err != nil {
		return "", err
	}
	if c.PauseFile != h.configPath("owner.pause") || c.ProfilesFile != h.configPath("profiles.json") {
		return "", errors.New("controller must honor the fixed owner.pause and reviewed profiles paths")
	}
	pause, err := h.pauseState()
	if err != nil {
		return "", err
	}
	prof, err := h.readConfig("profiles.json", 1<<20)
	if err != nil {
		return "", err
	}
	return pause + ", profiles.json " + digestHex(prof), nil
}

// pauseState is "owner.pause absent" or the file's digest and identity,
// read between two equal lstats.
func (h *Helper) pauseState() (string, error) {
	path := h.configPath("owner.pause")
	identity := func() (string, error) {
		info, err := os.Lstat(path)
		if err != nil {
			return "", err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return "", errors.New("owner.pause: no file identity")
		}
		return fmt.Sprintf("inode %d:%d mtime %d", uint64(st.Dev), uint64(st.Ino), info.ModTime().UnixNano()), nil
	}
	before, err := identity()
	if errors.Is(err, fs.ErrNotExist) {
		return "owner.pause absent", nil
	}
	if err != nil {
		return "", err
	}
	data, err := h.readConfig("owner.pause", 64<<10)
	if err != nil {
		return "", fmt.Errorf("owner.pause: %w", err)
	}
	if after, err := identity(); err != nil || after != before {
		return "", errors.Join(errors.New("owner.pause changed while it was read"), err)
	}
	return "owner.pause " + digestHex(data) + " " + before, nil
}

// errAnotherBoot refuses approve-and-start after a restart: approval is
// boot-bound.
var errAnotherBoot = errors.New("approve-and-start began before the Mac restarted, and approval is bound to one boot; nothing was started. Requalify after the restart (docs/install.md, requalification after reboot)")

// summaryVerb begins approve-and-start and returns the summary.
func (h *Helper) summaryVerb(l *Ledger, loc LedgerLocation) (Response, error) {
	boot, err := h.Boot()
	if err != nil {
		return Response{}, fmt.Errorf("boot identity: %w", err)
	}
	r := l.record(StepApproveAndStart)
	if r.Status == StatusPending {
		if boot, err = h.begin(l, loc, StepApproveAndStart); err != nil {
			return Response{}, err
		}
	} else if !r.Boot.same(boot) {
		return Response{}, errAnotherBoot
	}
	text, _, err := h.summary(l)
	if err != nil {
		return Response{}, err
	}
	return Response{Detail: text}, nil
}

// summary is the one screen the owner approves and the bindings it shows.
// Its digest is recorded with the approval; approve recomputes it and
// refuses any difference.
func (h *Helper) summary(l *Ledger) (string, string, error) {
	e, envData, err := h.installedEnv(l)
	if err != nil {
		return "", "", err
	}
	c, err := controller.LoadConfig(h.configPath("controller.json"))
	if err != nil {
		return "", "", err
	}
	if c.GitHub == nil {
		return "", "", errors.New("controller.json has no GitHub section")
	}
	registry, err := h.registry()
	if err != nil {
		return "", "", err
	}
	round1, _, err := h.readRound(StepRound1)
	if err != nil {
		return "", "", err
	}
	round2, _, err := h.readRound(StepRound2)
	if err != nil {
		return "", "", err
	}
	if round1.Phase != phaseDone || round2.Phase != phaseDone {
		return "", "", errors.New("both qualification rounds must be recorded")
	}
	candidate, err := h.Store.readPrivate(filepath.Join(h.sessionDir(round2.Session), "candidate.json"), 4<<20)
	if err != nil {
		return "", "", err
	}
	var cand qualification.Candidate
	if err := json.Unmarshal(candidate, &cand); err != nil {
		return "", "", fmt.Errorf("candidate.json: %w", err)
	}
	var b strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	line("Summary: what you approve")
	line("  Owner: %s (uid %d). Build account: %s (uid %d). Controller account: %s (uid %d).", e.OwnerUser, e.OwnerUID, e.JobUser, e.JobUID, e.ControllerUser, e.ControllerUID)
	line("  API: https://%s:%d, reachable from your tailnet.", e.TailnetIP, e.Port)
	line("  Xcode: %s.", e.DeveloperDir)
	installations := []string{strconv.FormatInt(c.GitHub.InstallationID, 10)}
	for _, owner := range slices.Sorted(maps.Keys(c.GitHub.Installations)) {
		installations = append(installations, owner+":"+strconv.FormatInt(c.GitHub.Installations[owner], 10))
	}
	line("  GitHub App %d, installation %s.", c.GitHub.AppID, strings.Join(installations, ", "))
	var repos []string
	for _, name := range slices.Sorted(maps.Keys(c.Receipt.Repositories)) {
		repos = append(repos, fmt.Sprintf("%s (id %d)", name, c.Receipt.Repositories[name]))
	}
	line("  Repositories: %s.", strings.Join(repos, ", "))
	if len(c.Receipt.Owners) > 0 {
		line("  Every repository of these GitHub accounts: %s.", strings.Join(c.Receipt.Owners, ", "))
	}
	for _, p := range registry.List() {
		line("  Build profile %s: repository %s, Xcode %s (%s).", p.ID, p.Repo, p.Xcode.Version, p.Xcode.Build)
	}
	for _, t := range registry.Templates() {
		line("  Build template %s: every repository of %s, Xcode %s (%s).", t.ID, strings.Join(t.Owners, ", "), t.Xcode.Version, t.Xcode.Build)
	}
	if pins, err := h.readConfig("qualification-sources.json", 1<<20); err == nil {
		var sp qualification.SourcePins
		if err := json.Unmarshal(pins, &sp); err != nil {
			return "", "", err
		}
		for _, s := range sp.Sources {
			line("  Qualified with a real build of %s at %s (%s).", s.Profile, s.Commit, s.Repo)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", "", err
	}
	line("  Qualification: round 1 %s, round 2 %s (after the restart).", round1.Session, round2.Session)
	for _, name := range slices.Sorted(maps.Keys(cand.Categories)) {
		line("    %s: %s", name, cand.Categories[name].Status)
	}
	line("  macserve builds only the repositories above and trusts their code, everyone who can write to them and their dependencies (docs/install.md).")
	line("  Approving installs the approval and the activation anchor and starts the three services. owner.pause is removed once health is valid.")
	bindings, err := h.pauseBinding()
	if err != nil {
		return "", "", err
	}
	if strings.HasPrefix(bindings, "owner.pause absent") {
		return "", "", errors.New("owner.pause is missing; deploy-install set it and setup removes it only after the start, once health is valid. Restore it (docs/install.md) before approving")
	}
	line("  Bound: deploy.env %s, round 2 candidate %s, %s.", digestHex(envData), digestHex(candidate), bindings)
	return b.String(), bindings, nil
}

// approve records the owner's typed approval of the summary (digest) and
// starts the services. Once qualify approve has run for the recorded
// approval, the summary must still be exactly the approved one: any change
// then fails the step (the approval cannot be replaced any more).
func (h *Helper) approve(l *Ledger, loc LedgerLocation, digest string) (Response, error) {
	boot, err := h.Boot()
	if err != nil {
		return Response{}, fmt.Errorf("boot identity: %w", err)
	}
	r := l.record(StepApproveAndStart)
	if r.Status != StatusRunning {
		return Response{}, errors.New("read the summary first")
	}
	if !r.Boot.same(boot) {
		return Response{}, errAnotherBoot
	}
	console, err := h.ConsoleUID()
	if err != nil {
		return Response{}, err
	}
	if console != h.Owner.UID {
		return Response{}, errors.New("approve at this Mac's screen, logged in as yourself; nothing was approved")
	}
	text, bindings, err := h.summary(l)
	if err != nil {
		return Response{}, err
	}
	current := digestHex([]byte(text))
	if a := l.Approval; a != nil && a.Approved != nil && a.SummarySHA256 != current {
		return Response{}, h.fail(l, loc, StepApproveAndStart, errors.New("the summary changed after qualify approve ran for your approval; nothing was started. Reconcile by hand (docs/install.md)"))
	}
	if current != digest {
		return Response{}, errors.New("the summary changed since you read it; nothing was approved. Run macserve setup again")
	}
	if l.Approval == nil || l.Approval.Approved == nil {
		if err := l.Approve(digest, bindings, boot, h.Now()); err != nil {
			return Response{}, err
		}
		if err := h.Store.Save(l, loc); err != nil {
			return Response{}, err
		}
	}
	return h.startServices(context.Background(), l, loc, boot)
}

// approvedDigests reads the digests of ApprovedFiles.
func (h *Helper) approvedDigests(session string) (map[string]string, error) {
	files := map[string]string{}
	evidence, err := h.Store.readPrivate(filepath.Join(h.sessionDir(session), "approved-boundary-evidence.json"), 4<<20)
	if err != nil {
		return nil, err
	}
	files["approved-boundary-evidence.json"] = digestHex(evidence)
	for _, name := range []string{"qualification.json", "activation-anchor.json"} {
		data, err := h.readConfig(name, 4<<20)
		if err != nil {
			return nil, err
		}
		files[name] = digestHex(data)
	}
	return files, nil
}

// startServices runs qualify approve once for the recorded approval and
// records what it wrote; a later run trusts only exactly those files.
// Then activation-check, then the services start. Nothing starts unless
// the ledger holds an approval given in this boot, and owner.pause and
// profiles.json are still as the approved summary showed them.
func (h *Helper) startServices(ctx context.Context, l *Ledger, loc LedgerLocation, boot Boot) (Response, error) {
	if err := l.AuthorizeStart(boot); err != nil {
		return Response{}, err
	}
	a := l.Approval
	round2, _, err := h.readRound(StepRound2)
	if err != nil {
		return Response{}, err
	}
	bindingsHeld := func(when string) error {
		now, err := h.pauseBinding()
		if err == nil && now == a.Bindings {
			return nil
		}
		return errors.Join(fmt.Errorf("owner.pause or profiles.json changed %s; no services started", when), err)
	}
	if a.Approved == nil {
		if approved, err := h.Approved(); err != nil || approved {
			return Response{}, errors.Join(errors.New("this Mac has an approved qualification this setup did not record; nothing was started. Reconcile by hand (docs/install.md)"), err)
		}
		if err := bindingsHeld("since you approved; run macserve setup again to read the new summary"); err != nil {
			return Response{}, err
		}
		if err := h.servicesDisabled(ctx); err != nil {
			return Response{}, err
		}
		if err := h.Qualify.Approve(ctx, h.sessionDir(round2.Session)); err != nil {
			return Response{}, fmt.Errorf("qualify approve: %w", err)
		}
		files, err := h.approvedDigests(round2.Session)
		if err != nil {
			return Response{}, h.fail(l, loc, StepApproveAndStart, fmt.Errorf("qualify approve left no approved evidence: %w", err))
		}
		if err := l.RecordApproved(files); err != nil {
			return Response{}, err
		}
		if err := h.Store.Save(l, loc); err != nil {
			return Response{}, err
		}
	} else {
		files, err := h.approvedDigests(round2.Session)
		if err != nil || !maps.Equal(files, a.Approved) {
			return Response{}, h.fail(l, loc, StepApproveAndStart, errors.Join(errors.New("the files qualify approve wrote changed since it ran; nothing was started"), err))
		}
		if err := h.servicesDisabled(ctx); err != nil {
			return h.partialStart(l, loc, nil, err)
		}
	}
	// From here the approval is spent: a changed binding needs a reviewed
	// recovery, not a new approval.
	if err := bindingsHeld("during approval"); err != nil {
		return Response{}, h.fail(l, loc, StepApproveAndStart, err)
	}
	if err := h.Qualify.ActivationCheck(ctx); err != nil {
		return Response{}, fmt.Errorf("activation-check: %w", err)
	}
	started, err := h.startLabels(ctx, a.Bindings)
	if err != nil {
		return h.partialStart(l, loc, started, err)
	}
	inputs := map[string]string{"activation-anchor.json": a.Approved["activation-anchor.json"], "summary": a.SummarySHA256}
	if err := h.complete(l, loc, StepApproveAndStart, boot, inputs); err != nil {
		return Response{}, err
	}
	h.started = true
	return Response{Done: true, Items: started}, nil
}

// startLabels enables and bootstraps each service, checking the bindings
// before each and after all.
func (h *Helper) startLabels(ctx context.Context, before string) ([]string, error) {
	var started []string
	for _, label := range serviceLabels {
		if now, err := h.pauseBinding(); err != nil || now != before {
			return started, errors.Join(errors.New("owner.pause/profile bindings changed; stop and review"), err)
		}
		if err := h.launchctlOK(ctx, "enable", "system/"+label); err != nil {
			return started, err
		}
		if err := h.launchctlOK(ctx, "bootstrap", "system", h.daemonPlist(label)); err != nil {
			return started, err
		}
		started = append(started, label)
		if err := h.launchctlOK(ctx, "print", "system/"+label); err != nil {
			return started, err
		}
	}
	if now, err := h.pauseBinding(); err != nil || now != before {
		return started, errors.Join(errors.New("owner.pause/profile bindings changed after startup"), err)
	}
	return started, nil
}

// partialStart fails approve-and-start: every further mutation needs a
// reviewed recovery. The recovery commands are returned, not run.
func (h *Helper) partialStart(l *Ledger, loc LedgerLocation, started []string, cause error) (Response, error) {
	var recovery []string
	for _, label := range serviceLabels {
		recovery = append(recovery, "sudo /bin/launchctl disable system/"+label, "sudo /bin/launchctl bootout system/"+label)
	}
	names := "none"
	if len(started) > 0 {
		names = strings.Join(started, ", ")
	}
	err := fmt.Errorf("PARTIAL START (bootstrapped by setup: %s): %w. owner.pause was not removed. Inspect only these labels and resolve by hand; setup changes nothing more", names, cause)
	return Response{Items: recovery}, h.fail(l, loc, StepApproveAndStart, err)
}

// releasePause removes owner.pause once the readiness gate reports no
// blocker other than owner_pause (health valid in launchd context, written
// by the maintenance service). It is served once, only by the helper run
// that started the services, and removes only the owner.pause the
// approval bound: one the owner sets again is never removed. It is
// logged separately.
func (h *Helper) releasePause(l *Ledger) (Response, error) {
	if !h.started {
		return Response{}, errors.New("setup removes owner.pause only right after it started the services, in the same run; remove it yourself once health is valid (docs/install.md)")
	}
	boot, err := h.Boot()
	if err != nil {
		return Response{}, fmt.Errorf("boot identity: %w", err)
	}
	if l.Approval == nil || !l.Approval.Boot.same(boot) {
		return Response{}, errAnotherBoot
	}
	if now, err := h.pauseBinding(); err != nil || now != l.Approval.Bindings {
		h.started = false
		return Response{}, errors.Join(errors.New("owner.pause or profiles.json changed since your approval; setup does not remove owner.pause"), err)
	}
	path := h.configPath("owner.pause")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	blockers, err := h.Qualify.Health(ctx)
	if err != nil {
		return Response{}, err
	}
	var others []string
	for _, b := range blockers {
		if b != "owner_pause" {
			others = append(others, b)
		}
	}
	if len(others) > 0 {
		return Response{Detail: "health is not valid yet", Items: others}, nil
	}
	h.started = false
	if err := os.Remove(path); err != nil {
		return Response{}, err
	}
	if err := syncDir(filepath.Dir(path)); err != nil {
		return Response{}, err
	}
	h.audit(VerbReleasePause, "owner.pause removed", nil)
	return Response{Done: true, Detail: "owner.pause removed"}, nil
}

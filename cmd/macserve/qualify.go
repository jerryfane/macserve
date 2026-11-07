package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jerryfane/macserve/internal/qualification"
	"github.com/jerryfane/macserve/internal/setup"
	"github.com/jerryfane/macserve/internal/worker"
)

const qualifyUsage = `Usage: macserve qualify COMMAND [options]

All privileged commands require macOS root. Network reachability is informational:
not enforced in phase 1. No command writes or loads PF.
No command changes launchd, accounts, GUI baselines, owner state or health.
Reuse the installed deploy.env.

plan --env PATH
  Print network target matrix and evidence categories without probes.
begin --session /Library/macserve/var/qualification/NAME
  --env /Library/macserve/config/deploy.env --owner-canary /Users/OWNER/private/canary
  [--allow IP:PORT[,IP:PORT...]] [--udp-canary IP:PORT[,IP:PORT...]]
  [--private-path PATH[,PATH...]] [--previous PROTECTED_PREVIOUS_SESSION | --requalify | --carry]
  Root creates an immutable two-hour challenge and initial live observations.
  Protected ports on loopback, host and tailnet addresses are observed, not gated.
  Records available main/peer rule digests and configured running service PIDs.
  Observed rule changes or PID changes refuse the sitting; unreadable PF does not.
canary --session DIR --transport udp|tcp|owner-home --out NEW_FILE
  [--listen IP:PORT[,IP:PORT...]] [--duration 120s]
  Actual owner GUI account: owner-home only reads the owner canary before/after
  the bounded interval, without any network listener. Start BEFORE either probe
  and leave running until BOTH finish to provide mandatory owner-home controls.
  Optional TCP accepts/closes only; UDP records/echoes challenge nonces.
  Multiple network listeners write NEW_FILE.1.json, NEW_FILE.2.json, etc.
  --requalify chains to the session the owner last approved (activation anchor)
  and requires the live configuration to equal it.
  --carry begins a release-carry sitting: it chains to the anchored session,
  allows only /Library/macserve/bin/macserve and bin/macserve-controller to
  differ from the anchor (schema-3 anchors only), needs
  the installed approval from this boot, the anchor's carry cap and the
  approved owner canary, and rebinds only the persistence attestation build
  (any other attestation binding difference refuses). It is never collected,
  approved or reapproved.
probe --session DIR --role owner --out NEW_FILE
  Owner account with full memberships; no sudo/su impersonation. Real or
  effective UID 0 refuses before session access or any --out write. The job
  probe is not run here: root runs it with
  /bin/launchctl asuser JOB_UID macserve _qualify-job-probe SESSION_ID
  in the job's background GUI session with the production credential, and
  captures its report into the protected session.
collect --session DIR --owner OWNER_REPORT
  --receipts OWNER_HOME_RECEIPT[,UDP_RECEIPT...]
  Root reads the launcher-captured job report and tool evidence from the session,
  snapshots the owner report, owner-home controls, optional receiver evidence and
  current observations into schema 4 candidate and qualification artifacts.
  Every category is machine-checked: reboot needs a predecessor sitting on an
  earlier boot; tool_profiles needs root-run recipes on pinned sources.
  Once candidate.json exists, begin a new session rather than recollecting.
approve --session DIR
  The owner's root approval: checks all mandatory categories, artifacts,
  freshness, exact maintenance bindings and maintenance.Evaluate, installs the
  protected approval records and writes the activation anchor. Does not clear
  owner.pause or activate services.
reapprove --session DIR
  Agent requalification commit for a --requalify sitting: as approve, and the
  live configuration must equal the activation anchor, with no earlier approval
  on this boot. Never writes the anchor.
carry --session DIR --proof PROTECTED_CARRY_PROOF
  Agent commit of a --carry sitting after its job probe and tool evidence:
  the proof must bind the anchored and installed binaries and claim only
  carry classes; probe denials, tool identities, parameters, the cap and
  live health with the kept approval are rechecked. Rewrites the activation
  anchor with only the bin/macserve and bin/macserve-controller digests
  rebound plus one carries[] record
  bound to the proof, then runs activation-check. Once per sitting.
activation-check
  Read-only: the anchor matches the live configuration and installed approval
  evaluates to valid health now.
rebind-controller --from-installed-sha256 OLD --to-installed-sha256 NEW
  Root, after macserve-admin installed and health-checked a controller-only
  carry: the live configuration may differ from the schema-3 anchor only in
  bin/macserve-controller (OLD to NEW, on-disk digests) and
  config/installed-binaries.json, which must record NEW and keep the anchored
  bin/macserve release. Rebinds those two paths, appends a rebinds[] record
  and runs activation-check. On a Mac set up by macserve setup it first
  requires the setup ledger's approval and no running upgrade, then records
  the new controller release digest and anchor digest in the ledger. Prints
  one JSON line {"result":"rebound" or "already-bound",...,"anchor_sha256"};
  re-running once bound and recorded is a no-op.
`

func runQualify(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprint(stdout, qualifyUsage)
		return 0
	}
	command := args[0]
	fs := flag.NewFlagSet("qualify "+command, flag.ContinueOnError)
	fs.SetOutput(stderr)
	session := fs.String("session", "", "protected sitting directory")
	var env, allow, udp, ownerCanary, private, previous, role, out, listen, transport, owner, receipts *string
	var requalify, carry *bool
	var proof, rebindFrom, rebindTo *string
	var duration *time.Duration
	switch command {
	case "plan":
		env = fs.String("env", "/Library/macserve/config/deploy.env", "reviewed environment")
	case "begin":
		env = fs.String("env", "/Library/macserve/config/deploy.env", "reviewed installed environment")
		allow = fs.String("allow", "", "optional authorized TCP observation endpoints")
		udp = fs.String("udp-canary", "", "optional controlled UDP observation endpoints")
		ownerCanary = fs.String("owner-canary", "", "existing private owner file")
		private = fs.String("private-path", "", "additional private paths")
		previous = fs.String("previous", "", "protected previous sitting")
		requalify = fs.Bool("requalify", false, "chain to the anchored approved session")
		carry = fs.Bool("carry", false, "release-carry sitting chained to the anchored session")
	case "probe":
		role = fs.String("role", "", "job or owner")
		out = fs.String("out", "", "new report file")
	case "canary":
		listen = fs.String("listen", "", "explicit reviewed endpoints")
		transport = fs.String("transport", "udp", "tcp, udp or owner-home")
		out = fs.String("out", "", "new receipt file")
		duration = fs.Duration("duration", 120*time.Second, "bounded receiver lifetime")
	case "collect":
		owner = fs.String("owner", "", "owner report")
		receipts = fs.String("receipts", "", "owner-home control and optional UDP receiver reports")
	case "carry":
		proof = fs.String("proof", "", "root-protected carry-proof.json")
	case "rebind-controller":
		rebindFrom = fs.String("from-installed-sha256", "", "anchored on-disk controller digest")
		rebindTo = fs.String("to-installed-sha256", "", "installed on-disk controller digest")
	case "approve", "reapprove", "activation-check":
	default:
		fmt.Fprint(stderr, qualifyUsage)
		return 2
	}
	fs.Usage = func() { fmt.Fprint(stdout, qualifyUsage) }
	if err := fs.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "unexpected positional arguments")
		return 2
	}
	if command == "rebind-controller" {
		if *rebindFrom == "" || *rebindTo == "" {
			fmt.Fprintln(stderr, "--from-installed-sha256 and --to-installed-sha256 are required")
			return 2
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		ctx, cancel := context.WithTimeout(ctx, worker.PersistenceOperationTimeout)
		defer cancel()
		// Native setup's ledger vouches for the installed binaries and the
		// anchor: it must allow the rebind before the anchor changes, and it
		// records the new controller and anchor after (a re-run once both
		// are recorded is a no-op).
		// Both run under the activation anchor lock.
		ledger := setup.ControllerRebindLedger{Store: setup.SystemStore(), AnchorPath: setup.InstallRoot + "/config/activation-anchor.json", Now: time.Now}
		result, err := qualification.RebindController(ctx, *rebindFrom, *rebindTo, ledger)
		if err == nil {
			err = json.NewEncoder(stdout).Encode(result)
		}
		if err != nil {
			fmt.Fprintf(stderr, "macserve qualify %s: %v\n", command, err)
			return 1
		}
		return 0
	}
	if command != "plan" && command != "activation-check" && *session == "" {
		fmt.Fprintln(stderr, "--session is required")
		return 2
	}
	if command == "carry" && *proof == "" {
		fmt.Fprintln(stderr, "--proof is required")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := qualificationCommandContext(ctx, command)
	defer cancel()
	var err error
	switch command {
	case "plan":
		var v any
		v, err = qualification.Plan(*env)
		if err == nil {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			err = enc.Encode(v)
		}
	case "begin":
		err = qualification.Begin(ctx, qualification.BeginOptions{Environment: *env, Session: *session, Allow: *allow, UDP: *udp, OwnerCanary: *ownerCanary, PrivatePaths: *private, Previous: *previous, Requalify: *requalify, Carry: *carry})
	case "probe":
		err = qualification.Probe(ctx, *session, *role, *out)
	case "canary":
		err = qualification.Canary(ctx, *session, *listen, *transport, *out, *duration)
	case "collect":
		err = qualification.Collect(ctx, *session, *owner, *receipts)
	case "approve":
		err = qualification.Approve(ctx, *session)
	case "reapprove":
		err = qualification.Reapprove(ctx, *session)
	case "carry":
		err = qualification.Carry(ctx, *session, *proof)
	case "activation-check":
		err = qualification.ActivationCheck(ctx)
	}
	if err != nil {
		fmt.Fprintf(stderr, "macserve qualify %s: %v\n", command, err)
		return 1
	}
	if command != "plan" {
		fmt.Fprintf(stdout, "qualify %s: evidence operation completed; no service or health activation\n", command)
	}
	return 0
}

// Qualification snapshots need collector plus publication headroom; other
// commands retain their own existing probe/canary bounds and caller deadline.
func qualificationCommandContext(parent context.Context, command string) (context.Context, context.CancelFunc) {
	switch command {
	case "begin", "collect", "approve", "reapprove", "carry", "activation-check":
		return context.WithTimeout(parent, worker.PersistenceOperationTimeout)
	default:
		return context.WithCancel(parent)
	}
}

// runQualifyPrivate dispatches the hidden root launcher commands. Each takes
// exactly one session ID (or --self-test, which writes nothing); the
// executable, arguments and paths are fixed.
func runQualifyPrivate(command string, args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintf(stderr, "macserve %s: exactly one session ID required\n", command)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	switch command {
	case "_qualify-job-probe":
		if args[0] == "--self-test" {
			err = qualification.JobProbeSelfTest(ctx, stdout)
		} else {
			err = qualification.LaunchJobProbe(ctx, args[0])
		}
	case "_qualify-job-probe-child":
		if args[0] == "--self-test" {
			err = qualification.JobProbeChildSelfTest(stdout)
		} else {
			err = qualification.RunJobProbeChild(ctx, args[0], stdout)
		}
	case "_qualify-tool-evidence":
		err = qualification.RunToolEvidence(ctx, args[0])
	}
	if err != nil {
		fmt.Fprintf(stderr, "macserve %s: %v\n", command, err)
		return 1
	}
	return 0
}

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
  [--private-path PATH[,PATH...]] [--previous PROTECTED_PREVIOUS_SESSION]
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
probe --session DIR --role job|owner --out NEW_FILE
  Run directly in that actual account's existing GUI login with full memberships.
  Preserves non-root target/attempt/refusal evidence; no sudo/su impersonation.
  Real or effective UID 0 refuses before session access or any --out write.
collect --session DIR --job JOB_REPORT --owner OWNER_REPORT
  --receipts OWNER_HOME_RECEIPT[,UDP_RECEIPT...]
  Root snapshots bounded reports, owner-home controls, optional receiver evidence
  and current observations into schema2 candidate and qualification artifacts.
  Network results never gate; non-network failures cannot be manually attested.
  Incomplete attempts retain separate snapshots and can retry before expiry.
  Once candidate.json exists, begin a new session rather than recollecting.
attest --session DIR --category tool_profiles|fast_switch|reboot
  --artifact EXISTING_FILE --reason 'Owner-reviewed provenance and conclusions'
  Explicit root review of real owner/root artifacts only. Enabled profiles need
  genuine recipe/UI evidence for EVERY profile; tool inspection alone is not it.
  Lifecycle categories need full fresh predecessor sittings (--previous). Switch
  requires same boot. Reboot requires an observed boot transition to current boot.
approve --session DIR
  One explicit root command checks all mandatory categories, artifacts, freshness,
  exact current maintenance bindings and maintenance.Evaluate before installing
  protected approval records. Does not clear owner.pause or activate services.
  Rechecks coexistence rules and same running service PIDs after qualification.
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
	var env, allow, udp, ownerCanary, private, previous, role, out, listen, transport, job, owner, receipts, category, artifact, reason *string
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
	case "probe":
		role = fs.String("role", "", "job or owner")
		out = fs.String("out", "", "new report file")
	case "canary":
		listen = fs.String("listen", "", "explicit reviewed endpoints")
		transport = fs.String("transport", "udp", "tcp, udp or owner-home")
		out = fs.String("out", "", "new receipt file")
		duration = fs.Duration("duration", 120*time.Second, "bounded receiver lifetime")
	case "collect":
		job = fs.String("job", "", "job report")
		owner = fs.String("owner", "", "owner report")
		receipts = fs.String("receipts", "", "owner-home control and optional UDP receiver reports")
	case "attest":
		category = fs.String("category", "", "manual category")
		artifact = fs.String("artifact", "", "existing genuine artifact")
		reason = fs.String("reason", "", "review provenance and conclusions")
	case "approve":
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
	if command != "plan" && *session == "" {
		fmt.Fprintln(stderr, "--session is required")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
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
		err = qualification.Begin(ctx, qualification.BeginOptions{Environment: *env, Session: *session, Allow: *allow, UDP: *udp, OwnerCanary: *ownerCanary, PrivatePaths: *private, Previous: *previous})
	case "probe":
		err = qualification.Probe(ctx, *session, *role, *out)
	case "canary":
		err = qualification.Canary(ctx, *session, *listen, *transport, *out, *duration)
	case "collect":
		err = qualification.Collect(ctx, *session, *job, *owner, *receipts)
	case "attest":
		err = qualification.Attest(ctx, *session, *category, *artifact, *reason)
	case "approve":
		err = qualification.Approve(ctx, *session)
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

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

All privileged commands require macOS root. No command changes PF, launchd,
accounts, GUI baselines, owner state or health. Reuse the installed deploy.env.

plan --env PATH
  Print required TCP target matrix and mandatory categories without probes.
stage-policy --file ROOT_PROTECTED_REVIEWED_PF
  Explicit root staging only: archive prior policy/controller config privately,
  install reviewed PF bytes and update only controller policy_sha256. Print the
  new digest. Does NOT load PF; owner must separately review/apply native policy.
begin --session /Library/macserve/var/qualification/NAME
  --env /Library/macserve/config/deploy.env --allow IP:PORT[,IP:PORT...]
  --udp-canary IP:PORT[,IP:PORT...] --owner-canary /Users/OWNER/private/canary
  [--private-path PATH[,PATH...]] [--previous PROTECTED_PREVIOUS_SESSION]
  Root creates an immutable two-hour challenge and initial PF/live observations.
  Every protected port on loopback, host and tailnet addresses is required.
canary --session DIR --transport udp|tcp --listen IP:PORT[,IP:PORT...]
  --out NEW_FILE [--duration 120s]
  Actual owner GUI account: controlled receiver, never a service API. TCP accepts
  and closes only. UDP records/echoes challenge nonces. Refuses occupied ports.
  For multiple listeners writes NEW_FILE.1.json, NEW_FILE.2.json, etc.
  Start BEFORE either probe; leave running until BOTH probes finish.
probe --session DIR --role job|owner --out NEW_FILE
  Run directly in that actual account's existing GUI login with full memberships.
  Preserves every target/attempt/refusal; no sudo/su impersonation.
collect --session DIR --job JOB_REPORT --owner OWNER_REPORT
  --receipts UDP_RECEIPT[,UDP_RECEIPT...]
  Root snapshots bounded reports, receiver evidence, PF counters and current
  observations into candidate.json, boundary-evidence.json and qualification.json.
  Inspect ALL categories; failures never become success by manual attestation.
attest --session DIR --category delegated_boundary|tool_profiles|fast_switch|reboot
  --artifact EXISTING_FILE --reason 'Owner-reviewed provenance and conclusions'
  Explicit root review of real owner/root artifacts only. Enabled profiles need
  genuine recipe/UI evidence for EVERY profile; tool inspection alone is not it.
  Lifecycle categories need full fresh predecessor sittings (--previous). Switch
  requires same boot. Reboot requires an observed boot transition to current boot.
approve --session DIR
  One explicit root command checks all mandatory categories, artifacts, freshness,
  exact current maintenance bindings and maintenance.Evaluate before installing
  protected approval records. Does not clear owner.pause or activate services.
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
	var env, allow, udp, ownerCanary, private, previous, role, out, listen, transport, job, owner, receipts, category, artifact, reason, file *string
	var duration *time.Duration
	switch command {
	case "plan":
		env = fs.String("env", "/Library/macserve/config/deploy.env", "reviewed environment")
	case "begin":
		env = fs.String("env", "/Library/macserve/config/deploy.env", "reviewed installed environment")
		allow = fs.String("allow", "", "explicit allowed TCP endpoints")
		udp = fs.String("udp-canary", "", "controlled UDP endpoints")
		ownerCanary = fs.String("owner-canary", "", "existing private owner file")
		private = fs.String("private-path", "", "additional private paths")
		previous = fs.String("previous", "", "protected previous sitting")
	case "probe":
		role = fs.String("role", "", "job or owner")
		out = fs.String("out", "", "new report file")
	case "canary":
		listen = fs.String("listen", "", "explicit reviewed endpoints")
		transport = fs.String("transport", "udp", "tcp or udp")
		out = fs.String("out", "", "new receipt file")
		duration = fs.Duration("duration", 120*time.Second, "bounded receiver lifetime")
	case "stage-policy":
		file = fs.String("file", "", "root-protected reviewed PF file")
	case "collect":
		job = fs.String("job", "", "job report")
		owner = fs.String("owner", "", "owner report")
		receipts = fs.String("receipts", "", "UDP receiver reports")
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
	if command != "plan" && command != "stage-policy" && *session == "" {
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
	case "stage-policy":
		var hash string
		hash, err = qualification.StagePolicy(*file)
		if err == nil {
			fmt.Fprintf(stdout, "policy_sha256=%s\n", hash)
		}
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

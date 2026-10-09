# macserve

**Use your own Mac as a private iOS build-and-test service.**

Submit an exact Git commit, pick a pinned Xcode toolchain, and get back logs, test results, screenshots and a
signed evidence receipt. Jobs run natively on your Mac under a dedicated non-admin account, one at a time, at low
priority, and you can pause them whenever you need the machine. GitHub integration is pull-based, so your CI never
needs network credentials for your private network. No VM required.

> Status: early development. The private controller API, durable queue, exact source exporter, protected worker,
> GitHub polling, signed receipts, Linux waiter and reviewed deployment tooling are implemented.
> The protected root execution broker requires a separate non-admin GUI job account and an explicitly
> qualified process baseline. Execution stays disabled without fresh root-managed host and toolchain
> qualification. Phase 1 provides no network isolation. Privileged deployment and background GUI operation have not been qualified by the suite.

## Phase-1 capabilities

- Runs `build`, `unit_test` and `simulator_ui_test` jobs for a repository at an **exact 40-character commit SHA**.
- Uses controller-owned, versioned **profiles** (project/workspace, scheme, destination, allowed tests, artifacts);
  clients cannot inject shell commands, environment variables or paths.
- Pins the **Xcode version and build** and the **simulator runtime** per job.
- Returns status, paged logs, an `xcresult` summary (JSON/JUnit), artifacts, and a signed receipt
  (repo, SHA, tree, toolchain, runtime, exit status, test counts, log/artifact digests).
- **Pull model for GitHub**: a GitHub App polls allowlisted repositories and publishes results as check runs, which
  can be made required checks. No inbound access from GitHub to your Mac.
- Optional private HTTP API (bind to a private interface only, TLS, scoped bearer tokens) for local tooling.
- Plays nice with your daily use: **one job at a time**, background scheduling priority, memory budget, a persisted
  **pause / drain** switch, disk budget with per-job cleanup and simulator deletion.

## What it does not do (yet)

- **No code signing, archiving, App Store Connect or TestFlight in phase 1.** No signing credentials are ever given to
  build jobs.
- **Not a hostile-code sandbox.** Jobs run natively under a separate non-admin user, sharing the kernel,
  hardware and network reachability of the host. Only run repositories you trust.
- No VM management, no device farm, no multi-host scheduling.

## Network isolation: not provided in phase 1

The owner's accepted phase-1 model is **trusted repositories only**, including their build scripts and
dependencies. macserve does not install or load PF rules, manage anchors, or enforce job-network restrictions.
The job account may reach loopback, protected service ports, LAN, tailnet and internet destinations subject
to unrelated host/network policy. A separate UID and authenticated controller API do not provide network isolation.

Network probes record actual job-user reachability as **`not enforced in phase 1`**, for owner information;
reachable destinations are not qualification failures and failed connections are not denial proof.
Configured coexisting services must remain running with unchanged PIDs during installation and qualification
windows. Main and configured peer PF rules are measured read-only before/after; available measurements must
match, while unreadable PF is explicitly `unavailable` and does not block those operations.
PF enforcement may be a separately reviewed future opt-in; it is not implemented or implied by phase-1 health.

## Architecture

- `controller` (runs as a dedicated non-login service user): queue (SQLite), GitHub poller, API, receipt signer.
- `worker` (protected root execution broker): owns leases, control records and exports; executes tools only after
  dropping supplementary groups/GID/UID into the dedicated non-admin job account's existing GUI domain.
  The controller authenticates the broker's root Unix peer identity, never the job UID.
- Provisioning must deny access to owner files, keychains and service credentials. A separate UID alone does
  not protect world-readable owner data. No HTTP API or credential-bearing service runs as root.

## Implemented packages

- `internal/model`: job states, exact toolchain pins and controller-owned argv recipes.
- `internal/profiles`: strict JSON loading (`{"profiles": [...]}`), immutable recipe snapshots, exact-SHA
  admission, pinned Xcode/runtime matching, timeout limits and SHA-256 recipe digests. Relative paths cannot
  contain `..`; command placeholders are limited to `CHECKOUT`, `WORKSPACE`, `DERIVED_DATA`, `RESULT_BUNDLE`,
  `SIMULATOR_ID`, `JOB_ID` and `DEVELOPER_DIR`, each written `${NAME}`. Test profiles require explicit test scope.
- `internal/store`: SQLite WAL queue with principal-scoped idempotency, FIFO admission, database-enforced single
  active execution, lease-checked transitions and active-execution log writes, persistent pause/drain,
  cancellation and retention. Terminal logs and results cannot be amended by a late worker.
  Interrupted execution or uncertain cleanup quarantines dispatch. Clearing quarantine requires a caller-proven
  quiescent worker with a new authenticated epoch; subsequent claims must use that persisted epoch.
- `internal/worker`: exclusive execution, verified full-tree source extraction, pinned toolchain/runtime checks,
  per-job environments and owned simulators, background scheduling and dedicated-job-UID process cleanup,
  including descendants that leave their process group/session. Whole-job-UID RSS is monitored; this is not
  a kernel memory cap and excludes the broker and other-UID system daemons.
- `internal/evidence`: bounded xcresult test parsing, required-test execution checks, JUnit, deterministic
  artifact archives and content-addressed exports. Missing or incomplete test evidence cannot report success.
  Failed plans, bundles and suites remain explicit `container` diagnostics and JUnit errors even when child
  tests pass. Diagnostics cannot satisfy required-test selection or count as execution; aggregate record counts
  include them, while elapsed execution time excludes them. Ancestor failure messages are retained without
  counting the same failure repeatedly.
  Required selectors match canonical test IDs or suite identity/prefix, never a bare display-name fallback.
  Test JSON capture and parsing share the same 32 MiB input bound.
- `internal/workerclient`: authenticated Unix peer credentials, heartbeat cancellation, streamed logs and
  durable completion replay. Retrying delivery does not execute the job again. Uncertain cleanup stops dispatch.
- `internal/source`: isolated controller-side Git fetch, exact commit/tree verification and bounded deterministic
  full-tree tar export. Git archive attributes cannot omit or substitute committed bytes. Links, submodules and
  Git LFS requirements are rejected explicitly. Source exports default to a 2 GiB limit.
- `internal/controller`: Unix peer-UID authentication, asynchronous preparation, heartbeat/deadline fencing,
  independently parsed test evidence, immutable artifact storage, bounded retention and fail-closed host guards.
- `internal/api`: persisted bearer digests, repository/scoped authorization, idempotent admission, status,
  paged/SSE logs, JSON/JUnit results, range downloads and persisted administrative pause/resume.
- `internal/githubapi`: selected-repository App tokens, fresh repository-ID checks, bounded pagination,
  deadlines and rate-limit handling. Redirects cannot forward credentials to another origin.
- `internal/githubpull`: automatic exact-head enrollment, durable request/attempt correlations, explicit bounded
  reruns, dispatch revalidation and a transactional publication outbox.
- `internal/receipt`: Ed25519 signatures over RFC 8785 canonical JSON, pinned-key verification, evidence policy
  validation and immutable digest-addressed full manifests. Actual command records omit environment secrets.
- `internal/waiter`: token-only machine request/wait protocol; verifies current App, attempt, signature,
  recipe/toolchain/test pins and a final PR-head reread before returning success.
- `internal/deploy`: reviewed-env, checksum-verified prebuilt installation, disabled assets, matching configs,
  generated private keys and a one-time API token; no activation or owner permission changes.
- `internal/qualification`: actual job/owner probes, controlled receivers, protected evidence/candidate records,
  explicit owner approval and pending lifecycle/semantic evidence instead of fabricated qualification.

The store requires a dedicated private directory (mode `0700`) and private database files. Default limits are
50 outstanding jobs, 10 per principal, 24-hour queue expiry, 90-day terminal metadata retention, 64 MiB per
result envelope, 256 MiB of raw logs per job and 1 GiB of retained raw logs across jobs. Terminal log bytes
expire after seven days or under pool pressure, oldest completion first; active logs are never evicted.
`Logs` returns `ErrLogExpired` after eviction, while result envelopes, sequence/completeness metadata and
idempotency records remain unchanged. Schema upgrades account for existing log bytes.

Worker defaults are a 30 GiB workspace and 5 GiB artifact budget. Workspace usage is checked
at stages and every five seconds; it can overshoot between samples. Unfinished resource cleanup blocks
execution and retries without inventing process or simulator ownership.

The root worker takes `--config` with a root-owned JSON file under root-controlled, non-writable ancestors.
Fields are `socket`, `controller_uid`, `job_uid`, `job_gid`, `owner_uid`, `root`, `export_root`,
`workspace_root`, `helper_path`, `baseline_path`, and optional `poll_seconds`, `heartbeat_seconds`,
`request_timeout_seconds`. Paths are absolute. Owner, job and controller UIDs must differ and be non-root.
The job account must belong to neither `staff` (GID 20) nor `admin`, including supplementary groups.
Its dedicated primary group must not be shared with the owner or controller, including their supplementary
memberships. The helper is a protected executable.
Control and export roots are disjoint,
root-private (`0700`); the separate root-owned workspace parent must allow job traversal (for example `0711`),
but not replacement of other job directories. Only each individual workspace is transferred to the job UID.
Configuration rejects aliases between any of the three identities before connecting or executing tools.
Pinned toolchains and every path ancestor must be root-owned. The root:admin group-write exception
applies only when the job account is not a member of that group. Tool executables remain non-group-writable.
This exception does not relax configuration, helper or control-state protection.

An actual GUI login must already exist; `launchctl asuser` does not create one. The sole administrator
initialization/reset command, with the broker stopped, is:
`macserve worker-reset --config /absolute/worker.json --pids PID,PID`.
Explicitly audit the current trusted job-UID GUI PIDs before supplying this list: reset terminates other
job-UID processes, removes job-home LaunchAgents entries, crontab and legacy login items, and rechecks.
It records `job_uid`, kernel `boot` identity, and each selected `pid` with its exact kernel `start` identity.
It never adopts unselected processes or signals owner/controller processes. Missing/reused baseline
processes or changed boot refuse admission without creating quarantine; audit and use the same reset.

Before every registration/claim poll, recovery first cleans up recorded owned resources, then verifies
admission. Pending completion replay precedes recovery. A refusal leaves queued jobs untouched: the
worker logs its reason, waits the normal poll interval and retries; cancellation exits. Execute rechecks
admission after claim in case host state changed. Positive observation of a job-home LaunchAgents entry,
nonempty crontab, legacy/modern login registration or leftover process outside the audited baseline creates
the single durable `admission-quarantine.json` marker. Positive residuals after cleanup do likewise.
Cancellation, deadlines, I/O and inspection-command errors refuse admission without creating a marker.
Before registration/claim, the client atomically publishes `<root>/admission-status.json` (the worker config's
broker-private `root`, mode `0600`) with `state` (`admitting` or `not_admitting`), `reason` and UTC `checked_at`.
Status-write errors also block registration/claim and retry on the normal poll. This file is only the last
observation, not a live heartbeat or a second quarantine authority; it may be stale after shutdown and
requires no administrator clear. Editing/removing it cannot bypass recovery or clear quarantine.
The fixed probes have deadlines and output bounds. Modern registration inspection requires an
explicitly empty job-UID section from `sfltool dumpbtm`; missing/unfamiliar output is a transient refusal,
not proof of absence. GUI scripting permissions and any long-lived probe-created processes must be
prepared and explicitly audited beforehand; inspection never adopts a new process.

Recipe/simulator writers are stopped before pinned `xcresulttool` extraction; another UID barrier precedes
parsing and sealing. Raw logs and sealed exports are outside job-writable storage. Unproven quiescence blocks
success, sealing and the next lease. All finalization stages share one two-minute cooperative cleanup budget.
Confined permission and Darwin user-immutable/append flag repair permits cleanup of read-only output without
following symlinks or modifying external hardlink targets. System flags and ambiguous hardlinks are not repaired.

Reset holds the exclusive broker lock, updates the audited baseline, retries owned-resource cleanup
and clears the marker only after full clean verification. It removes recorded simulator UDIDs; for an
interrupted create, stable job-UID inventory is compared with the protected pre-create inventory and
only exact added UDIDs are removed. Baseline devices and unrelated workspaces are preserved.
Unknown legacy ownership is never guessed: a predeployment old record lacking inventory can recover
only when inspection proves the inventory empty.

Residual modern BTM registrations retain quarantine. The owner must resolve them and rerun the same
reset; macserve never runs host-wide `sfltool resetbtm` or changes owner registrations. Any failed or
unknown reset verification retains an existing marker. Pending completions and sealed evidence are
preserved; startup replays a pending completion before recovery. No registration or lease occurs before
recovery succeeds. Transient unclean completion fences the old controller epoch; verified recovery
automatically registers a fresh epoch, without a second administrator clear command.

**Trusted-native limit:** this service is for trusted repositories, not hostile contributors. A clean census
is a snapshot, not confinement: a delayed same-UID launchd/cron or other persistence mechanism can start after
the checks and affect a later job. Native shared-kernel execution and trusted GUI services do not provide VM
reset isolation. This residual risk is accepted by the operator; preflight checks do not eliminate it.
Root/GUI deployment, Unix/account boundaries and background UI operation require separate host qualification
before real repository enrollment. These native probes have not been qualified on a deployed host.

## Controller configuration and control

`macserve controller --config /absolute/path/to/controller.json` requires a root-controlled configuration and
a dedicated non-login, non-admin controller account distinct from the owner and job account. Configuration fields:
`root`, `socket`, `job_uid`, `owner_uid`, `profiles_file`, `listen`, `tls_certificate`, `tls_key`,
`principals`, `health_file`, `receipt`, and optional `allowed_networks`, `pause_file`, `github`.
Profiles and the public TLS certificate are root-controlled. TLS, receipt and App private keys are separate
controller-private files; no secret is supplied through command arguments or a worker lease.
`job_uid` identifies the unprivileged execution account. The private executor socket always
authenticates peer UID `0` in production, independently of `job_uid`.

The TLS 1.3 listener requires a literal assigned tailnet address and port. Allowed networks default to
`100.64.0.0/10` and `fd7a:115c:a1e0::/48`; configuration can narrow these ranges, not enable LAN/public,
wildcard or loopback listeners. Client authorization is independent of network membership.
Each principal has `id`, `token_sha256`, `repositories`, `scopes`, and optional `revoked`. Scopes are
`jobs:submit`, `jobs:read`, `jobs:cancel`, `service:admin`. Only SHA-256 digests are persisted; plaintext
high-entropy bearer credentials belong in the caller's private credential storage.

- `POST /v1/jobs` requires `Idempotency-Key` and a profile-matching exact-SHA request.
- `GET /v1/capabilities` and `/v1/jobs` expose authorized profiles and jobs without controller recipes or paths.
- `/v1/jobs/{id}` provides status, `/logs`, `/logs/stream`, `/results`, `/results/junit`, `/artifacts`,
  `/artifacts/{artifact_id}`, `/receipt`, `/receipt/manifest?sha256=DIGEST`, and `POST /cancel`.
  Missing signed receipts return `409`, not success. Non-executed cancellation/expiry or interrupted jobs with
  no collected completion have no execution receipt; GitHub reports non-success, never invented evidence.
- `PUT /v1/admin/pause` accepts `{"reason":"benchmark","mode":"drain"}` or `cancel_active`.
  Poll `GET /v1/admin/state` until `quiescent=true` before benchmarking; acceptance of pause is not quiescence.
  `DELETE /v1/admin/pause` clears only manual pause. An optional owner-controlled pause marker also blocks dispatch.

The controller requires schema-2 root-owned health attestation bound to current interface inventory, job UID
and qualified profile digests, not PF policy or rules. Health expires within 45 seconds. Missing, stale or
changed host/tool qualification stops admission and cancels active work. Merely creating a profile does not
qualify it. Installation and actual non-network boundary qualification remain separate provisioning work.

Disk admission reserves 30 GiB while preserving 120 GiB free; below 100 GiB active work is cancelled.
The total accounted mutable-data budget is 80 GiB. The retained evidence pool reserves 1 GiB for store log
rows and 14 GiB for artifacts, with seven-day expiry/oldest-terminal eviction. Metadata persists for 90 days;
expired downloads, log pages and newly opened log streams return `410`.
These are monitored application budgets, not filesystem quotas. Controller test parsing uses sealed JSON
exported by the pinned worker tool; it does not execute repository-provided parsers.

Offered/running workers retain the ordinary 30-second heartbeat-loss fence. Cancellation, deadline or finalizing
starts a fixed cleanup/delivery grace (two minutes each, plus heartbeat tolerance); repeated heartbeats cannot
extend it. Source streaming instead receives the ten-minute preparation budget plus heartbeat tolerance.
Controller source-cleanup debt is durable and independent of worker cleanup: registration cannot erase it,
and only successful protected source removal clears it. Retention may relieve disk-only pressure, but never
runs through manual/owner pause or unqualified security readiness.

Existing idempotent submissions replay read-only even when admission is unavailable. Once pruned, the key is
a new submission and must pass current readiness and profiles. JSON field names are case-exact.
Private API callers must independently approve repository-history membership of a SHA: exact-object fetch
proves identity, not reachability from the allowlisted repository's own heads or tags.

## Signed receipts and GitHub pull mode

The required `receipt` configuration contains `key_id`, `private_key_file`, opaque `service_id` and `host_id`,
`repositories` (canonical lowercase `owner/repo` to numeric repository ID), and optional `verification_keys`
(key ID to base64 Ed25519 public key). Every profile repository needs a pinned ID. The running executable's
actual SHA-256 and build identity are recorded. Use a controller-only Ed25519 PKCS#8 PEM key, raw seed/private
key, or base64 seed/private key. Pin public keys out of band; retain old verification keys during rotation and
remove revoked keys deliberately. A key fetched beside an untrusted receipt is not a trust anchor.

Receipts bind the admitted request digest, repository/commit/tree/export, recipe, observed toolchain/runtime,
actual argv/timing/exit, cleanup, test outcomes and artifact hashes. `complete` describes evidence completeness;
it is not a success verdict. Verification must also require successful state and the exact expected policy.
Container failures cannot count as executed tests. Build receipts explicitly say tests were not run.
Submodules and Git LFS are unsupported and rejected, not silently omitted.

Every public receipt is a compact signed core, regardless of size, with a full-manifest SHA-256, size and
authenticated URL. Full recipes and command manifests are never included in GitHub check output.
Canonical compact bytes remain unchanged through SQLite, HTTP and GitHub. The manifest route serves only
the digest committed by the terminal receipt, never an uncommitted cancellation-race candidate.
Full manifests remain immutable; cancellation during sealing produces a distinct candidate.
Legacy committed full receipts remain private and require an explicit rerun before public evidence publication.
This cutover does not erase check output already published by an older version.
Normal evidence maintenance removes manifests only after their 90-day job metadata expires. It may relieve
disk-only pressure, but does not run through manual/owner pause or security-readiness uncertainty.
Raw logs/artifacts still have their shorter seven-day retention.

Optional `github` configuration contains `app_id`, `installation_id`, RSA PEM `private_key_file`, `policies`,
and `poll_seconds` (30–60; default 45). Install the App only on approved repositories, with metadata/contents/
pull-request read and checks write permissions. The App must cover configured receipt repositories used
for source fetch; each token is scoped to one numeric repository ID and kept in memory. No App secret or Mac
API token belongs in Actions. Without App configuration, the private API can fetch public Git repositories;
numeric receipt repository identities then come from administrator configuration, not a fresh App lookup.

Each policy supplies `repository_id`, `repository`, `author_ids`, `base_branches`, `profiles`,
`policy_revision`, and optional `actions_bot_id`, `actions_app_id`. Numeric author and repository identity,
not display names or commit author text, control admission. Repository writers must all be trusted: allowlisting
a PR author does not authenticate everyone who can push to their branch.

Polling automatically enrolls each observed eligible open same-repository head; no comment or Linux workflow
is required. Forks, unlisted authors, disallowed bases and disabled profiles never execute. A current head is
eventually reconciled; transient heads overwritten between polls may not be observed. Immediately before source
preparation, head/policy is rechecked. Permanent rejection cancels without executing; transient transport,
server or rate-limit failures retry within the bounded preparation deadline. Active polling revalidates once
per poll rather than blocking on that retry loop. Removing GitHub configuration does not turn previously
enrolled jobs into private-API work.

Require `mac-evidence/<profile>` **from the configured App**. Checks target the PR head, never the synthetic
merge commit. Only the current attempt may update the stable check; publication retry/restart reconciles
`external_id=job-id` rather than rerunning work. Failure, timeout, cancellation, missing evidence and policy
rejection cannot publish success; policy rejection uses `action_required`, not passing `neutral`/`skipped`.
This does not implement merge-queue `merge_group` evidence.

Periodic repair considers only current eligible heads, including their terminal results, not historical or
currently ineligible fork heads. Each publication pass handles at most ten entries under one minute of network
deadline, prioritizing job-bound evidence. Jobless rejection checks are best-effort once; a missing required
check remains nonpassing. Obsolete blocked rows retire when no publisher lease is held. Obsolete terminal
publication retries drain for at most 24 hours; job-linked provenance/correlations remain until jobs are pruned.

Machine comments have exactly this grammar:

```text
/mac-evidence sha=<40-lowercase-hex> profile=<approved-id> request=actions:<run-id>:<attempt> mode=ensure
```

Only the configured numeric Actions bot is accepted; when an App identity is present it must match the pinned
Actions App. Edited comments are rejected. `ensure` joins the same logical run, including terminal results.
Explicit `mode=rerun` starts a new attempt only after termination, at most twice per head/profile per hour;
active attempts are joined. Correlations are durable and capped at 128 per attempt.

Initial comment intake starts 24 hours before startup with two minutes of overlap, never at repository creation.
One page of at most 100 comments is processed per poll; page position and scan-start watermark survive restart.
The watermark advances after the complete scan; transactional admission/storage errors retain their page.
An individual comment's PR lookup failure is logged with repository/comment/PR identifiers and skipped,
so later comments and pages still progress. No failed lookup authorizes work. This also applies to transient
lookup failures: overlap may revisit them, but there is no guaranteed retry queue for skipped comments.
Existing cursors are not reset after long downtime. Requests older than the initial window are not enrolled.
GitHub offset pagination is not a snapshot: historical edits/deletions during a prolonged scan can shift offsets;
the overlap mitigates recent churn but does not guarantee replay under adversarial historical mutation.

### Linux workflow waiter

Install a reviewed, checksummed `macserve` binary and trusted pins without checking out PR code. Give the
workflow only `GITHUB_TOKEN` permissions `contents: read`, `checks: read`, `pull-requests: write`.
Do not use `pull_request_target` to execute PR code or transfer App/private-network credentials.

```sh
macserve wait --pins /absolute/trusted-pins.json \
  --pr \"$PR_NUMBER\" --sha \"$PR_HEAD_SHA\" \
  --request \"actions:$GITHUB_RUN_ID:$GITHUB_RUN_ATTEMPT\" --timeout 90m
```

`PR_HEAD_SHA` must be the event's `pull_request.head.sha`, not `GITHUB_SHA`'s synthetic merge commit.
The pins JSON contains `repository_id`, `app_id`, `profile_digest`, `required_tests`, `verification_keys`,
and `request` with `repo`, `profile`, `kind`, `xcode` (version/build), and the exact `simulator` pins when needed.
An optional pinned `request.sha` must match `--sha`. Use the admitted profile digest, not a hash of hand-edited
JSON. Public keys are standard base64. Protect this policy independently of the submitted branch.

The waiter posts a machine comment, binds its immutable ID/body to the admitted job/attempt, filters paginated
checks by exact head/name/App, rereads the selected check, verifies the pinned receipt and rereads the PR head.
Timeout, supersession, missing/invalid evidence or non-success exits nonzero; it never cancels shared Mac work.
Success prints JSON and writes `job_id`, `check_url`, `receipt_digest` to `GITHUB_OUTPUT` when supplied, plus
verified test counts to `GITHUB_STEP_SUMMARY`. Downstream jobs can depend on this waiter job. Offline Mac/network
outages keep the required check pending or missing; they do not clear a gate.

Native signatures attest recorded observations for trusted code, not host integrity or honest tests. Private
screenshots/source and full manifests stay behind authenticated downloads; a compact GitHub receipt does not
give an uncredentialed Linux job arbitrary artifact access. Real App authorization, branch protection, target
recipes, account boundaries and GUI qualification still require the approved deployment acceptance window.

## Installation assets and host health

[Quick path: four owner-approved deployment sittings](docs/install.md#quick-path) starts with a reviewed
`v*` release, `deploy.env`, and `assets/install.sh` in plan mode. Tag CI publishes a CGO-disabled,
`-trimpath` Darwin arm64 binary and `SHA256SUMS` using only `GITHUB_TOKEN`; the deployed host needs no Go.
Explicit root apply stages disabled controller/worker/maintenance assets, empty profiles, generated keys
and a one-time API token. The installed `qualify.sh` collects actual account-specific probes and protected
candidate evidence; approval is a separate root command. Fast-switch/reboot and unperformed recipe/UI
evidence remain pending. Nothing activates services or changes owner ACLs; macserve never writes PF.

Keep the owner's home at **0700**, or **0750 with an owner-private group—not staff—that excludes the job
account**. Audit ACL grants separately. Qualification requires an `owner_home_denial` probe from the actual
job GUI identity with its full groups: directory access and reading an approved nonsecret home canary must
be denied while owner read controls succeed. The installer never changes owner-home permissions.

`macserve maintenance --config PATH` publishes short-lived root-owned health after checking protected
qualification/evidence bindings, interface state, exact GUI baseline identities, profile
digests, memory pressure and mutable storage including the entire job home. Failed observations publish
invalid health; startup/shutdown invalidate it. Probe cadence is measured from probe start, not completion.
`maintenance-observe` collects live inputs without approving the host or writing health. Both require
macOS root; neither modifies host policy, adopts processes or generates boundary-test evidence.

`maintenance-observe --coexistence-only --config PATH` reads configured peer service PIDs and opaque main/peer
PF rule digests without needing a GUI baseline or completed qualification. PF read failures are recorded as
`unavailable`; stopped, unreadable or restarted configured services are not silently accepted. No PF rule
syntax, UID matching, translation policy, ownership receipt or loopback-filtering claim is inferred.
Normal build directory churn is tolerated by the approximate mutable-budget census, not treated as an
isolation failure. Root-protected qualification still requires real approved boundary/owner-home/GUI/reboot
probes; fixtures and local checks are not native host qualification.

## Development

Use the Go version declared in `go.mod`. SQLite uses a pure-Go driver; no external database is required.

```sh
GOMAXPROCS=2 nice -n 10 go vet -p 2 ./...
GOMAXPROCS=2 nice -n 10 go test -p 2 ./...
GOMAXPROCS=2 nice -n 10 go run -p 2 ./cmd/macserve --help
```

`macserve --help` and `macserve <command> --help` exit 0. Service commands require `--config`; invalid or
missing arguments exit 2. Runtime safety failures exit 1. Help goes to stdout and errors to stderr.

CI pins third-party actions to immutable commit SHAs and runs vet, tests and a CLI build on GitHub-hosted
`ubuntu-latest` and `macos-latest`. Apple tool execution is faked in tests: no simulator boot or app build is
performed. Native process tests use harmless owned Go helpers, including a session-escaping child with
cleanup restricted to that exact PID. Privilege transitions use injected seams, not privileged test execution.
Linux exercises portable behavior but is not a supported Apple worker host.

## License

Apache-2.0

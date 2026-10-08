# macserve

**Use your own Mac as a private iOS build-and-test service.**

Submit an exact Git commit, pick a pinned Xcode toolchain, and get back logs, test results, screenshots and a
signed evidence receipt. Jobs run natively on your Mac under a dedicated non-admin account, one at a time, at low
priority, and you can pause them whenever you need the machine. GitHub integration is pull-based, so your CI never
needs network credentials for your private network. No VM required.

> Status: early development. The private controller API, durable queue, exact source exporter, native worker
> and evidence delivery are implemented. GitHub polling, receipt signing and installation assets are next.
> The protected root execution broker requires a separate non-admin GUI job account and an explicitly
> qualified process baseline. Execution stays disabled without fresh root-managed network and toolchain
> qualification. Privileged deployment and background GUI operation have not been qualified by the suite.

## Planned phase-1 capabilities

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
- **Not a hostile-code sandbox.** Jobs run natively under a separate non-admin user with network restrictions, but they
  share the kernel and hardware with your session. Only run repositories you trust.
- No VM management, no device farm, no multi-host scheduling.

## Planned architecture

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
The job account must be non-admin, with a dedicated primary group: no `staff` or group shared with the owner
or controller, including their supplementary memberships. The helper is a protected executable.
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
Root/GUI deployment, network boundaries and background UI operation require separate host qualification
before real repository enrollment. These native probes have not been qualified on a deployed host.

## Controller configuration and control

`macserve controller --config /absolute/path/to/controller.json` requires a root-controlled configuration and
a dedicated non-login, non-admin controller account distinct from the owner and job account. Configuration fields:
`root`, `socket`, `job_uid`, `owner_uid`, `profiles_file`, `listen`, `tls_certificate`, `tls_key`,
`principals`, `health_file`, `policy_sha256`, and optional `allowed_networks` and `pause_file`.
Profiles and the public TLS certificate are root-controlled; the TLS private key is a private controller secret.
`job_uid` identifies the unprivileged execution/network-policy account. The private executor socket always
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
  `/artifacts/{artifact_id}`, `/receipt`, and `POST /cancel`. Missing signed receipts return `409`, not success.
- `PUT /v1/admin/pause` accepts `{"reason":"benchmark","mode":"drain"}` or `cancel_active`.
  Poll `GET /v1/admin/state` until `quiescent=true` before benchmarking; acceptance of pause is not quiescence.
  `DELETE /v1/admin/pause` clears only manual pause. An optional owner-controlled pause marker also blocks dispatch.

The controller requires root-owned health attestation bound to the configured PF policy, current interface
inventory, job UID and qualified profile digests. Health expires within 45 seconds. Missing, stale or changed
security qualification stops admission and cancels active work. Merely creating a profile does not qualify it.
Installation and actual boundary qualification are separate provisioning work; no best-effort first build.

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

## Development

Use the Go version declared in `go.mod`. SQLite uses a pure-Go driver; no external database is required.

```sh
go vet ./...
go test ./...
go run ./cmd/macserve --help
```

`macserve --help` and `macserve <command> --help` exit 0. Both service commands require `--config`; invalid or
missing arguments exit 2. Runtime safety failures exit 1. Help goes to stdout and errors to stderr.

CI pins third-party actions to immutable commit SHAs and runs vet, tests and a CLI build on GitHub-hosted
`ubuntu-latest` and `macos-latest`. Apple tool execution is faked in tests: no simulator boot or app build is
performed. Native process tests use harmless owned Go helpers, including a session-escaping child with
cleanup restricted to that exact PID. Privilege transitions use injected seams, not privileged test execution.
Linux exercises portable behavior but is not a supported Apple worker host.

## License

Apache-2.0

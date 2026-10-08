# macserve

**Use your own Mac as a private iOS build-and-test service.**

Submit an exact Git commit, pick a pinned Xcode toolchain, and get back logs, test results, screenshots and a
signed evidence receipt. Jobs run natively on your Mac under a dedicated non-admin account, one at a time, at low
priority, and you can pause them whenever you need the machine. GitHub integration is pull-based, so your CI never
needs network credentials for your private network. No VM required.

> Status: early development. Durable admission, queue, native execution, evidence collection and the worker
> Unix-socket client are implemented. The controller service and installation assets are not yet available.
> The root execution broker requires a separate non-admin macOS GUI job account and an explicitly qualified
> process baseline. No privileged deployment or background GUI acceptance has been performed.

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
- `internal/workerclient`: authenticated Unix peer credentials, heartbeat cancellation, streamed logs and
  durable completion replay. Retrying delivery does not execute the job again. Uncertain cleanup stops dispatch.

The store requires a dedicated private directory (mode `0700`) and private database files. Default limits are
50 outstanding jobs, 10 per principal, 24-hour queue expiry, 90-day terminal metadata retention, 64 MiB per
result envelope, 256 MiB of raw logs per job and 1 GiB of retained raw logs across jobs. Terminal log bytes
expire after seven days or under pool pressure, oldest completion first; active logs are never evicted.
`Logs` returns `ErrLogExpired` after eviction, while result envelopes, sequence/completeness metadata and
idempotency records remain unchanged. Schema upgrades account for existing log bytes.

Worker defaults are a 30 GiB workspace and 5 GiB artifact budget. Workspace usage is checked
at stages and every five seconds; it can overshoot between samples. Interrupted or uncertain process ownership
quarantines execution rather than guessing which PIDs to kill. Only recorded simulator UDIDs are cleaned up.

The root worker takes `--config` with a root-owned JSON file under root-controlled, non-writable ancestors.
Fields are `socket`, `controller_uid`, `job_uid`, `job_gid`, `owner_uid`, `root`, `export_root`,
`workspace_root`, `helper_path`, `baseline_path`, and optional `poll_seconds`, `heartbeat_seconds`,
`request_timeout_seconds`. Paths are absolute. Owner, job and controller UIDs must differ and be non-root;
the job account must be non-admin. The helper is a protected executable. Control and export roots are disjoint,
root-private (`0700`); the separate root-owned workspace parent must allow job traversal (for example `0711`),
but not replacement of other job directories. Only each individual workspace is transferred to the job UID.
Configuration rejects aliases between any of the three identities before connecting or executing tools.

An actual GUI login must already exist; `launchctl asuser` does not create one. With the broker stopped and no
unresolved manifests, an administrator explicitly audits trusted GUI process PIDs and runs
`macserve worker-qualify --config /absolute/worker.json --pids PID,PID`. The protected baseline records
`job_uid`, kernel `boot` identity, and `processes` containing `pid` and exact kernel `start` identities.
Qualification rejects unlisted job-UID processes and never signals processes or implicitly adopts them.
Missing/reused baseline processes or a changed boot require explicit requalification.

Recipe/simulator writers are stopped before pinned `xcresulttool` extraction; another UID barrier precedes
parsing and sealing. Raw logs and sealed exports are outside job-writable storage. Unproven quiescence blocks
success, sealing and the next lease. After quiescence, confined directory permission repair permits deletion
of read-only output without following symlinks or modifying external hardlink targets.

Inactive, certain records can reconcile their exact recorded simulator and workspace under a valid baseline.
Active/uncertain records, or an invalid baseline with unresolved records, remain quarantined until an
administrator investigates and explicitly reconciles affected devices, workspace/control records and pending
completion. Do not delete records merely to bypass an unproven cleanup. `worker-qualify` alone is not crash or
reboot recovery. Native shared-kernel, trusted GUI-service and same-user persistence risks remain; this is not
a hostile-code sandbox. Root/GUI deployment, network boundaries and background UI operation require separate
host qualification before real repository enrollment.

## Development

Use the Go version declared in `go.mod`. SQLite uses a pure-Go driver; no external database is required.

```sh
go vet ./...
go test ./...
go run ./cmd/macserve --help
```

`macserve --help` and `macserve <command> --help` exit 0. `worker` requires `--config`; invalid or missing
arguments exit 2. Runtime safety or connection failures exit 1. Help goes to stdout and errors to stderr.
The controller command remains unavailable until its service implementation lands.

CI pins third-party actions to immutable commit SHAs and runs vet, tests and a CLI build on GitHub-hosted
`ubuntu-latest` and `macos-latest`. Apple tool execution is faked in tests: no simulator boot or app build is
performed. Native process tests use harmless owned Go helpers, including a session-escaping child with
cleanup restricted to that exact PID. Privilege transitions use injected seams, not privileged test execution.
Linux exercises portable behavior but is not a supported Apple worker host.

## License

Apache-2.0

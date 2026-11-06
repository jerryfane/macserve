# Architecture

This page was split out of the [README](../README.md); text is unchanged unless noted. Deployment steps live in the [installation guide](install.md).

## Components

- `controller` (runs as a dedicated non-login service user): queue (SQLite), GitHub poller, API, receipt signer.
- `worker` (protected root execution broker): owns leases, control records and exports; executes tools only after
  dropping supplementary groups/GID/UID into the dedicated non-admin job account's existing GUI domain.
  The controller authenticates the broker's root Unix peer identity, never the job UID.
- Provisioning must deny access to owner files, keychains and service credentials. A separate UID alone does
  not protect world-readable owner data. No HTTP API or credential-bearing service runs as root.

## Network isolation: not provided in phase 1

The owner's accepted phase-1 model is **trusted repositories only**, including their build scripts and
dependencies. macserve does not install or load PF rules, manage anchors, or enforce job-network restrictions.
The job account may reach loopback, protected service ports, LAN, tailnet and internet destinations subject
to unrelated host/network policy. A separate UID and authenticated controller API do not provide network isolation.

Network probes record actual job-user reachability as **`not enforced in phase 1`**, for owner information;
reachable destinations are not qualification failures and failed connections are not denial proof.
Configured coexisting services must remain running with unchanged PIDs during installation and qualification
windows. Main and configured peer PF rules are measured read-only before/after; available measurements must
match, while unreadable PF is explicitly `unavailable` and does not block those operations. After a qualification
window, steady-state health requires only that the same configured services are still running: a peer that
restarts under a new PID (for example its own redeploy) does not invalidate qualification, while a stopped or
changed peer set does.
PF enforcement may be a separately reviewed future opt-in; it is not implemented or implied by phase-1 health.

## Implemented packages

- `internal/model`: job states, the four job kinds (`build`, `unit_test`, `simulator_ui_test` and the
  template-only `simulator_script`), exact toolchain pins and controller-owned argv recipes.
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
  including descendants that leave their process group/session. The memory budget charges the summed
  `phys_footprint` of the job UID's live processes above the same sum sampled immediately before the job's
  first command (the always-logged-in GUI session's footprint, which includes compressed and swapped memory),
  so pages a booting simulator's processes share are not charged once per process. A command whose baseline
  cannot be sampled does not start; `peak_memory_mib` is the charged peak, and the baseline is written to the
  broker log at job start and to budget failures. A slow or failed sample is tolerated until memory has gone
  unobserved for 30 s. This is not a kernel memory cap and excludes the broker and other-UID system daemons.
- `internal/evidence`: bounded xcresult test parsing, required-test execution checks, JUnit, deterministic
  artifact archives and content-addressed exports, including a script job's required `output.tar.gz`. Missing or incomplete test evidence cannot report success.
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
at stages and every five seconds; it can overshoot between samples. Since v0.1.16 the workspace
budget, like the maintenance census, charges a regular file its allocated blocks, once per inode:
sparse files (Xcode 27 preallocates `CompilationCache.noindex` at 37 GiB logical, about 3 MiB on
disk) no longer inflate it, and APFS clones are charged per inode, which over-counts shared blocks.
Exported artifacts keep a logical-size bound, because collection copies them densely. The budget,
lockfile and artifact walks refuse a mount point inside the workspace and never descend it.
Quiesce gives every residual process instance two graces from the snapshot that first lists it
(SIGKILL at first sight after the first grace), so an extension orphaned when quiesce killed its
host is terminated, not reported unsignalled; residual processes still appearing ten graces in
are contamination. Unfinished resource cleanup blocks
execution and retries without inventing process or simulator ownership.

The root worker takes `--config` with a root-owned JSON file under root-controlled, non-writable ancestors.
Fields are `socket`, `controller_uid`, `job_uid`, `job_gid`, `owner_uid`, `root`, `export_root`,
`workspace_root`, `helper_path`, `baseline_path`, **`persistence_path`**, and optional `poll_seconds`, `heartbeat_seconds`,
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
GUI-baseline initialization/reset command, with the broker stopped, is:
`macserve worker-reset --config /absolute/worker.json --pids PID,PID`.
Explicitly audit the current trusted job-UID GUI PIDs before supplying this list: reset terminates other
job-UID processes, removes job-home LaunchAgents entries and crontab, and rechecks legacy login items without deleting them.
It records `job_uid`, kernel `boot`, exact selected `pid`/`start` identities, and the accepted persistence manifest digest.
It never adopts unselected processes or signals owner/controller processes. Missing/reused baseline
processes or changed boot refuse admission without creating quarantine; audit and use the same reset.

Before every registration/claim poll, recovery first cleans up recorded owned resources, then verifies
admission. Pending completion replay precedes recovery. A refusal leaves queued jobs untouched: the
worker logs its reason, waits the normal poll interval and retries; cancellation exits. Execute rechecks
admission after claim in case host state changed. Positive observation of a job-home LaunchAgents entry,
nonempty crontab, legacy login item, changed reviewed background census/code or leftover process outside the audited baseline creates
the single durable `admission-quarantine.json` marker. Positive residuals after cleanup do likewise.
Cancellation, deadlines, I/O and inspection-command errors refuse admission without creating a marker.
Before registration/claim, the client atomically publishes `<root>/admission-status.json` (the worker config's
broker-private `root`, mode `0600`) with `state` (`admitting` or `not_admitting`), `reason` and UTC `checked_at`.
Status-write errors also block registration/claim and retry on the normal poll. This file is only the last
observation, not a live heartbeat or a second quarantine authority; it may be stale after shutdown and
requires no administrator clear. Editing/removing it cannot bypass recovery or clear quarantine.
The fixed probes have deadlines and output bounds. Full inspection allows 30 seconds for native
SessionLoginItems/GUI-domain startup and host-wide BTM enumeration, and five seconds for metadata/cron.
Hot admission instead shares one fixed 30-second budget: two seconds each for its before/after authority
observations, cron, OS metadata and the entire root/ancestor ACL stage; six seconds for login items,
eight for BTM, and one second for each of six membership checks. Each share is clamped by the enclosing
deadline. Timeout or unavailable/partial output refuses this admission, never proves an empty census,
and does not by itself durably revoke the attestation. Full persistence collection has its own 480-second bound.
Modern registration inspection requires a complete,
recognized job-UID `sfltool dumpbtm` census matching the separately accepted protected manifest; missing,
unfamiliar or incomplete output is refusal, never absence. There is no automatic adoption or name/team/type
allowlist. The GUI process baseline and reviewed registration authority are independent and both must pass.
Legacy inspection uses CoreServices `LSSharedFileListSessionLoginItems` after dropping root credentials in
the existing job GUI domain. It does not send System Events AppleEvents or request Automation permission.
API creation/snapshot failure is never an empty list. **Nonzero legacy items refuse reset and admission;
macserve no longer deletes them automatically.** Scoped remediation requires a separate owner decision.

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

Unreviewed, unresolved or changed modern BTM registrations refuse admission. The owner must review attributable
eligible components or approve scoped remediation; reset itself never imports registrations. macserve never
runs host-wide `sfltool resetbtm` or changes owner registrations. Failed/unknown reset retains an existing marker.
Pending completions and sealed evidence are preserved; startup replays a pending completion before recovery. No registration or lease occurs before
recovery succeeds. Transient unclean completion fences the old controller epoch; verified recovery
automatically registers a fresh epoch, without a second administrator clear command.

**Trusted-native limit:** this service is for trusted repositories, not hostile contributors. A matching census
is a snapshot, not confinement: delayed same-UID mechanisms and explicitly approved extensions can run after
checks or process job-controlled inputs. Signed code is not necessarily harmless. Native shared-kernel execution
and trusted GUI services do not provide VM reset isolation. Root/GUI deployment, account boundaries and
background UI operation still require separate host qualification before enrollment.

The reviewed registration (persistence) policy is described in [persistence-policy.md](persistence-policy.md).

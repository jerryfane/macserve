# Architecture

This page was split out of the [README](../README.md); text is unchanged unless noted. Deployment steps live in the [installation guide](install.md).

## Components

- `controller` (runs as a dedicated non-login service user): queue (SQLite), GitHub poller, API, receipt signer.
  It is its own binary, `macserve-controller`; every other role runs from `macserve` (see
  [Two binaries and class K](#two-binaries-and-class-k)).
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
changed peer set does. A probe that reads a peer between two launchd runs (loaded but not running, or not loaded)
fails without evidence: it blocks admission, the last valid health stays (keeping active work) until its own 40 s
expiry, and a peer still down then invalidates it.
PF enforcement may be a separately reviewed future opt-in; it is not implemented or implied by phase-1 health.

## Implemented packages

- `internal/model`: job states, the five job kinds (`build`, `unit_test`, `simulator_ui_test` and the
  template-only `simulator_script` and `ios_archive`), exact toolchain pins and controller-owned argv recipes.
- `internal/profiles`: strict JSON loading (`{"profiles": [...]}`), immutable recipe snapshots, exact-SHA
  admission, pinned Xcode/runtime matching, timeout limits and SHA-256 recipe digests. Relative paths cannot
  contain `..`; command placeholders are limited to `CHECKOUT`, `WORKSPACE`, `DERIVED_DATA`, `RESULT_BUNDLE`,
  `SIMULATOR_ID`, `JOB_ID` and `DEVELOPER_DIR`, each written `${NAME}`. Test profiles require explicit test scope.
- `internal/controllerk/store`: SQLite WAL queue with principal-scoped idempotency, fair claim order across
  repositories (the repository waiting longest since its last claim goes next, FIFO within each repository;
  [configuration](configuration.md)), database-enforced single
  active execution, lease-checked transitions and active-execution log writes, persistent pause/drain,
  cancellation and retention. Terminal logs and results cannot be amended by a late worker.
  Interrupted execution or uncertain cleanup quarantines dispatch. Clearing quarantine requires a caller-proven
  quiescent worker with a new authenticated epoch; subsequent claims must use that persisted epoch.
  Every cancellation request records its cause in the job's `cancel_reason` column (schema version 6): source
  (client, admin pause, deadline, host readiness with the gate's blockers, gate error, log limit, controller
  shutdown, GitHub), principal, time and a detail bounded to 512 bytes. The first request wins and the job's
  finish keeps it; the API shows it on the job and in the job list, never in the receipt. The controller logs each
  cancellation it requests and each readiness change, and maintenance each invalid health record it publishes, on
  timestamped stderr lines ([configuration](configuration.md)).
- `internal/worker`: exclusive execution, verified full-tree source extraction, pinned toolchain/runtime checks,
  per-job environments and owned simulators, background scheduling and dedicated-job-UID process cleanup,
  including descendants that leave their process group/session. The memory budget charges the summed
  `phys_footprint` of the job UID's live processes above the same sum sampled immediately before the job's
  first command (the always-logged-in GUI session's footprint, which includes compressed and swapped memory),
  so pages a booting simulator's processes share are not charged once per process. A command whose baseline
  cannot be sampled does not start; `peak_memory_mib` is the charged peak, and the baseline is written to the
  broker log at job start and to budget failures. Memory is sampled beside the command, one sample at a time; only
  a completed sample over budget fails it. A sample that fails or is slow is degraded monitoring, never a failure:
  memory unobserved for 30 s is logged, the command keeps running, and its budget is enforced on the next sample
  that completes (until v0.1.67 it failed the command, which killed three parallel-testing UI-test runs together
  on 2026-11-17 and quarantined the worker). This is not a kernel memory cap and excludes the broker and other-UID
  system daemons.
  After a command exits, its output pipes get 10 s to reach end of file (each output chunk is a controller log
  request; 250 ms until v0.1.60 failed simulator boots at six lanes, #155), which still bounds a pipe a descendant
  that left the process group keeps open. A failed `simctl boot` or `bootstatus` is retried once on a new device,
  15 s after the failed device's teardown, so the retry does not meet the load that failed the first boot at once.
  A command's process group is cleaned up by SIGTERM to every listed member, SIGKILL after 0.5 s, then a 1 s window;
  each signal is a `_job-signal` helper run as the job UID that re-reads the target's identity, with 8 s and a 1 s
  output wait per run and up to three runs when one fails only on time. Each signalling round chooses SIGTERM or
  SIGKILL per member as it reaches it and ends with the cleanup's bound. If the group is still listed when the
  window closes, the worker keeps listing it with backoff (doubling to 5 s) and SIGKILLing what remains for up to
  `process_cleanup_seconds` in `worker.json` (180 s by default, also the maximum); a member listed then that no
  SIGKILL has reached gets one more 30 s SIGKILL round and 1 s to go before the verdict. The bound is hard, and
  cleanup is confirmed only when a listing shows no live group member and the direct child is reaped. A member still
  listed after a SIGKILL was delivered to it, a foreign UID or a GUI baseline PID in the group (checked in every
  listing, the final one included) is contamination. That refusal names the refused members (eight at most, then a
  count) by PID, UID, parent, process group, kernel start time and kernel command name (never arguments or the
  environment) in the broker's log and the quarantine record; the job's reason keeps only the refusal and the count
  (#196). The one UID 0 member that is not foreign is the command's own launcher: its unreaped direct child while
  still `launchctl asuser` or `_job-exec` before the drop, with the PID and start time recorded at spawn, leading
  its group. The kernel gives no other process that PID until it is reaped, so the worker SIGTERMs and SIGKILLs it
  by PID as root and judges it like any member; any other UID 0 member, or one whose PID or start time differs, is
  contamination. A member no SIGKILL reached within the bound leaves that command's cleanup unconfirmed instead: no
  quarantine marker, and the command fails. The job's finalization then
  tries to repair it: its account or lane quiesce SIGKILLs and judges what is left. Only if the job's final cleanup
  is still unconfirmed does the job end with `cleanup_ok=false`, which fences the epoch and drains the worker to the
  idle check, whose full-account quiesce and admission let it register again without an owner. At load 53 a 100 ms
  helper output wait and the 1.5 s window left a cancelled xcodebuild
  group judged contaminated and quarantined the worker (2026-11-18, #194). The account and lane quiesces judge a
  survivor by escalation too: an instance is a survivor only when still listed a grace after a SIGKILL to it
  completed, and their settle bound excludes time spent signalling. A job's finalization budget
  (`FinalizationTimeout`, 918.5 s, which sizes the controller's finalizing and cancelling leases) includes three such
  cleanups, one per context window that runs commands: a cancelled job's recipe command, the cleanup budget's
  evidence commands and the verification window's Metal toolchain unmount; plus one stall kill (one listing and one
  SIGKILL round, 35 s) before a stalled run command's cleanup.
- Stall watchdog (#201): a template job's run command (only it: never prepare, evidence or cleanup commands) whose
  combined stdout and stderr get no byte for its stall limit (`model.Profile.StallTimeout`: 600 s by default for
  `simulator_script`, opt-in `stall_seconds` for test templates) ends with `worker.ErrStalled`. The runner SIGKILLs at
  once every job-UID member of the command's process group and every descendant of its direct child that left the
  group (a hung `simctl` under `timeout` leads a group of its own, and on 2026-11-19 such children left a cancelled
  stalled job's cleanup unconfirmed), then runs the usual protected group cleanup. The finalization then stops and
  deletes the job's simulators, quiesces and takes its census as for any job. The job ends `cancelled`; its
  completion carries `stalled`, the controller records cancel source `stalled`, and pull mode reruns it once.
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
  Transiently failed heartbeat, log and stage requests are retried within the controller's lease window; log
  chunks carry a per-lease `seq` the store records once (see configuration, #174).
- `internal/source`: isolated controller-side Git fetch, exact commit/tree verification and bounded deterministic
  full-tree tar export. Git archive attributes cannot omit or substitute committed bytes. Links, submodules and
  Git LFS requirements are rejected explicitly. Source exports default to a 2 GiB limit.
- `internal/controllerk/controller`: Unix peer-UID authentication, asynchronous preparation, heartbeat/deadline fencing,
  independently parsed test evidence, immutable artifact storage, bounded retention and fail-closed host guards.
- `internal/controllerk/api`: persisted bearer digests, repository/scoped authorization, idempotent admission, status,
  paged/SSE logs, JSON/JUnit results, range downloads and persisted administrative pause/resume.
- `internal/githubapi`: selected-repository App tokens, fresh repository-ID checks, bounded pagination,
  deadlines and rate-limit handling. Redirects cannot forward credentials to another origin.
- `internal/controllerk/githubpull`: automatic exact-head enrollment, durable request/attempt correlations, explicit bounded
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
50 outstanding jobs, 10 per principal (the controller sets 100 and 30), 24-hour queue expiry, 90-day terminal
metadata retention, 64 MiB per result envelope, 256 MiB of raw logs per job and 1 GiB of retained raw logs across
jobs. Terminal log bytes expire after seven days or under pool pressure, oldest completion first; active logs are
never evicted.
`Logs` returns `ErrLogExpired` after eviction, while result envelopes, sequence/completeness metadata and
idempotency records remain unchanged. Schema upgrades account for existing log bytes.
The controller's minute sweep prunes in bounded batches, each its own short write transaction (at most 200 jobs,
or 2,000 log records, or 4 MiB, per batch), so the store's single connection is free between batches: a job's logs
are tombstoned before their records are deleted, the log-byte accounting follows every deleted record, and an
interrupted prune resumes on the next sweep. A sweep or prune slower than 2 s is logged with its counts, and a
sweep's errors are logged (#167).

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
Hot admission instead runs under one fixed 30-second budget per attempt: ten seconds each for its before/after
authority observations (the lock, whose wait alone is bounded by one second, the protected-input ACL inspections
and the reads) and for each attempt of the root/ancestor ACL stage; five each for cron, OS metadata and each of six
membership checks; six for login items and eight for BTM. Each share is clamped by the enclosing deadline. An
inspection command's output may take one second to close after it exits (its wait delay). Timeout or
unavailable/partial output refuses this admission, never proves an empty census, and does not by itself durably
revoke the attestation. A root/ancestor ACL stage its ten seconds cut short observed nothing: it starts again,
probing every path anew, with a fresh ten seconds, at most twice in all. An attempt the deadline of any of its
inspections ended observed nothing either and runs once more with a fresh 30 seconds, so an admission spends at most
60 seconds on it; a finding or a failure that ran ends it at once. Each `ls` of `hostguard`'s protected-input ACL
inspection has five seconds and runs once more when they cut it short. These sizes come from six lanes at load 20-35
(Studio v0.1.56, #150), where the former two-second shares (one second per membership check, a 100 ms wait delay)
expired seven times in 23 minutes and single small commands overran five seconds at times, never twice in a row.
An attempt still cut short refuses only the job about to start, and after a job's verified cleanup leaves the
verdict to the idle check (see **Cleanup** below). Full persistence
collection has its own 480-second bound.
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
success, sealing and the next lease. The writer barriers and evidence stages share one two-minute cooperative
cleanup budget; the final barrier, verification and workspace cleanup then get at least 90 seconds of their own
(see **Cleanup** below).
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

## Two binaries and class K

Releases ship two Darwin arm64 binaries, installed root:wheel `0755` under `/Library/macserve/bin`:

- `macserve-controller` runs only the controller daemon (`org.macserve.controller`, as the controller service
  user) and `macserve-controller version --json`, which prints `{"version","commit","store_schema_version"}`
  without opening the store or reading secrets.
- `macserve` runs every other role: the root worker, maintenance, the signer, qualification, deploy, setup,
  upgrade, doctor and the owner commands (`wait`, `testflight-upload`). It has no `controller` subcommand.

`BOUNDARY.json` (schema 2) adds class **K**: the controller-only packages `internal/controllerk/...` (controller
runtime, API, SQLite store, GitHub poller) and `cmd/macserve-controller`. K is classified per whole package, not
per file. `go test ./checks/boundary` (run in CI) enforces the link graph: `go list -deps ./cmd/macserve` contains
no K package, no non-K package imports a K package, and `macserve-controller` links only K packages, the standard
library, third-party modules and an explicit allowlist of B leaf packages. The types root code shares with the
controller live in B packages with unchanged JSON: `internal/controllerconfig` (`controller.json` and its
principals), `internal/health` (the health record and readiness gate), `internal/githubwire` (pull-request policy,
evidence packet) and `internal/daemonlog`.

The activation anchor (schema 3) binds both binaries; a release carry may rebind either or both, and
`macserve qualify rebind-controller` rebinds a controller-only change installed by the administrator. On a Mac set up by
`macserve setup` it also records the new controller and anchor in the setup ledger (refused while an upgrade runs), so
setup, upgrade and doctor keep accepting them.
When binaries are installed Developer ID signed, root-owned `config/installed-binaries.json` maps each installed
digest to its release digest; native checks compare on-disk bytes to `installed_sha256` and release provenance to
`release_sha256` (absent file: the installed bytes are the release bytes).

**Threat model of K (design r3 item 1, amended by r4).** K code is trusted only as far as merge, review and the
CI release key. A controller-only (K) release is carryable: `checks/carry-proof` accepts K paths, and
`qualification.ValidateCarryProof` refuses a K-only proof whose root `macserve` binary is not byte-identical to the
predecessor's. Arbitrary K code **can**: read or exfiltrate what the controller holds (the TLS private key, API
bearer verifiers, and the short-lived per-repository GitHub installation tokens it asked the keyholder for);
fabricate or drop queue records; admit jobs for any registered profile; choose the source bytes a job builds; forge
or withhold *non-release* receipts (the keyholder signs what the root worker sealed, but the commit-to-bytes binding
of a non-release job is K's statement); deny service; corrupt the queue database. For an otherwise fully scoped
release K may choose the version labels BuildName and BuildNumber, and nothing else that changes the build output.
It **cannot**: run as root or as the owner; change what a profile executes; read the receipt or GitHub App
long-lived keys; obtain Apple signing for anything outside the root release scope; or change any B artifact.

That rests on B processes, not on the controller:

- **Worker registry.** The root worker resolves every lease against the root-owned registry
  (`worker.json` `profiles_file`, `/Library/macserve/config/profiles.json`) exactly as admission does, and refuses a
  lease whose profile snapshot, digest, repository or request differs, or whose registry profile set differs from
  the qualified one (`qualification_file`). Template snapshots and replays resolve identically, since a replay is
  the stored first admission.
- **Worker build seal.** The root worker signs, with a root-only Ed25519 key (`/Library/macserve/var/broker/seal-key.pem`,
  public key pinned in `keyholder.json`), a canonical record of what it built: the request, its own registry
  resolution (profile id/version/digest, Xcode and DeveloperDir, Flutter pin), the snapshot and recipe digests, the
  Git tree it computed from the bytes it extracted, the result digest and the archive and signing-manifest digests,
  and for a build-for-testing producer its `test-products.tar` digest and `.xctestrun` name.
  The seal travels through the controller with the completion; a signature, not a channel, authenticates it, so K
  can withhold it but not forge or alter it, and a pending completion survives a worker restart sealed.
- **Keyholder.** `org.macserve.keyholder` runs as the non-login `_macserve_key`, holds the receipt and GitHub App
  keys in its own `0700` directory, and answers only the controller UID on its socket (the client equally checks
  the keyholder UID). It mints short-lived installation tokens only for repositories in the root-owned policy
  (`controller.json` `receipt.repositories` and `receipt.owners`). It signs a receipt only after verifying the worker
  seal and that the job record and result are the sealed ones (the controller may only drop unverified artifacts,
  shorten expiry, mark logs truncated, add a test summary or downgrade the state). A success receipt needs the
  worker's registry resolution, and a build-for-testing producer's the sealed products digest equal to its
  `test-products.tar` artifact's (no other seal may name products). A test-products consumer's success needs the
  products its worker verified and imported (`imported_products_sha256`) and the keyholder's own record of the
  producer's signed success for the same repository, commit, source tree and Xcode; the receipt's `products`
  block comes only from that record. A **release** receipt additionally needs the root-owned
  `/Library/macserve/config/release-scope.json` entry for the repository to match the seal exactly (profile
  id/version/digest, Xcode and Flutter pins, the exact Dart defines map; BuildName `^[0-9]+(\.[0-9]+){0,2}$`,
  BuildNumber `^[0-9]{1,9}$`), and the keyholder's own GitHub check that the repository ID is the scoped one, the
  commit is the default-branch head and the commit's tree equals the worker-computed tree. The receipt's
  `release_provenance` is the keyholder's check; controller-supplied provenance is ignored. The signer keeps
  accepting only receipts signed with the (keyholder-held) receipt key.
- **Accepted limit.** The TLS key stays with the controller: K code can impersonate the private API endpoint to
  clients that trust its certificate. Rollback of a bad K release is best-effort against a malicious K.

**Release provenance of K.** A controller-only release reaches the Mac as a *controller-carry* release: the
release workflow republishes the base release's root binary bytes, refuses unless the root binary's
`go list -deps` source closure, the store schema version and the base `BOUNDARY.json` classes allow it, and
signs `release-manifest.json` with the CI release key ([releases](releases.md)). K code is trusted only as far
as merge + review + that key: the Mac verifies the signature against its pinned public key and does not prove
that a change was reviewed or merged. The goal, reached only once the keyholder and worker changes above land,
is that a compromised key or a malicious merged K change reaches at most what K can reach as the controller UID,
never root, the owner's home or Apple signing.

## Code signer boundary

The optional `signer` daemon (`org.macserve.signer`, account `_macserve_sign`) is a separate privilege domain
from the controller, the worker and the job account. It alone holds the Apple Distribution identity (in its own
keychain under `/Library/macserve/var/signer/keychain`), the keychain secret and its Ed25519 signer receipt key,
all in `_macserve_sign`-owned `0700` directories. The controller reaches it only through
`/Library/macserve/var/signer-run/signer.sock` (`0660` in a `0750` directory) and hands archive and manifest copies
through `/Library/macserve/var/signer-inbox` (`0750`); both are group `_macserve_signrpc`, whose only members are
the controller and the signer. The job account is in neither signer group, so a compromised build cannot reach
the identity, the socket or the inbox. The signer verifies the controller's job receipt (pinned in `signer.json`),
applies only the root-owned admin policy (`signer-policy.json`: identity, allowed bundle IDs, team, profiles and
required entitlements) and signs its result with its own receipt key, which the controller pins.

**New qualification category `signer_denial`.** When the deployment has a signer (`SIGNER_*` in `deploy.env`,
an installed `config/signer.json`, or a controller `signer` section) the challenge sets `signer`, and the job probe
(`_qualify-job-probe`, run as the job account by the root launcher) adds `signer_denial` rows proving the job
cannot list or traverse `var/signer`, `var/signer/keychain`, `var/signer-run` and `var/signer-inbox`, cannot connect
to `signer.sock`, and cannot open `signing.keychain-db` or `keychain.secret`. Only a permission error
(EACCES/EPERM) passes a row; success, absence or any other error fails it. `signer_denial` is a job report
category, not a schema-4 record category: the maintenance record's categories and digests are unchanged, and with a
signer the `unix_socket_boundary` category passes only if every `signer_denial` row passes too (qualify carry
requires the same). The owner report never carries `signer_denial` rows, and a challenge without a signer refuses
them. An installed `org.macserve.signer.plist` is bound into the activation anchor.

## Concurrent jobs in one job account

With `max_concurrent_jobs` above 1 the broker runs up to that many jobs at once in the one job account (owner
decision: no second account). Paths are already per job (workspace, HOME, TMPDIR, caches, DerivedData, evidence,
export, manifest, simulator). Isolation between concurrent jobs is cooperative, not enforced: a job can still signal
or write a sibling's processes and files, act on a sibling's simulator through the shared CoreSimulator service, and
change launchd/persistence state. That fits only the phase-1 model of trusted repositories.

**Attribution** (`internal/worker/lanes.go`). The broker labels job-UID process instances (PID and kernel start time)
by lineage, sampled every 100 ms while a job runs: every command root the broker starts for a job, every
`launchd_sim` whose arguments name a device directory of a simulator the job created, and every process whose
executable lies under the job's workspace or device directory seed the job's label; a child first seen with a
labelled parent inherits it, and labels stay with the instance when it is reparented to launchd. On macOS the broker
also reads each new instance's kernel unique ID and its parent's unique ID at fork (`proc_pidinfo`
`PROC_PIDUNIQIDENTIFIERINFO`, `p_puniqueid`), which survives reparenting: a process whose parent exited before it was
sampled (a fast double fork, as SwiftPM's `git` does) inherits the label of that parent's unique ID if it was ever
labelled. Two seeds claiming
one instance make it nobody's. Validated on live Studio captures (`internal/worker/testdata/lanes`): a tandem unit-test
job and three booting simulators split with no unattributed process. Instances no lineage claims are judged by the
existing census (audited baseline, verified relaunches, tolerated Apple/developer-tool launches such as
CoreSimulatorService, SimLaunchHost, testmanagerd, CoreDevice); what remains is *unattributed*. The memory budget then
charges the summed `phys_footprint` of the job's own labelled processes (no job-UID baseline), by the labels the 100 ms
sampling keeps: a memory sample does not relabel. `host_peak_memory_mib` records the whole job UID. A labelling pass
reads each unlabelled instance's executable (and a `launchd_sim`'s arguments) from the kernel at most once.

**Cleanup.** A job that starts while no other job runs is admitted by the full admission and preflight quiesce. A job
started beside others is admitted by a lane admission: other jobs' labelled processes are not residual, and an
unattributed process refuses the start and *drains* the broker. A job whose finalization begins while no other job
runs ends with the unchanged full quiesce and admission (idle verdict `clean`); no other job starts until it ends. A
job finishing beside others deletes only its own simulator and quiesces only its labelled processes (SIGTERM, SIGKILL,
survivor = contamination and quarantine, as before), never a shared service or a sibling's process; any unattributed process still running in a
second census 1 s later (short-lived build helpers such as SwiftPM's `git` are not counted) drains the broker and
*holds* the job's completion. Attribution is not complete (a child reparented before it was labelled, or whose
lineage could not be read, is unattributed), so such a process may be the job's own, and only the idle check can tell.

*Crash agents* (`internal/worker/crash_agents.go`, #146) are the exception. When a job's process crashes (a crash test,
a failing UI test), launchd starts the macOS crash dialog `/System/Library/CoreServices/Problem Reporter.app` in the
job's GUI session, and beside it the XPC services `SetStoreUpdateService` (CascadeSets) and
`SpeechSynthesisServerXPC` (SpeechSynthesis). The dialog waits for a click that never comes, so before v0.1.56 every
lane that finished beside others deferred and drained the broker, and the lanes ran as batches. A process the census
leaves unattributed (it judges every process no job labels first, exactly as before: a verified relaunch of an audited
process or a tolerated launch running one of these executables serves every job and is never signalled) is a crash
agent when its kernel facts prove all of this: the job UID, parent PID 1 (launchd), a valid platform binary, a kernel
executable path (`PROC_PIDPATHINFO`) equal to one of those three paths and SIP-restricted, and a start after a running
job began and before that job's lane quiesce began. It is that job's to stop, not unattributed: it neither drains nor
refuses a lane admission. That job's lane quiesce terminates it with the job's own processes (same signals, survivor
rule and settle bound; only instances started before that quiesce began, so a sibling crashing again cannot keep it
busy). A job ending alone stops it with the full quiesce, like any residual process. They are terminated rather than
tolerated: none has a launchd record that proves Apple's own definition (the dialog is an application, not a
LaunchAgent; the XPC services belong to the dialog's pid domain, whose owner is never verified), terminating them loses
nothing (ReportCrash wrote the crash report before the dialog showed it; the XPC services are stateless and launchd
starts them again on demand), and nothing joins a tolerated set.

*Shared agents* (same file, v0.1.61, #155) are Apple per-user agents that launchd starts beside running jobs and that
may serve any of them: Spotlight's `mdworker` (`CoreServices.framework/…/Metadata.framework/Versions/A/Support/mdworker`,
indexing files any job wrote), the Lighthouse SELF ingestor extensions (`/System/Library/ExtensionKit/Extensions/{GMS,
IFTelemetry,Biome,AppleIntelligenceReporting}SELFIngestor.appex`, on-demand telemetry XPC services) and WebKit's
`com.apple.WebKit.GPU`, `.WebContent` and `.Networking` XPC services, which a web view in a job's GUI session starts.
The kernel names the WebKit services by their path in the sealed OS cryptex
(`/System/Volumes/Preboot/Cryptexes/OS/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/…`; the
`/System` path launchd names is a SIP symlink into it), whose files are SF_RESTRICTED like `/System`'s. A shared agent
has a crash agent's kernel facts with one of these paths and a start in the current busy period: after the first of
the jobs that have run without a break since the account was last idle. While any job runs it is not unattributed: it
neither defers a verdict, drains nor refuses a lane admission, also beside an audited agent that exited without a
verified relaunch (such a lane admission failed as unverified cleanup at 13:17:13Z on 2026-11-15, most likely beside
the GPU service). No lane quiesce signals it, since its client may be a sibling still running and nothing attributes
it to the finalizing job. The next idle point cleans the account of it: the job that finalizes alone ends with the full
quiesce, and so does the idle `Recover`, which stop it like any residual process. It is not tolerated across idle
points: `mdworker` runs Spotlight importer plug-ins as the job UID, and a web view's process owns the WebKit services'
pid domain unverified; all are on-demand services launchd starts again. The worker does not keep Spotlight off the
job's files: `.metadata_never_index` inside a folder is no longer honoured by current macOS, and Spotlight's privacy
list is a system setting.

A crash agent no running job covers (older than every running job, or started after the lane quiesce of every job that
began before it), a shared agent older than the busy period, a copy outside SIP, one the job forked itself, any other
path (the App cryptex's included), and every other unattributed process still drain and hold as above.

A lane admission that finds an audited GUI process exited beside an unattributed process it cannot verify as its
launchd relaunch is inconclusive, never contamination (#206). The broker still drains: no job starts beside the running
ones until the idle check verifies the account. The job being admitted is refused before it runs, though, not failed:
reason `lane admission: …`, `cleanup_ok` true, idle verdict `not_required`, and its completion carries
`admission_refused: relaunch_unverified`, which the controller records as the cancellation `worker_admission` like the
refusal below, so pull mode reruns its head (bounded like every automatic rerun: twice per run per hour, after which
the cancelled attempt stays with that reason). Contamination at a lane admission still fails the job. Every unverified
relaunch, at a lane admission, a cleanup barrier or the idle admission, names the audited processes that exited (PID,
start, launchd label, executable) and the unattributed ones beside them (PID, UID, parent, start, executable, kernel
command name; never an argument or the environment), at most eight of each, in the worker's log, the drain reason and
the job's reason, which the controller logs whole.

An admission or finalization inspection still cut short by its own deadline (a loaded host) observed nothing, which
is no evidence either way (#148, #150): the registered-root ACL census after its retries, `hostguard`'s
protected-input ACL inspection of the persistence authority (`cannot inspect protected input ACL: signal: killed:
context deadline exceeded`), an authority bracket whose time ran out between its commands (a bare `context deadline
exceeded`), a command whose output did not close within its wait delay (`exec: WaitDelay expired before I/O
complete`, for example a membership check with `registration service account memberships unavailable`), or a census
or quiesce of the job account that ran out of time. When the job is starting, only that job is refused before it
runs, with reason `lane admission: …` (`admission: …` for a job starting alone) naming the inspection, `cleanup_ok`
true and idle verdict `not_required`, since nothing of it ran. Nothing is quarantined, the broker does not drain and
the completion is not held: the running jobs were admitted on their own evidence, and every later admission takes its
own census before its job starts. The completion carries `admission_refused: acl_census_unavailable`, and the
controller records the cancellation `worker_admission` before judging it: the job ends `cancelled` by the service,
so pull mode reruns its head (#119). A controller from before this
field refuses such a completion (the worker transport refuses unknown fields), so the worker and the controller of one
release ship together. At a job's finalization, after its earlier barriers stopped and verified its processes, a
final job-account barrier, its admission alone or its residue count beside others cut short leaves the job's own
result and successful cleanup standing until the idle check, which holds the completion and drains the broker; a
final barrier cut short also leaves the workspace to that check's recovery. The final barrier, that inspection
(at most 45 seconds of it) and the workspace cleanup always get at least 90 seconds after the evidence steps, however
long those took (a passing UI test whose evidence used the whole 120-second cleanup budget left them none, #150), so
a finalization takes at most 210 seconds (`worker.FinalizationTimeout`) besides an archive job's own evidence window.
The controller derives its finalizing lease from it: that finalization plus the two-minute completion delivery
(`protocol.DeliveryTimeout`) plus heartbeat grace, 360 seconds by default (270 before), so a long finalization
followed by a slow upload no longer expires the lease mid-delivery and fences the epoch. A census or inspection that
ran and failed (its reason names the cause, such as `registered tree ACL census failed: exit status 1`), a barrier
before it that failed, or one that found a writable ACL or an unknown process, fails the cleanup or defers as before,
and a writable ACL or a survivor quarantines.
For a held completion, the worker reports the hold to the controller (stage `finalizing`, `held`), keeps the lease alive by heartbeat, asks for
no lease, and delivers the completion after the next idle `Recover`: with its own result and idle verdict `clean` when
that full quiesce and admission pass (the residue count stays recorded), else with `cleanup_ok` false (the job fails,
and a survivor quarantines the account). A worker that stops while a completion is held still waits for the other
lanes and runs that `Recover` first. The controller claims nothing while a completion is held and keeps it on its
heartbeats while another unheld lease is active, then for the idle check and delivery
(cleanup + delivery + heartbeat windows); a held job's deadline is judged when it was held, so the wait never times it
out. A lost heartbeat (a worker restart) ends it as for any lease: interrupted, quiescence required. While
draining, the broker claims nothing, lets running jobs finish, and the next idle `Recover` runs the full quiesce and
admission: contamination quarantines exactly as with one job, a clean account resumes intake. Only a completion with
`cleanup_ok=false` fences the epoch, so only it makes the worker register a new one; an unattributed process seen beside
running jobs (no completion fenced anything) keeps the epoch, and a lease the controller had already prepared for the
next lane is delivered after the idle `Recover` instead of being interrupted by the new epoch.
Simulator creation is serialized across lanes, and a sibling's recorded device is never an unrecorded device after an
interrupted create. The controller starts one simulator job at a time: the next once the previous one runs or was
delivered a minute ago ([configuration](configuration.md#concurrent-jobs-max_concurrent_jobs)). A broker restart with
several manifests recovers all of them at idle (full quiesce, then each job's simulator and workspace). Each completion
is saved as `pending-<job>.json` until acknowledged (a pre-lane `pending.json` is still delivered).

**Concurrent scripts.** `simulator_script` and `ios_archive` jobs run alone (`model.Job.Exclusive`), except a script
job of a template with `"concurrent": true` (`model.Profile.Concurrent`), which the controller claims and the engine
admits beside other jobs but beside no other such job. Its script runs arbitrary repository shell, and the simulators
it creates with `simctl` are booted by CoreSimulator, not by the script, so lineage alone would leave them
unattributed. Just before the script starts the engine records the device inventory in the job's manifest (under the
creation lock, so no engine creation is in flight) and makes the job the tracker's one *adopter*: a `launchd_sim` (or a
process executing from a device directory) of a device no running job created, started since, seeds the script job's
label. At finalization, again under the creation lock, every device then listed that was not in the recorded
inventory, is not recorded by another manifest and is not the job's own becomes one of the job's `script_devices`
(also attached to the tracker); they are shut down, deleted and proven absent with its own simulator, before the lane
quiesce. After that quiesce has stopped the job's processes, a second inventory adopts and deletes any device one of
them created in between, and only then is the recorded inventory released; a survivor is contamination, and a
failure keeps the inventory for recovery. Recovery after a restart does the same from the manifest. Anything else the
script leaves follows the residue, hold and idle-verdict rules above. The engine cannot detect a script acting on a
sibling's simulator or on CoreSimulator; the contract in [configuration.md](configuration.md) forbids it.

**Retried UI tests.** A `simulator_ui_test` job of a template with `retry_failed_tests`
(`model.Profile.RetryIterations`) adds `-retry-tests-on-failure -test-iterations 2` to its commands whose xcodebuild
action is `test` or `test-without-building` (`runsTestAction`: a bare word that is not an option's value, so a
scheme named `test` does not count), not to `build-for-testing`, after the parallel-testing options. Attempts are one
test's only by xcodebuild's retry provenance: the parser labels Repetition nodes `First Run`, `Retry 1`, ... that are
the only executions under one parent (`repetition` on each case), and drops the labels of a Test Case with a Device
node lacking an identifier. The worker, the controller's reparse and receipt validation all apply
`evidence.MarkRetries` to the labelled attempts: a group passes on retry when its last attempt passed after failed
ones, unless its identity (ID and suite) is shared with another group or case, as two same-named devices would be;
only failures may be retried, so a non-failed earlier attempt or more attempts than iterations is invalid evidence.
A superseded attempt explains only the failure it rolls up: a container's own failure messages (a suite teardown)
stay failures, and a test case's own messages (outside its attempts, or recorded by none of them) are fixed from the
tree before aggregate messages are copied onto attempts; they become the last attempt's `case_failures` and keep it
failed even when it passed or was an expected failure. Attribution goes by kind as well as text: an Expected Failure
issue's messages are never a case failure and never explain one away, even with identical text. Success still requires the test command's exit 0:
xcodebuild exits 0 when every test's last attempt passed, so no non-zero exit is reinterpreted.

**Parallel-testing clones.** A `simulator_ui_test` job of a template with `parallel_testing`
(`model.Profile.ParallelTestingWorkers`) runs its tests with xcodebuild parallel testing, which clones the job's
simulator into XCTest's device set (`simctl --set testing`, `Library/Developer/XCTestDevices` in the job's home), names each clone
`Clone <n> of macserve-<job>`, boots them and deletes them when the run ends. That set is not the default set the
engine lists, so before the test run the engine records the testing set's inventory in the manifest
(`test_clones_pending`, `test_clones_before`). Xcode creates the set's directory only with its first clone, and until
then `simctl --set testing list` exits 1 ("Provided set path does not exist"): every listing of the set (inventory,
discovery, census refresh, cleanup, recovery) that only exited non-zero while the directory does not exist (lstat
ENOENT) is an empty set; the engine never creates it. A failed listing of an existing set, or one whose path cannot be
checked or is not a directory, stays a failure. While the run runs, it lists the set every 5 s, and again inside every
lane census (a sibling's residue count, a lane admission or readiness check) after the census samples the processes
and before it judges them, and makes every
clone of its own simulator (added since, and named for its own device) one of the job's `test_clones` at once, saving
the manifest: from then on the clone is the job's by UDID, whatever it is named later, and a restart recovers it. In
lane mode it is also attached to the tracker; its `launchd_sim` (its arguments name `.../XCTestDevices/<UDID>/`) and
children are then the job's, charged to its memory budget and stopped by its lane quiesce, not unattributed residue
beside a sibling. A discovery listing that merely fails is retried; one whose process cleanup failed or found
contamination, or a failed manifest save, fails the job when the run ends, with the same quarantine authority as the
job's own commands, and a later successful listing never clears it. When the run ends the watch starts no new
listing and waits for the one in flight, which the run's end never cancels: a listing cut short while its launcher
still ran as root is the suspected cause of a smoke run's quarantine (#196). At finalization, before the lane
quiesce, every such clone still listed is adopted too, and all of the job's `test_clones` are shut down, deleted and
proven absent with the job's own simulator; a second pass after the quiesce, and recovery after a restart, do the
same from the manifest, and a survivor is contamination. Name and inventory together decide what is discovered: a
clone of another job's simulator (another job ID) or one listed before the run is never the job's. A parallel-testing
run boots its clones at once, after the build, which the controller's start stagger does not cover; in lane mode the
engine therefore starts the run only once 30 s have passed since the latest simulator boot or parallel-testing run
start of any lane, checking again after every wait, so a boot during the wait restarts it. This gate is the last step
before the run, after the clone inventory, so no work between the gate and the run can miss a boot.


# Installation, qualification and recovery

This is a **future, owner-approved deployment runbook**, not a report that this Mac has been installed or qualified. Repository checks and fixture results do not prove native GUI, PF, FileVault, App authorization or target-recipe behavior. Every administrative action below requires an approved owner sitting. No service should be enabled just to see whether a real build works.

## Trust boundary and stop conditions

Use only trusted repositories and trusted repository writers. A root broker handles protected leases, exports and cleanup, then executes tools as a separate non-admin GUI user; the credential-bearing controller is a different non-login user. A broker defect is a root risk. This is shared-kernel native execution, not a VM, disposable reset or hostile-code sandbox. Same-UID delayed persistence can run after a clean census and affect a later job. The owner must accept that residual risk explicitly; signatures attest observations, not host integrity or honest tests.

Keep all three LaunchDaemons disabled if PF UID matching, recursive rule inspection, loopback filtering, persistence inspection, real GUI operation or evidence accounting is unsupported. Do not replace a failed probe with a success boolean, adopt all current processes automatically, weaken the firewall, or run a first production build as a fallback. Phase 1 is unsigned build/test only: no signing identities, provisioning profiles, App Store Connect or TestFlight credentials, and no Apple ID required for the job account.

Four separate future owner sittings are required; no duration or unattended completion is promised:

1. **Administrative setup:** approve identities, protected installation, separately scoped owner-home ACL changes if needed, and a network maintenance window. Stage disabled assets; inspect and integrate only the dedicated PF anchor without disturbing existing policy.
2. **Job GUI/tool qualification:** log in as the job user at the actual GUI, handle approved tool prompts, audit baseline processes, exercise native target recipes and UI tests, and perform the complete boundary matrix before and after fast user switching.
3. **Repository/App enrollment:** approve selected repositories, numeric identity pins, controller-only keys, tailnet access and App-bound branch requirements. Qualify evidence publication and verification with trusted target code before opening production admission.
4. **Planned reboot:** arrange a person at the physical console for FileVault unlock after cold boot. Restore an actual job GUI login, preserve recorded state, audit retained GUI PIDs and use the same worker reset described below, then repeat qualification. Reboot is not automatically qualified by launchd.

Use only already-authorized console sharing. Do not enable sharing, grant blanket GUI privacy permissions, enable autologin, grant FileVault unlock rights, or alter the owner's services as an installation side effect.

## 1. Plan identities and stage protected assets

Review `assets/create-users.sh` before running it. From the reviewed source checkout, the following is a **plan-only** command; replace shell variables with explicitly approved values, not guessed unused IDs:

```sh
bash assets/create-users.sh \
  --controller-user "$CONTROLLER_USER" --controller-uid "$CONTROLLER_UID" --controller-gid "$CONTROLLER_GID" \
  --job-user "$JOB_USER" --job-uid "$JOB_UID" --job-gid "$JOB_GID" \
  --owner-user "$OWNER_USER" --owner-uid "$OWNER_UID"
```

The default plan makes no account/home/service queries and changes nothing; it is not proof that names or IDs are available. Account/group names and numeric IDs must be explicit. The script accepts canonical decimal IDs 501–999999999 for controller/job UIDs and GIDs and the existing owner UID; owner/controller/job UIDs must be distinct. Names are 1–31 lowercase ASCII letters/digits/underscores starting with a letter, with reserved names refused. Each service account has a same-named dedicated primary group. The job must not share a primary group with the owner/controller, including their supplementary memberships; `staff`, admin/root aliases and existing identities are not substitutes.

The job account must belong to neither `staff` (GID 20) nor `admin`, including supplementary memberships. A dedicated primary group alone is insufficient; native identity checks refuse either membership. Verify the actual GUI session's effective UID and full group list during qualification, not only a helper that drops supplementary groups.

Only during sitting 1 may an administrator run the same reviewed command with `--apply`, as root on Darwin. Apply checks prerequisites and collisions before mutation and refuses existing paths including `/Library/macserve` and the proposed job home. Do not repeatedly apply after a partial failure: retain the plan/output, audit exactly which new objects were created, and arrange a reviewed recovery. Never delete an existing account or reuse an unrelated directory to make a check pass. Passwords are disabled on creation; establish the job password privately through owner-approved interactive UI/password administration, never argv, shell history or logs. The controller remains non-login, non-admin with a disabled password. No owner ACL changes are implicit.

### Installation layout

All ancestors of protected policy, executable and control-state paths must be root-controlled, non-symlink and non-writable by the job or controller except the controller's own private state. ACLs must not silently undo these protections.

| Path | Owner and mode / purpose |
| --- | --- |
| `/Library/macserve`, `bin`, `config` | root:wheel `0755` |
| `var` | root:wheel `0711` |
| `bin/macserve` | reviewed prebuilt Darwin binary, root-owned executable, normally `0755` |
| `config/controller.json`, `worker.json`, `maintenance.json`, `profiles.json` | root-owned `0644` policy (no embedded secrets); controller configuration and profiles readable by controller |
| `config/gui-baseline.json`, `qualification.json`, `boundary-evidence.json`, `pf-anchor.conf` | root-approved policy/evidence, no job/controller write; baseline/evidence may be root-private `0600`, PF policy readable `0644` |
| `var/controller` and its `secrets` | controller-owned `0700`; secret files `0600` |
| `var/controller/run/worker.sock` | controller-private executor socket; production peer identity is root, not job UID |
| `var/broker`, `var/exports` | root-owned `0700`, disjoint protected worker state and sealed exports |
| `var/workspaces` | root-owned `0711`; only individual job workspace ownership is transferred |
| `health` / `health/current.json` | root-owned `0755` directory / atomically published `0644` file |
| `/Users/<job_user>` | dedicated job-owned `0700` home; entire home, including `Library`, is accounted |

The script creates only empty directories and accounts, not binaries, configurations, secrets or plists. It also creates controller-owned `0700` `var/controller/run` and `var/controller/log`, and root-owned `0700` `var/broker/log`. Controller stdout/stderr go to `var/controller/log/controller.{out,err}.log`; worker/maintenance logs go to `var/broker/log/{worker,maintenance}.{out,err}.log`. Keep these logs private and accounted. The controller uses `/usr/bin/false` and is hidden; the job uses `/bin/zsh`. Account/directory creation is nontransactional: use an exclusive approved administration window.

Install a reviewed, checksummed **prebuilt** binary at the fixed path. Verify its digest against a separately trusted release/build record before installation, retain that record, and protect the binary and parents from replacement. Do not install Go or compile the service on the deployed host. Root must never execute a repository-provided helper or build tool. Pinned Xcodes are protected installations; the narrowly supported root:admin group-writable `/Applications` ancestor is acceptable only when the job cannot write through that group. Tool executables themselves remain root-owned and non-group-writable.

Install TLS certificate, TLS private key, receipt signing key and App private key as separate files. Public certificates may be root-owned readable policy; all three private keys belong only to the controller's `0700` secrets directory as `0600` files. Never give keys, bearer credentials, owner files or source-fetch credentials to a worker lease. Caller API tokens are high-entropy secrets stored by the caller; controller policy contains only their SHA-256 digests. Make any owner-home access restriction a separately reviewed, reversible ACL operation: record existing ACLs and explicit paths first, do not recursively rewrite the owner home.

Keep the owner's home at **0700**, or **0750 with an owner-private group that is not staff and excludes the job account**. Audit ACLs for access grants; mode bits alone do not override an ACL. Any permission/ACL change is a separately approved owner action, never an installer side effect.

### Disabled launchd templates

Render the reviewed Go text/templates `assets/launchd/org.macserve.{controller,worker,maintenance}.plist.tmpl` outside job-writable storage. The controller template accepts `.ControllerUser` and `.ControllerGroup`; worker and maintenance use root/wheel. There is no template-rendering CLI in `macserve`: use a trusted administrative renderer, inspect the output and resolve every template marker before installation. Stage root-owned non-writable plists for the three labels under `/Library/LaunchDaemons` only with approval.

No deployment Go toolchain is needed: a reviewed administrative literal substitution can replace only `{{.ControllerUser}}` and `{{.ControllerGroup}}` with the script-validated account and group names. Keep all fixed paths/labels/disabled settings intact, reject any remaining `{{`/`}}` markers, and inspect the resulting plist with the platform's syntax validator during the approved sitting. Syntax acceptance does not qualify launchd behavior.

All templates have `Disabled=true`, `RunAtLoad=false`, conservative restart throttling, fixed PATH, `GOMAXPROCS=2`, umask `077` and background/nice scheduling. Arguments are `/Library/macserve/bin/macserve <role> --config /Library/macserve/config/<role>.json`, where role is `controller`, `worker` or `maintenance`. Staging is not bootstrap, GUI login or authorization to start. Review launchd's existing per-label enabled overrides too; a disabled plist alone must not be mistaken for proof of a disabled loaded service. Do not bootstrap or enable any label until the gates below are met.

## 2. Supply matching protected configurations

Use the documented JSON field names below; unknown fields are rejected. Replace all deployment values, use clean absolute paths, and do not paste angle-bracket metavariables as usable JSON. The following is the field contract, not fabricated credentials or a host-qualified example.

**`worker.json`:** `socket` = `/Library/macserve/var/controller/run/worker.sock`; `controller_uid`, `job_uid`, `job_gid`, `owner_uid` = the approved numeric identities; `root` = `/Library/macserve/var/broker`; `export_root` = `/Library/macserve/var/exports`; `workspace_root` = `/Library/macserve/var/workspaces`; `helper_path` = `/Library/macserve/bin/macserve`; `baseline_path` = `/Library/macserve/config/gui-baseline.json`. Optional timing fields are `poll_seconds` (default 2, range 1–30), `heartbeat_seconds` (default 5, range 1–5), `request_timeout_seconds` (default 10, range 1–10). Protect the helper and state first; initialize the protected baseline with `worker-reset` in section 3 before starting the broker.

**`controller.json`:** `root` = `/Library/macserve/var/controller`; `socket` as above; `job_uid`, `owner_uid`; `profiles_file` = `/Library/macserve/config/profiles.json`; `health_file` = `/Library/macserve/health/current.json`; `policy_sha256` = SHA-256 of the approved PF policy file's exact bytes; `listen` = an assigned literal tailnet IP and an approved port; `tls_certificate`, `tls_key` = protected certificate/private-key paths. No wildcard, LAN, public or loopback listener. Optional `allowed_networks` may narrow the supported tailnet ranges, not broaden them. Optional `pause_file` names a protected owner-controlled dispatch pause marker.

There is no `controller_uid` field in `controller.json`: launchd selects that account, and the worker's `controller_uid` must identify the same dedicated controller. The worker's `job_uid` must match the controller's execution/network-policy UID, not the controller account or root broker; both configurations must agree on `owner_uid` and `socket`. Keep the fixed paths above for this installation: maintenance supports the fixed controller/broker/export/workspace roots and health path, and derives the entire job home as `/Users/<job_user>`. A generic alternate worker layout is not an approved maintenance topology.

`principals` is an array of objects with `id`, `token_sha256`, `repositories` (for example `example-org/example-app`), `scopes`, and optional `revoked`. Grant only needed `jobs:submit`, `jobs:read`, `jobs:cancel`; reserve `service:admin` for approved operators. `receipt` contains `key_id`, `private_key_file`, opaque `service_id`, opaque `host_id`, `repositories` mapping canonical lowercase repository names to pinned numeric IDs, and optional `verification_keys` mapping key IDs to standard-base64 Ed25519 public keys. Use an accepted Ed25519 PKCS#8 PEM, raw seed/private key or base64 seed/private key for the private signing key. Keep old verification keys deliberately during rotation; remove revoked keys deliberately. Optional `github` is described below.

**`profiles.json`:** strict wrapper `{"profiles": [...]}`; `{"profiles": []}` intentionally disables every profile for staging. Each enabled profile needs `id`, positive `version`, canonical `repo`, `kind` (`build`, `unit_test`, `simulator_ui_test`), exact `xcode` (`version`, `build`), protected absolute `developer_dir`, relative `work_dir`, and `run` (`executable`, `args`). Optional `prepare` is an array of the same command objects, `generated_files` contains `path`/`content`, `artifacts` contains `path`/`required`, and `required_tests` lists the expected tests. Simulator profiles pin `simulator.runtime`, `runtime_build` and `device_type`. Budgets are `default_timeout_seconds`, `max_timeout_seconds`, `memory_limit_mib`; qualify the effective normalized values. Recipes are controller policy, never caller-provided argv/environment. Use profile digests from the service's normalized registry/admitted capabilities, not a hash of hand-formatted JSON. Adding or changing a recipe requires fresh qualification, not merely a new config entry.

### Maintenance configuration and approved records

The exact `maintenance.json` shape for the fixed installation is:

```json
{
  "controller_config": "/Library/macserve/config/controller.json",
  "worker_config": "/Library/macserve/config/worker.json",
  "qualification_file": "/Library/macserve/config/qualification.json",
  "boundary_evidence_file": "/Library/macserve/config/boundary-evidence.json",
  "pf_policy_file": "/Library/macserve/config/pf-anchor.conf",
  "pf_anchor": "org.macserve",
  "interval_seconds": 10
}
```

The interval defaults to 10 seconds and must be 5–15 seconds. Identities, profile registry, health path and accounting roots come from the protected controller/worker configurations rather than duplicate maintenance identity fields.

`qualification.json` is a root-approved object with these exact fields:

| Field | Meaning |
| --- | --- |
| `schema` | integer `1` |
| `approved_at` | actual approval timestamp, RFC3339 |
| `job_uid` | approved numeric job effective UID |
| `boot` | current kernel boot identity, matching the protected worker baseline |
| `interfaces_sha256` | controller network-interface inventory digest |
| `policy_sha256` | SHA-256 of exact `pf-anchor.conf` bytes; also controller `policy_sha256` |
| `root_rules_sha256` | SHA-256 of recursive loaded root rules command stdout |
| `anchor_rules_sha256` | SHA-256 of loaded `org.macserve` rules command stdout |
| `baseline_sha256` | SHA-256 of exact protected `gui-baseline.json` bytes |
| `boundary_evidence_sha256` | SHA-256 of exact approved `boundary-evidence.json` bytes |
| `profiles` | object mapping each qualified profile ID to its normalized registry digest |

`boundary-evidence.json` contains `schema` (integer `1`), `recorded_at` (actual RFC3339 timestamp), `job_uid`, `boot`, and `probes` (array). Each probe object has `category`, `artifact_sha256`, `passed`, `attempts`, `pf_hit_delta`, `authorized_control_successes`, `canary_receipts`. Required categories are exactly `tcp_denial`, `udp_denial`, `approved_allow`, `delegated_boundary`, `unix_socket_boundary`, `owner_unaffected`, `owner_home_denial`, `fast_switch`, `reboot`, `tool_profiles`. Each must pass with at least one attempt and a valid SHA-256 reference to preserved real evidence. TCP requires at least three attempts, positive labeled PF hits and successful authorized controls; UDP requires positive PF hits, successful controls and zero canary receipts. Owner-home denial requires successful owner read controls and zero job canary reads. These are minimum machine-readable checks, not a replacement for **every** destination/transport/profile row of the matrix below. Associate each category with a complete private evidence bundle and its exact-byte digest; a category's `passed:true` alone proves nothing.

Supply exactly one probe per required category, no duplicate/unknown categories, and nonnegative integer counts. Digests are 64 lowercase hexadecimal characters. Evidence `recorded_at` must be no later than `approved_at`, and approval must not be in the future. The qualification's profile map must exactly match the observed configured profiles, not an approved subset of an otherwise unqualified registry.

The operator records these only after actual probes, audits the full artifacts, then approves and installs the records root-owned under protected ancestors. Never copy an example digest, guess a value, predate approval or treat the evidence record as a test generator. Missing reboot evidence intentionally prevents first production qualification until sitting 4. Retain prior records/artifacts in access-controlled archival storage instead of overwriting the only incident evidence.

After the approved baseline reset and policy integration, the future root-only read-only collection command is:

```sh
/Library/macserve/bin/macserve maintenance-observe \
  --config /Library/macserve/config/maintenance.json
```

This command collects protected live facts without requiring qualification/evidence files and without writing health. Its JSON fields are `job_uid`, `boot`, `interfaces_sha256`, `policy_sha256`, `root_rules_sha256`, `anchor_rules_sha256`, `baseline_sha256`, `profiles`, `pf_enabled`, `loopback_filtered`, `identity_valid`, `baseline_valid`, `accounted_bytes`, `memory_pressure`. This is **not** boundary evidence or automatic approval. Construct qualification using only the matching identity/digest/profile fields, `schema:1`, the actual `approved_at` timestamp and the separately computed exact-byte `boundary_evidence_sha256`; approve it only after all real probes. Do not copy observation booleans/accounting into qualification or install the observation JSON as qualification: their schemas differ. The command permits hash collection without installing Go on the host.

For hash reproducibility, `anchor_rules_sha256` still covers exact stdout from `/sbin/pfctl -a org.macserve -sr`. `root_rules_sha256` now covers JSON framing of `Filter` (exact `/sbin/pfctl -a '*' -sr` stdout) and `Translations` (sorted objects with `Path` and exact `Rules` stdout, including the root). Use `maintenance-observe` to collect this digest; old raw-filter-only approvals must be replaced after requalification. Translation observations include discovered topology, not just root anchor references. Do not hash verbose hit counters; preserve them separately in evidence. Boot identity is SHA-256 of raw `kern.boottime` bytes. Interface/profile digests use the controller inventory and normalized registry; policy/baseline/evidence digests cover exact file bytes.

The observer requires recognized enabled/loopback status, a nonempty `org.macserve` filter anchor and literal static filter rules; table/dynamic-interface references remain unsupported. Stock root `nat-anchor "com.apple/*" all` and `rdr-anchor "com.apple/*" all` calls are supported without removing owner anchors: `-v -s Anchors` enumerates topology, explicit reserved `_pf` probes cover otherwise hidden children, and `-a PATH -sn` inspects the root and every discovered anchor. Root translation rules may be empty or unconditional calls into discovered paths; every descendant translation ruleset must be empty. Actual mappings, nested translation calls, unknown/opaque references, unreadable children and unstable observations are refused. Two matching translation sweeps are surrounded by three matching topology observations; this is not an atomic kernel snapshot. Limits are 64 non-root anchors, depth 8, 4 MiB total observation stdout, 1 MiB stdout/8 KiB stderr per command, 2 seconds per command and the existing 8-second overall context. Exact missing-reserved-anchor diagnostics are distinguished from permission/read errors. Do not remove or disable owner policy to satisfy remaining limits. This support is grounded in installed `pfctl(8)` anchor enumeration and [BSD printer behavior](https://github.com/freebsd/freebsd-src/blob/stable/10/sbin/pfctl/pfctl.c); the permitted local `pfctl -s info` returned `/dev/pf: Permission denied`, so live privileged PF behavior is not claimed.

Maintenance is a root/Darwin-only read-only observer except for its own health publication. It checks live PF enabled state, recursive policy and anchor hashes, loopback filtering, network inventory, boot/baseline process identity, account separation, profile digests, memory pressure and bounded mutable-byte accounting. It never reloads PF, adopts processes, runs root Apple tools or signals a job. A failed/unsupported observation invalidates health rather than refreshing stale success. Controller health must be fresh within 45 seconds; missing/stale/mismatched health blocks admission and cancels active work. Keep disabled if the native output cannot be interpreted safely.

Published health has exactly `schema`, `job_uid`, `policy_sha256`, `interfaces_sha256`, `boundary_receipt_sha256`, `boundary_validated`, `checked_at`, `expires_at`, `accounted_bytes`, `memory_pressure`, `qualified_profiles`. Here `boundary_receipt_sha256` is the approved boundary-evidence file digest (not a job receipt); `qualified_profiles` maps profile IDs to normalized digests. Successful evaluation sets schema 1, current bindings and a 30-second lifetime. The controller requires unexpired health, check age at most 45 seconds, lifetime at most 45 seconds, no check timestamp more than 5 seconds ahead, matching job/policy/interfaces/profile digests, validated boundary evidence and available accounting. Memory pressure or exhausted reservation can still block admission despite a valid boundary. Boot, baseline and PF-rule digest checks happen in maintenance before health publication; these are not additional health fields. Failed observations publish invalid health with `boundary_validated:false`, `accounted_bytes:-1` and `memory_pressure:true`; they do not create the worker's durable admission marker. Do not manually refresh timestamps or manufacture a healthy record.

Accounting walks the fixed `/Library/macserve/var` tree and entire dedicated `/Users/<job_user>` home, including `Library` and diagnostics. It never follows symlink targets or nested mounts, counts hardlinks/overlaps once, and charges the larger of logical and allocated bytes plus supported node metadata. This is an approximate live budget census, not an isolation snapshot: ordinary writes, creation, deletion, rename and directory timestamp changes do not invalidate health. Concurrent changes may be reflected only in a later sample; budget/free-space thresholds remain enforced by the controller. Unsupported special nodes, real I/O/permission failures, more than 1,000,000 entries, depth over 128 or the observation deadline still fail closed; those support limits are unchanged. Memory-pressure observation accepts the native normal/warning/critical values only; unknown sysctl behavior fails closed.

After preserving and protecting the actual boundary record, a future owner may compute its exact-byte digest with `/usr/bin/shasum -a 256 /Library/macserve/config/boundary-evidence.json` and place the resulting lowercase digest in `boundary_evidence_sha256`. This computes a hash only; it does not authenticate the truth of probes or replace operator approval.

## 3. Initialize/reset the GUI baseline and qualify target tools

During sitting 2, establish an actual job-user GUI login and retain that session while fast-switching to the owner. `launchctl asuser` is not login. Approve only prompts actually required by the pinned tools and intended UI recipe. Do not grant blanket Accessibility, Automation, screen recording or Full Disk Access; record exact consent, target applications and account scope.

During the approved sitting, with admission disabled and the broker stopped, preserve any existing execution records/evidence and audit **every retained** job-UID GUI process: executable provenance, PID and start identity. Include only trusted required long-lived processes. The sole future root administrative initialization/reset command is:

```sh
/Library/macserve/bin/macserve worker-reset \
  --config /Library/macserve/config/worker.json --pids "$AUDITED_PIDS"
```

`AUDITED_PIDS` is an explicitly audited comma-separated list of current retained GUI PIDs, never a blind process-list substitution. Reset holds the exclusive broker lock, removes job-home LaunchAgents entries, the job crontab and legacy login items, and terminates extra exact same-UID processes outside the selected baseline. It rechecks selected process start identities, records `job_uid`, kernel `boot` and `processes` with `pid`/`start`, retries owned-resource cleanup, then clears `admission-quarantine.json` only after full clean verification. It never adopts unselected processes or signals owner/controller processes. This is a mutating administrative operation even on first initialization, not a read-only qualification command; retain evidence and approve the job-account cleanup scope beforehand.

Before every lease claim, recovery completes owned-resource cleanup and checks admission: no job-home LaunchAgents entries, nonempty crontab, legacy/modern background registrations or extra job-UID processes. Refusal means no registration/claim, a broker-private `admission-status.json` observation (`not_admitting`, reason and timestamp), logging and retry on the next normal poll. Reboot, baseline drift/missing baseline and unsupported inspection output therefore leave queued jobs untouched. Execute retains a second admission check for changes after a claim. Only **positive contamination** creates `admission-quarantine.json`; cancellation, deadlines, I/O/inspection errors and baseline uncertainty do not. A preexisting marker still requires the single clean reset; the status file is observational and never another quarantine authority.

Modern registration inspection requires a recognized explicitly empty job-UID section from `sfltool dumpbtm`; missing/unfamiliar output is a transient refusal, not proof of absence. Reset does not remove modern BTM registrations: residual registrations require owner-resolved, specifically scoped job-account remediation and rerunning the same reset. Never run host-wide `sfltool resetbtm` or change owner registrations. Failed or unknown reset verification retains an existing marker. Prepare narrowly approved GUI scripting permissions and audit any long-lived probe-created processes before reset; inspection never adopts them. Do not install a login helper to make unattended GUI operation appear reliable.

Run the actual approved build, unit and simulator UI recipes as the job user with exact Xcode build, runtime build and device type. Prove expected test identities/counts, failure detection, timeouts, cancellation, screenshots/artifact privacy, no signing, and cleanup. Simulator cleanup is limited to recorded service UDIDs or exact job-UID additions proven against protected pre-create inventory as described in section 7; never run global simulator cleanup. Prove UI operation while the owner is foreground after fast switching, with the approved lock/display state, and that owner interaction does not redirect test input or leak owner data. Audit any required probe-created long-lived process and rerun the same reset before committing the final baseline and its evidence bindings. These real target runs remain future owner-authorized deployment acceptance; repository fixtures do not satisfy them.

## 4. Integrate PF and execute the boundary matrix

Render `assets/pf/org.macserve.conf.tmpl` using `.JobUID` (numeric effective execution UID), `.ProtectedPorts` (reviewed numeric PF port-list contents), and `.HostAddresses` (reviewed literal current host IPv4/IPv6 aliases). Install reviewed exact bytes as `/Library/macserve/config/pf-anchor.conf`. Neither the template nor the installer loads it. The fixed anchor name is `org.macserve`.

During the approved network window, a qualified administrator inspects the **whole recursive loaded policy**, integrates this anchor before any earlier quick-pass bypass, and confirms PF is enabled and `lo0` is filtered. Preserve the prechange rules/topology and recovery plan. Do not replace `/etc/pf.conf`, flush global states, toggle unrelated anchors, or reload a whole host policy blindly. Deal with preexisting job-owned states using a separately approved precisely scoped procedure; if attribution is uncertain, remain disabled. Verify that unrelated owner sessions/services stay intact.

For PF substitution, use a canonical decimal job UID at least 501, a nonempty comma-separated list of decimal ports 1–65535, and a nonempty comma-separated list of literal host IPv4/IPv6 addresses. Do not accept DNS names, macros, ranges or untrusted template text as `HostAddresses`. Review the rendered expanded rules and their order; future platform syntax inspection and actual loaded-rule/probe qualification are both required. No validator was run against the owner's PF here.

The template matches job effective UID for TCP/UDP on all interfaces, including loopback. Protected-port denies apply to every destination; private/tailnet/link-local/current-host denies precede exceptions, and the tail denies remaining job TCP/UDP. There are no default egress allows. Add only reviewed exact endpoint/protocol/port exceptions in an appropriate reviewed policy: DNS, constrained proxy or simulator needs are not a reason for blanket loopback/public access. An exception placed after a matching nonoverridable deny cannot work; redesign the approved endpoint/policy explicitly rather than weakening a deny silently. Never give a job an arbitrary CONNECT proxy that can reach denied networks on its behalf.

Perform and retain this matrix from the **actual job GUI effective UID**, not a root shell claiming to impersonate it:

| Probe | Required evidence |
| --- | --- |
| TCP to every protected port at loopback IPv4 and IPv6, each current host LAN/tailnet IP, every host alias, and all resolved addresses of relevant DNS names | Three **fresh sockets** per destination/port, each with a 2-second deadline; record failures and matching labeled PF rule counter deltas |
| Private, tailnet, link-local and direct/proxy bypass paths | Denied routes plus attributable rule-hit deltas; enumerate IPv4 and IPv6, not just one representative route |
| UDP denial | Random nonsecret nonce sent only to an approved canary receiver, denied-rule hit deltas and zero nonce receipts, with authorized nonjob controls proving that same receiver/path was reachable |
| Allowed endpoints | Each narrow approved DNS/proxy/simulator path actually works, while protected/private destinations through the proxy and direct paths still fail |
| Alternate networking | Ordinary sockets, raw sockets when available, URLSession/background transfers, delegated helpers and proxy paths; inability to attribute/control a required helper path is a failed boundary |
| Local delegation | Job cannot connect to controller executor Unix socket or read private controller/broker/export/secret paths; check other relevant Unix sockets and delegated services without invoking secret-bearing APIs |
| Owner controls | Authorized nonjob fresh connections succeed against live approved controls; owner services and interaction remain unchanged |
| Owner-home denial | From the actual job GUI identity with its full groups, owner-home listing/traversal and reading the approved nonsecret canary must be denied; owner reads the same canary successfully before/after |
| Lifecycle | Repeat after fast user switching and after the planned reboot/GUI login, recording boot/interface/baseline/policy changes |

Connection refusal, timeout to an offline service, DNS failure, or a successful unrelated nonjob request alone is **not denial proof**. Use live authorized controls, exact destinations, timestamps, effective UID, command/tool provenance, labeled before/after counters and correlated canary logs. Never send a probe nonce to production UDP services. If raw sockets are unavailable, record the restriction and why it is safe; never mark an untested required transport as tested. Delegated system services may use a different effective UID and bypass UID rules: prove their boundary or keep the deployment disabled. PF cannot substitute for Unix permissions or UI qualification.

Store detailed evidence privately, sanitized where exported. The root-approved evidence and qualification files authenticate an operator's real observations; arbitrary JSON does not perform tests. Their exact schema is specified in section 2.

For `owner_home_denial`, the owner creates a fresh nonsecret canary at an explicitly approved path inside their home, with file mode `0644` so denial tests the home boundary rather than a private file's mode. The owner verifies that exact path is readable before and after the probe. From the actual job GUI session, record `id -u` and `id -G`; attempt directory listing and reading only that canary, discarding stdout. Both must fail with permission denial, not a missing path, missing mount or unrelated command error. Do not enumerate/read private owner files. Record attempts, successful owner controls in `authorized_control_successes`, and successful job reads in `canary_receipts` (must be zero); `passed` also requires denied directory access. Preserve the evidence and let the owner remove only that canary. Repeat after relevant identity/permission changes and reboot; existing evidence without this category cannot qualify.

## 5. Enroll the App and require verified evidence

During sitting 3, install the GitHub App on **selected approved repositories only**. Minimal App permissions are metadata/contents/pull-request read and checks write. Controller `github` fields are `app_id`, `installation_id`, RSA PEM `private_key_file`, `policies`, and `poll_seconds` (30–60, default 45). Tokens are in-memory, single-numeric-repository scoped. Each policy has `repository_id`, `repository`, `author_ids`, `base_branches`, `profiles`, `policy_revision`, and optional `actions_bot_id`, `actions_app_id`. Pin numeric IDs out of band; names, commit authors and branch display text are not authorization. Trust every writer who can push to an enrolled branch. Forks and unapproved bases/authors/profiles must not execute.

Require `mac-evidence/<profile>` **from the configured App** on the exact PR head, not a synthetic merge commit. This is not merge-queue `merge_group` support. Tailnet membership is not API authorization; independently restrict peers and bearer scopes. App/TLS/receipt secrets and Mac API tokens never belong in Actions or source checkouts.

Automatic polling enrolls current eligible heads without a workflow/comment. Optional machine requests use exactly:

```text
/mac-evidence sha=<40-lowercase-hex> profile=<approved-id> request=actions:<run-id>:<attempt> mode=ensure
```

Only the numeric pinned Actions bot is accepted; an available App identity must match the pinned Actions App. Edited comments are rejected. `ensure` joins the existing logical run; `rerun` is explicit and bounded to two per head/profile/hour after termination; active attempts are joined. Initial intake starts 24 hours before startup with two minutes overlap, one page of at most 100 comments per poll. Page/watermark persist; existing cursors are not reset after downtime. Requests older than the initial window are not replayed; offset pagination under historical mutation is not a guaranteed event log. Do not depend on an ancient comment to request new work.

Every public receipt is a compact signed core with authenticated full-manifest digest, size and URL; recipes and full command manifests stay private. Compact bytes do not change between storage, API and GitHub. `complete` is not success: require successful state, exact head/profile/App/policy, expected test identities and valid pinned signatures. Legacy full receipts need a rerun before public publication; this does not erase old public output.

If using the Linux waiter, install a separately reviewed checksummed binary and trusted pins without checking out PR code. Grant only `GITHUB_TOKEN` `contents: read`, `checks: read`, `pull-requests: write`. Never execute PR code with `pull_request_target`. Pins include `repository_id`, `app_id`, `profile_digest`, `required_tests`, `verification_keys`, and `request` with `repo`, `profile`, `kind`, exact `xcode` and applicable `simulator` pins. Protect pins independently of the PR branch; keys fetched beside a receipt are not trust anchors. Use the event's `pull_request.head.sha`:

```sh
macserve wait --pins /absolute/trusted-pins.json \
  --pr "$PR_NUMBER" --sha "$PR_HEAD_SHA" \
  --request "actions:$GITHUB_RUN_ID:$GITHUB_RUN_ATTEMPT" --timeout 90m
```

Qualify real App permissions, numeric bot matching, branch gates and exact-head success/failure/cancellation behavior. An offline Mac, missing check, invalid signature, superseded head or incomplete evidence must remain nonpassing, not become skipped success.

## 6. Enable only after the gates; operate within budgets

Before any approved start: verify protected binary/config/secrets and identity separation; real GUI baseline; accepted native persistence limits; full current PF/network/tool/UI evidence; matching qualification bindings; actual root maintenance observation with fresh health; and explicit manual pause/disabled profiles preventing enrollment during commissioning. An operator may start the read-only maintenance observer under root using `macserve maintenance --config /Library/macserve/config/maintenance.json` to obtain real health; never manufacture `health/current.json`. Only after valid observation and approved enrollment may the operator deliberately enable/bootstrap the three specific labels in their approved launchd procedure. Staged files do not grant this approval. Controller runs as the dedicated user; broker/maintenance as root. No root Apple tools, background PF reload or automatic baseline adoption are allowed.

Allocate the 80 GiB mutable pool as **30 GiB workspaces + 15 GiB caches + 15 GiB logs/artifacts + 15 GiB simulators + 5 GiB metadata**. Include full job home/`Library`, diagnostics, controller/broker/exports/workspaces and service-owned logs. Avoid counting nested roots twice. Extra Xcodes/runtimes are separately approved installation storage, but still consume filesystem free space. These are monitored budgets, not hard filesystem quotas; sampled usage may overshoot. Admission reserves 30 GiB while preserving a 120 GiB free floor; below 100 GiB active work is cancelled. Monitor whole-UID memory pressure/RSS and leave owner headroom.

The retained evidence split reserves 1 GiB for store log rows and 14 GiB for artifacts. Raw logs/artifacts expire after seven days or oldest-terminal pressure eviction; metadata and full manifests persist 90 days. Expired reads return `410`, not fabricated empty success. Do not move mutable data outside accounted roots to avoid the budget.

For benchmarks or owner work, authenticated API `PUT /v1/admin/pause` accepts `{"reason":"owner maintenance","mode":"drain"}` or mode `cancel_active`. Poll `GET /v1/admin/state` until **`quiescent=true`**. An accepted pause only blocks new work; it is not proof of stopped tools, finalization or cleanup. Drain permits current work to finish; cancel_active requests cancellation and its cleanup barrier. Do not benchmark or manually clean while ownership is uncertain. Automatic retention/GC does not run through manual/owner pause or unqualified security readiness. `DELETE /v1/admin/pause` clears manual pause only, not an owner marker, quarantine or a failed health gate.

## 7. Reboot, recovery and evidence-preserving cleanup

Plan sitting 4 with a physical-console FileVault unlocker. Do not grant the job unlock rights or enable autologin. After cold boot, owner unlock and actual job GUI login are prerequisites; old boot-bound baseline/qualification records cannot authorize admission. Keep admission disabled/paused. Follow the same reset procedure below with explicitly audited current GUI PIDs, repeat the full network/UI/control matrix, then approve new evidence and qualification only from new real observations.

For a crash, reboot, GUI drift, missing baseline PID or cleanup uncertainty:

1. Block new admission and request pause/cancellation where possible. When the controller is reachable, poll for quiescence; an accepted pause is not enough. Stop only the dedicated broker under the approved service procedure before reset. A stopped/crashed broker is not proof its old job processes are gone; preserve unresolved ownership for reset rather than pretending it is quiescent.
2. Preserve protected broker records, queue database with its transactional companions, pending completions, sealed exports, manifests and probe evidence. Inventory unresolved work, recorded simulator UDIDs and protected pre-create inventories; do not delete records to bypass quarantine.
3. Investigate persistence, current job-UID processes and provenance, retaining evidence of the cause. Approve reset's job-only LaunchAgents/crontab/legacy-login-item removal and termination of nonretained exact same-UID processes. Resolve residual modern BTM registrations only through owner-approved scoped job-account remediation; no host-wide `sfltool resetbtm`, owner registration changes, indiscriminate PID signaling or shared-cache/service cleanup.
4. Explicitly audit every retained trusted current GUI PID/start identity and run the same future root command used for initialization:

   ```sh
   /Library/macserve/bin/macserve worker-reset \
     --config /Library/macserve/config/worker.json --pids "$AUDITED_PIDS"
   ```

   Reset holds the broker lock, removes supported job persistence and extra processes, updates the audited baseline, retries owned-resource cleanup and performs full clean verification before clearing the admission marker. It preserves pending completions and sealed evidence; failure retains unresolved records and any existing marker. For an interrupted simulator create, it compares stable job-UID inventory with the protected pre-create inventory and deletes only exact added UDIDs, preserving baseline devices. Recorded service UDIDs remain eligible for cleanup. It never guesses legacy ownership: an old record without inventory can recover only when inspection proves the inventory empty. Unrelated workspaces and owner devices are not cleanup targets. If modern BTM residuals or uncertain inspection remain, keep disabled, resolve the scoped cause and rerun this same reset.
5. A reset is not boundary approval: refresh qualification bindings for changed boot/baseline/interfaces/PF policy/topology/profiles and repeat affected real evidence gates. Restart only the dedicated services after valid fresh health and explicit approval. Startup replays pending completions before recovery; no registration or lease occurs before recovery succeeds. Transient unclean completion fences the old controller epoch; verified recovery registers a fresh epoch without another administrator clear command. Verify state and evidence delivery before clearing manual pause.

Manual disk relief is an administrative incident procedure, not `rm -rf` on the install root. First establish quiescence and preserve an access-controlled evidence inventory/backup. Identify ownership, exact recorded paths, retention eligibility, outstanding publication/completion references and current budget before removing only approved expired data. Never delete active records, pending receipts, source-cleanup debt or quarantine to force admission. If safe evidence-preserving cleanup cannot be established, keep disabled and add capacity or investigate; do not mutate unrelated owner infrastructure.

Changes to OS/PF behavior, binaries, pinned Xcodes/runtimes, recipes, network inventory, keys/policy or GUI permissions require a reviewed rollout and relevant requalification. Unsupported native behavior is a deployment limit, not a reason to relax the guard.

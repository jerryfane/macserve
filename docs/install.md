# Installation, qualification and recovery

This is a **future, owner-approved deployment runbook**, not a report that this Mac has been installed or qualified. Repository checks and fixture results do not prove native GUI, PF, FileVault, App authorization or target-recipe behavior. Every administrative action below requires an approved owner sitting. No service should be enabled just to see whether a real build works.

## Network isolation: not provided in phase 1

The owner's accepted model is **trusted repositories only**, including their writers, build scripts and dependencies. Native execution under a separate non-admin UID is not a network sandbox. Jobs may reach protected service ports, loopback, LAN, tailnet and internet destinations subject to unrelated host/network policy. macserve installs no PF template, manages no anchor, writes no PF rules, and requires no PF enforcement for health or qualification.

Network probes report actual reachability as **`not enforced in phase 1`** for the owner's information. A reachable protected endpoint is not a qualification failure; a timeout or refused connection is not proof of isolation. Unix permissions, controller/broker separation, owner-home protection, trusted toolchains, GUI/lifecycle evidence and resource limits remain required. PF enforcement is a possible separately reviewed future opt-in, not a phase-1 capability.

## Quick path

These are future commands for **four separately approved owner sittings**, not permission to run them now. Installation stages disabled services; qualification observes host state and collects evidence without writing PF. No command changes owner ACLs, logs in the job user, or turns an untested non-network boundary into a pass. Use a prebuilt release: no Go toolchain or JSON editing is needed for initial disabled staging.

### Sitting 1: review, plan, install disabled assets

Set `RELEASE_TAG` to an existing, reviewed `v*` release. Download its source and assets on an authorized administrative machine; the example uses GitHub CLI, but downloading the same files through GitHub's release page is equivalent:

```sh
: "${RELEASE_TAG:?Set the reviewed existing release tag}"
git clone --depth 1 --branch "$RELEASE_TAG" https://github.com/jerryfane/macserve.git macserve-deploy-kit
cd macserve-deploy-kit
gh release download "$RELEASE_TAG" --repo jerryfane/macserve \
  --pattern macserve-darwin-arm64 --pattern SHA256SUMS
cat SHA256SUMS
```

The tag workflow builds Darwin arm64 with CGO disabled and `-trimpath`, then publishes `macserve-darwin-arm64` and `SHA256SUMS` using only `GITHUB_TOKEN`. Review the tag/source/publisher and expected binary digest. A checksum downloaded beside a binary detects corruption, not an independently compromised release. Set `EXPECTED_SHA256` to the reviewed 64-character lowercase digest; do not substitute an unreviewed local hash.

Create and review `deploy.env`. **Every value below is illustrative**, not a claim that an identity, address, port, Xcode or repository ID is suitable or available. Include current non-link-local host aliases in `HOST_ADDRESSES`, choose the protected ports to include in informational reachability reports, and pin real repository IDs out of band:

```sh
cat > deploy.env <<'ENV'
CONTROLLER_USER=macservectl
CONTROLLER_UID=6201
CONTROLLER_GID=6201
JOB_USER=macservejob
JOB_UID=6202
JOB_GID=6202
OWNER_USER=owner
OWNER_UID=501
TAILNET_IP=100.64.0.10
PORT=8443
PROTECTED_PORTS=8443,19999
HOST_ADDRESSES=100.64.0.10,192.0.2.10
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
REPOSITORIES=example-org/example-app:12345
ENV
: "${EXPECTED_SHA256:?Set the reviewed release binary digest}"
/bin/bash assets/install.sh --env deploy.env \
  --binary macserve-darwin-arm64 --sha256 "$EXPECTED_SHA256"
```

`deploy.env` is bounded **data**, never shell-sourced: plain `KEY=VALUE`, blank/comment lines, comma-separated lists, and `owner/repo:numeric-id` repository pins. No shell expansions, commands, unknown keys or duplicate keys. Default plan verifies the binary digest and validates/renders the deployment without creating accounts or installation files. It does not prove native identity availability or any security boundary.

`HOST_ADDRESSES` also accepts canonical IPv6 link-local addresses with or without a `%scope` and canonical IPv4 link-local addresses. A scope is supported only for IPv6 link-local hosts: 1–63 ASCII letters, digits, underscores, dots or hyphens. Link-local entries are validated but omitted from the per-host inventory and TCP target expansion. This omission establishes no deny rule or isolation guarantee. Scoped non-link-local addresses, malformed addresses and exact duplicates remain refused. Tailnet/listener validation is unchanged; the raw reviewed environment is preserved and hashed exactly.

Optional read-only coexistence keys are `COEXISTING_ANCHORS` and `COEXISTING_SERVICES`, comma-separated exact anchor paths and system-domain launchd labels. Omission or an empty value means an empty list. Lists are unique, bounded and sorted internally; installation carries them into `maintenance.json`. For example:

```text
COEXISTING_ANCHORS=com.apple/guest-router
COEXISTING_SERVICES=com.example.guest-router
```

These entries do not grant ownership or approve translations. During installation and each qualification window, configured services must remain running with identical PIDs and available before/after PF measurements must match. Unreadable PF is recorded as `unavailable`, not a failure. macserve neither repairs nor interprets another manager's rules.

After reviewing the source, plan and actual host approvals, stage the reviewed inputs under root-controlled storage. The destination must be new; do not reuse a stale staging directory. These administrative commands are for the approved Darwin sitting only:

```sh
sudo /bin/mkdir -m 0700 /private/var/root/macserve-deploy-kit
sudo /bin/cp -R assets deploy.env macserve-darwin-arm64 /private/var/root/macserve-deploy-kit/
sudo /usr/sbin/chown -R root:wheel /private/var/root/macserve-deploy-kit
sudo /bin/chmod -R go-w /private/var/root/macserve-deploy-kit
sudo /bin/bash /private/var/root/macserve-deploy-kit/assets/install.sh \
  --env /private/var/root/macserve-deploy-kit/deploy.env \
  --binary /private/var/root/macserve-deploy-kit/macserve-darwin-arm64 \
  --sha256 "$EXPECTED_SHA256" --apply
```

Apply refuses existing installation/accounts/targets. It uses the existing account helper, verifies the staged executable, literal-renders and lints all three disabled plists, and writes matching controller/worker/maintenance configs plus `{"profiles":[]}`. It generates separate TLS and receipt keys; private keys are controller-owned `0600`. **The API token is printed once, only after success.** Move it directly into the authorized caller's secret storage: no `tee`, session transcript, shell-history assignment or shared log. Only its digest is installed. Preserve public trust pins from `/Library/macserve/config/deployment-pins.json`; never treat a receipt's own advertised key as an independent trust anchor.

`deployment-pins.json` includes `receipt_key_id`, standard-base64 `receipt_public_key`, opaque service/host IDs and `tls_certificate_sha256` over the certificate's **DER** encoding, not its PEM file text.

No daemon, PF rule, owner-home permission or GUI session was activated. An interrupted apply is not rerunnable recovery: retain evidence and inspect partial state instead of deleting objects and retrying. Before deployment mutation, apply durably saves `before.json` under a new root-private `/private/var/root/.macserve-install-evidence-*` directory; final `coexistence.json` records before/after observations and any installation error where possible. Owner-home restrictions remain a separately approved prerequisite; there is no service PF policy to stage or load.


### Sitting 2: actual job GUI, tools and boundary evidence

First establish the approved job GUI login/password and narrowly scoped prompts. With the broker stopped, audit retained GUI PID/start identities and run the existing reset once; `AUDITED_PIDS` is a reviewed list, never a process-list substitution. From the administrator's session:

```sh
sudo /Library/macserve/bin/macserve worker-reset \
  --config /Library/macserve/config/worker.json --pids "$AUDITED_PIDS"
/Library/macserve/bin/qualify.sh plan --env /Library/macserve/config/deploy.env
```

Create one fresh **nonsecret** owner-home canary from the actual owner session. This command refuses to overwrite an existing file and creates mode `0644`, so the job must be denied by the home boundary, not just a private canary-file mode:

```sh
(set -C; umask 022; printf '%s\n' 'macserve owner boundary canary' > "$HOME/macserve-boundary-canary.txt")
```

Use a new session directory for each complete probe round. Review the informational TCP matrix and any optional authorized endpoint/canary targets. `ALLOW_ENDPOINTS`, `UDP_ENDPOINTS` and `TCP_CANARY_ENDPOINTS` are optional comma-separated literal `IP:port` values (IPv6 `[address]:port`); omit their flags when unused. `OWNER_CANARY` identifies the required nonsecret owner-home control. Never send a UDP nonce to a production UDP service or replace an existing listener. Network success, failure, missing listeners and unsupported transports are reported, not isolation gates.

```sh
SESSION=/Library/macserve/var/qualification/before-switch
sudo /Library/macserve/bin/qualify.sh begin --session "$SESSION" \
  --env /Library/macserve/config/deploy.env --owner-canary "$OWNER_CANARY"
```

Each new sitting takes a read-only coexistence baseline. Before beginning, configure the exact peer anchors and system service labels whose continuity should be observed. Collection and approval compare available main/peer rule measurements and require unchanged running service PIDs. There is no policy load, ownership adoption, enable/disable or PF repair operation.

The root-owned challenge is readable by both accounts; private evidence remains root-only. Add `--private-path /absolute/path,...` at `begin` for other explicitly approved local boundaries. **The following is the probe round to repeat for every new session:**

1. In the actual owner GUI, start the required **file-only** owner-home control before either probe. It reads only the approved nonsecret canary before and after the window and opens no network listener. Keep it running across both account probes; `Ctrl-C` after both finalizes its receipt:

   ```sh
   /Library/macserve/bin/qualify.sh canary --session "$SESSION" \
     --transport owner-home --out "$HOME/owner-home-receipts.json" --duration 30m
   ```

   Optional TCP/UDP canaries use `--transport tcp|udp --listen IP:port --out FILE`; start only explicitly approved listeners. A comma-list receiver writes `OUTPUT.1.json`, `OUTPUT.2.json`, etc.; one listener writes `OUTPUT`. Use fresh outputs for each sitting. Their network outcomes remain informational.

   Both actual owner file reads must succeed and bracket both account reports; missing file controls still block owner-home qualification. No network receiver is required for that proof.

2. At the **actual job GUI console**, run the job probe. Set `SESSION` in that terminal to the same protected path; do not use root, `sudo -u`, `su`, or a helper that drops supplementary groups:

   ```sh
   /Library/macserve/bin/qualify.sh probe --session "$SESSION" \
     --role job --out "$HOME/job-probe.json"
   ```

   A probe with real or effective UID 0 refuses before reading the session or touching `--out`; it creates no root-owned refusal report. Non-root identity refusals may still produce a report.

3. At the actual owner GUI console, run controls, then stop the receivers gracefully in their original terminals:

   ```sh
   /Library/macserve/bin/qualify.sh probe --session "$SESSION" \
     --role owner --out "$HOME/owner-probe.json"
   ```

4. As administrator, collect the exact job/owner reports and the required file-only owner-home receipt. `RECEIPTS` is that real file, optionally followed by comma-separated UDP receipt files; it is not sample JSON. Optional network receipts cannot substitute for the independent owner-home controls:

   ```sh
   sudo /Library/macserve/bin/qualify.sh collect --session "$SESSION" \
     --job "$JOB_REPORT" --owner "$OWNER_REPORT" --receipts "$RECEIPTS"
   sudo /bin/cat "$SESSION/candidate.json"
   ```

Collection preserves bounded snapshots, hashes and current boot/baseline/profile bindings; inspect every artifact and status. Candidate `boundary-evidence.json` and `qualification.json` are **not approvals**. Network results are retained under `network_reachability` with status `not enforced in phase 1`; they do not gate approval. Unexpected owner-home access, failed Unix boundaries, missing file controls or unsupported non-network security observations still cannot be overridden by an attestation. Unix permission denial is not a claim that a disabled worker's credential-bearing API was exercised.

An incomplete collection can be retried in the same unexpired session after resolving its input error. Collection snapshots use immutable `collect-<random-id>-*` names, including receipt bytes that fail validation; evidence already saved by failed attempts remains available for inspection. Only the successful attempt's input hashes enter the candidate. Partial summary files are not a commit: `candidate.json` is published last. Once it exists, recollection refuses; begin a new session for another probe round, even if the completed candidate contains failed categories.

The persistent `.lock` file uses a nonblocking advisory lock, released by the kernel when the process exits. Do not delete it during collection. An old-version `.lock` directory or an unsafe lock object is refused, not automatically removed; preserve that session for reviewed recovery. Retries do not extend challenge expiry or relax live-binding checks.

Each boundary `artifact_sha256` identifies a preserved `category-<name>.json` manifest of the exact underlying artifact hashes. Session storage is under the accounted `var` tree; do not move generated mutable evidence outside the service budget to avoid accounting.

Read/list probes use nonblocking, no-follow opens. Missing paths and unsupported object types are not permission-denial proof, and a FIFO cannot stall the probe waiting for a peer.

`fast_switch` and `reboot` start **pending**. Finish the pre-switch round, then perform the actual foreground/lock/UI sitting. Begin a new `after-switch` session with the same reviewed endpoint arguments and `--previous /Library/macserve/var/qualification/before-switch`; repeat the entire probe round with fresh filenames. Preserve the real foreground/UI observations, including background job behavior while the owner is foreground, then explicitly attest that artifact:

```sh
sudo /Library/macserve/bin/qualify.sh attest \
  --session /Library/macserve/var/qualification/after-switch \
  --category fast_switch --artifact "$SWITCH_ARTIFACT" \
  --reason "$REVIEWED_SWITCH_CONCLUSIONS"
```

The same-boot predecessor must already be collected and remain unchanged. Attestation accepts real owner/root artifacts and records provenance; it is not a test generator. Required UI semantics still need genuine reviewed evidence. Delegated networking is informational, not a network-isolation attestation gate.

### Sitting 3: repository/App enrollment and real recipe evidence

Review the installed numeric repository/public-key pins, actual GitHub App enrollment and trust rules in section 5. The installer does **not** invent App credentials, policies, recipes or test outcomes. An empty registry admits no recipes; tool inspection then records the exact observed Xcode version/build and zero qualified recipes. Adding an actual approved profile changes the exact qualification binding and requires that profile's real recipe/UI evidence. Selected-repository App credential/config provisioning remains an explicit separate enrollment operation, not an installer side effect.

Run approved recipes only as the job user and retain their actual artifacts. Tool inspection may create long-lived job processes: audit them and use the existing reset explicitly, never auto-adopt them. Collect a fresh round after configuration/profile/baseline changes. For the current collected session, record genuine recipe/UI evidence with:

```sh
sudo /Library/macserve/bin/qualify.sh attest --session "$SESSION" \
  --category tool_profiles --artifact "$RECIPE_ARTIFACT" \
  --reason "$REVIEWED_RECIPE_CONCLUSIONS"
```

This command is needed when enabled profiles require semantic recipe/UI evidence; it cannot repair failed automated tool inspection. Keep profiles empty until real recipes and their trusted writers are approved. `reboot` is still pending before sitting 4, so no production approval is available yet.

### Sitting 4: planned cold reboot, repeat, explicit approval

Arrange physical-console FileVault unlock, an actual fresh job GUI login, approved prompts and a newly audited PID list. Keep admission disabled and use the **same** `worker-reset` command above. Begin a fresh `after-reboot` session with the reviewed endpoint arguments and `--previous` pointing to the preserved preboot collected session. Repeat the full probe round; prior boot-bound reports cannot substitute for it.

```sh
sudo /Library/macserve/bin/qualify.sh attest \
  --session /Library/macserve/var/qualification/after-reboot \
  --category reboot --artifact "$REBOOT_ARTIFACT" \
  --reason "$REVIEWED_REBOOT_CONCLUSIONS"
```

To prove fast switching on this boot too, finish that session, perform the real switch sitting, then begin `final-switch` with `--previous /Library/macserve/var/qualification/after-reboot`. Repeat the full round and record current real delegated/tool/switch/reboot artifacts using `attest`. The protected predecessor chain supplies the observed reboot transition and same-boot before/after comparison; artifacts and current observations must still match. A challenge and its probes expire after two hours; predecessors are bounded to seven days. Start a fresh round rather than changing timestamps or carrying forward stale success.

Inspect the final candidate and preserved evidence, then **one explicit owner-approved root command** installs the approval records:

```sh
sudo /bin/cat /Library/macserve/var/qualification/final-switch/candidate.json
sudo /Library/macserve/bin/qualify.sh approve \
  --session /Library/macserve/var/qualification/final-switch
```

Approval refuses pending/failed non-network categories, changed artifacts or current host/profile binding drift and checks the maintenance evaluator. It remeasures read-only coexistence, requiring unchanged running service PIDs and unchanged rule digests wherever both measurements are available, then saves exact final bytes as `approved-boundary-evidence.json`. PF unavailability alone never blocks approval. The candidate/predecessor chain remains unchanged. Approval does not manufacture health, clear `owner.pause`, adopt GUI processes or activate services. Only after remaining enrollment/health gates and separate explicit service-start approval may section 6 be followed. Preserve every session for review and recovery.

## Trust boundary and stop conditions

Use only trusted repositories and trusted repository writers. A root broker handles protected leases, exports and cleanup, then executes tools as a separate non-admin GUI user; the credential-bearing controller is a different non-login user. A broker defect is a root risk. This is shared-kernel native execution, not a VM, disposable reset or hostile-code sandbox. Same-UID delayed persistence can run after a clean census and affect a later job. The owner must accept that residual risk explicitly; signatures attest observations, not host integrity or honest tests.

Keep all three LaunchDaemons disabled if persistence inspection, required account/Unix boundaries, real GUI operation, tool evidence or accounting is unsupported. Do not replace failed non-network probes with success booleans, adopt all current processes automatically, or run a first production build as a fallback. Phase 1 is unsigned build/test only: no signing identities, provisioning profiles, App Store Connect or TestFlight credentials, and no Apple ID required for the job account. Network isolation is explicitly not provided.

Four separate future owner sittings are required; no duration or unattended completion is promised:

1. **Administrative setup:** approve identities, protected installation and separately scoped owner-home ACL changes if needed. Stage disabled assets; preserve before/after read-only coexistence measurements without modifying existing services or PF.
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

Both newly created service accounts are checked for supplementary `wheel`/root (GID 0), `staff` (GID 20), `admin` (GID 80), and the other service account's primary GID before provisioning directories. A dedicated primary group alone is insufficient. Unexpected membership leaves a partial account creation requiring reviewed recovery, not automatic deletion. Verify the actual GUI session's effective UID and full group list during qualification, not only a helper that drops supplementary groups.

Only during sitting 1 may an administrator run the same reviewed command with `--apply`, as root on Darwin. Apply checks prerequisites and collisions before mutation and refuses existing paths including `/Library/macserve` and the proposed job home. Do not repeatedly apply after a partial failure: retain the plan/output, audit exactly which new objects were created, and arrange a reviewed recovery. Never delete an existing account or reuse an unrelated directory to make a check pass. Passwords are disabled on creation; establish the job password privately through owner-approved interactive UI/password administration, never argv, shell history or logs. The controller remains non-login, non-admin with a disabled password. No owner ACL changes are implicit.

### Installation layout

All ancestors of protected policy, executable and control-state paths must be root-controlled, non-symlink and non-writable by the job or controller except the controller's own private state. ACLs must not silently undo these protections.

| Path | Owner and mode / purpose |
| --- | --- |
| `/Library/macserve`, `bin`, `config` | root:wheel `0755` |
| `var` | root:wheel `0711` |
| `bin/macserve` | reviewed prebuilt Darwin binary, root-owned executable, normally `0755` |
| `config/controller.json`, `worker.json`, `maintenance.json`, `profiles.json` | root-owned `0644` policy (no embedded secrets); controller configuration and profiles readable by controller |
| `config/qualification.json`, `boundary-evidence.json` | root-approved schema-3 evidence, mode `0600`; no job/controller write |
| `var/broker/gui-baseline.json` | root-private audited GUI baseline, written by the existing reset command |
| `var/qualification/<session>` | root-owned session `0755`; public challenge `0644`, preserved evidence/approval artifacts `0600` |
| `var/controller` and its `secrets` | controller-owned `0700`; secret files `0600` |
| `var/controller/run/worker.sock` | controller-private executor socket; production peer identity is root, not job UID |
| `var/broker`, `var/exports` | root-owned `0700`, disjoint protected worker state and sealed exports |
| `var/workspaces` | root-owned `0711`; only individual job workspace ownership is transferred |
| `health` / `health/current.json` | root-owned `0755` directory / atomically published `0644` file |
| `/Users/<job_user>` | dedicated job-owned `0700` home; entire home, including `Library`, is accounted |

`assets/create-users.sh` remains the narrow account/empty-directory helper; `assets/install.sh` verifies the prebuilt binary and adds rendered assets, matching configurations and generated keys without activation. The account helper creates controller-owned `0700` `var/controller/run` and `var/controller/log`, and root-owned `0700` `var/broker/log`. Controller stdout/stderr go to `var/controller/log/controller.{out,err}.log`; worker/maintenance logs go to `var/broker/log/{worker,maintenance}.{out,err}.log`. Keep these logs private and accounted. The controller uses `/usr/bin/false` and is hidden; the job uses `/bin/zsh`. Account/directory creation is nontransactional: use an exclusive approved administration window.

Install a reviewed, checksummed **prebuilt** binary at the fixed path. Verify its digest against a separately trusted release/build record before installation, retain that record, and protect the binary and parents from replacement. Do not install Go or compile the service on the deployed host. Root must never execute target-repository helpers or build tools. Pinned Xcodes are protected installations; the narrowly supported root:admin group-writable `/Applications` ancestor is acceptable only when the job cannot write through that group. Tool executables themselves remain root-owned and non-group-writable.

Install TLS certificate, TLS private key, receipt signing key and App private key as separate files. Public certificates may be root-owned readable policy; all three private keys belong only to the controller's `0700` secrets directory as `0600` files. Never give keys, bearer credentials, owner files or source-fetch credentials to a worker lease. Caller API tokens are high-entropy secrets stored by the caller; controller policy contains only their SHA-256 digests. Make any owner-home access restriction a separately reviewed, reversible ACL operation: record existing ACLs and explicit paths first, do not recursively rewrite the owner home.

Keep the owner's home at **0700**, or **0750 with an owner-private group that is not staff and excludes the job account**. Audit ACLs for access grants; mode bits alone do not override an ACL. Any permission/ACL change is a separately approved owner action, never an installer side effect.

### Disabled launchd templates

`assets/install.sh` calls the verified prebuilt binary's `deploy-install` command to render the reviewed `assets/launchd/org.macserve.{controller,worker,maintenance}.plist.tmpl` files. Rendering is literal substitution of recognized markers only; unknown or unresolved `{{`/`}}` markers refuse. Apply runs `/usr/bin/plutil -lint` on all three rendered plists before installing them root-owned under `/Library/LaunchDaemons`. No PF template or policy file is rendered or installed.

No deployment Go toolchain or separate JSON/template renderer is needed. Inspect the generated files: plist syntax acceptance does not qualify launchd behavior or grant permission to start services.

All templates have `Disabled=true`, `RunAtLoad=false`, conservative restart throttling, fixed PATH, `GOMAXPROCS=2`, umask `077` and background/nice scheduling. Arguments are `/Library/macserve/bin/macserve <role> --config /Library/macserve/config/<role>.json`, where role is `controller`, `worker` or `maintenance`. Staging is not bootstrap, GUI login or authorization to start. Review launchd's existing per-label enabled overrides too; a disabled plist alone must not be mistaken for proof of a disabled loaded service. Do not bootstrap or enable any label until the gates below are met.

## 2. Supply matching protected configurations

The installer supplies matching initial JSON configurations and `{"profiles":[]}` from the reviewed environment; no hand-written configuration JSON is needed for disabled staging. The contracts below are for inspecting generated policy and separately reviewed enrollment/changes. Unknown fields are rejected. Do not paste angle-bracket metavariables as usable JSON.

**`worker.json`:** `socket` = `/Library/macserve/var/controller/run/worker.sock`; `controller_uid`, `job_uid`, `job_gid`, `owner_uid` = the approved numeric identities; `root` = `/Library/macserve/var/broker`; `export_root` = `/Library/macserve/var/exports`; `workspace_root` = `/Library/macserve/var/workspaces`; `helper_path` = `/Library/macserve/bin/macserve`; `baseline_path` = `/Library/macserve/var/broker/gui-baseline.json`. Optional timing fields are `poll_seconds` (default 2, range 1–30), `heartbeat_seconds` (default 5, range 1–5), `request_timeout_seconds` (default 10, range 1–10). Protect the helper and state first; initialize the protected baseline with `worker-reset` in section 3 before starting the broker.

**`controller.json`:** `root` = `/Library/macserve/var/controller`; `socket` as above; `job_uid`, `owner_uid`; `profiles_file` = `/Library/macserve/config/profiles.json`; `health_file` = `/Library/macserve/health/current.json`; `listen` = an assigned literal tailnet IP and an approved port; `tls_certificate`, `tls_key` = protected certificate/private-key paths. No wildcard, LAN, public or loopback listener. Optional `allowed_networks` narrows the supported API-client tailnet ranges, not job egress. Optional `pause_file` names a protected owner-controlled dispatch pause marker.

There is no `controller_uid` field in `controller.json`: launchd selects that account, and the worker's `controller_uid` must identify the same dedicated controller. The worker's `job_uid` must match the controller's execution UID, not the controller account or root broker; both configurations must agree on `owner_uid` and `socket`. Keep the fixed paths above: maintenance supports fixed controller/broker/export/workspace roots and health path, and derives the entire job home as `/Users/<job_user>`. A generic alternate worker layout is not an approved maintenance topology.

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
  "interval_seconds": 10
}
```

The interval defaults to 10 seconds and must be 5–15 seconds. Identities, profile registry, health path and accounting roots come from the protected controller/worker configurations rather than duplicate maintenance identity fields.

Optional independent coexistence checks use exact paths and **system-domain** launchd labels:

```json
{
  "coexisting_anchors": ["com.apple/guest-router"],
  "coexisting_services": ["com.example.guest-router"]
}
```

Lists are unique, sorted internally and limited to 64 entries each. Wildcards and domain selectors refuse. Only each configured anchor's direct filter/translation stdout is measured; listing a parent does not recursively list its descendants. No path is owned by macserve and no rule syntax or isolation guarantee is inferred.

`boundary-evidence.json` carries a `coexistence` object with `before` and `after`. Each state records `recorded_at`, `main_rules_status`, optional `main_rules_sha256`, `anchors` (`path`, `status`, optional `filter_sha256` and `translation_sha256`) and `services` (`label`, `pid`). Status is `available` or `unavailable`. Main hashing frames exact direct `-sr` and `-sn` stdout with each byte length as big-endian uint64 before its bytes; anchor digests hash their exact direct stdout. Unknown diagnostics, permission errors, absent anchors and incomplete reads produce unavailable measurements, never inferred empty rules.

Services are read with `launchctl print system/<label>` and must be verifiably running. Before/after service sets and PIDs must match, timestamps cannot regress, and matching available PF measurements must be unchanged. A measurement unavailable on either side is not a comparison failure and is never described as verified unchanged. Installation and each qualification sitting preserve their own before/after windows, including fresh windows after a planned reboot. Health continues requiring service continuity but does not gate on live PF availability or rule digests.

`qualification.json` is a root-approved object with these exact fields:

| Field | Meaning |
| --- | --- |
| `schema` | integer `3`; schema-1/2 approvals require fresh qualification, never migration |
| `approved_at` | actual approval timestamp, RFC3339 |
| `job_uid` | approved numeric job effective UID |
| `boot` | current kernel boot identity, matching the protected worker baseline |
| `baseline_sha256` | SHA-256 of exact protected `gui-baseline.json` bytes |
| `boundary_evidence_sha256` | SHA-256 of exact approved `boundary-evidence.json` bytes |
| `profiles` | object mapping each qualified profile ID to its normalized registry digest |

`boundary-evidence.json` contains `schema` (integer `3`), `recorded_at`, `job_uid`, `boot`, `coexistence` and `probes`. Each probe has `category`, `artifact_sha256`, `status`, `attempts`, `authorized_control_successes` and `canary_receipts`. Required categories are `network_reachability`, `unix_socket_boundary`, `owner_unaffected`, `owner_home_denial`, `fast_switch`, `reboot` and `tool_profiles`. Network status is exactly `not enforced in phase 1`; its actual reachability/unsupported results are informational. Other categories require `passed`, actual attempts and valid artifact digests. Owner-home denial additionally requires successful owner file controls and zero successful job canary reads. There are no PF-hit counters or network-denial pass criteria.

Supply exactly one probe per required category, no duplicate/unknown categories, and nonnegative integer counts. Digests are 64 lowercase hexadecimal characters. Evidence `recorded_at` must be no later than `approved_at`, and approval must not be in the future. The qualification's profile map must exactly match the observed configured profiles, not an approved subset of an otherwise unqualified registry.

The operator records these only after actual probes, audits the full artifacts, then approves and installs the records root-owned under protected ancestors. Never copy an example digest, guess a value, predate approval or treat the evidence record as a test generator. Missing reboot evidence intentionally prevents first production qualification until sitting 4. Retain prior records/artifacts in access-controlled archival storage instead of overwriting the only incident evidence.

After the approved baseline reset, the future root-only read-only observation command is:

```sh
/Library/macserve/bin/macserve maintenance-observe \
  --config /Library/macserve/config/maintenance.json
```

This command collects protected live facts without qualification/evidence files and without writing health: `job_uid`, `boot`, `baseline_sha256`, `profiles`, `identity_valid`, `baseline_valid`, `accounted_bytes`, `memory_pressure` and `coexistence`. It is **not** boundary evidence or approval. `maintenance-observe --coexistence-only --config /Library/macserve/config/maintenance.json` emits only the read-only coexistence state and needs no GUI baseline/profile qualification. Do not install observation JSON as qualification or copy observation booleans into an approval record.

**Schema-3 cutover:** interface inventory is no longer collected or bound by maintenance, qualification or controller admission. VM bridge starts/stops, address/prefix changes and interface name/flag churn do not invalidate boundary qualification, health or active work. This removes an obsolete network gate, not a non-network protection: boot, exact GUI baseline, account separation, profiles and protected evidence remain binding. Health, qualification, boundary evidence and all challenge/report/receipt/candidate/attestation artifacts use schema 3. Schema-1/2 artifacts are refused and require new qualification; never rewrite a schema number to reuse old evidence. Informational target matrices still come from the reviewed deployment environment; this is not network isolation.

Maintenance is a root/Darwin-only observer except for its health publication. It checks boot/baseline process identity, account separation, configured peer services, profile digests, memory pressure and bounded mutable-byte accounting. It never writes PF, adopts processes, runs root Apple build tools or signals a job. Unsupported non-network security observations invalidate health rather than refreshing stale success. Missing/stale/mismatched health blocks admission and cancels active work; unavailable PF alone does not.

Published health has exactly `schema`, `job_uid`, `boundary_receipt_sha256`, `boundary_validated`, `checked_at`, `expires_at`, `accounted_bytes`, `memory_pressure`, `qualified_profiles`. `boundary_receipt_sha256` binds the approved evidence file, not a job receipt or network-isolation claim. Successful evaluation publishes schema 3 and a 30-second lifetime. The controller requires unexpired health, age and lifetime no greater than 45 seconds, no check timestamp more than 5 seconds ahead, matching job/profile bindings, validated non-network evidence and available accounting. Memory pressure or exhausted reservations still block admission. Failed observations publish `boundary_validated:false`, `accounted_bytes:-1`, `memory_pressure:true`; they do not create the worker's durable admission marker. Never manufacture or manually refresh health.

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

## 4. Record network reachability and qualify non-network boundaries

Run probes from the **actual job GUI effective UID**, not a root shell claiming to impersonate it. Keep admission disabled until the required non-network qualification is approved. The network report describes what trusted repository code can reach; it does not establish or test macserve-enforced isolation.

Read-only coexistence snapshots protect unrelated configured services from unnoticed changes during installation and qualification. They neither inspect rule semantics nor authorize changing the host firewall. PF read failures remain explicitly unavailable; running service/PID and readable before/after digest changes still require owner investigation.

| Probe | Required evidence |
| --- | --- |
| TCP to protected ports, loopback IPv4/IPv6, current host LAN/tailnet IPs and approved DNS targets | Record fresh connection outcomes and actual job UID under `network_reachability`; status `not enforced in phase 1`, whether reachable or not |
| Optional UDP, endpoint, proxy and delegated networking observations | Use only authorized test destinations; preserve successes, failures and unsupported paths without pass/fail gates or PF counters |
| Local delegation | Job cannot connect to controller executor Unix socket or read private controller/broker/export/secret paths; check other relevant Unix sockets and delegated services without invoking secret-bearing APIs |
| Owner controls | Independent file controls bracket both account reports; configured owner services retain their running PIDs |
| Owner-home denial | From the actual job GUI identity with its full groups, owner-home listing/traversal and reading the approved nonsecret canary must be denied; owner reads the same canary successfully before/after |
| Lifecycle | Repeat after fast switching and planned reboot/GUI login with fresh boot/baseline evidence |

Connection refusal, an offline timeout, DNS failure or an unrelated successful request is not denial proof. Never send nonces to production UDP services, silently skip observations, or mark unsupported transports as tested. Existing host/network restrictions belong to their owner, not macserve. Unix permissions and UI qualification remain separate required boundaries.

Store detailed evidence privately, sanitized where exported. The root-approved evidence and qualification files authenticate an operator's real observations; arbitrary JSON does not perform tests. Their exact schema is specified in section 2.

For `owner_home_denial`, create a fresh nonsecret mode0644 canary at an explicitly approved owner-home path. The owner's file-only control reads it before and after the job/owner probe window. From the actual job GUI identity and full groups, directory access and reading that exact canary must fail with permission denial, not missing-path/mount errors. Do not enumerate private owner files. Record real attempts, successful owner controls and zero successful job canary reads; status `passed` also requires denied directory access. Preserve evidence and let the owner remove only that canary. Repeat after identity/permission changes and reboot.

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

Before approved start: verify protected binary/config/secrets and identity separation; real GUI baseline; accepted native persistence and trusted-repository/no-network-isolation model; required account/tool/UI evidence and informational network report; matching qualification; fresh root maintenance health; and manual pause/disabled profiles during commissioning. An operator may run `macserve maintenance --config /Library/macserve/config/maintenance.json` to obtain actual health, never manufacture it. Only then may a separately approved procedure enable/bootstrap the three dedicated services. Controller runs as its dedicated user, broker/maintenance as root. No root Apple build tools, PF writes or automatic baseline adoption are allowed.

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
5. A reset is not boundary approval: refresh qualification bindings for changed boot/baseline/profiles and repeat affected real evidence gates, including a fresh coexistence window. Restart only the dedicated services after valid fresh health and explicit approval. Startup replays pending completions before recovery; no registration or lease occurs before recovery succeeds. Transient unclean completion fences the old controller epoch; verified recovery registers a fresh epoch without another administrator clear command. Verify state and evidence delivery before clearing manual pause.

Manual disk relief is an administrative incident procedure, not `rm -rf` on the install root. First establish quiescence and preserve an access-controlled evidence inventory/backup. Identify ownership, exact recorded paths, retention eligibility, outstanding publication/completion references and current budget before removing only approved expired data. Never delete active records, pending receipts, source-cleanup debt or quarantine to force admission. If safe evidence-preserving cleanup cannot be established, keep disabled and add capacity or investigate; do not mutate unrelated owner infrastructure.

Changes to host behavior, binaries, pinned Xcodes/runtimes, recipes, relevant inventory, keys/configuration or GUI permissions require reviewed rollout and relevant requalification. PF remains externally managed; macserve never repairs it. Unsupported non-network security behavior is a deployment limit, not a reason to relax required gates.

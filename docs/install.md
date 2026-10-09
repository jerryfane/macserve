# Installation, qualification and recovery

This is a **future, owner-approved deployment runbook**, not a report that this Mac has been installed or qualified. Repository checks and fixture results do not prove native GUI, PF, FileVault, App authorization or target-recipe behavior. Every administrative action below requires an approved owner sitting. No service should be enabled just to see whether a real build works.

## Quick path

These are future commands for **four separately approved owner sittings**, not permission to run them now. Installation stages disabled services without activating launchd or PF. Qualification's explicit `begin --load-policy` loads only the configured service-owned PF anchor and preserves coexistence evidence; no command enables PF, changes owner ACLs, logs in the job user, or turns an untested boundary into a pass. Use a prebuilt release: no Go toolchain or JSON editing is needed for initial disabled staging.

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

Create and review `deploy.env`. **Every value below is illustrative**, not a claim that an identity, address, port, Xcode or repository ID is suitable or available. Include every current host alias in `HOST_ADDRESSES`, approve the complete protected-port set, and pin real repository IDs out of band:

```sh
cat > deploy.env <<'ENV'
CONTROLLER_USER=macservecontroller
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

Optional firewall keys are `PF_ANCHOR` (default `com.apple/macserve`), `COEXISTING_ANCHORS`, `COEXISTING_SERVICES`, `TOLERATED_TRANSLATION_ANCHORS`, and `APPROVED_GUEST_SUBNETS`. Lists are comma-separated exact values; omission or an empty value means an empty list (or the default anchor). They use the same validation and canonical ordering as the corresponding maintenance JSON fields described below, including guest-range pairing and owned-anchor exclusions. Installation renders them directly into `maintenance.json`; no root JSON editing is needed. For example:

```text
PF_ANCHOR=com.apple/macserve
COEXISTING_ANCHORS=com.apple/guest-router
COEXISTING_SERVICES=com.example.guest-router
TOLERATED_TRANSLATION_ANCHORS=com.apple/guest-router
APPROVED_GUEST_SUBNETS=172.20.40.128/25
```

These illustrative ranges are not discovered or approved automatically. Live qualification still refuses host-overlapping sources, unsupported translations, missing peers, and stopped/restarted services.

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

No daemon, PF rule, owner-home permission or GUI session was activated. An interrupted apply is not rerunnable recovery: retain evidence and inspect the partial state instead of deleting objects and retrying. Approve/integrate PF and any owner-home restrictions separately using sections 1 and 4 below. The default PF template permits no job egress; an approved-allow probe requires a separately reviewed narrow exception, not a blanket bypass.

To stage a separately reviewed PF policy with narrow exceptions, keep the reviewed file root-controlled and use the explicit configuration-only command below. It archives the previous policy/config, installs the new exact bytes and updates the controller's matching policy digest without hand-editing JSON. **It does not load PF**; loading occurs only through the guarded `begin --load-policy` step during an approved network window:

```sh
sudo /Library/macserve/bin/qualify.sh stage-policy \
  --file /private/var/root/reviewed-macserve-pf.conf
```

Qualification JSON, including the controller configuration read by `stage-policy`, rejects duplicate keys under Go's case-insensitive field matching (including Unicode simple-fold aliases). Staging requires the canonical `policy_sha256` key and refuses ambiguous input rather than reordering keys and changing another field's meaning.

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

Use a new session directory for each complete probe round. Review the plan's full TCP matrix, exact allowed endpoint(s) and controlled UDP receivers. Set `ALLOW_ENDPOINTS`, `UDP_ENDPOINTS`, `TCP_CANARY_ENDPOINTS` and `OWNER_CANARY` to actual approved values; endpoints are comma-separated literal `IP:port` (IPv6 `[address]:port`). Never aim the UDP nonce sender at a production UDP service. `TCP_CANARY_ENDPOINTS` contains only unoccupied matrix endpoints that need an accept-and-close test listener; leave existing services untouched. All required TCP targets need live owner controls, not just timeouts:

```sh
SESSION=/Library/macserve/var/qualification/before-switch
sudo /Library/macserve/bin/qualify.sh begin --load-policy --session "$SESSION" \
  --env /Library/macserve/config/deploy.env --allow "$ALLOW_ENDPOINTS" \
  --udp-canary "$UDP_ENDPOINTS" --owner-canary "$OWNER_CANARY"
```

Every new sitting, including post-switch and post-reboot sittings, requires explicit `--load-policy`. Before loading, configure the exact foreign anchors and system service labels whose continuity must be proven (below). The command stages the pinned policy privately, saves the baseline, proves exact-leaf ownership, loads only that leaf, then requires unchanged main/peer rules and running service PIDs. Every source filter rule must be outbound and scoped to the configured numeric job UID (directly or through a scalar literal macro); missing/other users, user lists/ranges/operators and group-only predicates are refused. Missing consent or an unsafe policy source is refused; no command-line PF passthrough exists.

The root-owned challenge is readable by both accounts; private evidence remains root-only. Add `--private-path /absolute/path,...` at `begin` for other explicitly approved local boundaries. **The following is the probe round to repeat for every new session:**

1. In the actual owner GUI, start controlled receiver(s) in separate terminals before either probe. Keep them running across the job and owner probes; `Ctrl-C` after both probes finalizes receipts. Pick a bounded lifetime sufficient for the sitting (maximum two hours):

   ```sh
   /Library/macserve/bin/qualify.sh canary --session "$SESSION" \
     --transport udp --listen "$UDP_ENDPOINTS" --out "$HOME/udp-receipts.json" --duration 30m
   /Library/macserve/bin/qualify.sh canary --session "$SESSION" \
     --transport tcp --listen "$TCP_CANARY_ENDPOINTS" --out "$HOME/tcp-receipts.json" --duration 30m
   ```

   A comma-list receiver writes `OUTPUT.1.json`, `OUTPUT.2.json`, etc.; one listener writes `OUTPUT` itself. Use new output names for every session. Skip the TCP receiver command only where reviewed existing listeners already provide all live controls.

   The UDP receiver also reads only the approved nonsecret owner canary before and after the probe window. Both real owner reads must succeed and bracket both account reports; early receiver exit or missing controls blocks owner-home qualification.

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

4. As administrator, collect the exact new job/owner report paths and comma-separated UDP receipt paths. `JOB_REPORT`, `OWNER_REPORT` and `UDP_RECEIPTS` name those real files, not sample JSON:

   ```sh
   sudo /Library/macserve/bin/qualify.sh collect --session "$SESSION" \
     --job "$JOB_REPORT" --owner "$OWNER_REPORT" --receipts "$UDP_RECEIPTS"
   sudo /bin/cat "$SESSION/candidate.json"
   ```

Collection preserves bounded snapshots, hashes, PF counters and current boot/interface/baseline/policy/profile bindings; inspect every artifact and status. Candidate `boundary-evidence.json` and `qualification.json` are **not approvals**. TCP/UDP failures, missing controls, unexpected owner-home access or unsupported native output cannot be overridden by an attestation. Unix permission denial is not a claim that a disabled worker's credential-bearing API was exercised.

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

The same-boot predecessor must already be collected and remain unchanged. Attestation accepts real owner/root artifacts and records provenance; it is not a test generator. Delegated networking/helpers and any required UI semantics still need genuine owner-reviewed evidence as described in section 4.

### Sitting 3: repository/App enrollment and real recipe evidence

Review the installed numeric repository/public-key pins, actual GitHub App enrollment and trust rules in section 5. The installer does **not** invent App credentials, policies, recipes or test outcomes. An empty registry admits no recipes; tool inspection then records the exact observed Xcode version/build and zero qualified recipes. Adding an actual approved profile changes the exact qualification binding and requires that profile's real recipe/UI evidence. Selected-repository App credential/config provisioning remains an explicit separate enrollment operation, not an installer side effect.

Run approved recipes only as the job user and retain their actual artifacts. Tool inspection may create long-lived job processes: audit them and use the existing reset explicitly, never auto-adopt them. Collect a fresh round after any policy/profile/baseline changes. For the current collected session, record genuine manual categories with:

```sh
sudo /Library/macserve/bin/qualify.sh attest --session "$SESSION" \
  --category delegated_boundary --artifact "$DELEGATED_ARTIFACT" \
  --reason "$REVIEWED_DELEGATED_CONCLUSIONS"
sudo /Library/macserve/bin/qualify.sh attest --session "$SESSION" \
  --category tool_profiles --artifact "$RECIPE_ARTIFACT" \
  --reason "$REVIEWED_RECIPE_CONCLUSIONS"
```

The second command is needed when enabled profiles require semantic recipe/UI evidence; it cannot repair failed automated tool inspection. Keep profiles empty until real recipes and their trusted writers are approved. `reboot` is still pending before sitting 4, so no production approval is available yet.

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

Approval refuses pending/failed categories, changed artifacts or current binding drift and checks the existing maintenance evaluator. It remeasures main/peer rules and running service PIDs after qualification, requires continuity from the preserved firewall baseline, and saves the exact final bytes as `approved-boundary-evidence.json` before installation. The candidate/predecessor chain remains unchanged. Approval does not manufacture health, clear `owner.pause`, adopt GUI processes, load PF or activate services. Only after all remaining enrollment/health gates and a separate explicit service-start approval may section 6 be followed. Preserve all session directories for review and recovery.

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
| `config/qualification.json`, `boundary-evidence.json`, `pf-anchor.conf` | root-approved policy/evidence, no job/controller write; evidence `0600`, PF policy readable `0644` |
| `var/broker/gui-baseline.json` | root-private audited GUI baseline, written by the existing reset command |
| `var/qualification/<session>` | root-owned session `0755`; public challenge `0644`, preserved evidence/approval artifacts `0600` |
| `var/pf-ownership/<SHA256(anchor-path)>.json` | root-owned `0700` directory / single-link `0600` prior-load receipt; created by the guarded loader, not by policy staging |
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

`assets/install.sh` calls the verified prebuilt binary's `deploy-install` command to render the reviewed `assets/launchd/org.macserve.{controller,worker,maintenance}.plist.tmpl` files and the PF template. Rendering is literal substitution of the recognized markers only: validated controller user/group names, numeric job UID/ports and literal host addresses. Unknown or unresolved `{{`/`}}` markers are refused. Apply runs `/usr/bin/plutil -lint` on all three rendered plists before installing them root-owned under `/Library/LaunchDaemons`.

No deployment Go toolchain or separate JSON/template renderer is needed. Inspect the generated files: plist syntax acceptance does not qualify launchd behavior or grant permission to start services.

All templates have `Disabled=true`, `RunAtLoad=false`, conservative restart throttling, fixed PATH, `GOMAXPROCS=2`, umask `077` and background/nice scheduling. Arguments are `/Library/macserve/bin/macserve <role> --config /Library/macserve/config/<role>.json`, where role is `controller`, `worker` or `maintenance`. Staging is not bootstrap, GUI login or authorization to start. Review launchd's existing per-label enabled overrides too; a disabled plist alone must not be mistaken for proof of a disabled loaded service. Do not bootstrap or enable any label until the gates below are met.

## 2. Supply matching protected configurations

The installer supplies matching initial JSON configurations and `{"profiles":[]}` from the reviewed environment; no hand-written configuration JSON is needed for disabled staging. The contracts below are for inspecting generated policy and separately reviewed enrollment/changes. Unknown fields are rejected. Do not paste angle-bracket metavariables as usable JSON.

**`worker.json`:** `socket` = `/Library/macserve/var/controller/run/worker.sock`; `controller_uid`, `job_uid`, `job_gid`, `owner_uid` = the approved numeric identities; `root` = `/Library/macserve/var/broker`; `export_root` = `/Library/macserve/var/exports`; `workspace_root` = `/Library/macserve/var/workspaces`; `helper_path` = `/Library/macserve/bin/macserve`; `baseline_path` = `/Library/macserve/var/broker/gui-baseline.json`. Optional timing fields are `poll_seconds` (default 2, range 1–30), `heartbeat_seconds` (default 5, range 1–5), `request_timeout_seconds` (default 10, range 1–10). Protect the helper and state first; initialize the protected baseline with `worker-reset` in section 3 before starting the broker.

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
  "pf_anchor": "com.apple/macserve",
  "interval_seconds": 10
}
```

The interval defaults to 10 seconds and must be 5–15 seconds. Identities, profile registry, health path and accounting roots come from the protected controller/worker configurations rather than duplicate maintenance identity fields.

`pf_anchor` defaults to `com.apple/macserve` when omitted. It must be an exact dedicated leaf, not a wildcard. Under `com.apple`, only the direct `macserve` or `macserve-*` leaf namespace is writable; `com.apple` itself, other Apple children and every `_pf` component are refused. Custom non-Apple exact paths such as `org.macserve` remain selectable. The selected path must be reachable through unconditional loaded filter-anchor calls. Observation, qualification counter reads, and rule-counter evidence all use that path. A stock root `anchor "com.apple/*" all` reaches an immediate child without adding a main-ruleset call.

**Evaluation order is part of the proof.** Rules execute in order, with depth-first anchor traversal. Wildcards visit immediate children in case-sensitive ASCII path order, not the order printed by enumeration and not administrator preference: Apple's [anchor comparator](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/pf_ruleset.c#L148-L154) and [RB_MIN/RB_NEXT traversal](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/pf.c#L3119-L3200) define that order. A [quick match terminates the whole evaluation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/pf.c#L5355-L5375), including its anchor stack. The observer refuses any foreign quick pass that could match remaining outbound job-owned IPv4/IPv6 TCP/UDP traffic, including earlier main rules and earlier `com.apple/*` siblings. A foreign nonquick pass is accepted only if a guaranteed later decision overrides its entire affected domain; the owned protocol/family-complete quick default denies provide that proof. Later main/sibling passes are checked too unless guaranteed quick decisions already terminate the domain. Interface/address/port-restricted denies do not establish universal overrides. Unknown syntax, conditional/quick anchor calls, dynamic matches, named ports and ambiguous UID predicates fail closed; the supported normalized rules use literal addresses and numeric ports/UIDs.

By default no descendant NAT/RDR mapping is tolerated. To opt into separately reviewed guest-only translations, add both optional fields to the same protected configuration; these generic values are examples, not host discovery:

```json
{
  "tolerated_translation_anchors": ["com.apple/guest-router"],
  "approved_guest_subnets": ["172.20.40.128/25", "172.20.41.128/25"]
}
```

Each list is unique and limited to 64 entries. Anchor entries are exact paths distinct from the service filter anchor: listing a parent does not approve its descendants. Guest entries are canonical unicast CIDRs. Every approved guest range must exclude **all current host addresses**, including loopback, aliases, tailnet addresses and VM bridge gateways. The observer obtains those addresses and the interface digest from the same inventory and checks that the inventory digest remains unchanged after PF inspection.

A tolerated ruleset must contain only supported NAT/RDR mappings whose literal source is contained in an approved guest range. `from any`, negated/dynamic/table sources, `nat pass`/`rdr pass`, other bypass modifiers, `binat`, `no nat`, nested translation calls and unknown syntax are refused. RDR targets must be literal non-host unicast addresses; loopback, host aliases and dynamic RDR targets are refused. The bounded parser supports IPv4 and IPv6, optional simple interface/protocol restrictions, numeric port matches/translations, `round-robin`, and NAT `static-port`; NAT targets may be a literal address or `(interface)`/`(interface:0)`. Address pools, other interface modifiers, named ports and unrecognized options remain unsupported. Each ruleset is limited to 1 MiB, 1,024 lines and 4,096 bytes per line.

**A VM subnet is not automatically guest-only.** If a host bridge owns `172.20.40.1`, approving `172.20.40.0/24` is refused even when the currently observed NAT rule is narrower or the anchor is empty. A job can bind an assigned host address; an egress-interface condition does not exclude it. The example `/25` excludes that gateway, but the helper's actual rule must also be constrained to an approved guest-only source range. Merely allowlisting the anchor or approving a smaller range does not make a broad helper rule safe. Narrowing another PF user's rules is a separate owner-reviewed operation, never an installer or observer side effect.

Optional independent coexistence checks use exact paths and **system-domain** launchd labels:

```json
{
  "coexisting_anchors": ["com.apple/guest-router"],
  "coexisting_services": ["com.example.guest-router"]
}
```

Lists are unique, sorted internally, and limited to 64 entries each; wildcard/domain-selector inputs are refused. Coexisting anchors must not equal or descend from the owned anchor. An ancestor is permitted because only its **direct** rules are measured; descendants must be listed individually. These fields do not grant translation tolerance or ownership. `pf_anchor` must identify a dedicated leaf exclusively assigned to macserve by the administrator, never another manager's anchor.

Immediately before the sole `pfctl -a PATH -f FILE` operation, the loader requires no ordinary or hidden `_pf` children, no direct translations or tables, and successful direct filter reads. The path must not equal a coexisting/tolerated entry or contain a listed peer below it. A genuinely absent/empty leaf may be initialized. A populated leaf requires its `macserve-default-deny` block label, outbound exact-job-UID rules, and a matching prior-load receipt from protected storage; a label or configured path alone is not ownership. Receipts bind schema `1`, exact `anchor`, `job_uid`, and `rules_sha256` over the exact loaded `-sr` bytes. Root ownership, modes, non-symlink/single-link files and ancestor ACL protection are checked. After a successful load, fresh leaf/rule validation must succeed before an atomic synced receipt replacement.

Unreceipted legacy or foreign populated anchors are never adopted. A failed load, post-load read or receipt write stops qualification and retains evidence; it does not roll back PF or manufacture ownership. Native PF has no compare-and-swap for this operation: use the approved quiescent, single-writer window. The qualification parent lock serializes macserve's own load/staging commands, not unrelated root managers. Uninstall/own-anchor flush support is **deferred**; this change adds no destructive uninstall command, global flush or automatic cleanup. Preserve receipts and failed session artifacts for separately reviewed recovery.

Each firewall step records `before` and `after_firewall` measurements: timestamp, direct main filter-plus-translation digest, each selected anchor's direct filter/translation SHA-256, and each selected service's running PID. Table contents and hit counters are excluded. An empty anchor must still verifiably exist. Services are read only with `launchctl print system/<label>`; missing/stopped services, ambiguous output or PID changes refuse qualification. No service is started, stopped or restarted to satisfy the check. This digest exclusion does not relax the separate observer restriction on dynamic filter rules.

`boundary-evidence.json` requires a `coexistence` object containing `owned_anchor`, `policy_sha256`, `before`, `after_firewall`, and `after_qualification`. Each state contains `recorded_at`, `main_rules_sha256`, `anchors` (`path`, `filter_sha256`, `translation_sha256`), and `services` (`label`, `pid`). Main hashing frames exact direct `-sr` and `-sn` stdout with each byte length as a big-endian uint64 before its bytes. All three measurements must match, with nondecreasing timestamps; services must retain their original running PIDs. Collection and approval both recheck continuity. Maintenance continues checking these bindings: a later peer service restart invalidates health until requalification. Old approvals without this evidence are refused.

`qualification.json` is a root-approved object with these exact fields:

| Field | Meaning |
| --- | --- |
| `schema` | integer `1` |
| `approved_at` | actual approval timestamp, RFC3339 |
| `job_uid` | approved numeric job effective UID |
| `boot` | current kernel boot identity, matching the protected worker baseline |
| `interfaces_sha256` | controller network-interface inventory digest |
| `policy_sha256` | SHA-256 of exact `pf-anchor.conf` bytes; also controller `policy_sha256` |
| `root_rules_sha256` | SHA-256 binding selected anchor, reviewed translation policy, recursive filter rules and all translation observations, as returned by `maintenance-observe` |
| `anchor_rules_sha256` | SHA-256 of the selected filter anchor's exact `-sr` stdout |
| `baseline_sha256` | SHA-256 of exact protected `gui-baseline.json` bytes |
| `boundary_evidence_sha256` | SHA-256 of exact approved `boundary-evidence.json` bytes |
| `profiles` | object mapping each qualified profile ID to its normalized registry digest |

`boundary-evidence.json` contains `schema` (integer `1`), `recorded_at` (actual RFC3339 timestamp), `job_uid`, `boot`, the required `coexistence` object described above, and `probes` (array). Each probe object has `category`, `artifact_sha256`, `passed`, `attempts`, `pf_hit_delta`, `authorized_control_successes`, `canary_receipts`. Required categories are exactly `tcp_denial`, `udp_denial`, `approved_allow`, `delegated_boundary`, `unix_socket_boundary`, `owner_unaffected`, `owner_home_denial`, `fast_switch`, `reboot`, `tool_profiles`. Each must pass with at least one attempt and a valid SHA-256 reference to preserved real evidence. TCP requires at least three attempts, positive labeled PF hits and successful authorized controls; UDP requires positive PF hits, successful controls and zero canary receipts. Owner-home denial requires successful owner read controls and zero job canary reads. These are minimum machine-readable checks, not a replacement for **every** destination/transport/profile row of the matrix below. Associate each category with a complete private evidence bundle and its exact-byte digest; a category's `passed:true` alone proves nothing.

Supply exactly one probe per required category, no duplicate/unknown categories, and nonnegative integer counts. Digests are 64 lowercase hexadecimal characters. Evidence `recorded_at` must be no later than `approved_at`, and approval must not be in the future. The qualification's profile map must exactly match the observed configured profiles, not an approved subset of an otherwise unqualified registry.

The operator records these only after actual probes, audits the full artifacts, then approves and installs the records root-owned under protected ancestors. Never copy an example digest, guess a value, predate approval or treat the evidence record as a test generator. Missing reboot evidence intentionally prevents first production qualification until sitting 4. Retain prior records/artifacts in access-controlled archival storage instead of overwriting the only incident evidence.

After the approved baseline reset and policy integration, the future root-only read-only collection command is:

```sh
/Library/macserve/bin/macserve maintenance-observe \
  --config /Library/macserve/config/maintenance.json
```

This command collects protected live facts without requiring qualification/evidence files and without writing health. Its JSON fields are `job_uid`, `boot`, `interfaces_sha256`, `policy_sha256`, `pf_anchor`, `root_rules_sha256`, `anchor_rules_sha256`, `baseline_sha256`, `profiles`, `pf_enabled`, `loopback_filtered`, `identity_valid`, `baseline_valid`, `accounted_bytes`, `memory_pressure`, and `coexistence` (the current measurement). This is **not** boundary evidence or automatic approval. `macserve qualify` uses these bindings to generate inspectable candidate records and checks them again at explicit approval. Do not install observation JSON as qualification or copy its observation booleans/accounting into an approval record.

For hash reproducibility, `anchor_rules_sha256` covers exact stdout from `/sbin/pfctl -a "$PF_ANCHOR" -sr`, where `PF_ANCHOR` is the configured path. `root_rules_sha256` covers JSON framing, in order, of `PFAnchor`, sorted `ToleratedTranslationAnchors`, sorted `ApprovedGuestSubnets`, sorted `CoexistingAnchors`, sorted `CoexistingServices`, `Filter` (exact `/sbin/pfctl -a '*' -sr` stdout), `Translations` (path-sorted objects with `Path` and exact `Rules` stdout, including the root), and `DirectFilters` (the corresponding path-sorted direct `-sr` snapshots used for evaluation order). Empty optional lists are normalized to null in this framing. Thus rule order, tolerated mappings, their paths, complete topology and review/coexistence policy are cryptographically bound into qualification. A change invalidates previous approval, even if a newly allowed translation anchor is currently absent. Use `maintenance-observe` to obtain this digest; older digest formats require fresh qualification. This composite digest is **not** another PF user's main-only ruleset hash. Do not hash verbose hit counters; preserve them separately in evidence. Boot identity is SHA-256 of raw `kern.boottime` bytes. Interface/profile digests use the controller inventory and normalized registry; policy/baseline/evidence digests cover exact file bytes.

The observer requires recognized enabled/loopback status, a nonempty selected filter anchor, a proven unconditional call path and safe evaluation order from root, and literal static filter rules; table/dynamic-interface references in filter rules remain unsupported. Stock `scrub-anchor` and `dummynet-anchor` calls are accepted and hashed but are not filter-call edges. A wildcard call reaches immediate children, not arbitrary descendants. Stock root `nat-anchor "com.apple/*" all` and `rdr-anchor "com.apple/*" all` calls are supported without removing owner anchors: `-v -s Anchors` enumerates topology, explicit reserved `_pf` probes cover otherwise hidden children, and `-a PATH -sn` inspects the root and every discovered anchor. Root translation rules may be empty or unconditional calls into discovered paths. Descendant mappings are refused unless their exact anchor is listed and every rule passes the guest-only checks above; all other nonempty descendant translation rulesets remain refused. Unreadable children and unstable observations fail closed. Each direct-filter and translation observation uses two matching rule sweeps and three matching topology observations; recursive and selected filter text are rechecked too. This is not an atomic kernel snapshot. Limits are 64 non-root anchors, depth 8, 4 MiB total PF observation stdout, 1 MiB stdout/8 KiB stderr per command, 2 seconds per command and the existing 8-second overall context. Filter evaluation additionally bounds anchor visits at 4096 and rule steps at 65536. Exact missing-reserved-anchor diagnostics are distinguished from permission/read errors. Do not remove or disable owner policy to satisfy remaining limits. Anchor handling follows installed `pfctl(8)`/`pf.conf(5)`, [BSD enumeration behavior](https://github.com/freebsd/freebsd-src/blob/stable/10/sbin/pfctl/pfctl.c), and [Apple anchor path semantics](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/pf_ruleset.c). Offline fixtures do not establish privileged native behavior or qualify a host.

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

Render `assets/pf/org.macserve.conf.tmpl` using `.JobUID` (numeric effective execution UID), `.ProtectedPorts` (reviewed numeric PF port-list contents), and `.HostAddresses` (reviewed literal current host IPv4/IPv6 aliases). Install reviewed exact bytes as `/Library/macserve/config/pf-anchor.conf`. Neither the template nor the installer loads it. The target is the exact `pf_anchor` in protected `maintenance.json`, defaulting to `com.apple/macserve`; the template filename is not the anchor path.

During the approved network window, a qualified administrator inspects the **whole recursive loaded policy**, verifies that the selected anchor's call path cannot be bypassed by an earlier quick pass, and confirms PF is enabled and `lo0` is filtered. Preserve the prechange rules/topology and recovery plan. Do not replace `/etc/pf.conf`, flush global states, toggle unrelated anchors, or reload a whole host policy blindly. Deal with preexisting job-owned states using a separately approved precisely scoped procedure; if attribution is uncertain, remain disabled. Verify that unrelated owner sessions/services stay intact.

### Load only the service child anchor

On a stock host with the existing `com.apple/*` filter call, **do not add `anchor "org.macserve"` to the main ruleset**. Other PF owners can pin the main ruleset's hash; adding a call or reloading a modified root policy breaks that contract. After reviewing the staged policy and configuration, use the `qualify begin --load-policy` command shown in sitting 2. Do not bypass its before/after measurements with manual loads.

The sole PF write API constructs exactly `/sbin/pfctl -a <configured-owned-anchor> -f <private-staged-policy>`. It exposes no arbitrary arguments, global flush/reload, foreign-anchor writes, enable/disable, or uninstall operation. Read-only PF invocations necessarily inspect main and peer rulesets. The loader accepts bounded, single-line `block`/`pass` rules, literal numeric/address/list macros and literal labels, including the rendered template. Includes, `load anchor`, anchor declarations, global options, tables, translation rules, keyword macros and line continuations are refused before execution. No shell or helper bypass accepts raw PF arguments.

The public challenge binds `firewall_step_sha256`; detailed `firewall-policy.conf`, `firewall-before.json`, `firewall-after.json`, and `firewall-step.json` stay root-private and are included in collected artifact hashes. Baseline persistence must succeed before loading. After-state capture is attempted even if the load fails. A failed step may have changed the **owned** anchor: retain its evidence, keep admission disabled and arrange reviewed recovery/new qualification. There is no automatic rollback or foreign-policy repair.

This requires no `/etc/pf.conf` edit and adds no main-ruleset call. Do not load at `com.apple`, use another manager's child, change its pinned hash, or use global flush/enable/disable operations as a workaround. A custom `pf_anchor` requires its own already-reachable unconditional call path; an orphan loaded ruleset is not protection. If the stock call is absent or its ordering permits a bypass, stop for an owner-reviewed integration plan rather than silently changing the root policy.

Loading a child is not boot persistence. After its PF owner is ready, use a fresh explicitly approved `begin --load-policy` sitting and requalify after reboot. If another manager removes/replaces the child, maintenance refuses health; it does not repair PF. `qualify stage-policy` still stages files only. Loading under the existing wildcard preserves the main-only rule text, but changes macserve's recursive observation digest, so previous qualifications cannot be reused.

### Coexist with reviewed guest translations

An unrelated guest router may continue using its own exact child anchor and the stock NAT/RDR wildcard calls. Configure the optional lists above only after reviewing its actual normalized `-sn` rules and the complete host-address inventory. For example, a helper rule with source `172.20.40.128/25` can coexist when that is an approved guest-only range; one with source `172.20.40.0/24` cannot if the host owns a gateway inside it. NAT source restrictions, not a helper's name, root ownership or pinned main hash, establish this exclusion.

No allowance is inferred from a running VM, launchd entry or a parent anchor. Re-run the actual job/owner boundary matrix after loading or changing the service policy, reviewed guest ranges, tolerated rules, interface inventory, or anchor topology. Keep admission disabled until those live bindings and genuine evidence are approved.

### Execute the boundary matrix

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

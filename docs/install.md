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
  --pattern macserve-darwin-arm64 --pattern macserve-controller-darwin-arm64 --pattern SHA256SUMS
cat SHA256SUMS
```

The tag workflow builds Darwin arm64 with `checks/release-build.sh` (CGO disabled, `-trimpath`, `-buildvcs=true`, Go exactly as pinned in `go.mod`), rebuilds the tag on a second runner (macOS, different checkout path) and publishes only if both binaries are byte-identical. It then records a GitHub build provenance attestation for `macserve-darwin-arm64` and publishes it with `SHA256SUMS` using only `GITHUB_TOKEN`. Review the tag/source/publisher and expected binary digest. A checksum downloaded beside a binary detects corruption, not an independently compromised release. Set `EXPECTED_SHA256` to the reviewed 64-character lowercase digest; do not substitute an unreviewed local hash.

For releases that contain `checks/release-build.sh`, you can check the digest independently of the release workflow. Rebuild from a separate clean clone of the tag (the tag must be present: Go stamps the module version from it, and any untracked file marks the build modified) with the Go version pinned in `go.mod`, then confirm the attestation names this repository's release workflow at that tag:

```sh
git clone --depth 1 --branch "$RELEASE_TAG" https://github.com/jerryfane/macserve.git macserve-rebuild
macserve-rebuild/checks/release-build.sh "$PWD/macserve-rebuild-out"   # prints the sha256
gh attestation verify macserve-deploy-kit/macserve-darwin-arm64 --repo jerryfane/macserve \
  --signer-workflow jerryfane/macserve/.github/workflows/release.yml \
  --source-ref "refs/tags/$RELEASE_TAG" --deny-self-hosted-runners
```

The rebuilt sha256 of each binary must equal `EXPECTED_SHA256` / `EXPECTED_CONTROLLER_SHA256` and the downloaded binary's digest. The release ships two binaries: `macserve` (every root, worker, signer and owner role) and `macserve-controller` (the controller daemon only); both install root:wheel `0755` under `/Library/macserve/bin` (see [architecture](architecture.md#two-binaries-and-class-k)).

Every release also publishes `release-manifest.json` and `release-manifest.json.sig`, signed by the CI release key and listed in `SHA256SUMS` (see [releases](releases.md)). A release whose manifest has `"kind": "controller-carry"` republishes its base tag's `macserve-darwin-arm64` byte for byte and is for the administrator's carry verb only: install full releases with `macserve setup` and `macserve upgrade`. For such a release, rebuild `macserve` from the manifest's `base_tag`, not from the release tag.

#### Homebrew formula (release asset)

Each release also publishes `macserve.rb`, rendered by `checks/homebrew-formula` from `assets/homebrew/macserve.rb.tmpl` only after the byte-identical rebuild and attestation checks pass. It pins the release URL and the `macserve-darwin-arm64` digest from that release's `SHA256SUMS`, requires macOS on arm64, and installs `macserve` only into the Homebrew prefix. That copy is owner-writable and never becomes the service binary: `macserve setup` verifies the release digest itself and copies those bytes into root-owned `/Library/macserve/bin`. The formula's caveats point to `macserve setup --plan`.

The tap `jerryfane/homebrew-macserve` is maintained by hand; CI holds no token for it. For each release, open a one-line bump PR in the tap that replaces `Formula/macserve.rb` with the release's `macserve.rb` asset, after checking that its `sha256` equals the `macserve-darwin-arm64` line of that release's `SHA256SUMS`:

```sh
gh release download "$RELEASE_TAG" -R jerryfane/macserve -p macserve.rb -p SHA256SUMS
grep -F "sha256 \"$(awk '$2 == "macserve-darwin-arm64" {print $1}' SHA256SUMS)\"" macserve.rb
```

Users then run `brew tap jerryfane/macserve`, trust the tap as Homebrew 6 requires, and `brew install macserve`.

`macserve setup --plan --repository OWNER/NAME:ID`, run as yourself (not with `sudo`), can propose the `deploy.env` below from detected values. It is read-only: it checks the Mac (administrator, macOS, Apple silicon, SIP, FileVault, Xcode, Tailscale address, free port and account IDs, owner-home mode, existing `/Library/macserve`), prints a `deploy.env` already accepted by the `deploy-install` parser and the ordered setup steps, and writes, creates or starts nothing. Review its output like any other `deploy.env`; the remaining setup steps are not available in this release.

`macserve setup --repository OWNER/NAME:ID --sha256sums SHA256SUMS`, without `--plan` and again as yourself, applies that plan through qualification, your typed approval and the service start. Run it from the downloaded `macserve-darwin-arm64` after verifying the release as above (`gh attestation verify`); `--sha256sums` is that release's `SHA256SUMS` (or pass the digest with `--sha256 HEX`). Setup never takes the digest from the binary itself: it refuses to start when the binary does not match, and the root helper re-hashes itself and refuses a mismatch too. The first `sudo` still runs your downloaded, owner-writable copy, so malware already running as you could replace it between the check and `sudo`; such malware can subvert `sudo` in other ways as well. After install the helper is only ever the root-owned `/Library/macserve/bin/macserve` with the digest install recorded. After the preflight and a typed `yes` setup asks for your password once, for `sudo macserve _setup-root`: a root helper that takes an exclusive lock (one helper at a time), serves a fixed set of steps on a root-owned socket to your UID only, clears its environment, refuses everything once `activation-anchor.json` or `qualification.json` exists (except finishing an approval this setup ledger recorded, including the digests of the files `qualify approve` wrote: the summary, the approval itself and removing `owner.pause`), and exits when setup disconnects or after 15 idle minutes. Its ledger is kept root-only in `/private/var/root/.macserve-setup` until install and in `/Library/macserve/var/setup/ledger.json` after. The steps are as follows. Install runs `deploy-install --apply` with the plan's `deploy.env`, the verified binary and the release's assets; the `sysadminctl` password prompt appears in your terminal. The one-time `API_BEARER_TOKEN` line is taken out of that output and put into your login keychain as the generic password `macserve API token`; it never appears on the terminal, in the ledger, in the helper's audit log or in any file. Only if the keychain refuses it does setup offer to show it once (type `show`); otherwise it is discarded and a new token needs a reviewed credential rotation. Setup refuses when its output is not a terminal. For GitHub, setup prints the `profiles.json` entry and the `sudo /Library/macserve/bin/macserve connect-github` command to run and detects the result (temporary until setup does this itself). The Xcode steps run `xcodebuild -license accept` and `-runFirstLaunch` as root, because they write system locations, and `-downloadComponent MetalToolchain` as you; the toolchain is checked before each command. Last, you grant Full Disk Access to `/Library/macserve/bin/macserve`, which setup checks from a transient launchd job (`org.macserve.setup.fda-check`), and log in to the build account once and Switch User back, which setup detects. Then setup runs the two qualification rounds of sitting 2 below for you. Each round needs the build account logged in in the background and you (or the login window) at the screen; setup shows the build account's third-party login items and agents (anything listed needs the typed word `accept`) and the proposed GUI baseline (every build-session process must be an Apple SIP-protected, root-owned, non-writable program that is not a shell, interpreter or Terminal; `y` to use it), then accepts the persistence list, resets the worker baseline, pins one `internal/source` archive of each profile's repository at its default-branch head for tool evidence, and runs `qualify begin`, the owner-home control and owner probe (as you), the job probe (as the build account), tool evidence and `qualify collect`. A round is recorded only when every category passes (reboot stays pending in round 1); otherwise nothing is approved and the next run begins a new session. Between the rounds setup restarts the Mac on a typed `y` (`fdesetup authrestart` when FileVault supports it; FileVault asks for your password, never macserve) and detects the new boot. After round 2 setup prints one summary; typing `approve` at this Mac's screen, logged in as yourself and in the same boot, records the approval of exactly that summary, including the state of `owner.pause` (digest, inode and modification time) and `profiles.json` it shows. Setup then runs `qualify approve`, records the digests of the files it wrote, runs `activation-check` and starts the three services with the start checks of sitting 2. A retry trusts only exactly those recorded files, never an approval it did not record. A change to `owner.pause` or `profiles.json` after the summary needs a new summary and approval; a change after `qualify approve` ran fails the step. Kernel boot session UUID identifies the boot, so a clock step does not void an approval. In the same run, once health is valid, setup removes the `owner.pause` the approval recorded, once; it never removes it on a later run, nor an `owner.pause` set or changed after the approval. If health is not valid in time, remove `owner.pause` yourself once it is. A failed or interrupted install, reboot step or service start blocks setup (do not rerun `deploy-install`; reconcile by hand); the other steps resume when you run `macserve setup` again.

**Upgrading a Mac set up by `macserve setup`.** Stop the services first (`sudo /bin/launchctl bootout system/org.macserve.controller`, then `.keyholder`, `.maintenance` and `.worker`) and log the build account out. Download and verify the new release as above, then run it as yourself: `./macserve-darwin-arm64 upgrade --plan --sha256sums SHA256SUMS [--tag vX.Y.Z]` is read-only and compares the installed and new release, checks the digest against `SHA256SUMS` (never against the file itself), the stopped services and the build account's session, says whether a release carry is possible and lists what will happen. Without `--plan`, after you type `yes`, `sudo` starts the same setup root helper (fixed verbs, your UID only, one lock) from the new binary, which repeats every check as root and refuses a running service, a controller-UID process or the installed binary still running, a live build-account GUI session, the same or an older release, a development build and an approval or activation anchor this setup ledger did not record. It then records the release in the setup ledger, writes `owner.pause` if absent, removes the approval, activation anchor, reviewed persistence, attestation and GUI baseline, replaces `/Library/macserve/bin/macserve` atomically (root-owned 0755, digest re-checked after the write), migrates an installation from before the keyholder (see [Keyholder](#keyholder)) and resets the ledger to owner-actions: run `macserve setup` to re-grant Full Disk Access to the new build and requalify. An interrupted upgrade blocks setup until the same release's `macserve upgrade` finishes it. A carry is accepted only from the release's own `carry-proof.json` asset, which the release workflow publishes when the release changes no boundary path and lists in that release's `SHA256SUMS`. Download it with the binary (`--pattern carry-proof.json`) and pass `--carry-proof carry-proof.json --sha256sums SHA256SUMS`. Before any `macserve upgrade`, verify that `SHA256SUMS` (and `carry-proof.json`, when present) were built by this repository's release workflow, exactly as for the binary: `gh attestation verify SHA256SUMS --repo jerryfane/macserve --signer-workflow jerryfane/macserve/.github/workflows/release.yml --source-ref "refs/tags/$RELEASE_TAG" --deny-self-hosted-runners`, and the same for `carry-proof.json`. The host checks only that the proof is the one `SHA256SUMS` lists: it trusts an honestly built release, and these attestations are how you check that you have one. The helper requires the proof's digest to be the one listed in `SHA256SUMS`, the proof to be for exactly the installed release to this one, and the proof to pass the checks `qualify carry` applies. It also runs `qualify carry`'s own read-only pre-check as root (schema-2 anchor equal to the live configuration, installed binary anchored, the carry cap, the activation check), requires your own completed approval and a live build-account session, and requires `worker-quiescent` to pass. Only then does it skip the job-session guard and run the job-probe self-test, `qualify begin --carry`, the job probe, tool evidence and `qualify carry --proof` with the new binary, keeping the approval. Any failure falls back to full requalification, which is recorded in the ledger, and `macserve setup` then counts no job login until it has seen the build account logged out. Services stay stopped after a carry: re-grant Full Disk Access to the new binary, start the services, and remove `owner.pause` once health is valid. Do not swap the binary by hand: that skips the stopped gate and the job-session guard.

Create and review `deploy.env`. **Every value below is illustrative**, not a claim that an identity, address, port, Xcode or repository ID is suitable or available. Include current non-link-local host aliases in `HOST_ADDRESSES`, choose the protected ports to include in informational reachability reports, and pin real repository IDs out of band:

```sh
cat > deploy.env <<'ENV'
CONTROLLER_USER=macservectl
CONTROLLER_UID=6201
CONTROLLER_GID=6201
JOB_USER=macservejob
JOB_REAL_NAME=macserve build
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
KEYHOLDER_UID=499
KEYHOLDER_GID=499
KEYRPC_GID=498
ENV
: "${EXPECTED_SHA256:?Set the reviewed release binary digest}"
: "${EXPECTED_CONTROLLER_SHA256:?Set the reviewed controller binary digest}"
/bin/bash assets/install.sh --env deploy.env \
  --binary macserve-darwin-arm64 --sha256 "$EXPECTED_SHA256" \
  --controller-binary macserve-controller-darwin-arm64 --controller-sha256 "$EXPECTED_CONTROLLER_SHA256"
```

`deploy.env` is bounded **data**, never shell-sourced: plain `KEY=VALUE`, blank/comment lines, comma-separated lists, and `owner/repo:numeric-id` repository pins. No shell expansions, commands, unknown keys or duplicate keys. Default plan verifies the binary digest and validates/renders the deployment without creating accounts or installation files. It does not prove native identity availability or any security boundary.

`KEYHOLDER_UID`, `KEYHOLDER_GID` and `KEYRPC_GID` are required: the [keyholder](#keyholder)'s system account `_macserve_key`, its own primary group and the RPC group `_macserve_keyrpc` it shares only with the controller. They are canonical system IDs (200–499); the two GIDs differ, and none equals a service, job, owner or signer ID; `macserve setup` picks free ones. `deploy-install` refuses a `deploy.env` without them; an installation from before the keyholder gets them from [`macserve upgrade`](#keyholder).

`JOB_REAL_NAME` is the optional GUI job account display name (`RealName`), defaulting to `macserve build` when omitted. Spaces are allowed in the unquoted data value; an explicitly empty value is refused. The job account is created by `sysadminctl` with an interactive password prompt, not by manually writing `AuthenticationAuthority` with `dscl`. The controller stays on the `dscl` creation path, hidden (`IsHidden 1`) with `Password '*'`.

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
  --sha256 "$EXPECTED_SHA256" \
  --controller-binary /private/var/root/macserve-deploy-kit/macserve-controller-darwin-arm64 \
  --controller-sha256 "$EXPECTED_CONTROLLER_SHA256" --apply
```

Apply refuses existing installation/accounts/targets. It uses the existing account helper, verifies the staged executable, literal-renders and lints all three disabled plists, and writes matching controller/worker/maintenance configs plus `{"profiles":[]}`. It generates separate TLS, receipt and worker seal keys: the TLS key is controller-owned `0600` in `var/controller/secrets`, the receipt key keyholder-owned `0600` in `var/keyholder/secrets` and the seal key root-only `0600` at `var/broker/seal-key.pem`. **The API token is printed once, only after success.** Move it directly into the authorized caller's secret storage: no `tee`, session transcript, shell-history assignment or shared log. Only its digest is installed. Preserve public trust pins from `/Library/macserve/config/deployment-pins.json`; never treat a receipt's own advertised key as an independent trust anchor.

`deployment-pins.json` includes `receipt_key_id`, standard-base64 `receipt_public_key` (the receipt key the keyholder holds), opaque service/host IDs and `tls_certificate_sha256` over the certificate's **DER** encoding, not its PEM file text.

Run apply from the administrator's interactive terminal; its stdin must remain attached to that terminal. The installer forwards stdin to the account helper. During job creation, `sysadminctl -password -` prompts for the password. Enter it only at that private prompt—never in argv, environment variables, `deploy.env`, shell history or logs. Do not pipe a password into apply or wrap it in session recording. No `-admin` flag is used. Password setup happens during creation, not through a later `dscl -passwd` step.

The helper invokes the following command **only after its collision and host checks**; this fragment is for review, not a standalone replacement for those checks:

```sh
/usr/sbin/sysadminctl -addUser "$JOB_USER" -fullName "${JOB_REAL_NAME:-macserve build}" \
  -UID "$JOB_UID" -GID "$JOB_GID" -shell /bin/zsh \
  -home "/Users/$JOB_USER" -password -
```

This creates the account/home but does not establish a GUI login. Log in as the job account during the approved sitting.

No daemon, PF rule, owner-home permission or GUI session was activated. An interrupted apply is not rerunnable recovery: retain evidence and inspect partial state instead of deleting objects and retrying. Before deployment mutation, apply durably saves `before.json` under a new root-private `/private/var/root/.macserve-install-evidence-*` directory; final `coexistence.json` records before/after observations and any installation error where possible. Owner-home restrictions remain a separately approved prerequisite; there is no service PF policy to stage or load.


### Sitting 2: actual job GUI, tools and boundary evidence

First establish the approved job GUI login/password. Before PID reset, separately inspect and explicitly accept the reviewed persistence manifest as described below. This does not authorize Automation/TCC grants. With the broker stopped and the manifest accepted, audit retained GUI PID/start identities; `AUDITED_PIDS` is a reviewed list, never a process-list substitution.

On SIP-enabled hosts, first grant Full Disk Access to `/Library/macserve/bin/macserve` and to the terminal app used for `qualify.sh`; see **Full Disk Access on SIP hosts** under [Maintenance configuration and approved records](#maintenance-configuration-and-approved-records).

```sh
sudo /Library/macserve/bin/macserve worker-reset \
  --config /Library/macserve/config/worker.json --pids "$AUDITED_PIDS"
/Library/macserve/bin/qualify.sh plan --env /Library/macserve/config/deploy.env
```

**Reviewed-registration migration (unreleased; deployment remains separately gated):** `worker.json` now requires a separate `persistence_path`, normally `/Library/macserve/var/broker/reviewed-persistence.json`. Existing installed configs/binaries must be migrated only through a reviewed owner-approved rollout, not by rerunning the fresh-install helper or silently accepting old schemas. Deployment creates no trusted registration list.

Before reset, an approved administrator runs `macserve worker-persistence inspect --config /Library/macserve/config/worker.json --out /private/var/root/registration-candidate.json`. This creates an exclusive mode-0600 candidate, not authority. Keep the candidate private; review each third-party registration and exact nested code binding. Any unresolved reference, unknown/third-party autostart kind, unsigned/ad-hoc third-party code, unsafe ownership/ACL/link, or incomplete inspection prohibits acceptance. An ordinary-looking developer/container with an absent embedded target still refuses; required installed apps do not create an exemption.

`inspect` and `accept` use a fixed six-minute inspection deadline, with no user override and below the ten-minute ceiling. The full native collector initially exceeded the old 120-second limit; a complete warm collection measured 113.7 seconds. The six-minute bound is three times that measurement rounded up to allow cold-cache variation. Deadline expiry remains an inspection failure and cannot authorize acceptance. Each unique parent tree is measured once per pass, preserving both the initial measurement and mandatory post-signature tree/ACL rechecks.

The reviewed-registration code tree and **every ancestor** may be owned by root or the configured owner (`owner_uid`, UID 501 in the reviewed deployment). Mode and ACL write rights are limited to root, that owner and the verified `wheel` (GID 0) and `admin` (GID 80) groups; unambiguous inherited ACLs and group grants are included. `staff` (GID 20), everyone and job/controller groups are not allowed writers. Root, owner, job and controller must be distinct identities and the named groups must resolve to their expected GIDs. Actual primary, supplementary and nested memberships of **both** service accounts are resolved, not inferred from account creation: native Directory Services membership queries supplement group lists. Membership in `wheel`/root, `staff` or `admin`, unavailable membership data, unknown ACL identities or unknown rights refuses inspection. Deny ACLs do not excuse unsafe ownership, write modes or other grants. Non-symlink ancestry is rechecked around inspection; internal bundle links must still resolve inside the protected tree. Signed-executable containment uses actual filesystem directory identity with descriptor confinement, so `Plugins` and `PlugIns` are equivalent only on a filesystem that resolves them to the same directory, never through string lowercasing. Broker configuration, review authority, macserve-owned services and all non-registration protection retain their stricter root-only rules.

Allowing root/owner/wheel/admin updaters to maintain an app does not approve its next version. The full tree digest, signature/team/requirement and exact registration bindings remain mandatory, including strict/deep verification with the inline `=anchor apple generic` requirement and tree/ACL rechecks after signature inspection. Failed initial tree measurements remain unresolved Problems in the private candidate; they are not cached as successful digests or eligible for acceptance. Any app or extension update that changes the reviewed binding requires a fresh private inspection, explicit re-review/acceptance, baseline reset and qualification; the same signer or bundle identifier is not an update exemption.

ACL text is parsed with a strict single-token principal grammar. Because native `ls` output does not quote principal names, an `inherited` marker cannot be distinguished from a literal name ending in “ inherited”; such ambiguous entries are refused, including deny entries. Unexpected principal tokens such as “ allow” or “ deny” are also refused rather than resolved as a shorter trusted name. ACL changes made by allowed writers between collection and acceptance are covered by the accept-time fresh re-collection; ACL bytes are not a separate manifest digest.

The opened-executable descriptor is pinned to the inspected inode before signing, but `codesign` itself still opens by pathname. A trusted root/owner/wheel/admin writer can change the path during that signing window. The post-signing ancestry/ACL checks and full tree re-hash detect persistent changes; they do not claim an atomic signature operation or defeat a malicious trusted writer that swaps and restores content. This is within the documented trusted-writer boundary; untrusted job/controller writers remain excluded, and acceptance performs a fresh collection.

Only after that review, `macserve worker-persistence accept --config /Library/macserve/config/worker.json --candidate /private/var/root/registration-candidate.json --reviewed-sha256 REVIEWED_SHA256` may write the configured authority. The exact reviewed digest must match a fresh native inspection while the stopped broker's lock is held. Neither command resets processes, removes registrations, clears quarantine, approves qualification nor starts services. Reset subsequently records this authority's digest in the boot/PID baseline; maintenance rejects a changed manifest, and fresh baseline/boundary qualification remains mandatory.

Legacy SessionLoginItems inspection now uses the Darwin-only pinned purego/CoreServices bridge, without System Events AppleEvents or a permission grant. The deprecated API must return a real non-null snapshot; unavailable APIs refuse. **Nonzero items refuse both reset and admission without automatic deletion.** Removal semantics were not qualified and no removal function is bound. Scoped legacy remediation is a separate owner decision. Read-only positive/empty native observations do not prove all future OS/System Events coverage or deployment safety; the independent BTM, LaunchAgents, cron and process checks remain required.

Native BTM enumeration, `/usr/bin/dsmemberutil` membership queries and the CoreServices job-GUI probe each have a 30-second bound to allow cold/loaded native services; metadata/cron probes keep their five-second bound. The enclosing reset/admission or persistence-inspection deadline still wins. Timeout or partial output is never interpreted as an empty census or nonmembership; this allowance does not reinstate AppleEvents or grant permissions.

The exact manifest includes the per-UID BTM **header UUID**. Its stability across reboot or BTM-store migration must be established during host qualification, not assumed from one dump. If it changes, admission refuses until explicit re-review/acceptance, baseline reset and requalification. Do not edit the manifest or discard the UUID to force a match.

**Owned services, separately live-verified:** a job-UID developer container can be excluded from the third-party candidate only when every embedded item resolves in UID `-2` to a legacy daemon for one of `org.macserve.controller`, `org.macserve.worker`, or `org.macserve.maintenance`. The exact `16.<label>` identifier, `/Library/LaunchDaemons/<label>.plist` URL and configured-helper executable path must match. The plist/helper and ancestors require protected root ownership, no group/other writes, no symlinks and no ACLs. XML plist Label/first ProgramArguments entry (and any Program override) must match. The helper's opened-file device/inode must equal the `os.Executable()` file of the binary performing inspection, so inspecting from a separate staged binary does not satisfy this check.

This is not a digest/signature exception for arbitrary code. No new digest field is introduced: root tampering is outside the job-UID persistence threat model, and file identity is not attestation against hostile-root image replacement. Mixed, missing or foreign references still refuse. Only verified owned notification metadata is excluded; third-party records still require explicit review, and live owned checks repeat before and after native inspection. All three owned labels are supported when enabled later; no requirement that they remain unloaded/disabled is introduced. Requalification, review and separate rollout approval remain required; this change performs no install, reset or enable operation.

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

2. As administrator, run the **background job probe**. The job account's GUI must be logged in, and the console must be held by the owner or by the login window (after the owner logged into the job account, use Switch User to return to the login window or the owner). Nobody types in the job session:

   ```sh
   sudo /bin/launchctl asuser "$JOB_UID" /Library/macserve/bin/macserve \
     _qualify-job-probe "$SESSION_ID"
   ```

   `SESSION_ID` is the session directory's name (`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`); it is the only input. The root launcher refuses unless it is the installed binary, has no `SUDO_*` environment, runs in the job's GUI audit session and the console is the owner's or the login window's. `launchctl asuser` adopts the user's "security audit session" (launchctl(1)); in XNU, joining a session replaces the process's whole audit info, audit user included (`audit_session_join_internal`, `bsd/security/audit/audit_session.c`). The launcher accepts **either** audit user = job UID **or** audit session = the job GUI login session as measured by root from the job's own loginwindow (`auditon(A_GETPINFO_ADDR)`) and/or launchd's `security context` for `gui/JOB` (the two must agree when both are available). A plain `sudo` or a root SSH session matches neither and refuses. The job child's audit identity must equal the verified launcher's. It then runs the probe through the production job path: `_job-exec` drops to the job UID and primary group with **no supplementary groups** and execs under `taskpolicy -b`, exactly like CI jobs. Root captures the report into the session (`job-probe.json`, `job-launch.json`, root-owned). A launch refused before the probe runs (wrong context, console, sudo, stale session) can be retried in the same session once fixed; an attempt that actually ran the probe, whatever its outcome, consumes the session, so begin a new session to retry it. To validate this on a host before any round, run the read-only self-test: `sudo /bin/launchctl asuser "$JOB_UID" /Library/macserve/bin/macserve _qualify-job-probe --self-test`. It runs every launcher check and the production credential drop, prints one JSON report (audit user and session, measured GUI session, child groups, console, `would_accept`) and writes nothing. A probe run in the job account itself is never evidence: `qualify probe --role job` refuses, and `collect` reads only the root capture.

3. As the owner (over SSH is fine), run controls, then stop the receivers gracefully in their original terminals:

   ```sh
   /Library/macserve/bin/qualify.sh probe --session "$SESSION" \
     --role owner --out "$HOME/owner-probe.json"
   ```

4. With enabled profiles, as administrator and with the broker stopped, run the pinned recipes (see **Tool evidence** below):

   ```sh
   sudo /Library/macserve/bin/macserve _qualify-tool-evidence "$SESSION_ID"
   ```

5. As administrator, collect the owner report and the required file-only owner-home receipt. `RECEIPTS` is that real file, optionally followed by comma-separated UDP receipt files; it is not sample JSON. Optional network receipts cannot substitute for the independent owner-home controls:

   ```sh
   sudo /Library/macserve/bin/qualify.sh collect --session "$SESSION" \
     --owner "$OWNER_REPORT" --receipts "$RECEIPTS"
   sudo /bin/cat "$SESSION/candidate.json"
   ```

Collection preserves bounded snapshots, hashes and current boot/baseline/profile bindings; inspect every artifact and status. Candidate `boundary-evidence.json` and `qualification.json` are **not approvals**. Network results are retained under `network_reachability` with status `not enforced in phase 1`; they do not gate approval. Unexpected owner-home access, failed Unix boundaries, missing file controls or unsupported non-network security observations still cannot be overridden by an attestation. Unix permission denial is not a claim that a disabled worker's credential-bearing API was exercised.

An incomplete collection can be retried in the same unexpired session after resolving its input error. Collection snapshots use immutable `collect-<random-id>-*` names, including receipt bytes that fail validation; evidence already saved by failed attempts remains available for inspection. Only the successful attempt's input hashes enter the candidate. Partial summary files are not a commit: `candidate.json` is published last. Once it exists, recollection refuses; begin a new session for another probe round, even if the completed candidate contains failed categories.

The persistent `.lock` file uses a nonblocking advisory lock, released by the kernel when the process exits. Do not delete it during collection. An old-version `.lock` directory or an unsafe lock object is refused, not automatically removed; preserve that session for reviewed recovery. Retries do not extend challenge expiry or relax live-binding checks.

Each boundary `artifact_sha256` identifies a preserved `category-<name>.json` manifest of the exact underlying artifact hashes. Session storage is under the accounted `var` tree; do not move generated mutable evidence outside the service budget to avoid accounting.

Read/list probes use nonblocking, no-follow opens. Missing paths and unsupported object types are not permission-denial proof, and a FIFO cannot stall the probe waiting for a peer.

**Console state (v0.1.13).** Jobs run only in the job account's *background* GUI domain. Admission, `worker-reset` and probes refuse, and maintenance health is invalid, while any account other than the owner holds `/dev/console` (the login window, owned by root, is accepted). A foreground job session is never a qualified state, so there is no foreground switch left to qualify and the `fast_switch` category was removed in schema 4. A job already running when someone switches to the job account is not cancelled; no new job is admitted until the console returns to the owner or the login window.

**Tool evidence.** Enabled profiles need real recipe runs. `_qualify-tool-evidence SESSION_ID` (root, broker stopped) runs each enabled profile's prepare/run recipe through the production worker engine (admission, workspace, `launchctl asuser` + `_job-exec`, `taskpolicy`, cleanup and quarantine) on source archives pinned by `/Library/macserve/config/qualification-sources.json` (root-protected; per profile `profile`, `commit`, `tree`, `sha256`, `size_bytes`) and stored root-owned as `/Library/macserve/qualification-sources/<sha256>.tar`. The engine verifies the archive's size, sha256 and git tree before any recipe runs. The pin file's digest is bound into the challenge at `begin`. Each run is capped at the profile's default timeout and the time left in the challenge minus 15 minutes; the measured v0.1.11 compile of both profiles took about five minutes. `tool_profiles` passes only when every profile succeeded with clean cleanup, the exact profile digest and the pinned Xcode. Nothing is attested by hand.

A run that fails records `runs[].failure` in `tool-evidence.json` (v0.1.14): `command_index` (the failing command's index in `result.commands`, in run order: observe probes, simulator commands, prepare, run; the first observe probe, index 0, is the Metal toolchain probe below, so `xcodebuild -version` is index 1), its `executable`, `args`, `exit_code` and `signal`, and `stderr_tail`, the last 4 KiB of the run's root-captured `evidence/stderr.log`. The run's export is removed afterwards, so this is the record diagnostics can export. Job commands see `USER` and `LOGNAME` set to the job account (resolved from the configured job UID); without `USER`, XcodeGen exits 1 with `Couldn't find current username` (v0.1.13). `SHELL`, `__CF_USER_TEXT_ENCODING` and the GUI session's launchd variables such as `SSH_AUTH_SOCK` are deliberately not set.

Every job's `HOME` and `CFFIXED_USER_HOME` are a fresh, empty directory in the job workspace. Since Xcode 26, `xcrun` and `xcodebuild` use the downloaded Metal toolchain only if `~/Library/Developer/Xcode/XcodeToMetalToolchainIndexMapping.plist` exists (Apple FB20389216); without it, any `.metal` source fails with `cannot execute tool 'metal' due to missing Metal Toolchain`. Before any other job command, the worker therefore runs the fixed `/usr/bin/xcodebuild -showComponent MetalToolchain` as the job, with the job environment and pinned `DEVELOPER_DIR`, bounded to 30 seconds. This writes the mapping into the job home, which is deleted with the workspace. The reported `Status:` and `Build Version:` lines are recorded as `observation.metal_toolchain` in the job result. A failing probe, or a status other than `installed`, is recorded in `metal_toolchain.error` or `status` and never fails the job, so projects without Metal sources keep building. Contamination or unconfirmed process cleanup still fails it. The toolchain itself is installed host-wide by the administrator (`xcodebuild -downloadComponent MetalToolchain`); jobs never download it.

### Sitting 3: repository/App enrollment and real recipe evidence

Review the installed numeric repository/public-key pins, actual GitHub App enrollment and trust rules in section 5. The installer does **not** invent App credentials, policies, recipes or test outcomes. An empty registry admits no recipes; tool inspection then records the exact observed Xcode version/build and zero qualified recipes. Adding an actual approved profile changes the exact qualification binding and requires that profile's real recipe/UI evidence. Selected-repository App credential/config provisioning remains an explicit separate enrollment operation, not an installer side effect.

Apple helpers in the job GUI session may exit on their own during a round or between jobs (issue #27: a KeepAlive `corespeechd` crashed itself and launchd relaunched it under a new PID). Since v0.1.9 an audited PID that is simply absent is recorded, not refused: `begin`/`collect` snapshots and live health observations list it in `observation.baseline_exited` (PID and start token), and broker cleanup and admission continue. An audited process (same PID and start token) now under another UID or a zombie still refuses everywhere. An audited PID number now held by a different process (changed start token) is not the audited process: the kernel recycles PID numbers once its PID counter wraps, which the build host does several times a day under job load (macserve#108, where every such wrap during a job invalidated health and cancelled the job). Since v0.1.42 that holder is classified by its own UID like a process on any other number: another UID's process is ignored, and a job-UID process is launchd's verified relaunch under the rule in section 3, a tolerated launch, or residual (the job's, terminated by cleanup), while the audited process stays exited and unresolved. Only worker-reset still refuses any other holder of a selected PID number. Launchd relaunches are handled by the rule in section 3. The baseline file and its digest are never rewritten for exits or relaunches, so these never require requalification.

Tool inspection and recipe runs may leave long-lived job processes: audit them and use the existing reset explicitly, never auto-adopt them. Collect a fresh round after configuration/profile/baseline changes. `reboot` stays pending until a sitting on a later boot, so no production approval is available yet.

### Sitting 4: planned cold reboot, repeat, explicit approval

Reboot (`fdesetup authrestart` or FileVault unlock at the console), log into the job account, then Switch User back to the login window or the owner. Keep admission disabled and use the **same** `worker-reset` command above. Begin a fresh `after-reboot` session with the reviewed endpoint arguments and `--previous` pointing to the preserved preboot collected session, and repeat the full round.

`reboot` is machine-checked at `collect`: it passes when the predecessor sitting was collected on a different boot, with both the `kern.boottime` digest and `kern.bootsessionuuid` changed (a clock step alone cannot pass), or when the predecessor passed `reboot` on this same boot. A challenge expires after two hours; predecessors are bounded to seven days.

Inspect the final candidate and preserved evidence, then the owner's **one explicit root command** installs the approval records and the activation anchor:

```sh
sudo /bin/cat /Library/macserve/var/qualification/after-reboot/candidate.json
sudo /Library/macserve/bin/qualify.sh approve \
  --session /Library/macserve/var/qualification/after-reboot
```

Approval refuses pending/failed categories, changed artifacts or current host/profile binding drift and checks the maintenance evaluator. It remeasures read-only coexistence, requiring unchanged running service PIDs and unchanged rule digests wherever both measurements are available, then saves exact final bytes as `approved-boundary-evidence.json`. PF unavailability alone never blocks approval. Approval does not manufacture health, clear `owner.pause`, adopt GUI processes or activate services.

**Activation anchor and requalification after reboot.** `approve` also writes `/Library/macserve/config/activation-anchor.json` (root, 0600). It binds the sha256 of every protected file in `/Library/macserve/config` (except `owner.pause`, the approval records and the anchor) and `/Library/macserve/bin`, the three LaunchDaemon plists and the reviewed persistence manifest, plus the profile digests, job/owner/controller UIDs and challenge parameters (TCP, UDP, allowed endpoints, private paths, socket). It does **not** bind boot-bound facts (boot, baseline digest, evidence, coexistence PIDs, persistence attestation) or the GUI baseline's process set: real audited baselines differ on every boot because Apple helpers start on demand. Instead every audited baseline process must run a SIP-restricted (`SF_RESTRICTED`), root-owned, non-writable executable that is not a shell, interpreter or Terminal; `begin`, `collect` and approval refuse otherwise.

Approval stays boot-bound. After a reboot, with the anchor in place, an administrator can requalify with no owner password: `worker-reset`, `begin --requalify` (chains to the anchored session), the probe round, tool evidence, `collect`, then:

```sh
sudo /Library/macserve/bin/qualify.sh reapprove --session "$SESSION"
sudo /Library/macserve/bin/qualify.sh activation-check
```

`reapprove` performs every `approve` check and additionally requires the live configuration and challenge parameters to equal the anchor, and no earlier approval on this boot (so no job can have run since boot). It never writes the anchor. Any configuration change (release, manifest, profiles, plists, deploy environment, narrowed endpoints or private paths) refuses until the owner approves again. `activation-check` is read-only. Remove the anchor to revoke carry-forward.

**Anchor schema 2.** `approve` writes schema 2: the schema-1 fields plus `carries`, empty after an owner approval. Each entry (`at`, `session`, `from_binary_sha256`, `to_binary_sha256`, `proof_sha256`) records one release carry (below); entries chain from one binary digest to the next, the last one equals the `/Library/macserve/bin/macserve` binding, and no session or proof appears twice. Schema-1 anchors written by earlier releases still verify for `reapprove` and `activation-check`, but cannot be carried: the owner's next approval writes schema 2. Removing the anchor revokes requalification and release carry alike.

## Boundary-preserving releases: path classification

Every release still requires the full owner requalification above unless it is carried (next section). This section describes the source classification the release workflow's carry proof (`checks/carry-proof`) relies on; nothing on the host reads it.

`BOUNDARY.json` at the repository root sorts every tracked file into one class:

| Class | Meaning |
|---|---|
| **B** (boundary) | Creates, enforces, measures or qualifies the isolation boundary, runs as root with job-influenced input, or builds and guards this classification (`assets/**`, `go.mod`, `go.sum`, `.github/**`, `checks/**`, `BOUNDARY.json`, `cmd/macserve/**`, `internal/worker/**`, `internal/maintenance/**`, `internal/qualification/**`, principal authorization, …). A change needs full requalification. |
| **G** (gate tuning) | Health-loop cadence and resource accounting. Empty: enabling it is itself a B change in a fully requalified release. |
| **C** (carry) | Code that reaches root processes only through reviewed seams and cannot choose what a job runs: `internal/worker/job_observation.go`, `internal/worker/report_types.go`, `internal/evidence/{junit,types}.go`. The store, GitHub polling and publication, receipts, source export and the controller stay B because the root worker trusts the job snapshot (repository, commit, source tree, profile, recipe) they produce. |
| **T** (text/tests) | Documentation, licence and tests named for a C/G file. |

Classification is default-deny: an unlisted file is an error. Patterns use `*` within one path segment and `**` for whole segments; an exact path beats a pattern without `**`, which beats one with `**`, and more literal characters win within a tier. Two classes matching at the same specificity is an error.

`go test ./checks/boundary` (a named CI step) enforces it on the darwin/arm64 build:

- every tracked file is a regular file with exactly one class; symlinks and submodules are refused; C and G hold only non-test Go source; a T test file is named for a C or G file beside it;
- C and G files import none of `unsafe`, `syscall`, `golang.org/x/sys/...`, `os/exec`, `os/user`, `plugin`, `runtime/debug`, `github.com/ebitengine/purego` or the hostguard, peercred, pfctl, deploy, qualification and launchctlprint packages (G files may use only the `syscall`/`x/sys` identifiers listed in `g_calls`), and use no cgo or compiler directives (`//go:linkname`, `//go:embed`, `//go:generate`, …);
- C and G files declare no `init` function and no methods at all (no method on a boundary type, and no `MarshalJSON`, `String`, `Error` or other method through which a C/G type could change how boundary code handles it), and no package-level initializer other than constants, literals, conversions, `errors.New` and `regexp.MustCompile`;
- boundary code hands C/G code only values and capabilities and writes back what it returns (`(*execution).observe` in `execute.go` calls `observeToolchain` in `job_observation.go`). So a C/G function or function literal takes and returns no type that can reference boundary state: a pointer, slice, map, channel, function or interface reaching a boundary-declared type, a boundary value type that itself holds a reference, or an empty interface;
- C and G files never write through anything rooted in a boundary-typed value (assignment, `++`/`--`, `&`, `append`, `copy`, `delete`, `clear`, channel send, pointer-receiver method call or method value); they never assign to or take the address of a package-level variable declared outside C/G, and read one only if its type holds no references (`error` variables excepted); they never assert or type-switch to a type that involves a boundary type;
- in the root packages (`internal/worker`, `internal/maintenance`), C and G files call only C/G declarations, the `seams` listed for that package, and the std packages `bytes`, `context`, `encoding/json`, `errors`, `fmt`, `io`, `maps`, `regexp`, `slices`, `sort`, `strconv`, `strings` and `time`; calls through function values not declared in C/G are refused. Elsewhere they call no boundary function of the module except listed seams.

`internal/maintenance/maintenance_invariants_test.go` (B) pins what any health-timing change must keep: the published lifetime stays within the controller's 45 s acceptance window, a probe that failed without evidence never keeps expired or invalid health and a finding never keeps any, and removing any single boundary fact makes `Evaluate` publish invalid health.

Because the workflows, `checks/**`, `BOUNDARY.json` and every test not named for a C/G file are B, a release cannot weaken these checks and still be classified as carry.

## Boundary-preserving releases: release carry

A release whose changed files are all C, T (or G) relative to its predecessor, by the release's `carry-proof.json` (or an administrator's), can keep the owner's qualification. Only `bin/macserve` is replaced; config, plists, `qualify.sh`, the GUI baseline, the reviewed manifest, `qualification.json`, `boundary-evidence.json` and the job GUI session are kept. The native verbs re-measure the new binary; none of them writes the approval records, `owner.pause`, launchd or PF:

```sh
# Services booted out, before the swap (predecessor binary):
sudo /Library/macserve/bin/macserve worker-quiescent --config /Library/macserve/config/worker.json
# After the swap (new binary):
sudo /Library/macserve/bin/qualify.sh begin --carry --session "$SESSION" --env /Library/macserve/config/deploy.env --owner-canary "$APPROVED_CANARY"
sudo /bin/launchctl asuser "$JOB_UID" /Library/macserve/bin/macserve _qualify-job-probe "$(basename "$SESSION")"
sudo /Library/macserve/bin/macserve _qualify-tool-evidence "$(basename "$SESSION")"
sudo /Library/macserve/bin/qualify.sh carry --session "$SESSION" --proof /path/to/root-protected/carry-proof.json
```

- `worker-quiescent` is read-only. It runs the broker admission census against the audited GUI baseline and prints a JSON report. It fails on any job-UID process outside the baseline (after verified relaunches and tolerated launches are filtered out), and also when the worker is quarantined or its admission is inconclusive. It never signals, adopts or quarantines. The maintenance census (`ObserveGUIBaseline`) tolerates active-job processes; this one does not.
- `begin --carry` refuses with `--previous` or `--requalify`. It must run as the installed `bin/macserve`, whose digest it records in the challenge. It chains to the anchored session and requires a schema-2 anchor whose bindings equal the live ones except exactly `bin/macserve`; fewer than 5 carries and less than 14 days since the owner's approval; the approved session's owner canary; and the installed `qualification.json` from this boot and this GUI baseline. Its full persistence scan is the strict build rebind (see `docs/persistence-policy.md`), not the explicit scan. A carry sitting is never collected, approved or reapproved.
- `carry` runs once per sitting under the session lock. It and the sitting's tool evidence must run as the binary the sitting began with (tool evidence records its digest). It requires a fresh carry challenge with the installed deployment environment; the same carryable configuration, cap and anchored parameters; a proof (`schema` 1, `kind` `release-carry-proof`, `release_effect` `QualificationCarried`) whose `from.binary_sha256` is the anchored binary and `to.binary_sha256` the installed one, with only C/G/T changes; a launcher-captured job report denying every protected socket, private path and owner-home target; for every enabled profile a successful tool-evidence run with the approved session's Xcode, SDK, OS and runtime identities; and valid health with the kept approval. It then preserves the proof and the intended anchor in the session, rewrites the anchor (only if it is byte-equal to the one checked) with only the `bin/macserve` digest rebound and one appended `carries` entry (`proof_sha256` = sha256 of the proof bytes), runs `activation-check`, and writes `carry.json` (anchor digests before and after, carry index and cap).

`approve`, `reapprove` and `carry` take one global anchor lock, `/Library/macserve/var/qualification/.anchor.lock`, without waiting. A commit that finds it held refuses as busy and changes nothing. `carry` also re-reads the anchor under that lock and writes its evidence and the new anchor only if the bytes still equal the ones it checked. The host does not authenticate the proof beyond its digest: `macserve upgrade` takes it only from the release's `carry-proof.json` asset listed in the `SHA256SUMS` you give it, so verify the release attestations of `SHA256SUMS` and `carry-proof.json` first (below); an administrator who supplies a proof directly to `qualify carry` produces it off-host and verifies the committed anchor against it independently. Every refusal before the anchor rewrite leaves the anchor unchanged. If `activation-check` fails after the rewrite, `carry` reports it and writes no `carry.json`; the session keeps `carry-proof.json` and `carry-intent.json`. In both cases the administrator falls back to the full requalification, which removes the anchor. After a later reboot, `begin --requalify` and `reapprove` still chain to the owner's session.

The release workflow builds `carry-proof.json` with `checks/carry-proof` and publishes it, with its digest appended to `SHA256SUMS`, only when the release qualifies; otherwise the release publishes without it. `macserve upgrade` accepts a carry only from that asset. The generator classifies every path whose mode or blob differs between the predecessor tag (the highest lower `vX.Y.Z`) and the tag by the predecessor's `BOUNDARY.json`, default-deny, and writes no proof for a B or unlisted path, a symlink or submodule change, a missing or changed `BOUNDARY.json`, or no change. It also requires the codeload source archive of both tags to equal their git trees (`source_sha256` is that archive's digest), the full boundary check, C/G source rules included, to pass on the tag's source, the predecessor's `macserve-darwin-arm64` digest from its own `SHA256SUMS` to differ from this one, and a completed successful `.github/workflows/ci.yml` run on the tag commit. To check a release locally: `go run ./checks/carry-proof -repo jerryfane/macserve -tag vX.Y.Z -binary-sha256 HEX -rebuilt-sha256 HEX -out carry-proof.json`.

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
  --job-real-name "${JOB_REAL_NAME:-macserve build}" \
  --owner-user "$OWNER_USER" --owner-uid "$OWNER_UID"
```

The default plan makes no account/home/service queries and changes nothing; it is not proof that names or IDs are available. Account/group names and numeric IDs must be explicit. The script accepts canonical decimal IDs 501–999999999 for controller/job UIDs and GIDs and the existing owner UID; owner/controller/job UIDs must be distinct. Names are 1–31 lowercase ASCII letters/digits/underscores starting with a letter, with reserved names refused. Each service account has a same-named dedicated primary group. The job must not share a primary group with the owner/controller, including their supplementary memberships; `staff`, admin/root aliases and existing identities are not substitutes.

After creation, both service accounts are checked for their approved UIDs and dedicated primary GIDs, supplementary `wheel`/root (GID 0), `staff` (GID 20), `admin` (GID 80), and the other service account's primary GID. The job's directory UID/GID, home and shell are checked independently because a successful `sysadminctl` exit alone does not prove creation succeeded. The job must have no `IsHidden` attribute; unreadable, missing or ambiguous visibility records refuse.

`sysadminctl` may add the new job user to `staff`. After refusing any other prohibited memberships, the helper removes that membership with `/usr/sbin/dseditgroup -o edit -d <job> -t user staff` and re-reads the group list. A failed removal, failed read or remaining `staff` membership refuses. No other membership is silently repaired, and no existing account is adopted. A failed postcheck leaves a partial creation requiring reviewed recovery, not automatic deletion. Verify the actual GUI session's effective UID and full group list during qualification, not only a helper that drops supplementary groups.

Only during sitting 1 may an administrator run the same reviewed command with `--apply`, as root on Darwin with interactive stdin. Apply checks prerequisites and collisions before mutation and refuses existing paths including `/Library/macserve` and the proposed job home. Do not repeatedly apply after a partial failure: retain the plan/output, audit exactly which new objects were created, and arrange a reviewed recovery. Never delete an existing account or reuse an unrelated directory to make a check pass. The job uses `sysadminctl -addUser` with the reviewed UID/GID, `/bin/zsh`, `/Users/<job>`, `-fullName` (default `macserve build`, overridden by `--job-real-name`) and `-password -`; never `-admin` or a password value in argv. The controller remains hidden, non-login, non-admin with `Password '*'`. No owner ACL changes are implicit.

Job qualification and native health identity checks read `AuthenticationAuthority` with `dscl` and require the literal `;ShadowHash;` marker. A missing marker or failed read refuses with `job user not listable at login window`; failed health observations remain invalid. The metadata read itself needs no root privileges. This check does not replace the existing dedicated-group, actual GUI login or qualification requirements.

### Installation layout

All ancestors of protected policy, executable and control-state paths must be root-controlled, non-symlink and non-writable by the job or controller except the controller's own private state. ACLs must not silently undo these protections.

| Path | Owner and mode / purpose |
| --- | --- |
| `/Library/macserve`, `bin`, `config` | root:wheel `0755` |
| `var` | root:wheel `0711` |
| `bin/macserve` | reviewed prebuilt Darwin binary, root-owned executable, normally `0755` |
| `config/controller.json`, `worker.json`, `maintenance.json`, `profiles.json` | root-owned `0644` policy (no embedded secrets); controller configuration and profiles readable by controller |
| `config/qualification.json`, `boundary-evidence.json` | root-approved schema-4 evidence, mode `0600`; no job/controller write |
| `var/broker/gui-baseline.json` | root-private audited GUI baseline, written by the existing reset command |
| `var/qualification/<session>` | root-owned session `0755`; public challenge `0644`, preserved evidence/approval artifacts `0600` |
| `var/controller` and its `secrets` | controller-owned `0700`; only the TLS key `tls-key.pem`, `0600` |
| `config/keyholder.json` | keyholder configuration (identities, paths, the worker seal public key); root:wheel `0644`, no secrets |
| `config/release-scope.json` | owner-written release scope; root:wheel `0644`; not created by deploy (absent: every release receipt is refused) |
| `var/keyholder` and its `secrets`, `receipts`, `release`, `log` | `_macserve_key:_macserve_key` `0700`; `secrets/receipt-key.pem` and `secrets/github-app.pem` are keyholder-owned `0600`; full receipt manifests `0600` in `receipts` |
| `var/keyholder-run` / `keyholder.sock` | `_macserve_key:_macserve_keyrpc` `0750` directory; the socket admits only the controller UID |
| `var/broker/seal-key.pem` | root:wheel `0600` Ed25519 key the worker seals builds with; its public key is pinned in `keyholder.json` |
| `var/controller/run/worker.sock` | controller-private executor socket; production peer identity is root, not job UID |
| `var/broker`, `var/exports` | root-owned `0700`, disjoint protected worker state and sealed exports |
| `var/workspaces` | root-owned `0711`; only individual job workspace ownership is transferred |
| `health` / `health/current.json` | root-owned `0755` directory / atomically published `0644` file |
| `/Users/<job_user>` | dedicated job-owned `0700` home; entire home, including `Library`, is accounted |
| `config/signer.json`, `config/signer-policy.json` | optional code signer configuration and admin signing policy; root:wheel `0644`, no secrets |
| `signer-profiles/` | App Store provisioning profiles for the signer; root:wheel `0755` directory, root `0644` files |
| `var/signer` and its `keychain`, `key`, `work`, `log` | `_macserve_sign:_macserve_sign` `0700`; signing keychain, keychain secret and signer receipt key are `0600` |
| `var/signer-run` / `signer.sock` | `_macserve_sign:_macserve_signrpc` `0750` directory / `0660` socket created by the signer |
| `var/signer-inbox` | `<controller>:_macserve_signrpc` `0750`; the controller hands archive and manifest copies to the signer |

`assets/create-users.sh` remains the narrow account/directory helper; `assets/install.sh` verifies the prebuilt binary and adds rendered assets, matching configurations and generated keys without activation. `sysadminctl` creates the GUI job account and may populate its home with normal macOS initial content; the helper enforces job ownership and `0700` on that home. The account helper creates controller-owned `0700` `var/controller/run` and `var/controller/log`, and root-owned `0700` `var/broker/log`. Controller stdout/stderr go to `var/controller/log/controller.{out,err}.log`; worker/maintenance logs go to `var/broker/log/{worker,maintenance}.{out,err}.log`. Keep these logs private and accounted. The controller uses `/usr/bin/false` and is hidden; the job uses `/bin/zsh`. Account/directory creation is nontransactional: use an exclusive approved administration window.

Install a reviewed, checksummed **prebuilt** binary at the fixed path. Verify its digest against a separately trusted release/build record before installation, retain that record, and protect the binary and parents from replacement. Do not install Go or compile the service on the deployed host. Root must never execute target-repository helpers or build tools. Pinned Xcodes are protected installations; the narrowly supported root:admin group-writable `/Applications` ancestor is acceptable only when the job cannot write through that group. Tool executables themselves remain root-owned and non-group-writable.

Install TLS certificate, TLS private key, receipt signing key and App private key as separate files. Public certificates may be root-owned readable policy. The TLS key belongs only to the controller's `0700` secrets directory; the receipt and App keys belong only to the keyholder's `0700` secrets directory; each is a `0600` file. Never give keys, bearer credentials, owner files or source-fetch credentials to a worker lease. Caller API tokens are high-entropy secrets stored by the caller; controller policy contains only their SHA-256 digests. Make any owner-home access restriction a separately reviewed, reversible ACL operation: record existing ACLs and explicit paths first, do not recursively rewrite the owner home.

Keep the owner's home at **0700**, or **0750 with an owner-private group that is not staff and excludes the job account**. Audit ACLs for access grants; mode bits alone do not override an ACL. Any permission/ACL change is a separately approved owner action, never an installer side effect.

### Disabled launchd templates

`assets/install.sh` calls the verified prebuilt binary's `deploy-install` command to render the reviewed `assets/launchd/org.macserve.{controller,worker,maintenance,keyholder}.plist.tmpl` files, plus `org.macserve.signer.plist.tmpl` when `deploy.env` declares the code signer (see [Code signer](#code-signer-optional-signed-testflight)). Rendering is literal substitution of recognized markers only; unknown or unresolved `{{`/`}}` markers refuse. Apply runs `/usr/bin/plutil -lint` on every rendered plist before installing it root-owned under `/Library/LaunchDaemons`. No PF template or policy file is rendered or installed.

No deployment Go toolchain or separate JSON/template renderer is needed. Rendering requires unique `Disabled=true` and `RunAtLoad=false` booleans in the plist's root dictionary; nested fields cannot supply or override those activation flags. Inspect the generated files: plist syntax acceptance does not qualify launchd behavior or grant permission to start services.

All templates have `Disabled=true`, `RunAtLoad=false`, conservative restart throttling, fixed PATH, `GOMAXPROCS=2`, umask `077` and background/nice scheduling. Arguments are `/Library/macserve/bin/macserve <role> --config /Library/macserve/config/<role>.json`, where role is `controller`, `worker` or `maintenance`. Staging is not bootstrap, GUI login or authorization to start. Review launchd's existing per-label enabled overrides too; a disabled plist alone must not be mistaken for proof of a disabled loaded service. Do not bootstrap or enable any label until the gates below are met.

## 2. Supply matching protected configurations

The installer supplies matching initial JSON configurations and `{"profiles":[]}` from the reviewed environment; no hand-written configuration JSON is needed for disabled staging. The contracts below are for inspecting generated policy and separately reviewed enrollment/changes. Unknown fields are rejected. Do not paste angle-bracket metavariables as usable JSON.

**`worker.json`:** `socket` = `/Library/macserve/var/controller/run/worker.sock`; `controller_uid`, `job_uid`, `job_gid`, `owner_uid` = the approved numeric identities; `root` = `/Library/macserve/var/broker`; `export_root` = `/Library/macserve/var/exports`; `workspace_root` = `/Library/macserve/var/workspaces`; `helper_path` = `/Library/macserve/bin/macserve`; `baseline_path` = `/Library/macserve/var/broker/gui-baseline.json`. Optional timing fields are `poll_seconds` (default 2, range 1–30), `heartbeat_seconds` (default 5, range 1–5), `request_timeout_seconds` (default 10, range 1–10). Protect the helper and state first; initialize the protected baseline with `worker-reset` in section 3 before starting the broker.

**`controller.json`:** `root` = `/Library/macserve/var/controller`; `socket` as above; `job_uid`, `owner_uid`; `profiles_file` = `/Library/macserve/config/profiles.json`; `health_file` = `/Library/macserve/health/current.json`; `listen` = an assigned literal tailnet IP and an approved port; `tls_certificate`, `tls_key` = protected certificate/private-key paths. No wildcard, LAN, public or loopback listener. Optional `allowed_networks` narrows the supported API-client tailnet ranges, not job egress. Optional `pause_file` names a protected owner-controlled dispatch pause marker.

There is no `controller_uid` field in `controller.json`: launchd selects that account, and the worker's `controller_uid` must identify the same dedicated controller. The worker's `job_uid` must match the controller's execution UID, not the controller account or root broker; both configurations must agree on `owner_uid` and `socket`. Keep the fixed paths above: maintenance supports fixed controller/broker/export/workspace roots and health path, and derives the entire job home as `/Users/<job_user>`. A generic alternate worker layout is not an approved maintenance topology.

`principals` is an array of objects with `id`, `token_sha256`, `repositories` (for example `example-org/example-app`), `scopes`, and optional `revoked`. Grant only needed `jobs:submit`, `jobs:read`, `jobs:cancel` and, for `ios_archive` release archives (which also need `jobs:submit`), `release:archive`; reserve `service:admin` for approved operators. `receipt` contains `key_id`, `private_key_file`, opaque `service_id`, opaque `host_id`, `repositories` mapping canonical lowercase repository names to pinned numeric IDs, and optional `verification_keys` mapping key IDs to standard-base64 Ed25519 public keys. Use an accepted Ed25519 PKCS#8 PEM, raw seed/private key or base64 seed/private key for the private signing key. Keep old verification keys deliberately during rotation; remove revoked keys deliberately. Optional `github` is described below.

**`profiles.json`:** strict wrapper `{"profiles": [...]}`; `{"profiles": []}` intentionally disables every profile for staging. Each enabled profile needs `id`, positive `version`, canonical `repo`, `kind` (`build`, `unit_test`, `simulator_ui_test`; `simulator_script` and `ios_archive` are template-only), exact `xcode` (`version`, `build`), protected absolute `developer_dir`, relative `work_dir`, and `run` (`executable`, `args`). Optional `prepare` is an array of the same command objects, `generated_files` contains `path`/`content`, `artifacts` contains `path`/`required`, and `required_tests` lists the expected tests. Simulator profiles pin `simulator.runtime`, `runtime_build` and `device_type`. Budgets are `default_timeout_seconds`, `max_timeout_seconds`, `memory_limit_mib`; qualify the effective normalized values. Recipes are controller policy, never caller-provided argv/environment. Use profile digests from the service's normalized registry/admitted capabilities, not a hash of hand-formatted JSON. Adding or changing a recipe requires fresh qualification, not merely a new config entry.

**Org-level templates (optional `templates` array beside `profiles`):** `{"profiles": [...], "templates": [...]}`. A file without `templates` loads exactly as before, with the same profile digests. Each template has `id` (sharing one namespace with profile IDs), positive `version`, `kind` (`build`, `unit_test`, `simulator_ui_test`, `simulator_script` or `ios_archive`), `owners` (unique lowercase GitHub account logins, for example `["themartianapp","jerryfane"]`), exact `xcode`, protected absolute `developer_dir`, and the same optional budgets and defaults as profiles. A test template (`unit_test` or `simulator_ui_test`) and a script template (`simulator_script`) also pin `simulators`: one to four unique exact `runtime`, `runtime_build` and `device_type` entries with the profile simulator rules; a build or archive template (`ios_archive`) pins none. A template carries no `run`, `prepare`, `generated_files` or `required_tests`: the command line is fixed in code, and a test template's required tests are the job's shard selectors from `.macserve.json`. A job naming a template admits any repository whose owner is listed, with the template's kind and exact Xcode pin, unless that repository has an explicit profile of the same kind (explicit profiles keep precedence). A build-template job has no simulator; a test- or script-template job names one of the template's simulators (an omitted simulator is the first pin, also on idempotent replay) and exactly one `shard`, and `GET /v1/capabilities` lists each test and script template's `simulators`. Script templates default to a 3600-second timeout with a 7200-second maximum, archive templates to 3600 seconds with a 5400-second maximum; UI-test templates default to 2400 seconds with a 3600-second maximum and may set `max_timeout_seconds` up to 7200; other kinds keep the 3600-second maximum. After extracting the source, the worker reads the repository-root `.macserve.json` (see *Onboarding a repository*) and, for a build template, derives `/usr/bin/xcrun xcodebuild (-project P | -workspace W) -scheme S -configuration Debug -sdk iphonesimulator -destination 'generic/platform=iOS Simulator' -derivedDataPath ${DERIVED_DATA} CODE_SIGNING_ALLOWED=NO build`, optionally preceded by `/Library/macserve/tools/xcodegen generate --spec project.yml` and `xcodebuild … -scheme S -resolvePackageDependencies`; test and script template derivations are in *Onboarding a repository*, and the archive derivation in [configuration.md](configuration.md). The usual recipe hardening (`-jobs 4`, forbidden flags, fixed environment) applies. A missing or invalid file fails the job before any command runs with `repository has no valid .macserve.json: …`. The template digest is sha256 of the normalized template's canonical JSON; maintenance observations, `qualified_profiles`, the controller guard, qualification challenges and the activation anchor bind it like a profile digest, so editing a template requires owner requalification. Its qualification source pin (`qualification-sources.json`) is keyed by the template ID and additionally names `repo` (a repository of a template owner); that pinned archive must contain a valid `.macserve.json`. A test or script template's pin also names the `shard` its tool-evidence run executes (on the template's first simulator), and qualification's tool inspection checks the template's simulator runtimes and SDKs; a build-template or profile pin must not name a shard. The worker records the file's sha256, its parsed form and the derived commands in the result observation (`recipe`); the controller re-derives and compares them, and the signed receipt carries `observation.repo_config_sha256`.

**Concurrent script templates:** a `simulator_script` template may set `"concurrent": true` (every other kind refuses it) so its jobs run beside other jobs instead of alone; it is part of the template digest only when set, so templates without it keep their digests, and setting it requires owner requalification. Its scripts must follow the concurrent script contract in [configuration.md](configuration.md#controller-configuration-and-control) (only their own and `MACSERVE_SIMULATOR_ID`'s simulators, nothing on all devices or on CoreSimulator); the worker adopts and deletes the simulators such a script creates.

**Owner-level allowlists for template repositories:** `receipt.owners` lists GitHub account logins whose repositories may be built through templates; every template owner must be listed, and owners require a `github` App. Their numeric repository IDs are not pinned: when fetching the source the controller mints an installation token scoped by repository name and requires the reply to name exactly that repository, owner login and a valid ID, then re-checks `GET /repos/<repo>`; the verified ID is recorded in the receipt. A principal `repositories` entry of the form `<owner>/*` allows submissions for every repository of that owner; exact entries keep working. `github.installations` maps owner logins to App installation IDs (`{"themartianapp": <id>, "jerryfane": <id>}`) and takes precedence over the legacy single `installation_id`, which stays valid. Token permissions are unchanged (contents/metadata/pull_requests read, checks write). PR-comment `policies` remain per-repository and optional for template repositories.

### Onboarding a repository

For a repository owned by an account listed in an enabled, qualified template: commit a `.macserve.json` at the repository root, then submit jobs naming the template ID. That is all. The file is strict JSON (unknown, duplicate or null fields and trailing data are refused; at most 16384 bytes, test and script shards included; a regular file, not a symlink):

```json
{"version": 1, "work_dir": "ios", "project": "App.xcodeproj", "scheme": "App", "xcodegen": true, "resolve_packages": true}
```

`work_dir` is a relative directory (`.` allowed) with the same rules as a profile `work_dir`; exactly one of `project` (`<Name>.xcodeproj`) or `workspace` (`<Name>.xcworkspace`) names a single path component; `scheme` matches `^[A-Za-z0-9][A-Za-z0-9 _.-]{0,127}$`; `xcodegen` and `resolve_packages` are optional booleans. Repository content cannot choose executables, flags, environment, destinations, configurations or signing.

For test templates the file also lists the tests each job may run, in optional `ui_test` (for `simulator_ui_test` jobs) and `unit_test` (for `unit_test` jobs) sections of named shards:

```json
{"version": 1, "work_dir": ".", "project": "Herdr.xcodeproj", "scheme": "Herdr",
 "ui_test": {"shards": {"terminal": ["HerdrUITests/TerminalControlTests", "HerdrUITests/TerminalSearchTests/testEngineAndWiringAgree()"]}}}
```

A section has 1 to 16 shards named `^[a-z0-9][a-z0-9-]{0,31}$`, each listing 1 to 32 selectors (at most 256 per section). A selector is `Target/Class` or `Target/Class/method` (an optional trailing `()`); within a shard it may not repeat, also as `method` and `method()`, nor be a `/`-prefix of another. A test-template job names one shard in its request (`"shard": "terminal"`; required for test templates and refused otherwise). The worker runs `xcrun xcodebuild (-project P | -workspace W) -scheme S -configuration Debug -sdk iphonesimulator -destination id=${SIMULATOR_ID} -derivedDataPath ${DERIVED_DATA} CODE_SIGNING_ALLOWED=NO build-for-testing -only-testing:<selector>…` in prepare (after the optional XcodeGen and package steps) and the same arguments with `-resultBundlePath ${RESULT_BUNDLE}` and `test-without-building` as the run, on the job's own simulator. The shard's selectors become the job's required tests: every selector must match a non-skipped executed case, where Xcode's class-relative case IDs under the plan-rooted suite path (`Plan/Target/Class`) count for `Target/Class[/method]`. The controller reparses the result bundle against them, the signed receipt's `tests.required` carries them, and receipt validation (including the GitHub publication check) compares them on the recipe derived from the recorded `.macserve.json`, not the empty admitted snapshot. A shard the file does not define fails the job before any command runs.

For script templates (`simulator_script`) the file names the script each job may run, in an optional `script` section of named shards:

```json
{"version": 1, "work_dir": ".", "project": "Herdr.xcodeproj", "scheme": "Herdr", "xcodegen": true, "resolve_packages": true,
 "script": {"shards": {"duo-screenshots": {"run": "Tools/ci/duo-screenshots.sh"}}}}
```

The section has 1 to 16 shards with the test shard name rules; each shard has exactly one `run` key, a relative file path (at most 1024 bytes, resolved against `work_dir`) with the `work_dir` character rules and no empty, `.` or `..` component. A script-template job names one shard in its request (`"kind": "simulator_script", "shard": "duo-screenshots"`); its `timeout_seconds` is admitted against the template cap, and the file has no timeout fields. The worker builds the scheme for the job's own simulator in prepare, after the optional XcodeGen and package steps: `xcrun xcodebuild (-project P | -workspace W) -scheme S -configuration Debug -sdk iphonesimulator -destination id=${SIMULATOR_ID} -derivedDataPath ${DERIVED_DATA} build -jobs 4 CODE_SIGNING_ALLOWED=NO`. Immediately before launch the script must be a regular checkout file reached without any symlink (opened with `O_NOFOLLOW`), or the job fails without running it. It then runs `/bin/bash ${CHECKOUT}/<work_dir>/<run>` in `work_dir`, with the fixed job environment plus exactly `MACSERVE_APP_DIR` (`${DERIVED_DATA}/Build/Products/Debug-iphonesimulator`), `MACSERVE_SIMULATOR_ID` (the booted simulator's UDID), `MACSERVE_OUTPUT` (the job-writable `<workspace>/output` directory) and `MACSERVE_JOB_ID`; `PATH` is unchanged. Exit 0 is success. The derived recipe requires the artifact `output`: afterwards the directory is exported as `output.tar.gz` within the usual artifact count and size budgets, and its digest is bound by the receipt artifact digest; a symlink, special file or mount point under it fails the job. A script job has no xcresult, test JSON or required tests; its receipt says tests were not run.

For Flutter templates (a template with a `flutter` pin) the file has a `flutter` section, and only a Flutter template serves a file with one: a Flutter template refuses a file without it and any other template refuses a file with it, at derivation.

```json
{"version": 1, "work_dir": "apps/mobile/ios", "workspace": "Runner.xcworkspace", "scheme": "Runner",
 "flutter": {"app_dir": "apps/mobile", "prepare_ruby": ["scripts/add_call_directory_target.rb"]},
 "unit_test": {"shards": {"all": ["RunnerTests/RunnerTests"]}}}
```

The section has exactly the keys `app_dir` (required; a clean relative directory with the `work_dir` rules) and `prepare_ruby` (optional; at most 8 checkout-relative `.rb` file paths with the script path rules). The layout is fixed: `work_dir` must be `<app_dir>/ios`, `workspace` must be `Runner.xcworkspace` with no `project`, `scheme` must be `Runner` (Flutter flavors and custom schemes are not supported: `flutter build` does not take the scheme), and `xcodegen` and `resolve_packages` must be absent or false. A Flutter template serves `build`, `unit_test`, `simulator_ui_test` and `ios_archive` jobs (not `simulator_script`), and each request must name the template's Flutter version exactly, `"flutter": {"version": "3.41.9"}`, like `xcode`; a request naming a Flutter version for any other recipe is refused. `GET /v1/capabilities` lists a Flutter template's `flutter` version.

Before any command the worker preflights the checkout: `<app_dir>/pubspec.lock` and `<app_dir>/ios/Podfile.lock` must exist as regular single-link files reached without a symlink (opened with `O_NOFOLLOW`), and `Podfile.lock` must have exactly one `COCOAPODS: <version>` line naming the pinned CocoaPods version. A Flutter job also tracks `pubspec.lock` with the other lockfiles, and any lockfile created during the job, at a path that had none, fails it (other jobs keep recording new lockfiles without failing). Every command runs in `app_dir` (Xcode names `ios/Runner.xcworkspace`); prepare, within a 30-minute budget, is `/bin/cp -c -R <sdk> ${WORKSPACE}/flutter-sdk` (the APFS clone Flutter needs writable), then the `flutter-sdk/bin/flutter` script (run with `/bin/bash`) `pub get --enforce-lockfile --suppress-analytics` and `build ios --config-only --simulator --debug --suppress-analytics` (which runs `pod install`), then `<ruby> ${CHECKOUT}/<path>` for each `prepare_ruby` script (a regular checkout file reached without a symlink, checked before it runs), then a test template's `build-for-testing`. A build job runs `xcrun xcodebuild -workspace ios/Runner.xcworkspace -scheme Runner -configuration Debug -sdk iphonesimulator -destination 'generic/platform=iOS Simulator' -derivedDataPath ${DERIVED_DATA} CODE_SIGNING_ALLOWED=NO ARCHS=arm64 build` (plus the worker's usual `-jobs 4 CODE_SIGNING_ALLOWED=NO`), an arm64-only simulator build: `flutter build ios --simulator` and any universal simulator build fail with Xcode 27.1, whose `lipo` refuses the `-verify_arch arm64 x86_64` check of Flutter's `debug_unpack_ios`. A test job runs the usual `test-without-building` on the job's simulator (active architecture only). Xcode 27.1 also rejects the Flutter pod's default `IPHONEOS_DEPLOYMENT_TARGET` 13.0, so the repository's `ios/Podfile` must raise every pod's `IPHONEOS_DEPLOYMENT_TARGET` to at least 15.0 in `post_install` (and commit the resulting `Podfile.lock`). Every Flutter job command gets `FLUTTER_ROOT=${WORKSPACE}/flutter-sdk`, `PUB_CACHE=${WORKSPACE}/pub-cache`, `CP_HOME_DIR=${WORKSPACE}/cocoapods`, `GEM_HOME` and `GEM_PATH` set to the pinned gem tree only, `FLUTTER_SUPPRESS_ANALYTICS=true`, `CI=true` and `PATH=${WORKSPACE}/flutter-sdk/bin:<ruby bin>:<gems>/bin:/usr/bin:/bin:/usr/sbin:/sbin`. After the clone the worker records `flutter --version --machine` (framework and Dart versions, the framework version must equal the pin), `ruby -v` and `pod --version` (must equal the pinned CocoaPods version) in the job observation and the receipt's `observation.flutter`; receipts of other jobs are unchanged.

A template's `flutter` pin is `{"version": "3.41.9", "sdk_sha256": "<sha256>", "ruby_sha256": "<sha256>", "cocoapods_version": "1.16.2", "gems_sha256": "<sha256>"}` (three-part versions, lowercase hex digests of the Flutter release archive, the portable Ruby archive and the gem lockfile the gem tree was installed from). It fixes the root-owned tool layout the admin package installs: the precached SDK at `/Library/macserve/tools/flutter/<version>/flutter`, Ruby at `/Library/macserve/tools/ruby/<ruby_sha256[:12]>/bin/ruby`, the CocoaPods gem tree at `/Library/macserve/tools/cocoapods/<cocoapods_version>/gems` and `pod` at `<gems>/bin/pod`. The worker refuses a Flutter job unless each is root-owned, not symlinked and not job-writable (the developer directory policy), and the job-role `tool_profiles` probe checks the same, reads the SDK's `bin/cache/flutter.version.json`, runs `ruby -v` and requires the pinned CocoaPods gem specification. A Flutter template's tool-evidence source pin is like any template's (repository and, for a test template, shard), and its run must have observed the pinned Flutter and CocoaPods versions.

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

Services are read with `launchctl print system/<label>` and must be verifiably running. Before/after service sets and PIDs must match, timestamps cannot regress, and matching available PF measurements must be unchanged. A measurement unavailable on either side is not a comparison failure and is never described as verified unchanged. Installation and each qualification sitting preserve their own before/after windows, including fresh windows after a planned reboot. Health then requires the same configured services to be running, under any PID, but does not gate on live PF availability or rule digests. A health probe that reads a service between two launchd runs (a well-formed `launchctl print` in a state other than `running`, such as `not running` or `spawn scheduled`, or exit status 113, not loaded) is inconclusive: the last valid health stays until its own 40-second expiry, so a service still down then publishes invalid health. Two root PIDs, a missing or noncanonical PID of a running service, another target, a diagnostic or malformed output remain findings.

`qualification.json` is a root-approved object with these exact fields:

| Field | Meaning |
| --- | --- |
| `schema` | integer `4`; schema-1/2/3 approvals require fresh qualification, never migration |
| `approved_at` | actual approval timestamp, RFC3339 |
| `job_uid` | approved numeric job effective UID |
| `boot` | current kernel boot identity, matching the protected worker baseline |
| `baseline_sha256` | SHA-256 of exact protected `gui-baseline.json` bytes |
| `boundary_evidence_sha256` | SHA-256 of exact approved `boundary-evidence.json` bytes |
| `profiles` | object mapping each qualified profile ID to its normalized registry digest |

`boundary-evidence.json` contains `schema` (integer `4`; schema 3 records fail closed), `recorded_at`, `job_uid`, `boot`, `coexistence` and `probes`. Each probe has `category`, `artifact_sha256`, `status`, `attempts`, `authorized_control_successes` and `canary_receipts`. Required categories are `network_reachability`, `unix_socket_boundary`, `owner_unaffected`, `owner_home_denial`, `reboot` and `tool_profiles`. Network status is exactly `not enforced in phase 1`; its actual reachability/unsupported results are informational. Other categories require `passed`, actual attempts and valid artifact digests. Owner-home denial additionally requires successful owner file controls and zero successful job canary reads. There are no PF-hit counters or network-denial pass criteria.

Supply exactly one probe per required category, no duplicate/unknown categories, and nonnegative integer counts. Digests are 64 lowercase hexadecimal characters. Evidence `recorded_at` must be no later than `approved_at`, and approval must not be in the future. The qualification's profile map must exactly match the observed configured profiles, not an approved subset of an otherwise unqualified registry.

The operator records these only after actual probes, audits the full artifacts, then approves and installs the records root-owned under protected ancestors. Never copy an example digest, guess a value, predate approval or treat the evidence record as a test generator. Missing reboot evidence intentionally prevents first production qualification until sitting 4. Retain prior records/artifacts in access-controlled archival storage instead of overwriting the only incident evidence.

After the approved baseline reset, the future root-only read-only observation command is:

```sh
/Library/macserve/bin/macserve maintenance-observe \
  --config /Library/macserve/config/maintenance.json
```

This command collects protected live facts without qualification/evidence files and without writing health: `job_uid`, `boot`, `baseline_sha256`, `profiles`, `identity_valid`, `baseline_valid`, `accounted_bytes`, `memory_pressure`, `coexistence` and protected `persistence` attestation metadata. It does not run the full persistence collector or renew an attestation; its observation deadline remains eight seconds. It is **not** boundary evidence or approval. `maintenance-observe --coexistence-only --config /Library/macserve/config/maintenance.json` emits only the read-only coexistence state and needs no GUI baseline/profile qualification. Do not install observation JSON as qualification or copy observation booleans into an approval record.

**Schema-3 cutover:** interface inventory is no longer collected or bound by maintenance, qualification or controller admission. VM bridge starts/stops, address/prefix changes and interface name/flag churn do not invalidate boundary qualification, health or active work. This removes an obsolete network gate, not a non-network protection: boot, exact GUI baseline, account separation, profiles and protected evidence remain binding. Qualification, boundary evidence and all challenge/report/receipt/candidate artifacts use schema 4 since v0.1.13 (published health remains schema 3). Schema-1/2/3 artifacts are refused and require new qualification; never rewrite a schema number to reuse old evidence. Informational target matrices still come from the reviewed deployment environment; this is not network isolation.

Maintenance is a root/Darwin-only observer except for its health and protected persistence-attestation publication. It checks boot/baseline process identity, account separation, configured peer services, profile digests, memory pressure and bounded mutable-byte accounting. It never writes PF, adopts processes, runs root Apple build tools or signals a job. Unsupported non-network security observations invalidate health rather than refreshing stale success. Missing/stale/mismatched health blocks admission and cancels active work; unavailable PF alone does not. A probe that failed without evidence (a deadline, the CoreDevice `devicefs` race, a peer service between launchd runs) blocks admission at once and cancels active work from the third in a row, never later than the last valid health's expiry ([#53](https://github.com/jerryfane/macserve/issues/53); see the configuration guide for the classification and bounds).

Published health has `schema`, `job_uid`, `boundary_receipt_sha256`, `boundary_validated`, `checked_at`, `expires_at`, `accounted_bytes`, `memory_pressure`, `qualified_profiles`, `persistence_last_verified`, `persistence_valid`, `persistence_needs_review`, and optional `persistence_reason`, `admission_inconclusive` and `probe_failures`. `persistence_last_verified` is the last successful full scan, not this health tick; revocation preserves that timestamp and does not claim fresh verification. `boundary_receipt_sha256` binds the approved evidence file, not a job receipt or network-isolation claim. Successful evaluation publishes schema 3 and a 40-second lifetime. `probe_failures` counts the probes in a row since the last valid health that failed without evidence: while that health is unexpired maintenance republishes it unchanged with the count, after it publishes invalid health with the count; the controller reports `maintenance_probe_failed` and cancels active work from 3 (at the 10-second cadence before the 40-second lifetime ends). The controller requires unexpired health, age and lifetime no greater than 45 seconds, no check timestamp more than 5 seconds ahead, matching job/profile bindings, validated non-network evidence, valid full-scan attestation and available accounting. Memory pressure or exhausted reservations still block admission. Other failed observations (findings) publish `boundary_validated:false`, `accounted_bytes:-1`, `memory_pressure:true`; they do not create the worker's durable admission-quarantine marker. Never manufacture or manually refresh health.

Accounting walks the fixed `/Library/macserve/var` tree and entire dedicated `/Users/<job_user>` home, including `Library` and diagnostics. It never follows symlink targets or nested mounts, counts hardlinks/overlaps once, charges a regular file its allocated blocks and every other node the larger of logical and allocated bytes (since v0.1.16: a sparse file no longer inflates the census, so Xcode 27's preallocated 37 GiB-logical `CompilationCache.noindex` costs about what it occupies; an APFS clone is charged per inode, which over-counts shared blocks). This is an approximate live budget census, not an isolation snapshot: ordinary writes, creation, deletion, rename and directory timestamp changes do not invalidate health. Concurrent changes may be reflected only in a later sample; budget/free-space thresholds remain enforced by the controller. Unsupported special nodes, real I/O/permission failures, more than 1,000,000 entries, depth over 128 or the observation deadline still fail closed; those support limits are unchanged. Memory-pressure observation accepts the native normal/warning/critical values only; unknown values and sysctl errors fail closed. `memory_pressure` is true only at critical: since v0.1.17 normal and warning both admit, because a large host running other memory-heavy services can sit at warning indefinitely with ample free memory. A build can itself raise pressure; once the kernel reports critical, the next health sample blocks new admission (`host_memory_pressure`) without cancelling the running job.

Any nested mount refuses the census and fails health closed, naming the root and the quoted relative path, with two exceptions. First ([#36](https://github.com/jerryfane/macserve/issues/36)), a real Xcode/`devicectl` run by the job user starts its `CoreDeviceService`, which mounts an FSKit `devicefs` at `/Users/<job_user>/Library/Developer/CoreDevice/DeviceFS` for the life of the job GUI session (`nodev`, `nosuid`, not read-only, mounted by the job user). The census records but never opens or descends that mount, and only when the cached mount table (`getfsstat`, `MNT_NOWAIT`) has exactly one record for its device with type `devicefs`, that exact mount point, the job UID as owner, `nodev`+`nosuid`, and source `devices -- file:///Users/<job_user>/Library/Containers/com.apple.CoreDevice.CoreDeviceService/Data/`. That backing directory is inside the counted home and the FSKit server runs as the job user, so no bytes leave the budget. The same name must still resolve to that mount root after the decision, and the record must be unchanged when the census ends; an accepted mount that disappears or changes in between (CoreDeviceService remounting, the worker unmounting the Metal image below) makes that census inconclusive, never a finding, and the next census decides. Second, Xcode's Metal toolchain image in a job workspace (below), on the same terms with its own exact record: type `apfs`, source a `/dev/disk<N>s<M>` slice, the job UID as owner, `rdonly`+`nodev`+`nosuid`, mounted exactly at `/Library/macserve/var/workspaces/<job>/home/Library/Developer/DVTDownloads/MetalToolchain/mounts/<40 hex digit asset ID>`. Any other nested mount still refuses: another disk image, another FSKit/network type, a `devicefs` at another path, owned by another user or backed elsewhere, or any other mount under `/Library/macserve/var`. Bytes written into the mount-point directory before the mount covers them are not counted, but they still use free space checked by the controller's free-disk gate. Do not unmount the `devicefs` by hand; it goes away when the job user logs out or the host reboots. No cleanup path enters the job home's `Library/Developer`. Workspace cleanup refuses any other nested mount under a job workspace (including its `home`) before deleting. `worker-reset` clears `~/Library/LaunchAgents` without following links or crossing mounts: any nested filesystem there (or a mount on `Library`/`LaunchAgents` itself) is contamination, and nothing is removed.

**Xcode's Metal toolchain image in a job workspace.** Xcode 27 installs the Metal toolchain once per host (the owner's `xcodebuild -downloadComponent MetalToolchain` during setup) as a MobileAsset cryptex under `/System/Library/AssetsV2/com_apple_MobileAsset_MetalToolchain`. It is not mounted at boot: the first `xcodebuild`/`xcrun` after each boot that needs it asks `cryptexd` to personalize and mount it system-wide at `/private/var/run/com.apple.security.cryptexd/mnt/com.apple.MobileAsset.MetalToolchain-<version>`. When that first use is a job's (in practice the job's Metal toolchain probe, `xcodebuild -showComponent MetalToolchain`, with `HOME` = `<workspace>/home`, which has no `~/Library/Developer/DVTDownloads/Personalization` manifest), that attempt can fail, and Xcode's automatic mount method falls back to attaching the asset's disk image itself, as the job user, at `$HOME/Library/Developer/DVTDownloads/MetalToolchain/mounts/<asset ID>` (read-only, `nodev`, `nosuid`, `noowners` apfs, "mounted by" the job user). It outlives that `xcodebuild`, and the job's later commands may use it; once the system-wide cryptex is mounted, later jobs mount nothing. Through v0.1.42 the workspace budget walk refused it (`mount point in workspace: "home/Library/Developer/DVTDownloads/MetalToolchain/mounts/<asset ID>"`), cleanup quarantined the workspace (`job-user contamination observed: foreign workspace entry`) and `worker-reset` kept refusing until the owner unmounted it by hand; it happened at the v0.1.40 and v0.1.42 after-reboot qualification rounds. Now the workspace budget walk and the evidence pass record that exact mount (the same mount-table rule as the census above) without descending or charging it; the lockfile walk, the prepare pass and every other mount still refuse. Cleanup (after a job, in recovery and in `worker-reset`) first unmounts it as the job, `/sbin/umount <mount point>` without force (the kernel lets only a mount's owner or root unmount it, so this can do nothing the job could not), after opening `home/Library/Developer/DVTDownloads/MetalToolchain/mounts` without following links or leaving the workspace device; then the cleanup pass refuses anything still mounted. A failed unmount, or a mount still present afterwards, fails cleanup without contamination and keeps the workspace for recovery to retry. The disk image device stays attached, unmounted, until reboot.

Accepted residuals of this exemption ([#38](https://github.com/jerryfane/macserve/issues/38)): (1) the check trusts the kernel-recorded type and source strings, so it assumes only Apple's signed CoreDeviceService produces a `devicefs` on a qualified host; installing another FSKit module needs administrator approval the job account lacks, and anything hidden is still bounded by the free-disk floors; (2) the record match is exact, so a future macOS that changes the source format fails closed (health invalid, no work admitted) until the rule is updated; the fixtures were probed on macOS 27.0 (26A428); (3) bytes shadowed under the mount point stay outside the 80 GiB accounted budget while the mount is live, bounded by free space above the 100 GiB cancellation floor.

**Full Disk Access on SIP hosts ([#35](https://github.com/jerryfane/macserve/issues/35)).** With SIP enabled, macOS privacy protection (TCC) denies even root access to protected data the job's Xcode/simulator runs create in its home (for example containers), and the census fails closed with `operation not permitted` naming the path. Before qualification, in System Settings > Privacy & Security > Full Disk Access, add `/Library/macserve/bin/macserve` (the root launchd daemons are charged to that binary) and the terminal app used for `sudo /Library/macserve/bin/qualify.sh attest`/`approve` (those runs are charged to the terminal). Recheck the grant after every binary upgrade; it can be lost when the binary is replaced. Without it, maintenance health stays invalid and admits no work.

After replacing the native binary, verify health in its **launchd context**, not just an interactive terminal. The Studio's interactive `maintenance-observe` and `qualify activation-check` passed while background checks were denied Full Disk Access, despite an ON entry in Settings. Removing and re-adding only the current `/Library/macserve/bin/macserve` entry, with owner approval, restored valid daemon health without a restart. An ON switch alone is not admission proof; do not reset TCC globally or bypass the census.

The full persistence scan runs in a separate maintenance background task every six hours, with a fixed 480-second deadline. A cross-process `persistence-attestation.json.scan.lock` serializes the initial observation, scan and publication, including explicit qualification/reset scans. Acquisition polls `LOCK_NB` under a context deadline; contention refuses the invocation without revocation. The separate short publication lock is also bounded. Health reads the protected atomic record without acquiring either lock, so a long scan or held lock cannot block the eight-second tick. Neither lock is the worker admission lock.

The hot registration/claim, pre-job and post-job path shares one fixed 30-second budget: before/after authority observations, cron, OS metadata and the entire root/ancestor ACL stage each get two seconds; login items gets six, BTM eight, and each of six membership commands one. Every stage also honors the enclosing deadline. An ACL stage its two seconds cut short starts again, re-probing every root and ancestor, with a fresh two seconds, at most three in all; one still cut short leaves the verdict to the worker's idle check instead of failing the job's cleanup (docs/architecture.md, Cleanup). It freshly checks exact accepted BTM records/identities, zero legacy items, LaunchAgents/crontab, membership, and registration-root/ancestor ownership, modes and ACLs; no descendant walk or hashing. Timeout, unavailable `sfltool`, incomplete diagnostics or other transient inspection failures refuse this admission but do not change the last attestation. A positive observed mismatch (new/removed/changed registration, job-writable root/ancestor, forbidden membership, legacy item, LaunchAgent or crontab) durably revokes it.

The protected attestation binds the accepted manifest to boot and relevant identities/version. Missing attestation blocks admission and schedules an initial full scan. Full-scan mismatch revokes only the exact revision inspected; compare-and-swap prevents a stale failure from overwriting a newer valid scan or review. Explicit scans (qualification, reset) also revoke on collection failure. The periodic maintenance scan revokes on contamination at once, but a failure that observed nothing (deadline, a background registration changing mid-scan, incomplete inspection, maintenance stopping) leaves the attestation in place and is retried 10 minutes after it ended; the scan after three consecutive such failures revokes on any failure (`inspection_unavailable`). A verified scan resets the count. One inconclusive scan took the Studio out of service on 2026-11-08 until an owner sitting although nothing had changed. Reason precedence is explicit: `reset_required` > `mismatch` > `authority_changed` > `inspection_unavailable`; a later weaker error cannot replace the stronger reason, and revocation preserves the last successful verification timestamp. `authority_changed` reports binding drift, never permission to clear the record. Periodic scans never silently undo revocation.

Recovery: preserve the failure evidence, inspect and explicitly approve/accept the current registrations, then run the approved GUI-baseline reset and requalification flow. Acceptance establishes a new `reset_required` revision, even when the reviewed manifest bytes are unchanged; only successful explicit reset completes that recovery. A transient hot-path refusal needs no re-review unless a later observation finds positive contamination. Reset does not implicitly erase an unrelated quarantine. Do not edit/delete attestation or lock files to resume admission. There is no FSEvents watcher or TTL-cache admission substitute.

Qualification `begin`, `collect`, `approve` and `reapprove` perform explicit full verification before their eight-second observation. Their command deadline is 540 seconds, so it does not truncate the 480-second scan; `qualify.sh` execs the binary without a shorter wrapper timeout. External per-operation wrappers allow 600 seconds. If an external procedure runs reset followed by qualification, budget for **two** full scans plus overhead (at least 1260 seconds), not one 600-second wrapper around both. Maintenance's launchd `ExitTimeOut` (the documented case-sensitive key) is 600 seconds so a cancelled background scan can finish protected revocation publication. Inspection, acceptance and reset retain full verification. The protected attestation lives at `persistence-attestation.json` beside the accepted manifest, with a separate `.lock` file; it is not a controller/job-writable cache.
The periodic maintenance operation uses the same 540-second outer deadline, leaving protected publication/revocation headroom outside its worker-enforced 480-second collector deadline.

Budget evidence: a cold native full `collectPersistence` replay took 157.806467208 seconds for all 16 accepted registrations (apps and nested plug-ins/extensions), with zero problems including final rechecks. Three times that observation rounded up gives the fixed 480-second budget. The cheap registration portion took 0.160902417 seconds. The replay ran as the owner with the accepted v016 census substituted as raw input and the installed helper supplying executable context. These timings cover registration checks only, **not** complete login-items/admission: root-only legacy-item and job-home checks were excluded, and no fresh root BTM census was collected. This is not a claim that every native admission prerequisite was exercised.

**Residual trusted-writer window:** root, the owner, and trusted admin/wheel may update code while job/controller writers remain excluded. Descendant changes that leave registration-root protection and accepted BTM identities unchanged are detected by the next full scan, not every job (normally six hours plus scan time; stopped/unavailable maintenance can delay it). Such updates still require explicit review, acceptance, reset and qualification. This design does not promise immediate trusted-writer change detection or protection against hostile root. The six-hour cadence is not an expiry-based admission cache; use the reported last-verification time as historical evidence only.


After preserving and protecting the actual boundary record, a future owner may compute its exact-byte digest with `/usr/bin/shasum -a 256 /Library/macserve/config/boundary-evidence.json` and place the resulting lowercase digest in `boundary_evidence_sha256`. This computes a hash only; it does not authenticate the truth of probes or replace operator approval.

## 3. Initialize/reset the GUI baseline and qualify target tools

During sitting 2, establish an actual job-user GUI login and retain that session while fast-switching to the owner. `launchctl asuser` is not login. Approve only prompts actually required by the pinned tools and intended UI recipe. Do not grant blanket Accessibility, Automation, screen recording or Full Disk Access; record exact consent, target applications and account scope.

During the approved sitting, with admission disabled and the broker stopped, preserve any existing execution records/evidence and audit **every retained** job-UID GUI process: executable provenance, PID and start identity. Include only trusted required long-lived processes. The sole future root administrative initialization/reset command is:

```sh
/Library/macserve/bin/macserve worker-reset \
  --config /Library/macserve/config/worker.json --pids "$AUDITED_PIDS"
```

The three GUI anchors are a minimum, not the complete retained-process audit.
macOS can run a system LaunchAgent that the job account cannot terminate even
when its real, effective and saved UIDs all match. For example, the signed
Safari Safe Browsing service may carry
`com.apple.private.security.signal-exempt=true`. Omitting such an instance
from `$AUDITED_PIDS` leaves it subject to ordinary residual termination;
`EPERM` correctly stops reset.

Do not retry with an exception inferred from the error or executable name.
Before proposing retention, inspect the exact instance's kernel identity,
platform signature, SIP-protected executable, system launch definition and
launchd provenance. Treat signed entitlements as additional evidence, not as
an automatic admission rule. If the owner explicitly approves retaining that
trusted required service, include its freshly audited PID alongside the GUI
anchors in the existing baseline selection. Do not add arbitrary processes or
infer that other processes are signalable merely because this entitlement is
absent. The native reset must still validate the selection, provenance,
environment and final baseline; unselected residuals and unclassified signal
failures must continue to refuse. A failed reset may already have side effects:
preserve its evidence and review recovery before another authorized attempt.

`AUDITED_PIDS` is an explicitly audited comma-separated list of current retained GUI PIDs, never a blind process-list substitution. Reset holds the exclusive broker lock, removes job-home LaunchAgents entries, the job crontab and legacy login items, and terminates extra exact same-UID processes outside the selected baseline. It rechecks selected process start identities, records `job_uid`, kernel `boot` and `processes` with `pid`/`start`, retries owned-resource cleanup, then clears `admission-quarantine.json` only after full clean verification. It never adopts unselected processes or signals owner/controller processes. This is a mutating administrative operation even on first initialization, not a read-only qualification command; retain evidence and approve the job-account cleanup scope beforehand.

**Launchd relaunches (v0.1.9).** For each audited process that is verifiably a system launchd service, reset also records launchd provenance in the baseline (`processes[].service`): domain (`gui` LaunchAgent, `user` XPC service, or `pid` XPC service with its audited `owner` PID), label, launchd `path`, kernel `executable` path, `launch_sha256`, a digest of the exact exec path and arguments from `KERN_PROCARGS2` (since v0.1.11 nothing after argv is read), and `inherited_sha256`, a digest of the `inherited environment` that root `launchctl print` lists for the service. Only LaunchAgents whose launchd path is exactly `/System/Library/LaunchAgents/<label>.plist` and XPC services whose `.xpc` bundle lies under `/System` (not `/System/Volumes`), `/usr` (not `/usr/local`), `/bin` or `/sbin` qualify, and only when the rule below already holds for the audited instance itself; `worker-reset` prints how many audited processes received a record. After an audited PID exits, a new job-UID process stands in for it (cleanup does not terminate it, admission does not refuse it) only if **all** hold: (1) the kernel reports a valid platform binary whose executable is the recorded path; (2) its parent is launchd (PPID 1); (3) it started after the audited process; (4) its launch digest equals the recorded one; (5) root `launchctl print` of the recorded target shows that PID running with the recorded path, type (`LaunchAgent` or `XPCService`) and inherited environment, and kernel facts read again afterwards are unchanged; (6) an XPC service is looked up only in the domain of its audited owner or of that owner's verified relaunch, in any baseline order (owners that are themselves XPC services resolve first). A relaunch that lands on the exited audited PID number is accepted under the same rule. Every other process stays residual and is terminated as before.

**Audited Apple-managed LaunchAgents.** The recorded-relaunch rule also covers
an explicitly selected `gui` or `user` LaunchAgent defined by
`/Library/Apple/System/Library/<app>.app/Contents/Resources/<label>.plist`,
with its executable inside that same app's `Contents` tree. This covers the
observed XProtect service: despite its executable living in an `.xpc` bundle,
launchd runs this instance as a GUI LaunchAgent, not an application XPC service.
Both files and every directory through `/Library/Apple` must be root-owned,
SIP-restricted, non-symlinks and not group/other writable. The native inspector
checks the protected plist's label, enabled state, program and arguments
against launchd and the kernel exec/argv; the recorded identity, platform
signature, inherited environment and final process-identity recheck still apply.
These checks run when provenance is recorded and on each replacement.

This does not make `/Library/Apple` a general system path, automatically retain
unselected services, or forgive signal failures. Explicitly audit and select
required retained instances before reset. An unselected signal-exempt service
still causes reset to refuse; a changed or unverified replacement stays residual.
Static `codesign --verify --strict` rejecting XProtect's obsolete resource
envelope is not silently treated as passing: this native rule uses the live
kernel's valid platform signature plus SIP-protected files and ancestors,
not that distinct static resource-envelope check.

**Reset keeps what survives (v0.1.10).** Reset takes minutes: it removes job persistence, terminates job processes, runs the full persistence attestation, terminates again and audits. Apple helpers in the job GUI session exit on their own in that time, and launchd starts them again on demand (MachServices) or keeps them alive. Reset therefore defines the new baseline from the selection as it survives:

- **Provenance first.** Launchd provenance is recorded from the selected instances themselves before cleanup, while they still run. A Background-session system LaunchAgent in the job's `user` domain (for example `com.apple.TrustEvaluationAgent`, `LimitLoadToSessionType=Background`) now qualifies like a `gui` one: its launchd path must be exactly `/System/Library/LaunchAgents/<label>.plist` with type `LaunchAgent`.
- **Exits.** A selected process that exits during reset is replaced by launchd's relaunch if that passes the full rule above, kept as an exited identity if it has provenance (so its later relaunch is verified), or otherwise dropped. A requested PID already absent when reset starts is dropped instead of refused. `worker-reset` prints every `dropped`, `exited`, `relaunched` and `adopted` entry with PID, start token and path.
- **GUI anchors.** The selection must include the job session's loginwindow, Dock and Finder, and they, plus any selected Terminal or system shell (`/bin/zsh`, `/bin/bash`, …), must still run with their selected identity at the final audit, or reset fails. These are the processes whose exit means the session changed (logout, crash or console loss), not the helper lifecycle; even a verified KeepAlive relaunch of Finder fails reset.
- **Unselected system LaunchAgents.** Excluding an on-demand agent cannot work: reset terminates it and a surviving client makes launchd start it again. So reset records provenance for every unselected process that is a system LaunchAgent in the job's `gui` or `user` domain and still terminates the running instance; launchd's relaunch of it is then verified like a selected one, during reset or later. A new one that launchd starts during reset is kept if it passes the same checks. Either way it must also have been exec'd with exactly launchd's recorded `program` and `arguments`, and root `launchctl print` must list for it exactly the `inherited environment` of the selected LaunchAgents of its domain; a `user`-domain agent without a selected one is compared with the `gui` one minus `SSH_AUTH_SOCK`, which launchd lists only for the Aqua domain (measured on macOS 26.6 and 27.0). A launch that launchctl lists with the job's `launchctl setenv` therefore stays residual. XPC services are never adopted; select them. Outside reset nothing is adopted.
- **Everything else** is terminated as residual, including a relaunch that cannot be verified. Survivors after termination still fail closed with the rule below; a reset failure never writes the quarantine record, and only a successful reset clears it.

Dropping is safe because a reset defines the baseline from what survives it and an exited process cannot be part of any baseline: the job can only end its own UID's processes, which hides or retains nothing, nothing joins the baseline without verification against launchd's own record, and the published baseline is freshly audited after cleanup. A PID held by another UID, a zombie, or a new process on a selected PID number that is not its verified relaunch still refuses. The `launchctl setenv` domain environment is recorded by reset and censused afterwards (see **Domain environment** below).

**Apple-defined launches (v0.1.14).** A build makes launchd start Apple on-demand LaunchAgents in the job's `gui` or `user` domain that the audited baseline never contained. On macOS 27.0 an Xcode build looks up the MachServices of `com.apple.accessibility.heard` (which then respawns every second) and `com.apple.BTServer.cloudpairing`. v0.1.13 treated them as contamination, so every real build quarantined the worker. Outside reset, a job-UID process that is neither audited nor a verified relaunch is now an Apple-defined launch, not residual, only if launchd's own record proves all of the following:

- **Kernel.** It runs as the job UID, with PPID 1. It is a valid platform binary at a system path or, since v0.1.19, a canonical path inside the sealed App cryptex. That file is SIP `SF_RESTRICTED`, root-owned, and neither group- nor other-writable. It is not a shell, an interpreter or Terminal.
- **Launchd.** The `gui` or `user` domain lists its PID. `launchctl print` of that exact service reports the PID and type `LaunchAgent` (never `Submitted`). Ordinary system executables require a plist directly in `/System/Library/LaunchAgents`; App-Cryptex executables require a plist directly in that same image's `/System/Volumes/Preboot/Cryptexes/App/System/Library/LaunchAgents`.
- **Plist.** The plist is itself `SF_RESTRICTED`, read through `/usr/bin/plutil -convert xml1`. It names the label, is not `Disabled` (a feature-flag condition counts as not proven), has no `BundleProgram`, and its `Program`/`ProgramArguments` are launchd's `program` and `arguments`.
- **Exec.** The `KERN_PROCARGS2` exec path is exactly that program string and the argv is those arguments. The program is a system path, or a canonical App-Cryptex path for that class of agent, once redundant separators are removed; it resolves to the kernel executable. v0.1.15: Apple's own plists for `com.apple.cloudphotod` (`.../Versions/A/Support//cloudphotod`) and `com.apple.AquaAppearanceHelper` (`SkyLight.framework//Versions/...`) name their programs with a double slash, and launchd execs them verbatim. v0.1.14 refused cloudphotod when launchd started it on an xpc event after `worker-reset`, and that quarantined the worker before tool evidence ran a recipe. A `.` or `..` component is never accepted.
- **No override.** The service's inherited environment equals the domain environment recorded at reset, which the census has just required to be unchanged, so no `launchctl setenv` was in effect when it spawned. Neither domain's `disabled services` table lists the label (no `launchctl enable` or `disable`).

**App-Cryptex LaunchAgents (v0.1.19).** Apple's `guidedbrowsingd` exposed this case after the approved GUI baseline was recorded: the kernel reports `/System/Volumes/Preboot/Cryptexes/App/usr/libexec/guidedbrowsingd`, while its protected plist and launchd name `/System/Cryptexes/App/usr/libexec/guidedbrowsingd`. Both that system alias and a canonical App-Cryptex program are accepted only when they resolve to the verified executable and match the exact exec path and argv. This is not a process-name exception or general trust of `/System/Volumes/Preboot`: the same-image system LaunchAgents directory and every signature, protection, PID, plist, environment and override check above are required. The separate developer-tool rules remain unchanged.

Anything else stays residual and is contamination as before. That includes a `launchctl submit` of an Apple binary, a home or `/Library` plist under an Apple label, a program or argv override, a setenv, an enable override, and a binary outside SIP. Quiesce signals Apple-defined launches with the residual processes, but it does not wait for them to stay gone, because launchd may start them again on the next lookup. Nothing is added to the baseline: every census verifies each instance from scratch. Reset keeps its own adoption rule.

**Diagnosable refusals (v0.1.15).**

- **Vanished candidates.** Admission recounts its census against a fresh snapshot of the process table. A process that was refused only because it exited (or its PID was reused) before launchd could be asked about it is not contamination. Apple agents can live for 40 ms; heard respawns every second. Such a snapshot is not clean either: admission samples again, at most 10 times, then refuses without quarantine ("admission inconclusive"). The refusal is recorded in `admission-inconclusive.json` and published as health `admission_inconclusive`, like a persisting tolerated child. The record is cleared by the next admission that passes or by `worker-reset`.
- **Listed refusals.** A contamination refusal now lists the refused processes, sorted by PID, at most 8 of them, each field bounded:
  - PID and start;
  - kernel parent and executable;
  - the launchd target found;
  - why the Apple-defined and developer-tool rules each refused it.
- **Where the list goes.** The list stays on the host: in the broker log and `admission-status.json`, in the stderr of root-run qualification commands (and so in the admin diagnostics export), and in the root-only quarantine record `admission-quarantine.json` in the worker root, now `{"quarantined": true, "reason": ..., "recorded_at": ...}`. The record's presence alone quarantines, as before. A job's reason reported to the controller and its API clients says only `job-user contamination: N unexpected process(es); see host diagnostics`.
- **Renamed system plists.** Reset adoption and launchd provenance also accept a system LaunchAgent whose plist is not named after its label, if the SIP plist's own `Label` is that label (AquaAppearanceHelper's plist is `com.apple.AquaAppearanceHelper.agent.plist`).
- **Feature-flag plists.** A system LaunchAgent plist whose `Disabled` value is a feature-flag condition no longer refuses. The condition must be exactly one `#IfFeatureFlagEnabled` or `#IfFeatureFlagDisabled` string, a `#Then` and an optional `#Else`, each `true`, `false` or a nested condition. Examples: `keychain-circle-notification`, `hybridsearchd`, `visualintelligenced`. Feature flags are system state the job cannot set, and launchd runs only a service it loaded as enabled; the running PID launchd reports for the SIP plist is that evidence. The job's `gui`/`user` disabled-services overrides are still refused. A literal `<true/>` and any other conditional key still refuse.
- **Bundle executable default.** An XPC bundle whose `Info.plist` names no `CFBundleExecutable` uses CFBundle's default, the bundle name (RemoteManagement's `ASConfigurationSubscriber.xpc`).
- **OS cryptex.** A `pid`-domain or `user` XPC service whose executable lies in the sealed OS cryptex `/System/Volumes/Preboot/Cryptexes/OS/` is a developer-tool-rule launch under these conditions:
  - launchd names it through `/System`'s SIP symlinks (SafariFoundation's `SafariConfigurationSubscriber`);
  - its bundle path and program resolve into the cryptex;
  - the executable and `Info.plist` are SIP `SF_RESTRICTED`.
  The App cryptex is not covered by this OS-cryptex developer-tool rule. App-Cryptex LaunchAgents require the separate verified same-image definition described above; `/Library/Apple` LaunchAgents (XProtect) remain untrusted.
- **Brief pid-domain services.** Apple services start briefly in the pid domains of audited owners in the idle job session: about 40 in 73 minutes, and 18 to 101 per label since boot. Their bundles were checked statically on the host:
  - `deleted`'s Mail, Music and TV CacheDelete `.appex` extensions;
  - WorkflowKit's BackgroundShortcutRunner;
  - ReportCrashService;
  - VTDecoderXPCService;
  - unilog's and lighthouse's ExtensionKit workers and UnilogConfigXPCService;
  - SAExtensionOrchestrator;
  - FedStatsPluginStatic;
  - PhotosReliveWidget.
  All lie under `/System`, are SIP `restricted`, and their `Info.plist` `CFBundleIdentifier` is the launchd label (or `original`) with `CFBundleExecutable` as the bundle executable. So the developer-tool rule classifies a live instance if launchd's record matches. Their inherited environment is the one part not observed live.
- **App cryptex, pid domains only.** Safari's CacheDeleteExtension lies in the App cryptex. `deleted` starts it in bursts, about 18 times per boot. It is tolerated only as an `XPCService` or `Extension` in a verified owner's `pid` domain, under the same checks as the OS cryptex: sealed path, SIP `SF_RESTRICTED` executable and `Info.plist`, bundle id, and environment. An App-cryptex binary as a `gui` or `user` service stays residual.

Threat model: a job can always make launchd start any Apple on-demand agent in its own domains by looking up a MachService, and have the agent do XPC work for it while the job runs. Quarantine afterwards never prevented that. The rule proves the process is Apple's SIP binary, exec'd by launchd from Apple's SIP plist with Apple's argv and no setenv or enable override: the code that lookup would run in any login session. That is the same exposure as the audited relaunches the census has tolerated since v0.1.9, with stronger cleanup. As with those relaunches, three things are not covered:

- state such agents read from the job home (preferences, caches), which a job can write;
- an agent's own entitlements, used on the job's behalf while the job runs;
- a pending `launchctl debug --environment` for the agent's next spawn, which `launchctl print` does not list as inherited environment.

**Developer-tool launches (v0.1.14).** After quiesce terminates a build's processes, launchd starts the CoreSimulator/CoreDevice XPC stack again on its own about 9 s later (measured on macOS 27.0): CoreSimulatorService, CoreDeviceService, SimulatorTrampoline, SimLaunchHost and remotepairingd in `user/<job>`, SimAudio/SimStreamProcessorService in CoreSimulatorService's `pid` domain, and extensionkitservice and the DeviceFS extension in `fskit_agent`'s `pid` domain. Without a rule the next admission refused them and the worker stopped after its first build. Outside reset, a job-UID process that is neither audited, a verified relaunch nor an Apple-defined launch is a tolerated developer-tool launch only if all of the following hold:

- **Kernel.** Its sampled start, the job UID, PPID 1, `CS_VALID|CS_PLATFORM_BINARY`, not a shell, interpreter or Terminal. The executable lies under `/System` (not `/System/Volumes`), `/Library/Apple/System/Library/` or `/Library/Developer/PrivateFrameworks/`, and its path chain passes the toolchain check for the job UID (root-owned, no symlinks, not job-writable).
- **Launchd.** The `gui` or `user` domain table lists the PID with type `XPCService`, or the `pid` domain of an owner verified in the same census (a present audited service, an Apple-defined launch or another tolerated launch, evaluated to a fixpoint) lists it with type `XPCService` or `Extension`. `launchctl print` of that exact target reports the PID. `Submitted` and `LaunchAgent` never qualify.
- **Bundle.** launchd's path is a `.xpc` or `.appex` bundle under the same roots that passes the toolchain directory check; the executable is `<path>/Contents/MacOS/<CFBundleExecutable>`; launchd's `bundle id` equals the label (or `original` for an `<original>.<UUID>` instance) and the root-owned `Info.plist` `CFBundleIdentifier` (read with `plutil`); the exec path and argv are launchd's `program` and `arguments`.
- **Environment.** For `gui`/`user` the inherited environment equals the domain environment recorded at reset. For a `pid` domain it is exactly `HOME` = the job home, `PATH=/usr/bin:/bin:/usr/sbin:/sbin` and `TMPDIR` = the job's `DARWIN_USER_TEMP_DIR` (`/usr/bin/getconf` run as the job credential). v0.1.15: it also includes the domain environment recorded at reset of the `gui` or `user` domain that lists the owner. On macOS 27.0 the services of a `gui` owner inherit its `SSH_AUTH_SOCK`: RemoteManagementAgent's subscribers and assistantd's media-indexer. A domain entry that would replace `HOME`, `PATH` or `TMPDIR` refuses.
- **No override.** Neither the label nor the original appears in the `gui` or `user` disabled-services table.

Cleanup is as for Apple-defined launches: quiesce signals them but does not wait for them to stay gone, and nothing joins the baseline. Deliberately excluded: `/Library/Developer/CoreSimulator` (simulator runtimes and `launchd_sim` run code the job built) and the Xcode bundle; their processes stay residual. A restarted CoreDeviceService briefly runs `/sbin/mount`. While every residual process is a direct child of a tolerated launch verified in the same census, admission retries for up to 30 s; if one persists, admission refuses without quarantine (inconclusive), and such a child is never tolerated.

Each such refusal also writes the broker-private durable record `admission-inconclusive.json` in the worker root (`reason`, `since` = first refusal since the last admission that passed, `checked_at`). It is not quarantine: no administrator clear is required and every admission runs again. Maintenance publishes its reason as health `admission_inconclusive`, and the controller gate then reports the blocker `worker_admission_inconclusive` in `gate.blockers` of `GET /v1/admin/state` (and `blocked_by` of the service description) without cancelling active work, so a child that keeps running is visible instead of a silently idle worker. The record is removed by the next admission that passes (recovery once the child has exited) and by `worker-reset`, whose cleanup terminates the child. A job never starts while it exists, because its own admission runs before preflight quiesce.

Threat model: the job cannot modify these binaries, bundles or `Info.plist` files (root-owned and not job-writable; SIP for `/System` and `/Library/Apple`). It can only ask launchd to start them over XPC, which it can do anyway while it runs. The residual risks are those of Apple-defined launches: state these services keep in the job home (`~/Library/Developer/CoreSimulator`, CoreDevice), and their entitlements used on the job's behalf while it runs (simulator creation, paired devices).

**SIP-enabled hosts and macOS 27 (v0.1.11).** Supported: macOS 26.6 and macOS 27.0 (26A428), with System Integrity Protection enabled. With SIP enabled, the kernel withholds the `KERN_PROCARGS2` environment of every `CS_RESTRICT` process from every caller, root included. On macOS 27.0 that covers every process under `/System`, `/usr`, `/bin` and `/sbin`: the buffer ends after argv. v0.1.10 parsed that environment, and on such a host it refused every correct selection with `audited selection lacks the job GUI's running loginwindow`; its launchd provenance never verified. v0.1.11 never reads a process environment:

- **GUI anchors** are selected from kernel facts alone: effective UID, start, csops `CS_VALID|CS_PLATFORM_BINARY` and the exact `PROC_PIDPATHINFO` path.
- **Provenance and relaunches** use launchd's own record. Root `launchctl print` of the job's `gui`/`user` domain, or of an audited owner's `pid` domain, names the service for a PID. Root `launchctl print` of that exact service must then show the PID with the SIP-protected plist path, type, program, arguments and inherited environment. The kernel facts and the exec path/argv digest are added to that. A job's `launchctl submit` (path `(submitted by launchctl[N])`, type `Submitted`; its macOS 27 print does not even parse) or a `~/Library/LaunchAgents` copy never qualifies, whatever its environment.
- **Domain environment.** Reset records the root `environment` that `launchctl print gui/<job_uid>` and `user/<job_uid>` list (`launchd_environment` in the baseline), and prints its keys. Review them: launchd's own is `SSH_AUTH_SOCK` in `gui` and nothing in `user`. A later difference (a job's `launchctl setenv`) is contamination at every census: reset audit, cleanup, admission, health and qualification collection. An unreadable domain is inconclusive.
- **Trust limit.** A job that sets a variable, makes launchd launch a service, and unsets it again before the next check leaves no trace in the domain environment. Such a relaunch is refused only if launchd lists the variable in that service's inherited environment. Whether launchd lists the environment from spawn time or the current domain environment is not measured (a probe over ssh could not reach the Aqua domain). Before v0.1.11, this was caught only on hosts where the kernel exposes the environment (SIP disabled).
- **Cutover.** Baselines written before v0.1.11 fail to load (`GUI baseline lacks the job launchd domain environment (written before v0.1.11); worker-reset required`); run `worker-reset` once, which needs a fresh qualification round like any reset.

When job processes survive cleanup, or are present at admission, the broker distinguishes evidence from an inconclusive verification. If every audited process is running or verifiably relaunched, a survivor is contamination: admission is quarantined durably, as in v0.1.8. If an audited process is gone without a verified relaunch (for example a v0.1.8 baseline without launchd records, or a system service whose launchd record does not match), a survivor may be launchd bringing that process back in a way the host could not verify. Cleanup and admission then fail with `audited GUI process exited and a surviving job process could not be verified as its launchd relaunch; worker-reset required`, without writing the quarantine record, which is what v0.1.8 did for any disappeared audited process.

Why the rule binds launchd's record and not just the binary (measured on macOS 26.6): a job can start Apple platform binaries as PPID-1 launchd services under its own UID with `launchctl submit` (launchd path `(submitted by launchctl[N])`, type `Submitted`) or with a `~/Library/LaunchAgents` plist copying the Apple label and program (launchd path in the home; `launchctl print` even lists `system service` among its properties). Platform signing, executable path and PPID alone therefore prove nothing; the exact launchd plist path binds the service to the SIP-protected Apple plist. A job can also run `launchctl setenv` in its GUI domain, which changes the environment of every service launched afterwards; the launch digest covers only the exec path and argv, never the environment. A still-set change to the domain environment is contamination at the next census; a relaunch whose inherited environment differs from the recorded one is refused as an unverified relaunch (see **Trust limit** above). `launchctl debug` (program, argument and environment override) requires root. A job restarting the system agent itself (`kickstart -k`, or booting it out and bootstrapping the system plist again) produces the same Apple-defined launch as a crash and is accepted, like the audited instance it replaces. Baselines written before v0.1.9 carry no records: their absent PIDs are tolerated, but relaunches are terminated until one `worker-reset` (which, like any reset, needs a fresh qualification round).

Before every lease claim, recovery completes owned-resource cleanup and checks admission: no job-home LaunchAgents entries, nonempty crontab, legacy/modern background registrations or extra job-UID processes. Refusal means no registration/claim, a broker-private `admission-status.json` observation (`not_admitting`, reason and timestamp), logging and retry on the next normal poll. Reboot, baseline drift/missing baseline and unsupported inspection output therefore leave queued jobs untouched. Execute retains a second admission check for changes after a claim. Only **positive contamination** creates `admission-quarantine.json`; cancellation, deadlines, I/O/inspection errors and baseline uncertainty do not. A preexisting marker still requires the single clean reset; the status file is observational and never another quarantine authority.

Modern registration inspection requires a recognized explicitly empty job-UID section from `sfltool dumpbtm`; missing/unfamiliar output is a transient refusal, not proof of absence. Since v0.1.18 the macOS 27 `Last Use: <timestamp>` record line (`YYYY-MM-DD HH:MM:SS±HH:MM`, `Z`, or `(null)`) is validated once per record and discarded, never reviewed: it changes on every daemon run, so binding it would fail persistence after every job. Other unknown record fields still refuse. Reset does not remove modern BTM registrations: residual registrations require owner-resolved, specifically scoped job-account remediation and rerunning the same reset. Never run host-wide `sfltool resetbtm` or change owner registrations. Failed or unknown reset verification retains an existing marker. Prepare narrowly approved GUI scripting permissions and audit any long-lived probe-created processes before reset; inspection never adopts them. Do not install a login helper to make unattended GUI operation appear reliable.

Run the actual approved build, unit and simulator UI recipes as the job user with exact Xcode build, runtime build and device type. Prove expected test identities/counts, failure detection, timeouts, cancellation, screenshots/artifact privacy, no signing, and cleanup. Simulator cleanup is limited to recorded service UDIDs or exact job-UID additions proven against protected pre-create inventory as described in section 7; never run global simulator cleanup. Prove UI operation while the owner is foreground after fast switching, with the approved lock/display state, and that owner interaction does not redirect test input or leak owner data. Audit any required probe-created long-lived process and rerun the same reset before committing the final baseline and its evidence bindings. These real target runs remain future owner-authorized deployment acceptance; repository fixtures do not satisfy them.

## 4. Record network reachability and qualify non-network boundaries

Run probes from the **actual job GUI effective UID**, not a root shell claiming to impersonate it. Keep admission disabled until the required non-network qualification is approved. The network report describes what trusted repository code can reach; it does not establish or test macserve-enforced isolation.

Read-only coexistence snapshots protect unrelated configured services from unnoticed changes during installation and qualification. They neither inspect rule semantics nor authorize changing the host firewall. PF read failures remain explicitly unavailable; running service/PID and readable before/after digest changes still require owner investigation.

Service observations parse the complete, newline-terminated `launchctl print system/LABEL` snapshot, bounded to 1 MiB and 16 container levels. Balanced nested dictionaries and arrays (including LWCR requirements with quoted keys, `=>` entries, and an indexed value whose closing `]` is on the same line) are metadata, not health authority. Only one unquoted service-root `state = running` and one canonical positive 32-bit `pid = N` qualify the exact requested service. Nested environment, LWCR, and coalition state/PID text cannot substitute for those fields. Duplicate or noncanonical root fields, controls, malformed or truncated nesting, and trailing output refuse observation rather than guessing service health. The regression fixture preserves the read-only Studio keyring launchd snapshot, including its empty indexed LWCR array; it contains no keyring contents or secret environment values.

| Probe | Required evidence |
| --- | --- |
| TCP to protected ports, loopback IPv4/IPv6, current host LAN/tailnet IPs and approved DNS targets | Record fresh connection outcomes and actual job UID under `network_reachability`; status `not enforced in phase 1`, whether reachable or not |
| Optional UDP, endpoint, proxy and delegated networking observations | Use only authorized test destinations; preserve successes, failures and unsupported paths without pass/fail gates or PF counters |
| Local delegation | Job cannot connect to controller executor Unix socket or read private controller/broker/export/secret paths; check other relevant Unix sockets and delegated services without invoking secret-bearing APIs |
| Owner controls | Independent file controls bracket both account reports; configured owner services retain their running PIDs |
| Owner-home denial | From the actual job GUI identity with its full groups, owner-home listing/traversal and reading the approved nonsecret canary must be denied; owner reads the same canary successfully before/after |
| Lifecycle | Repeat after fast switching and planned reboot/GUI login with fresh boot/baseline evidence |

Connection refusal, an offline timeout, DNS failure or an unrelated successful request is not denial proof. Never send nonces to production UDP services, silently skip observations, or mark unsupported transports as tested. Existing host/network restrictions belong to their owner, not macserve. Unix permissions and UI qualification remain separate required boundaries.

The qualification network matrix runs at most 16 transport attempts concurrently while preserving its canonical serialized TCP/UDP/allow evidence order, all targets, existing attempts/timeouts, nonce bindings and observational-only judgment. Workers join before the matrix returns, including cancellation. For illustration only, 130 TCP targets with three two-second timeouts would take 780 seconds serially versus 50 seconds of transport waves at concurrency 16; these are modeled bounds excluding overhead and other transports, **not measured native performance**.

Collection accepts at most 129 receipt documents: one for each of the maximum 128 approved UDP endpoints, plus the mandatory owner-home control. A 130th document is refused. Each artifact retains its 4 MiB bound; this count correction changes neither receipt JSON nor network evidence scope.

Store detailed evidence privately, sanitized where exported. The root-approved evidence and qualification files authenticate an operator's real observations; arbitrary JSON does not perform tests. Their exact schema is specified in section 2.

For `owner_home_denial`, create a fresh nonsecret mode0644 canary at an explicitly approved owner-home path. The owner's file-only control reads it before and after the job/owner probe window. From the actual job GUI identity and full groups, directory access and reading that exact canary must fail with permission denial, not missing-path/mount errors. Do not enumerate private owner files. Record real attempts, successful owner controls and zero successful job canary reads; status `passed` also requires denied directory access. Preserve evidence and let the owner remove only that canary. Repeat after identity/permission changes and reboot.

## 5. Enroll the App and require verified evidence

During sitting 3, install the GitHub App on **selected approved repositories only**. Minimal App permissions are metadata/contents/pull-request read and checks write. Controller `github` fields are `app_id`, `installation_id`, RSA PEM `private_key_file`, `policies`, and `poll_seconds` (30–60, default 45). Tokens are in-memory, single-numeric-repository scoped. Each policy has `repository_id`, `repository`, `author_ids`, `base_branches`, `profiles`, `policy_revision`, and optional `actions_bot_id`, `actions_app_id`. Pin numeric IDs out of band; names, commit authors and branch display text are not authorization. Trust every writer who can push to an enrolled branch. Forks and unapproved bases/authors/profiles must not execute.

A policy `profiles` entry may name an org build template instead of an explicit profile (for example `org-ios-sim-build-v1`), so that committing `.macserve.json` and opening a PR yields `mac-evidence/<template>`. The poller applies the API admission rule: the policy repository's owner must be in the template's `owners`, and the repository must have no explicit profile of the template's kind; otherwise the controller refuses to start (`invalid GitHub profile policy`). A repository-form policy needs a numeric `repository_id` pinned in `receipt.repositories`, because that pin binds PR events, check runs and receipts to one repository. An owner-form policy (`owner`, `owner_id`) instead covers every repository its owner's App installation lists, with no per-repository setup; see [receipts and GitHub](receipts-and-github.md#owner-policies). Run keys and receipts bind the template digest exactly as for API template jobs.

`sudo macserve connect-github --profile ID` does this enrollment for one repository through GitHub's App manifest flow ([Registering a GitHub App from a manifest](https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest)). Run it with `sudo` from your own login at the Mac, after `deploy-install` and before `qualify begin`; it refuses a root shell without `SUDO_UID`, a `SUDO_UID` other than the console user and `OWNER_UID`, an existing `var/keyholder/secrets/github-app.pem` or `github` section, an installation without the keyholder (upgrade it first), and an existing `activation-anchor.json`/`qualification.json`. It prints a `127.0.0.1` address (it never opens a browser; from another device use `ssh -L` or paste GitHub's redirect address back into the terminal) whose page posts a private manifest with exactly the permissions above, no webhook and no events, and a 256-bit `state`. The returned code is exchanged at once; an App of another account, with other permissions or events is refused and its key is not kept. The `installation_id` from GitHub's setup redirect is confirmed with the App's JWT (`GET /app/installations/{id}`: this App, your account, same permissions), the installation must grant the pinned repository ID, and a controller-identical token request must succeed before anything is written. `controller.json` gains one policy: the pinned repository, the numeric ID of `--author` (default the repository owner), the default branch, the given profiles, revision 1, `poll_seconds` 45; the new file must pass the controller's loader first. Only then is the key created keyholder-owned (`_macserve_key`) `0600`, single-link, exclusive and without following symlinks in the keyholder-owned `0700` `var/keyholder/secrets` directory (an existing key is never overwritten; the controller cannot open it), and only then is `controller.json` replaced; if that replace fails, the just-created key is removed again. Temporarily until PR-policy templates (O7), `--profile` must name a per-repository profile of that repository (templates are refused), and such a policy needs the App on "Only select repositories" with just that repository, so an all-repositories installation is refused. Finally it reads `.macserve.json` at the default branch head through the contents API and, if missing, suggests one from the tree listing's shared schemes without running any repository code.

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

`--timeout` must cover queueing plus the job: raise it above the recipe's `max_timeout_seconds` (for example `--timeout 150m` for a UI-test template allowing 7200 seconds); the wait deadline never cancels Mac work.

Qualify real App permissions, numeric bot matching, branch gates and exact-head success/failure/cancellation behavior. An offline Mac, missing check, invalid signature, superseded head or incomplete evidence must remain nonpassing, not become skipped success.

## 6. Enable only after the gates; operate within budgets

Before approved start: verify protected binary/config/secrets and identity separation; real GUI baseline; accepted native persistence and trusted-repository/no-network-isolation model; required account/tool/UI evidence and informational network report; matching qualification; fresh root maintenance health; and manual pause/disabled profiles during commissioning. An operator may run `macserve maintenance --config /Library/macserve/config/maintenance.json` to obtain actual health, never manufacture it. Only then may a separately approved procedure enable/bootstrap the dedicated services (the keyholder before the controller, which refuses to start without it). Controller runs as its dedicated user, the keyholder as `_macserve_key`, broker/maintenance as root. No root Apple build tools, PF writes or automatic baseline adoption are allowed.

Allocate the 80 GiB mutable pool as **30 GiB workspaces + 15 GiB caches + 15 GiB logs/artifacts + 15 GiB simulators + 5 GiB metadata**. Include full job home/`Library`, diagnostics, controller/broker/exports/workspaces and service-owned logs. Avoid counting nested roots twice. Extra Xcodes/runtimes are separately approved installation storage, but still consume filesystem free space. These are monitored budgets, not hard filesystem quotas; sampled usage may overshoot. Admission reserves 30 GiB while preserving a 120 GiB free floor; below 100 GiB active work is cancelled. Monitor whole-UID memory pressure/RSS and leave owner headroom.

The retained evidence split reserves 1 GiB for store log rows and 14 GiB for artifacts. Raw logs/artifacts expire after seven days or oldest-terminal pressure eviction; metadata and full manifests persist 90 days. Expired reads return `410`, not fabricated empty success. Do not move mutable data outside accounted roots to avoid the budget.

For benchmarks or owner work, authenticated API `PUT /v1/admin/pause` accepts `{"reason":"owner maintenance","mode":"drain"}` or mode `cancel_active`. Poll `GET /v1/admin/state` until **`quiescent=true`**. An accepted pause only blocks new work; it is not proof of stopped tools, finalization or cleanup. Drain permits current work to finish; cancel_active requests cancellation and its cleanup barrier. Do not benchmark or manually clean while ownership is uncertain. Automatic retention/GC does not run through manual/owner pause or unqualified security readiness. `DELETE /v1/admin/pause` clears manual pause only, not an owner marker, quarantine or a failed health gate.

## Keyholder

The keyholder (`macserve keyholder`, launchd label `org.macserve.keyholder`) holds the job receipt Ed25519 key and the GitHub App key, so the controller never reads either. It runs as the hidden non-login system account `_macserve_key` (UID 200–499, shell `/usr/bin/false`, password disabled, home `/Library/macserve/var/keyholder`, primary group `_macserve_key`, never in `staff`, `admin` or `wheel`). The RPC group `_macserve_keyrpc` has exactly two members, the controller account and `_macserve_key`; the job account is in neither group. The controller reaches the keyholder only through `var/keyholder-run/keyholder.sock`, and the keyholder accepts only the controller UID as its peer. It mints per-repository installation tokens (for an owner-form pull policy's owner only when the repository's owner account ID is the policy's `owner_id`), lists those owners' installation repositories for the poller (the listing token never leaves it) and signs receipts; every receipt needs the root worker's build seal (signed with `var/broker/seal-key.pem`, pinned in `keyholder.json`), and a release receipt also needs the owner's `config/release-scope.json` (see [configuration](configuration.md#release-scope)) and the keyholder's own GitHub check. Paths, owners and modes are in the [installation layout](#installation-layout).

`deploy-install` passes `--keyholder-uid`, `--keyholder-gid` and `--keyrpc-gid` to `create-users.sh`, which creates the account, both groups and the directories after the same collision checks as the service accounts and verifies shell, home, groups and the exact `_macserve_keyrpc` membership. It installs the keyholder-owned receipt key, the root seal key, root:wheel `0644` `config/keyholder.json`, the controller.json `keyholder` section and the disabled `org.macserve.keyholder.plist`. Start the keyholder before the controller; `macserve setup` does.

**Release scope (owner step).** Release receipts need `/Library/macserve/config/release-scope.json`, written by you, root:wheel `0644` (`sudo /usr/sbin/chown root:wheel` and `sudo /bin/chmod 0644`). It is anchored configuration: adding or changing it needs a new qualification approval. Without it the keyholder refuses every release receipt and still signs ordinary job receipts.

**The TLS key stays with the controller.** The controller terminates TLS itself, so `var/controller/secrets/tls-key.pem` remains controller-owned: a compromised controller can impersonate the API endpoint to clients that pin only the certificate. This is an accepted limit of class K; it cannot mint tokens or sign receipts.

**Migrating an installation from before the keyholder.** `macserve upgrade` does it in the full-requalification path, after replacing the binaries (such a release is never carried). It picks free system IDs from `dscl` (search and local nodes) and adds `KEYHOLDER_UID`, `KEYHOLDER_GID` and `KEYRPC_GID` to the installed `deploy.env` (recording the new digest in the setup ledger first), runs the release's `create-users.sh --keyholder-only` (which records its IDs in root-only `var/.keyholder-provisioning` before the first Directory Services write and removes it only after the account, groups and directories verify, so an interrupted run is completed by the next), creates `var/broker/seal-key.pem` if absent, moves `receipt-key.pem` and `github-app.pem` from `var/controller/secrets` and every full receipt manifest from `var/controller/receipts` into the keyholder's `secrets` and `receipts` (each copy created exclusively, keyholder-owned `0600`, synced and read back before the controller's copy is removed), writes `keyholder.json`, adds the lease fields to `worker.json` and the keyholder paths and section to `controller.json` (every other field unchanged), and installs the disabled keyholder plist last. Each step is idempotent: an interrupted migration resumes when you run the same release's `macserve upgrade` again. A key that differs from the keyholder's copy, a hard-linked or group-readable key, or a `controller.json` naming other key paths is refused for manual reconciliation. Afterwards `macserve setup` requalifies as for any release. An installation not set up by `macserve setup` is migrated by hand with the same steps (`create-users.sh ... --keyholder-uid UID --keyholder-gid GID --keyrpc-gid GID --keyholder-only --apply` creates the account and directories).

## Code signer (optional, signed TestFlight)

An `ios_archive` job produces an **unsigned** App Store archive. The optional code signer (`macserve signer`, launchd label `org.macserve.signer`) signs it with the owner's Apple Distribution identity in a separate account, so no job, controller or owner process ever holds the signing key. The controller reaches it only through a Unix socket that the job account cannot open.

### Accounts and directories

| Identity | Definition |
| --- | --- |
| `_macserve_sign` | hidden non-login system account (UID 200–499), shell `/usr/bin/false`, password disabled, home `/Library/macserve/var/signer`, primary group `_macserve_sign` (its own GID); never in `staff`, `admin` or `wheel` |
| `_macserve_signrpc` | RPC group with its own GID; members exactly the controller user and `_macserve_sign` |
| job account | member of neither group; `create-users.sh` refuses if it is |

The signer paths, owners and modes are listed in the [installation layout](#installation-layout). Every ancestor is root-owned and not group/world writable.

**New installation.** Add the three system IDs to `deploy.env` (all three or none; canonical decimals 200–499, the two GIDs distinct and different from the controller/job GIDs):

```sh
SIGNER_UID=<unused system UID>
SIGNER_GID=<unused system GID>
SIGNRPC_GID=<unused system GID>
```

`deploy-install --apply` then passes `--signer-uid`, `--signer-gid` and `--signrpc-gid` to `create-users.sh`, which creates the account, both groups and the directories after the same collision checks as the service accounts, and verifies shell, home, groups and the exact `_macserve_signrpc` membership. It installs root:wheel `0644` `config/signer.json` (pinning the controller's job receipt key) and the disabled `org.macserve.signer.plist`, and finally runs, as the signer account,

```sh
sudo -u _macserve_sign /Library/macserve/bin/macserve signer-init --config /Library/macserve/config/signer.json
```

which creates (if absent) the Ed25519 signer receipt key, the keychain secret and the **empty** keychain and prints one JSON line `{"key_id":"...","public_key":"..."}`. `deploy-install` prints the matching controller.json `signer` section; add it to `/Library/macserve/config/controller.json` (see [configuration](configuration.md#code-signer)).

**Existing installation.** From the reviewed release's `assets` directory, plan and then (as root, in an approved window) apply only the signer part; no terminal password prompt is involved:

```sh
bash assets/create-users.sh \
  --controller-user "$CONTROLLER_USER" --controller-uid "$CONTROLLER_UID" --controller-gid "$CONTROLLER_GID" \
  --job-user "$JOB_USER" --job-uid "$JOB_UID" --job-gid "$JOB_GID" \
  --owner-user "$OWNER_USER" --owner-uid "$OWNER_UID" \
  --signer-uid "$SIGNER_UID" --signer-gid "$SIGNER_GID" --signrpc-gid "$SIGNRPC_GID" --signer-only [--apply]
```

`--signer-only` checks that the named controller and job accounts are the installed ones and refuses existing signer paths. Then install, root:wheel `0644`, the reviewed `assets/launchd/org.macserve.signer.plist.tmpl` as `/Library/LaunchDaemons/org.macserve.signer.plist` (it has no markers) and write `/Library/macserve/config/signer.json` as described in [configuration](configuration.md#code-signer), with `receipt_keys` pinning `receipt_key_id`/`receipt_public_key` from `config/deployment-pins.json` and `key_id` `macserve-signer-<host_id>`. Run `signer-init` as above. Do not add `SIGNER_*` keys to the installed `deploy.env` of a `macserve setup` installation: setup verifies that file against the digest it recorded. Qualification detects the signer from `signer.json` or the controller `signer` section either way.

### Importing the Apple Distribution identity (owner, interactive)

The owner imports the `.p12` once, at the console, into the signer's keychain. The keychain password is the content of `keychain.secret`; read it with `sudo cat /Library/macserve/var/signer/keychain/keychain.secret` when prompted.

```sh
sudo -u _macserve_sign /usr/bin/security unlock-keychain /Library/macserve/var/signer/keychain/signing.keychain-db
sudo -u _macserve_sign /usr/bin/security import /path/AppleDistribution.p12 -k /Library/macserve/var/signer/keychain/signing.keychain-db -f pkcs12 -T /usr/bin/codesign
sudo -u _macserve_sign /usr/bin/security set-key-partition-list -S apple-tool:,apple: -s -k "$(sudo cat /Library/macserve/var/signer/keychain/keychain.secret)" /Library/macserve/var/signer/keychain/signing.keychain-db
sudo -u _macserve_sign /usr/bin/security find-identity -v -p codesigning /Library/macserve/var/signer/keychain/signing.keychain-db
```

`import` prompts for the `.p12` password. `set-key-partition-list` puts the keychain secret in that command's argv for the duration of the call, visible to process listings on the host: this is an owner-only interactive step, run it only in an approved sitting with no other users or jobs active (keep services paused), and delete the `.p12` copy afterwards. `find-identity` must list the identity; its 40-hex SHA-1 goes into `signer-policy.json` `identity_sha1`.

**Reboot behavior.** At every start the signer unlocks its keychain from `keychain.secret`, passing the secret to `security -i` on stdin, never in argv, and refuses to start if the configured `identity_sha1` is not in the keychain. A reboot therefore needs no owner action; a missing or replaced identity keeps the signer down until the owner re-imports it.

### Admin policy and provisioning profiles

`/Library/macserve/config/signer-policy.json` (root-owned, `0644`) is the only authority on what may be signed:

```json
{"identity_sha1": "<40 hex>",
 "apps": {"com.example.app": {"profile_path": "/Library/macserve/signer-profiles/example.mobileprovision",
                              "team_id": "ABCDE12345", "required_entitlements": ["aps-environment"]}}}
```

Place each App Store provisioning profile under `/Library/macserve/signer-profiles/` as a root `0644` file. An archive whose bundle ID is not in `apps`, whose team differs, or whose profile lacks a required entitlement is refused.

### Requesting a signature

Grant `release:sign` to the principal (in `principals[].scopes` of `controller.json`). For a succeeded `ios_archive` job, a caller holding `release:sign` that is the job's own principal or also holds `service:admin` calls `POST /v1/jobs/<id>/sign` (no body): `202` while signing (also when signing was already started), `200` once signed; a failed signing is retried by calling it again. Without `release:sign` the call is `403`; a job that has not finished is `409 result_not_ready`; a job whose archive or signing manifest has expired or been evicted from the artifact pool is `410 expired` (rerun the archive job; a signing in progress keeps its inputs from eviction); a controller without a `signer` section answers `422`. The job's `state` never changes; the job view and `GET /v1/jobs/<id>/signing` carry `signing: {status: signing|signed|sign_failed, reason?, started_at, updated_at, artifacts?}`, where a signed job's `App.ipa` and `signer-receipt.json` are listed with their `/v1/jobs/<id>/artifacts/<sha256>` download links. `GET /v1/capabilities` publishes the signer receipt key as `signer: {key_id, public_key}`.

The agent uploads the signed `App.ipa` to App Store Connect itself with `macserve testflight-upload`, verifying the signer receipt against that key first; see [TestFlight](testflight.md).

### Enabling

Enable `org.macserve.signer` only after `signer-init`, the identity import, `signer-policy.json` and the controller `signer` section are in place and a fresh qualification (which now includes the job probe's [`signer_denial`](architecture.md#code-signer-boundary) rows) has been approved. Adding the signer changes the anchored configuration (`config/` files and the signer plist), so the owner approves again.

## 7. Reboot, recovery and evidence-preserving cleanup

Plan sitting 4 with a physical-console FileVault unlocker. Do not grant the job unlock rights or enable autologin. After cold boot, owner unlock and actual job GUI login are prerequisites; old boot-bound baseline/qualification records cannot authorize admission. Keep admission disabled/paused. Follow the same reset procedure below with explicitly audited current GUI PIDs, repeat the full network/UI/control matrix, then approve new evidence and qualification only from new real observations.

For a crash, reboot, GUI drift, missing baseline PID or cleanup uncertainty:

1. Block new admission and request pause/cancellation where possible. When the controller is reachable, poll for quiescence; an accepted pause is not enough. Stop only the dedicated broker under the approved service procedure before reset. A stopped/crashed broker is not proof its old job processes are gone; preserve unresolved ownership for reset rather than pretending it is quiescent.
2. Preserve protected broker records, queue database with its transactional companions, pending completions, sealed exports, manifests and probe evidence. Inventory unresolved work, recorded simulator UDIDs and protected pre-create inventories; do not delete records to bypass quarantine.
3. Investigate persistence, current job-UID processes and provenance, retaining evidence of the cause. Approve reset's job-only LaunchAgents/crontab removal and termination of nonretained exact same-UID processes. Legacy login items are census-only: nonzero refuses and requires separately approved scoped remediation. Review eligible modern registrations through the separate digest-pinned inspect/accept flow; unknown or unresolved records cannot be adopted. No host-wide `sfltool resetbtm`, owner registration changes, indiscriminate PID signaling or shared-cache/service cleanup.
4. Explicitly audit every retained trusted current GUI PID/start identity and run the same future root command used for initialization:

   ```sh
   /Library/macserve/bin/macserve worker-reset \
     --config /Library/macserve/config/worker.json --pids "$AUDITED_PIDS"
   ```

   Reset holds the broker lock, removes supported job persistence and extra processes, updates the audited baseline, retries owned-resource cleanup and performs full clean verification before clearing the admission marker. It preserves pending completions and sealed evidence; failure retains unresolved records and any existing marker. For an interrupted simulator create, it compares stable job-UID inventory with the protected pre-create inventory and deletes only exact added UDIDs, preserving baseline devices. Recorded service UDIDs remain eligible for cleanup. It never guesses legacy ownership: an old record without inventory can recover only when inspection proves the inventory empty. Unrelated workspaces and owner devices are not cleanup targets. If modern BTM residuals or uncertain inspection remain, keep disabled, resolve the scoped cause and rerun this same reset.

   A failed cleanup signal reports the target PID, kernel start identity, signal number and quoted helper stderr (at most 4096 captured bytes). Preserve this diagnostic; do not retry merely because the outer error says `worker process cleanup failed`. An output-limit error means the helper diagnostic is incomplete. Signals still run as the job UID, and any helper failure still refuses cleanup. A missing baseline does not prove reset made no changes: job persistence removal and partial process termination may already have occurred.

5. A reset is not boundary approval: refresh qualification bindings for changed boot/baseline/profiles and repeat affected real evidence gates, including a fresh coexistence window. Restart only the dedicated services after valid fresh health and explicit approval. Startup replays pending completions before recovery; no registration or lease occurs before recovery succeeds. Transient unclean completion fences the old controller epoch; verified recovery registers a fresh epoch without another administrator clear command. Verify state and evidence delivery before clearing manual pause.

Manual disk relief is an administrative incident procedure, not `rm -rf` on the install root. First establish quiescence and preserve an access-controlled evidence inventory/backup. Identify ownership, exact recorded paths, retention eligibility, outstanding publication/completion references and current budget before removing only approved expired data. Never delete active records, pending receipts, source-cleanup debt or quarantine to force admission. If safe evidence-preserving cleanup cannot be established, keep disabled and add capacity or investigate; do not mutate unrelated owner infrastructure.

Changes to host behavior, binaries, pinned Xcodes/runtimes, recipes, relevant inventory, keys/configuration or GUI permissions require reviewed rollout and relevant requalification. PF remains externally managed; macserve never repairs it. Unsupported non-network security behavior is a deployment limit, not a reason to relax required gates.

# Controller configuration and control

This page was split out of the [README](../README.md); text is unchanged unless noted. Installed values are listed in [install.md](install.md#2-supply-matching-protected-configurations).

`macserve-controller --config /absolute/path/to/controller.json` (the separate controller binary; `macserve` has
no `controller` subcommand) requires a root-controlled configuration and
a dedicated non-login, non-admin controller account distinct from the owner and job account. Configuration fields:
`root`, `socket`, `job_uid`, `owner_uid`, `profiles_file`, `listen`, `tls_certificate`, `tls_key`,
`principals`, `health_file`, `receipt`, `keyholder`, and optional `allowed_networks`, `pause_file`, `github`.
Profiles and the public TLS certificate are root-controlled. The TLS private key is a controller-private file; the
receipt and App private keys are the [keyholder](#keyholder)'s, and `receipt.private_key_file` and
`github.private_key_file` name them only for the keyholder (exactly
`/Library/macserve/var/keyholder/secrets/receipt-key.pem` and `.../github-app.pem`; the controller never opens
them). No secret is supplied through command arguments or a worker lease.
`job_uid` identifies the unprivileged execution account. The private executor socket always
authenticates peer UID `0` in production, independently of `job_uid`.

The TLS 1.3 listener requires a literal assigned tailnet address and port. Allowed networks default to
`100.64.0.0/10` and `fd7a:115c:a1e0::/48`; configuration can narrow these ranges, not enable LAN/public,
wildcard or loopback listeners. Client authorization is independent of network membership.
Each principal has `id`, `token_sha256`, `repositories`, `scopes`, and optional `revoked`. Scopes are
`jobs:submit`, `jobs:read`, `jobs:cancel`, `release:archive`, `release:sign`, `service:admin`. Only SHA-256 digests are persisted; plaintext
high-entropy bearer credentials belong in the caller's private credential storage.
`keyholder` connects the controller to the [keyholder](#keyholder); the controller refuses to start without it.
Optional `signer` connects the controller to the [code signer](#code-signer).

- `POST /v1/jobs` requires `Idempotency-Key` and a profile-matching exact-SHA request.
- `GET /v1/capabilities` and `/v1/jobs` expose authorized profiles and jobs without controller recipes or paths.
- `/v1/jobs/{id}` provides status, `/logs`, `/logs/stream`, `/results`, `/results/junit`, `/artifacts`,
  `/artifacts/{artifact_id}`, `/receipt`, `/receipt/manifest?sha256=DIGEST`, and `POST /cancel`.
  Missing signed receipts return `409`, not success. Non-executed cancellation/expiry or interrupted jobs with
  no collected completion have no execution receipt; GitHub reports non-success, never invented evidence.
- A job whose cancellation was requested carries `cancel_reason` in `GET /v1/jobs/{id}`, the `GET /v1/jobs` list and
  the cancel response: `source` (`client`, `admin_pause`, `deadline`, `host_readiness`, `gate_error`, `log_limit`,
  `controller_shutdown` or `github`), `at` (when the request was recorded), `principal` for `client` and
  `admin_pause`, `blockers` (the readiness gate's, e.g. `isolation_unavailable`, `host_memory_pressure`) for
  `host_readiness`, and an optional `detail` of at most 512 bytes (the client or pause reason, the gate error, the
  gate's free and accounted bytes). Only the first request is recorded and it survives the job's finish, whose
  `reason` says only `cancellation requested`. Receipts never carry it and are byte-identical with or without it;
  jobs never cancelled, or cancelled before this field existed (store schema version 6), have none.
- `PUT /v1/admin/pause` accepts `{"reason":"benchmark","mode":"drain"}` or `cancel_active`.
  Poll `GET /v1/admin/state` until `quiescent=true` before benchmarking; acceptance of pause is not quiescence.
  `DELETE /v1/admin/pause` clears only manual pause. An optional owner-controlled pause marker also blocks dispatch.
- `POST /v1/jobs/{id}/sign` (scope `release:sign`; the job's own principal or `service:admin`) signs a succeeded
  `ios_archive` job through the code signer: `202` while signing, `200` once signed, a failed signing is retried.
  `GET /v1/jobs/{id}/signing` reports the signing sub-status. The agent then uploads the signed `App.ipa` with
  `macserve testflight-upload` ([TestFlight](testflight.md)); macserve never contacts App Store Connect.

Job kinds are `build`, `unit_test`, `simulator_ui_test`, `simulator_script` and `ios_archive`; the last two run only
from an org template. A `simulator_script` request names a `shard` of the repository's `.macserve.json` `script` section,
`{"script": {"shards": {"duo-screenshots": {"run": "Tools/ci/duo-screenshots.sh"}}}}`, where `run` is a relative path
(no absolute path, `..`, empty or `.` component) resolved against `work_dir`; an omitted simulator is the
template's first pin. The worker builds the scheme for that simulator
(`xcrun xcodebuild … -destination id=${SIMULATOR_ID} -derivedDataPath ${DERIVED_DATA} build`) and then runs
`/bin/bash <work_dir>/<run>` in `work_dir` (the script must be a regular checkout file reached without a
symlink, checked just before launch) with `PATH` unchanged and exactly these additions:

| Variable | Value |
| --- | --- |
| `MACSERVE_APP_DIR` | `${DERIVED_DATA}/Build/Products/Debug-iphonesimulator` |
| `MACSERVE_SIMULATOR_ID` | UDID of the job's booted simulator |
| `MACSERVE_OUTPUT` | `<workspace>/output`, created job-writable before the run |
| `MACSERVE_JOB_ID` | the job ID |

Exit 0 is success. The `MACSERVE_OUTPUT` directory is the job's required artifact: `/artifacts` lists it as
`output.tar.gz`, downloaded from `/artifacts/{artifact_id}`, within the usual artifact count and size budgets; a
symlink or special file under it fails the job. Script jobs have no `/results` test evidence. The request's
`timeout_seconds` is admitted against the template cap (default 3600 seconds, maximum 7200); there are no
per-shard timeouts. Preparation has a 30-minute budget. The full
`.macserve.json` rules are in [install.md](install.md#onboarding-a-repository).

A Flutter template (one with a `flutter` pin: `version`, `sdk_sha256`, `ruby_sha256`, `cocoapods_version`,
`gems_sha256`) runs `build`, `unit_test`, `simulator_ui_test` or `ios_archive` jobs for repositories whose `.macserve.json` has a
`flutter` section, `{"app_dir": "apps/mobile", "prepare_ruby": ["scripts/add_call_directory_target.rb"]}` (at most 8
checkout-relative `.rb` scripts), with `work_dir` `<app_dir>/ios`, `workspace` `Runner.xcworkspace`, `scheme`
`Runner` (Flutter flavors and custom schemes are not supported), no `project`, `xcodegen` or `resolve_packages`;
other templates refuse such a file and a Flutter template refuses any other. Its
requests must name the pinned version exactly, `"flutter": {"version": "3.41.9"}`, and requests for any other recipe
must not name one. `<app_dir>/pubspec.lock` and `<app_dir>/ios/Podfile.lock` must be committed regular files (the
latter naming the pinned `COCOAPODS:` version); both are tracked, and a lockfile created during a Flutter job fails it.
The worker clones the root-owned SDK (`/Library/macserve/tools/flutter/<version>/flutter`) into
`${WORKSPACE}/flutter-sdk`, runs `flutter pub get --enforce-lockfile`, `flutter build ios --config-only --simulator
--debug`, each script with Ruby (`/Library/macserve/tools/ruby/<ruby_sha256[:12]>/bin/ruby`, gems from
`/Library/macserve/tools/cocoapods/<cocoapods_version>/gems`), then the simulator build `xcrun xcodebuild -workspace
ios/Runner.xcworkspace -scheme Runner -configuration Debug -sdk iphonesimulator -destination 'generic/platform=iOS
Simulator' ... CODE_SIGNING_ALLOWED=NO ARCHS=arm64 build` (not `flutter build ios --simulator`: its universal-arch
`lipo -verify_arch arm64 x86_64` check fails with Xcode 27.1's lipo) or the usual test steps on
`ios/Runner.xcworkspace`, all in `app_dir` with `FLUTTER_ROOT`,
`PUB_CACHE`, `CP_HOME_DIR`, `GEM_HOME`/`GEM_PATH`, `FLUTTER_SUPPRESS_ANALYTICS=true`, `CI=true` and the Flutter, Ruby
and gem `bin` directories first on `PATH`. Preparation has a 30-minute budget; the observed Flutter, Dart, Ruby and
CocoaPods versions are in the job observation and the receipt's `observation.flutter`. Xcode 27.1 rejects the
Flutter pod's default deployment target 13.0: the repository's `ios/Podfile` must raise every pod's
`IPHONEOS_DEPLOYMENT_TARGET` to at least 15.0 in `post_install`.

An `ios_archive` template (native, or Flutter with a `flutter` pin) builds an unsigned App Store release archive of
the repository's scheme. It pins no simulator; its timeout defaults to 3600 seconds (maximum 5400) and its
preparation has a 30-minute budget. The request needs both `jobs:submit` and `release:archive` and a `release`:

```json
{"kind": "ios_archive", "release": {"build_name": "1.4.0", "build_number": "42",
 "dart_defines": {"REVENUECAT_PUBLIC_KEY": "appl_xxx"}}}
```

`build_name` is one to three dot-separated numbers of one to four digits; `build_number` is one to nine digits
without a leading zero. `dart_defines` is for Flutter templates only (other archive templates refuse it): at most 32
entries, keys matching `^[A-Z][A-Z0-9_]{0,63}$`, values of at most 1024 printable ASCII characters without `$`, at
most 4096 bytes in all, counting keys plus values as JSON encodes them (`<`, `>` and `&` count six bytes, `"` and `\`
two). Dart defines are non-secret app configuration: they are stored in the job
record and the signed receipt. Every other kind refuses `release`, and configured profiles cannot be `ios_archive`.

Admission binds the archive to the repository's default branch: the controller's GitHub App reads the numeric
repository ID, the default branch and that branch's head commit (`GET /repos/<repo>` and
`GET /repos/<repo>/git/ref/heads/<branch>`, which must name exactly `refs/heads/<branch>` and a commit), and the
request `sha` must equal that head. A token without `release:archive` gets `403` (also on idempotent replay), a
controller without a GitHub App `422`, a commit other than the head `409` naming both SHAs and the branch, and a
failed lookup `503`. The resolved facts are stored with the job and signed in the receipt's `release_provenance`;
a later push does not affect a job already admitted, and an idempotent replay returns the admitted job without a
new lookup. Pull-mode GitHub policies cannot select `ios_archive` templates, `macserve build` never chooses one
and `macserve wait` refuses the kind.

The native run is `xcrun xcodebuild (-project P | -workspace W) -scheme S -configuration Release -sdk iphoneos
-destination generic/platform=iOS -archivePath ${WORKSPACE}/App.xcarchive -derivedDataPath ${DERIVED_DATA}
CODE_SIGNING_ALLOWED=NO MARKETING_VERSION=<build_name> CURRENT_PROJECT_VERSION=<build_number> archive` (with the
worker's `-jobs 4 CODE_SIGNING_ALLOWED=NO`), after the optional XcodeGen and package steps. A Flutter archive
writes the iOS configuration with `flutter build ios --config-only --release --no-codesign --build-name <build_name>
--build-number <build_number> [--dart-define KEY=VALUE ...]` (one `--dart-define` per key, sorted) instead of the
simulator debug configuration, then runs the same archive on `ios/Runner.xcworkspace`. `--no-codesign` keeps Flutter
from looking for a signing identity: nothing in this kind signs.

After the run, once every job process has stopped, the worker (as root, never as the job user) reads the archive
descriptor-relative and refuses symlinks, hard links, special files and mount crossings. It builds the signing
manifest: exactly one `Products/Applications/*.app`, and below each listed bundle every `PlugIns`/`Extensions`
`.appex`, `Frameworks` `.framework` and `Watch` `.app`, each with its `Info.plist` bundle identifier, executable,
package type and version (decoded with `/usr/bin/plutil`), and the entitlements the build requested (from the
`.xcent` files in derived data, `{}` if none). Apps and app extensions must carry `build_name` and
`build_number` (frameworks are exempt); a duplicate bundle identifier, a Mach-O file under `Products` that is not
a listed executable or a `Frameworks` `.dylib`, or a missing executable fails the job. It then seals the archive as
a deterministic tar (sorted entries, owner 0, mtime 0, directories 0755, files 0755 if executable else 0644, every
0755 path listed in the manifest). The two required artifacts, `App.xcarchive.tar` and `signing-manifest.json`, are
written to the protected evidence directory and exported from there, never from the job-writable workspace.
Sealing and export have their own 15-minute bound, and the controller's finalizing window grows by it for this
kind; the request's `timeout_seconds` must still leave room for them. Signing and upload are not part of this kind.

The controller requires schema-3 root-owned health attestation bound to job UID and qualified profile
digests, not interface inventory or PF policy/rules. VM bridge/address churn does not invalidate health
or cancel work. Health expires within 45 seconds; missing, stale or changed non-network host/tool
qualification stops admission and cancels active work. Schema-1/2 records require fresh qualification,
not migration. Merely creating a profile does not qualify it. Installation and actual non-network
boundary qualification remain separate provisioning work.

Every stderr line of the controller, worker and maintenance daemons
(`/Library/macserve/var/controller/log/controller.err.log`, `/Library/macserve/var/broker/log/worker.err.log` and
`maintenance.err.log`) starts with its RFC 3339 UTC time in milliseconds, e.g. `2026-11-07T03:16:26.412Z`, so a
cancellation can be placed against its cause. The controller logs `controller readiness: ready=… cancel_active=…
blockers=… active_job=…` at its first readiness evaluation and whenever the outcome changes, and
`controller job cancellation requested: job=… source=… blockers=… detail=…` for each cancellation it requests
itself (deadline, readiness, gate error, log limit, shutdown), naming the cause recorded as the job's
`cancel_reason`. Maintenance logs `published invalid health checked_at=… last_valid_until=… blockers=…
cancels_active_job=…: <cause>` for every invalid record it publishes, including at its own start and stop, after
the existing `probe failed` line; `last_valid_until=none` means no valid health was held, so even an inconclusive
probe could not keep one. A valid record is logged as `published health … blockers=…` when its blockers (for
example `host_memory_pressure`, `service_disk_budget_exceeded`) differ from the previous record's. Toolchain
qualification is the controller's own comparison and appears only in its lines.

Disk admission reserves 30 GiB while preserving 120 GiB free; below 100 GiB active work is cancelled.
The total accounted mutable-data budget is 80 GiB. The retained evidence pool reserves 1 GiB for store log
rows and 14 GiB for artifacts, with seven-day expiry/oldest-terminal eviction. Metadata persists for 90 days;
expired downloads, log pages and newly opened log streams return `410`.
These are monitored application budgets, not filesystem quotas. Controller test parsing uses sealed JSON
exported by the pinned worker tool; it does not execute repository-provided parsers.
The census refuses nested mounts except the job user's own CoreDevice `devicefs` (Xcode), and on SIP hosts
needs Full Disk Access for `/Library/macserve/bin/macserve`; see the installation guide.

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

## Keyholder

The keyholder (`macserve keyholder --config /Library/macserve/config/keyholder.json`, account `_macserve_key`) holds
the receipt and GitHub App keys; see [install.md](install.md#keyholder). `deploy-install` (or the `macserve upgrade`
migration) writes `keyholder.json`, root:wheel `0644`, unknown fields rejected:

| Key | Value |
| --- | --- |
| `keyholder_uid`, `keyholder_gid` | the `_macserve_key` UID (`KEYHOLDER_UID`) and its dedicated primary GID (`KEYHOLDER_GID`) |
| `rpc_gid` | the `_macserve_keyrpc` GID (`KEYRPC_GID`; members: controller and keyholder only) |
| `controller_uid` | the only peer UID the keyholder socket serves |
| `job_uid`, `job_gid` | the job account, which must never share a keyholder group |
| `state_dir` | `/Library/macserve/var/keyholder`: `secrets/` (`receipt-key.pem`, `github-app.pem`), `receipts/` (full receipt manifests), `release/` (verified release provenance) |
| `socket` | `/Library/macserve/var/keyholder-run/keyholder.sock` |
| `controller_config` | `/Library/macserve/config/controller.json`: the receipt and github sections, service identity and repository policy |
| `release_scope_file` | `/Library/macserve/config/release-scope.json` |
| `seal_keys` | `{"macserve-worker-<host_id>": "<base64 Ed25519 public key>"}`: the root worker's build seal keys |

Controller `keyholder` section: `{"keyholder":{"socket":"/Library/macserve/var/keyholder-run/keyholder.sock","uid":<KEYHOLDER_UID>}}`.
The controller checks the socket peer is `uid` on every connection.

`worker.json` names, for the lease path, `profiles_file` (`/Library/macserve/config/profiles.json`),
`qualification_file` (`/Library/macserve/config/qualification.json`), `seal_key_file`
(`/Library/macserve/var/broker/seal-key.pem`, root:wheel `0600` Ed25519 PKCS#8 PEM) and `seal_key_id`
(`macserve-worker-<host_id>`, the `seal_keys` entry). The broker refuses to run without them; older files still
load for the root tools that do not lease.

### Release scope

`/Library/macserve/config/release-scope.json` is written by the owner, root:wheel `0644`, unknown fields rejected,
and is anchored configuration (changing it needs a new approval). Absent, the keyholder refuses every release
receipt. It lists, per repository, every input that changes an Apple-signed build's output except its version labels:

```json
{
  "schema": "macserve-release-scope/1",
  "repositories": {
    "example-org/example-app": {
      "repository_id": 12345,
      "profile_id": "example-app-archive-v1",
      "profile_version": 1,
      "profile_digest": "<64 lowercase hex: the profile's digest in profiles.json>",
      "xcode": {"version": "16.2", "build": "16C5032a"},
      "flutter": {"version": "3.27.1", "sdk_sha256": "<64 hex>", "ruby_sha256": "<64 hex>", "cocoapods_version": "1.16.2", "gems_sha256": "<64 hex>"},
      "dart_defines": {"FLAVOR": "prod"}
    }
  }
}
```

| Key | Value |
| --- | --- |
| `schema` | exactly `macserve-release-scope/1` |
| `repositories` | keyed by the lowercase `owner/name` a release job requests |
| `repository_id` | the numeric GitHub repository ID (also pinned in `receipt.repositories`) |
| `profile_id`, `profile_version`, `profile_digest` | the exact profile or template identity the release must run |
| `xcode` | `{"version","build"}` the release must use |
| `flutter` | the Flutter pin of a Flutter release, in the profile's pin format; omitted for a non-Flutter release |
| `dart_defines` | the exact map of Dart defines; omitted or empty for none |

A release job's only free inputs are its version labels: build name `^[0-9]+(\.[0-9]+){0,2}$` and build
number `^[0-9]{1,9}$`.

## Code signer

The optional code signer (`macserve signer --config /Library/macserve/config/signer.json`, account `_macserve_sign`)
signs `ios_archive` results; see [install.md](install.md#code-signer-optional-signed-testflight). Its configuration,
the admin policy and the controller section are root-owned `0644` files with unknown fields rejected.

`signer.json` (written by `deploy-install` when `deploy.env` sets `SIGNER_UID`, `SIGNER_GID` and `SIGNRPC_GID`):

| Key | Value |
| --- | --- |
| `signer_uid`, `signer_gid` | the `_macserve_sign` UID and its dedicated primary GID |
| `rpc_gid` | the `_macserve_signrpc` GID (members: controller and signer only) |
| `controller_uid` | the only peer UID the signer socket serves |
| `job_uid`, `job_gid` | the job account, which must never share a signer group |
| `state_dir` | `/Library/macserve/var/signer` |
| `socket` | `/Library/macserve/var/signer-run/signer.sock` |
| `inbox` | `/Library/macserve/var/signer-inbox` |
| `keychain` | `/Library/macserve/var/signer/keychain/signing.keychain-db` |
| `keychain_secret_file` | `/Library/macserve/var/signer/keychain/keychain.secret` |
| `key_file` | `/Library/macserve/var/signer/key/signer-receipt.key` (Ed25519 seed PEM, created by `signer-init`) |
| `key_id` | signer receipt key ID, `macserve-signer-<host_id>` |
| `receipt_keys` | `{"<controller receipt key_id>": "<base64 Ed25519 public key>"}`: the controller job receipt keys whose receipts the signer accepts |
| `policy_file` | `/Library/macserve/config/signer-policy.json` |

`signer-policy.json` (written by the owner):

| Key | Value |
| --- | --- |
| `identity_sha1` | SHA-1 of the Apple Distribution identity in the signer keychain (40 hex digits, either case) |
| `apps` | object keyed by the bundle ID of the app and of each app extension it embeds |
| `apps.<bundle_id>.profile_path` | absolute path of the App Store provisioning profile, kept in `/Library/macserve/signer-profiles/` |
| `apps.<bundle_id>.team_id` | the 10-character Apple team ID the profile and identity must match |
| `apps.<bundle_id>.required_entitlements` | entitlement keys the profile must grant, for example `aps-environment` |

Controller `signer` section (printed by `deploy-install` from `signer-init`'s `{"key_id","public_key"}` line):
`{"signer":{"socket":"/Library/macserve/var/signer-run/signer.sock","uid":<signer UID>,"rpc_gid":<_macserve_signrpc GID>,"inbox":"/Library/macserve/var/signer-inbox","key_id":"<signer key_id>","public_key":"<base64>"}}`.
The controller checks the socket peer is `uid` on every connection and pins the signer receipt key. Without the
section, `POST /v1/jobs/{id}/sign` reports signing unavailable.

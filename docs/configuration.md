# Controller configuration and control

This page was split out of the [README](../README.md); text is unchanged unless noted. Installed values are listed in [install.md](install.md#2-supply-matching-protected-configurations).

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

Job kinds are `build`, `unit_test`, `simulator_ui_test` and `simulator_script`; the last runs only from an org
template. A `simulator_script` request names a `shard` of the repository's `.macserve.json` `script` section,
`{"script": {"shards": {"duo": {"run": "Tools/ci/duo-screenshots.sh"}}}}`, where `run` is a relative path
(no absolute path, `..`, empty or `.` component) resolved against `work_dir`; an omitted simulator is the
template's first pin. The worker builds the scheme for that simulator
(`xcrun xcodebuild … -destination id=${SIMULATOR_ID} -derivedDataPath ${DERIVED_DATA} build`) and then runs
`/bin/bash <work_dir>/<run>` in `work_dir` with `PATH` unchanged and exactly these additions:

| Variable | Value |
| --- | --- |
| `MACSERVE_APP_DIR` | `${DERIVED_DATA}/Build/Products/Debug-iphonesimulator` |
| `MACSERVE_SIMULATOR_ID` | UDID of the job's booted simulator |
| `MACSERVE_OUTPUT` | `<workspace>/output`, created job-writable before the run |
| `MACSERVE_JOB_ID` | the job ID |

Exit 0 is success. Every regular file the script leaves under `MACSERVE_OUTPUT`, at most 8 levels deep, is
listed by `/artifacts` as `output/<path>` and downloaded from `/artifacts/{artifact_id}`; symlinks are skipped,
and the usual artifact count and size budgets apply. Script jobs have no `/results` test evidence. They default
to a 3600-second timeout with a 7200-second maximum and a 30-minute preparation budget. The full
`.macserve.json` rules are in [install.md](install.md#onboarding-a-repository).

The controller requires schema-3 root-owned health attestation bound to job UID and qualified profile
digests, not interface inventory or PF policy/rules. VM bridge/address churn does not invalidate health
or cancel work. Health expires within 45 seconds; missing, stale or changed non-network host/tool
qualification stops admission and cancels active work. Schema-1/2 records require fresh qualification,
not migration. Merely creating a profile does not qualify it. Installation and actual non-network
boundary qualification remain separate provisioning work.

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

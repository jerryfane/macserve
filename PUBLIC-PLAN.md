# Public native artifact contract — ordinary PR CI design

SOURCE ONLY. No build, test, download, upload, PR or CI execution has occurred.
Exact pre-upload source review is the authorization gate. The cooperative hosted
supervision decision is still PENDING; no waiver is assumed. Do not push/upload
this workflow or open/update a PR that would trigger it until both gates are met.
The workflow is a proposal for the admitted run, not an authorization mechanism.

## Scope and immutable inputs

Only the twelve files in `PUBLIC-SOURCE-ALLOWLIST.txt` form this public packet.
`PUBLIC-SOURCE-MANIFEST.json` records the other eleven files' SHA256 and sizes;
its own hash is excluded and recorded outside this packet by the source review.
No expected manifest digest is embedded in any file that it hashes. No commit
contains its own expected commit SHA. CI computes the checked-out manifest digest
and exports it for comparison with the independent pre-upload review record.
This measurement does not authorize its own source.

Public repository: `jerryfane/macserve`, baseline native commit
`40bba7e4d15395e794e2719ed750a90fca7be9fe`, tag `v0.1.16`.
Pinned native archive:
`https://codeload.github.com/jerryfane/macserve/tar.gz/refs/tags/v0.1.16`
SHA256 `9440aedf29fa10b9fb879f018cdd034162c20527732176e999d239d566647ba2`.
Pinned native go.mod SHA256:
`3450762136865aa091c5cc245feb3ee1d032f38e6a1a7656f6102ca151d13945`.
Pinned native go.sum SHA256:
`c31cd1a8b7973f212d426dc55fb58890cd3d16b28a892d35e41ae634dbd86add`.
Preparation preserves the archive's original native production files and adds
only the reviewed history test helper; the profile oracle is public source.
Host observations and profiles are synthetic. No actual installed configuration,
owner data, service, ledger, secrets, private source or private artifact is used.

## Ordinary launch route; no new repository configuration

One `native-contract` job uses the existing pinned checkout, setup-go,
setup-python and upload-artifact actions. No repository environment, secret,
variable, permission setting or manual binary-approval service is introduced.
The existing read-only contents permission remains unchanged. No shared settings
are to be created or edited as part of this packet.

- `pull_request` is the first-run route, restricted to same-repository heads.
- `workflow_dispatch` is optional after default-branch registration. It does not
  bypass GitHub's registration rule. Do not merge an unrun workflow to register it.
- Checkout the event's exact PR head (or exact manual event SHA) into `source`.
- Checkout `github.workflow_sha` into `workflow-source`, using the same pinned
  checkout action with credentials not persisted. Verify both Git HEAD values
  against their event identities, then byte-compare the executing workflow's
  source with the workflow file in the source checkout. This handles the PR
  merge-workflow versus PR-head distinction without a manually preapproved
  workflow commit variable. Mismatch refuses before builds/root work.
- Record both source head and executing-workflow head in build and run receipts.
  A source change or synchronized PR head needs renewed source review before push;
  ordinary PR CI does not authenticate that organizational decision itself.

Official manual dispatch rule:
https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow

## Build-derived receipt, not independent binary approval

After source review admits this exact workflow, its serial build records the
source-to-binary relationship. No external preapproved helper hash is required.
The single job builds once, writes/fsyncs/reads back `build-provenance.json`, fsyncs
its directory, captures its SHA256, and only then enters the narrow root protocol.
The receipt records:

- exact source head, executing-workflow head, source manifest digest and all source
  file hashes/sizes; native archive and fixture source hashes;
- verified go.mod/go.sum hashes, Go version and Python version; Go and Python
  executable hashes checked before/after building;
- both compiled helper hashes and the source-preparation receipt hash;
- serial command resource/deadline/exit receipts and hosted run/attempt IDs;
- `independent_runtime_approval: false` and the cooperative-policy description.

These are executable-file toolchain identities, not an attestation of every
compiler/runtime library. Pinned setup actions, Go 1.26.4, public dependency sums,
and the trusted fresh hosted build are the build trust boundary. Python is >=3.11
(the workflow selects 3.12). Compilation is offline after public dependency
fetch/verification; no direct/VCS fallback or private dependency is permitted.
The source manifest is checked again after compilation before receipt creation.

The unprivileged corpus driver verifies the captured build-receipt digest,
archive/fixture identity and all three build-output hashes before invoking root.
The expected native-helper hash is taken from that saved build receipt, not
recalculated from a mutable source copy at privilege entry. The root bootstrap
freezes bytes in exclusive owned scratch and hashes the frozen file against it
BEFORE execution. The broker repeats the file/identity hash in its receipt.
Both the helper and receipt changing after their checkpoint causes refusal.

Threat addressed: accidental or concurrent helper replacement between the
reviewed build, client read, privileged copy and execution; mismatched oracle,
fixture or source receipts. Threat NOT claimed solved: a malicious admitted build
or compromised runner rewriting both code and all evidence before the checkpoint.
A manual hash pasted by the same runner would not solve that threat either.
No private material or shared service exists on this disposable hosted VM, and
root is confined by the reviewed protocol to owned scratch and fixed helpers.
Protecting against a hostile build/runner would require a separately specified
trust boundary, not an invented environment approval service. This packet does
not request or assume that stronger threat model.

## Serialized command plan and budgets

No commands below have been executed. The workflow invokes the unprivileged
`ci.py run` driver with runtime event heads, run identity, checked-out manifest
measurement, setup-action Go executable and fresh work/export paths. It accepts
no preapproved binary-hash or repository-policy-variable argument.

All commands are serial. The clean child environment has fresh HOME/TMPDIR and
caches, Go 1.26.4 with `GOTOOLCHAIN=local`, `CGO_ENABLED=0`, `GOMAXPROCS=2`,
`GOMEMLIMIT=768MiB`, and no inherited private Git configuration/credentials.
Only dependency acquisition enables `https://proxy.golang.org` and
`sum.golang.org`; later commands use GOPROXY/GOSUMDB off. The manifest module pins
are checked before downloads and remain unchanged after compilation.

| Command / stage | Deadline | Sampled process-group RSS budget |
|---|---:|---:|
| `/usr/sbin/sysctl -n hw.memsize` | 15s | 256MiB |
| selected `go version` | 15s | 256MiB |
| SHA-verified public archive download | 90s | 256MiB |
| safe pinned source preparation | 60s | 256MiB |
| `go mod download`, then separately `go mod verify` | 300s / 120s | 1536MiB each |
| `go test -c -p=1 -mod=readonly -trimpath -buildvcs=false -o stage/native-history-fixture ./internal/qualification` | 600s | 3072MiB |
| `go build -p=1 -mod=readonly -trimpath -buildvcs=false -o stage/native-profile-oracle ./cmd/profile-oracle` | 180s | 1536MiB |
| unprivileged corpus driver plus root broker | 720s | 1536MiB |
| each broker native request / oracle invocation | 120s | enclosing budget |

History/oracle compilation runs with nice=10. The standalone test binary's
TestMain serves only the fixture protocol; no native test suite is run by it.
The runner must have at least 6GiB physical memory and 8GiB free scratch. The
workflow has a 45-minute job deadline and a 38-minute driver-step deadline. These
checks/proposals are not observed capacity or executed runtime evidence.

## Narrow root protocol and evidence custody

All Python, the oracle, build tools, corpus assembly and artifact export remain
unprivileged. Root never executes a setup-action Python runtime or checkout
script. `root_protocol.py` calls fixed `/usr/bin/sudo -n /usr/bin/env -i ...
/bin/sh -c` with a literal source-controlled bootstrap. Variable arguments are
only the build-receipt SHA256 and bounded binary byte count, not command/path
selectors. Stdin is helper bytes followed by bounded protocol data, never code.

The bootstrap checks canonical root-owned/non-writable/no-ACL ancestors, creates
exclusive0700 scratch under `/private/var/root`, installs a regular single-link
root-owned0500 helper, then checks its SHA256 using trusted system tools before
exec. No `/Library/macserve` access, general command/argv/path dispatch, eval,
checkout-script sourcing or root traversal/chown of runner-owned output parents.
The sole root code change from the previous protocol is naming its expected hash
as a build-receipt digest rather than an externally approved digest.

The broker accepts exactly32 bounded native requests (4 generation +28 controls)
then a transcript/corpus-hash ACK. It invokes only its frozen own executable with
fixed scratch environment. Generated request directories remain through corpus
file fsync, byte-for-byte readback and parent-directory fsync by the unprivileged
client. Only the matching ACK authorizes successful root-scratch deletion; EOF,
wrong ACK, failed checks or timeout retain scratch for disposable-VM teardown.
The client requires the explicit cleanup receipt. Root emits synthetic results
on stdout and never follows a runner-owned output path.

Original controls remain: empty and two-profile registries, previous/current
histories, four unchanged positives and24 refusals. Raw byte tamper,
self-consistent noncanonical framing, mode0666, ownerUID65534, actual everyone-write
ACL and same-byte symlink negatives use unchanged native writers/verifier and real
scratch protections. Failed mutation/setup cannot count as verifier rejection.
No fake ACL/ownership verifier, real profile collection, recipe, Collect, Approve,
service install or installed-reset execution is introduced.

## Cooperative supervision and the scoped timing trial

The monitor measures a sampled cooperative process group, not an OS memory cap
or hostile-process sandbox. It detects observed escapes but cannot guarantee
immediate discovery/accounting/termination of detached or reparented descendants.
Unprivileged Python cannot reliably signal root. The broker checks that it
inherits the dedicated caller session/group, enforces its own700s lifetime and
120s request limits, and signals only that still-owned original group on failure.
The 45-minute disposable hosted-VM job deadline is a separate provider boundary,
not proof of immediate tree termination. Policy acceptance must come from an
explicit decision, not a string argument, environment variable or build receipt.

Reviewed non-detaching graph: monitor creates one caller session; Python client
inherits it when starting sudo; fixed bootstrap creates no background jobs or
sessions; broker native CommandContext children have no Setpgid/Setsid override;
native protected metadata uses fixed `/bin/ls`, and protection-negative setup uses
fixed `/bin/chmod`; oracle only reads synthetic stdin. Native writer/verifier
functions operate on scratch bytes. No production service/recipe/host collector
entrypoint is reached. Trusted hosted sudo/session behavior and actual controls
still need runtime evidence. This policy is not transferred to other harnesses
whose production children create separate groups.

The reconciled owner-authorized hosted trial changes only the paired sampling limits:

| Policy | Previous | Trial |
|---|---:|---:|
| Per-sample deadline (execution, drainage and parsing) | 250 ms | 500 ms |
| Maximum sample-start gap | 300 ms | 750 ms |
| Nominal sample interval | 100 ms | 100 ms |

This allows 250 ms between the two limits. It is a deliberate
cooperative-policy relaxation, not a demonstrated implementation fix, an optimal
threshold or a promised pass. Longer tolerated observation gaps retain the
existing unbounded RSS-overshoot risk. `PS_REAP_TIMEOUT` remains 200 ms; RSS
budgets, overall stage deadlines, TERM/KILL grace, ownership checks, cleanup,
failure refusal, root protocol and diagnostic allowlist are unchanged.

All nine orchestrator stages and standalone `budget.py` use the same policy.
Existing receipt fields record the actual limits; prior failed receipts retain
their original source/policy bindings. One independent exact-head review is
required before one trial run; normal Go CI may accompany that push. Stop after
that run, including failure. Do not ratchet beyond 500/750 ms or retry. No added
telemetry, Studio action, merge, release or deployment follows from this trial.

## Export and independent post-run binding

Only five bounded public artifacts are exported:
`build-provenance.json`, `public-corpus.json`, `provenance.json`,
`command-receipts.json`, `SHA256SUMS`. No binary/cache/source archive or private
artifact is uploaded. Per-command stdout/stderr are bounded at1MiB each; corpus
at32MiB and total export at36MiB. Receipts omit raw argv/env/process listings and
console errors are bounded/sanitized. Export hashes are read back before deleting
build caches; no broad privileged cleanup. Failed root scratch is left for VM
teardown, not reclaimed through untrusted paths.

On a bounded-command failure, the console reports a fixed stage, monitor exit,
bounded command exit and allowlisted reason codes **in recorded order**. Unknown
codes become `unclassified_failure` in place; missing/malformed/oversized or
wrongly bound receipts disclose no contents.

The owner-authorized bounded diagnostic projection additionally permits:

- Existing aggregate timings: `elapsed_seconds`, `deadline_overshoot_seconds`,
  `max_observed_ps_duration_seconds`, `max_observed_sample_start_gap_seconds`.
- Existing counts: `sample_count`, `positive_sample_count`,
  `peak_sample_process_count`, `sampled_aggregate_peak_kib`.
- Build hashes: archive, fixture source, Go executable, Python executable,
  `native-history-fixture`, `native-profile-oracle`, `history-fixture-source.json`
  and the build receipt itself.
- Targeted timeout observations under `ps_timeout`: fixed `phase`
  (`pre_completion_check` or `post_parse`), cached `exit_code` in -255..255,
  and boolean `stdout_eof` / `stderr_eof`. Missing or invalid observations are
  explicitly null; unknown phase invalidates the whole observation.

These four timeout fields are captured before the exception and cleanup, only
when the sampling deadline fails. `pre_completion_check` means the deadline
check ran before confirming process and pipe completion, not that `ps` was
necessarily running. Null cached exit means no exit was observed; no added poll
or wait is performed. EOF booleans describe what the monitor consumed, not
whether the process has finished writing. `post_parse` means parsing returned
before the late deadline check; it does not identify parsing as the delay source.
The elapsed timeout observations remain censored, not completed `ps` latency.
Cleanup cannot overwrite this snapshot. No phase-duration attribution is added.

The targeted-diagnostic authorization permits one exact-head independently
reviewed run at unchanged 500/750 ms limits, then requires stopping. All other
guards and the existing public artifact allowlist remain unchanged. No further
fields, retries, Studio actions, merge or release are authorized.

Timings must be nonboolean finite numbers in 0..86400; counts must be nonboolean
integers in 0..2^53-1; hashes must be 64 lowercase hexadecimal characters.
Every missing or invalid field is explicitly `null`, never an invented zero.
These are receipt observations, not independent build or runtime attestation.
No per-phase timing, PID/PGID, UID, errno, raw stream, argv, environment, runtime
path or arbitrary exception text is exported. The console projection needs no
additional artifact upload and still runs before the original nonzero refusal.
Failure diagnostics do not themselves change monitor policy, root authority or
the five-file artifact allowlist. The separately authorized timing trial above
requires independent exact-head review before its single triggering push; it
does not authorize retries or deployment.

Independent post-run review must compare source/workflow heads and measured
manifest with the pre-upload review, verify source/archive/module/toolchain and
binary hashes against the build receipt, bind the root frozen-helper identity and
corpus to that receipt, and inspect all command/negative-control/custody/resource
results. Build receipt existence, upload success and a green job are not by
themselves independent approval or installed/live proof.

Meaningful later controls, NOT RUN: changed head or workflow bytes, missing source
manifest member, changed module pins, replaced helper/oracle/receipt, wrong root
copy hash, symlink/ACL/owner violations, malformed/oversized protocol, early EOF,
wrong ACK, missing durable readback, budget/deadline breach and actual sudo group
behavior. No source-text/wiring tests are added. This revision is awaiting exact
source review and the separate cooperative-policy decision before any upload.

# Signed receipts and GitHub pull mode

This page was split out of the [README](../README.md); text is unchanged unless noted.

The required `receipt` configuration contains `key_id`, `private_key_file`, opaque `service_id` and `host_id`,
`repositories` (canonical lowercase `owner/repo` to numeric repository ID), and optional `verification_keys`
(key ID to base64 Ed25519 public key). Every profile repository needs a pinned ID. The running executable's
actual SHA-256 and build identity are recorded. Use a controller-only Ed25519 PKCS#8 PEM key, raw seed/private
key, or base64 seed/private key. Pin public keys out of band; retain old verification keys during rotation and
remove revoked keys deliberately. A key fetched beside an untrusted receipt is not a trust anchor.

Receipts bind the admitted request digest, repository/commit/tree/export, recipe, observed toolchain/runtime,
actual argv/timing/exit, cleanup, test outcomes and artifact hashes. `complete` describes evidence completeness;
it is not a success verdict. Verification must also require successful state and the exact expected policy.
Container failures cannot count as executed tests. Build receipts explicitly say tests were not run.
A `simulator_script` receipt also says tests were not run (`tests_not_run`, no required tests, no xcresult):
it proves the derived script exited 0 on the pinned, observed simulator, and its `output.tar.gz` is a required,
hashed artifact. A script receipt without its simulator pin or with test evidence is refused.
An org-template job's admitted snapshot carries no recipe; its success is checked against the recipe derived
from the reported `.macserve.json`, which must equal the reported recipe and whose executable must have exited 0.
A Flutter template job's receipt has `request.flutter.version` equal to the template's pin and
`observation.flutter` with the `framework_version` and `dart_sdk_version` the job's SDK clone reported
(`flutter --version --machine`), the first line of `ruby -v` (`ruby`) and `pod --version` (`cocoapods`). Success
requires `framework_version` and `cocoapods` to equal the pin and the other two to be non-empty. Receipts of other
jobs have no `flutter` key, and a receipt for a non-Flutter recipe with a Flutter request or observation is refused.
The controller logs a refused or failed worker request with its method, route and job ID; a receipt refusal
returns HTTP 422.
Submodules and Git LFS are unsupported and rejected, not silently omitted.

Every public receipt is a compact signed core, regardless of size, with a full-manifest SHA-256, size and
authenticated URL. Full recipes and command manifests are never included in GitHub check output.
Canonical compact bytes remain unchanged through SQLite, HTTP and GitHub. The manifest route serves only
the digest committed by the terminal receipt, never an uncommitted cancellation-race candidate.
Full manifests remain immutable; cancellation during sealing produces a distinct candidate.
Legacy committed full receipts remain private and require an explicit rerun before public evidence publication.
This cutover does not erase check output already published by an older version.
Normal evidence maintenance removes manifests only after their 90-day job metadata expires. It may relieve
disk-only pressure, but does not run through manual/owner pause or security-readiness uncertainty.
Raw logs/artifacts still have their shorter seven-day retention.

Optional `github` configuration contains `app_id`, `installation_id`, RSA PEM `private_key_file`, `policies`,
and `poll_seconds` (30–60; default 45). Install the App only on approved repositories, with metadata/contents/
pull-request read and checks write permissions. The App must cover configured receipt repositories used
for source fetch; each token is scoped to one numeric repository ID and kept in memory. No App secret or Mac
API token belongs in Actions. Without App configuration, the private API can fetch public Git repositories;
numeric receipt repository identities then come from administrator configuration, not a fresh App lookup.

Each policy supplies `repository_id`, `repository`, `author_ids`, `base_branches`, `profiles`,
`policy_revision`, and optional `actions_bot_id`, `actions_app_id`. Numeric author and repository identity,
not display names or commit author text, control admission. Repository writers must all be trusted: allowlisting
a PR author does not authenticate everyone who can push to their branch.

Polling automatically enrolls each observed eligible open same-repository head; no comment or Linux workflow
is required. Forks, unlisted authors, disallowed bases and disabled profiles never execute. A current head is
eventually reconciled; transient heads overwritten between polls may not be observed. Immediately before source
preparation, head/policy is rechecked. Permanent rejection cancels without executing; transient transport,
server or rate-limit failures retry within the bounded preparation deadline. Active polling revalidates once
per poll rather than blocking on that retry loop. Removing GitHub configuration does not turn previously
enrolled jobs into private-API work.

Require `mac-evidence/<profile>` **from the configured App**. Checks target the PR head, never the synthetic
merge commit. Only the current attempt may update the stable check; publication retry/restart reconciles
`external_id=job-id` rather than rerunning work. Failure, timeout, cancellation, missing evidence and policy
rejection cannot publish success; policy rejection uses `action_required`, not passing `neutral`/`skipped`.
This does not implement merge-queue `merge_group` evidence.

Periodic repair considers only current eligible heads, including their terminal results, not historical or
currently ineligible fork heads. Each publication pass handles at most ten entries under one minute of network
deadline, prioritizing job-bound evidence. Jobless rejection checks are best-effort once; a missing required
check remains nonpassing. Obsolete blocked rows retire when no publisher lease is held. Obsolete terminal
publication retries drain for at most 24 hours; job-linked provenance/correlations remain until jobs are pruned.

Machine comments have exactly this grammar:

```text
/mac-evidence sha=<40-lowercase-hex> profile=<approved-id> request=actions:<run-id>:<attempt> mode=ensure
```

Only the configured numeric Actions bot is accepted; when an App identity is present it must match the pinned
Actions App. Edited comments are rejected. `ensure` joins the same logical run, including terminal results.
Explicit `mode=rerun` starts a new attempt only after termination, at most twice per head/profile per hour;
active attempts are joined. Correlations are durable and capped at 128 per attempt.

Initial comment intake starts 24 hours before startup with two minutes of overlap, never at repository creation.
One page of at most 100 comments is processed per poll; page position and scan-start watermark survive restart.
The watermark advances after the complete scan; transactional admission/storage errors retain their page.
An individual comment's PR lookup failure is logged with repository/comment/PR identifiers and skipped,
so later comments and pages still progress. No failed lookup authorizes work. This also applies to transient
lookup failures: overlap may revisit them, but there is no guaranteed retry queue for skipped comments.
Existing cursors are not reset after long downtime. Requests older than the initial window are not enrolled.
GitHub offset pagination is not a snapshot: historical edits/deletions during a prolonged scan can shift offsets;
the overlap mitigates recent churn but does not guarantee replay under adversarial historical mutation.

## Linux workflow waiter

Install a reviewed, checksummed `macserve` binary and trusted pins without checking out PR code. Give the
workflow only `GITHUB_TOKEN` permissions `contents: read`, `checks: read`, `pull-requests: write`.
Do not use `pull_request_target` to execute PR code or transfer App/private-network credentials.

```sh
macserve wait --pins /absolute/trusted-pins.json \
  --pr \"$PR_NUMBER\" --sha \"$PR_HEAD_SHA\" \
  --request \"actions:$GITHUB_RUN_ID:$GITHUB_RUN_ATTEMPT\" --timeout 90m
```

`PR_HEAD_SHA` must be the event's `pull_request.head.sha`, not `GITHUB_SHA`'s synthetic merge commit.
The pins JSON contains `repository_id`, `app_id`, `profile_digest`, `required_tests`, `verification_keys`,
and `request` with `repo`, `profile`, `kind`, `xcode` (version/build), and the exact `simulator` pins when needed.
An optional pinned `request.sha` must match `--sha`. For an org test-template job, `required_tests` is the job's
`.macserve.json` shard selectors in file order (its admitted snapshot has none). Use the admitted profile digest,
not a hash of hand-edited JSON. Public keys are standard base64. Protect this policy independently of the
submitted branch.

The waiter posts a machine comment, binds its immutable ID/body to the admitted job/attempt, filters paginated
checks by exact head/name/App, rereads the selected check, verifies the pinned receipt and rereads the PR head.
Timeout, supersession, missing/invalid evidence or non-success exits nonzero; it never cancels shared Mac work.
Success prints JSON and writes `job_id`, `check_url`, `receipt_digest` to `GITHUB_OUTPUT` when supplied, plus
verified test counts to `GITHUB_STEP_SUMMARY`. Downstream jobs can depend on this waiter job. Offline Mac/network
outages keep the required check pending or missing; they do not clear a gate.

Native signatures attest recorded observations for trusted code, not host integrity or honest tests. Private
screenshots/source and full manifests stay behind authenticated downloads; a compact GitHub receipt does not
give an uncredentialed Linux job arbitrary artifact access. Real App authorization, branch protection, target
recipes, account boundaries and GUI qualification still require the approved deployment acceptance window.

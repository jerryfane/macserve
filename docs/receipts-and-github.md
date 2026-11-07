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
An `ios_archive` receipt says tests were not run and carries three fields no other receipt has: `release` (the
admitted `build_name`, `build_number` and `dart_defines`, equal to `request.release`), `release_provenance`
(`repository_id`, `default_branch`, `head_sha`, `resolved_at` and `source`, resolved by the keyholder's own
GitHub App check before it signs; receipts from before the keyholder carry the admission-time resolution) and
`signing_manifest_sha256`, the SHA-256 of the `signing-manifest.json` artifact. Success
requires `source` `github_app`, `repository_id` equal to the receipt's repository, `head_sha` equal to the request
and source commit, a `resolved_at` not after sealing, both required artifacts `App.xcarchive.tar` and
`signing-manifest.json`, and the manifest digest equal to that artifact's. A receipt of any other kind with one of
these fields is refused; their absence keeps other receipts' bytes unchanged. The receipt proves an unsigned
archive of a default-branch head; it does not sign or upload anything.

Receipts are signed by the keyholder (`org.macserve.keyholder`, account `_macserve_key`), which alone holds the
receipt key; the controller asks for each one and never reads the key. The keyholder first verifies the root
worker's build seal over the job and its result (docs/architecture.md, K threat model). It signs an `ios_archive`
success receipt only when the seal matches the repository's entry in the root-owned
`/Library/macserve/config/release-scope.json` (profile id, version and digest, Xcode and Flutter pins, the exact
`dart_defines` map; `build_name` `^[0-9]+(\.[0-9]+){0,2}$`, `build_number` `^[0-9]{1,9}$`) and its own GitHub check
finds the scoped repository ID, the commit at the default-branch head and that commit's tree equal to the tree the
worker computed from the bytes it built; the controller's admission-time provenance is ignored. Without a release
scope entry no release receipt is signed. A refusal is definitive: the controller records the job as `failed` with
the refusal as its reason, keeping the worker's cleanup proof, and asks for that failure receipt instead; signed
receipt and manifest bytes cross the keyholder socket as opaque byte strings, never re-encoded. `service.binary_sha256` is the SHA-256 of the root `macserve` binary
that runs the keyholder.
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

## Signer receipts

`POST /v1/jobs/<id>/sign` (see [install](install.md#code-signer-optional-signed-testflight)) has the controller
send the signer one JSON line over its socket, `{"job_id","receipt" (base64 of the exact job receipt envelope),
"archive_path","manifest_path"}`, with the two paths fixed to `<inbox>/<job id>/App.xcarchive.tar` and
`<inbox>/<job id>/signing-manifest.json`. The signer answers one JSON line `{"ok":true,"receipt","ipa_sha256",
"ipa_size"}` followed by the ipa bytes, or `{"ok":false,"error":"<reason>"}`. Each side checks the other's peer UID.

Before it opens archive bytes the signer requires: the job receipt's Ed25519 signature under a key pinned in
`signer.json`; complete succeeded `ios_archive` evidence (`ValidateSuccess` against the receipt's own identity,
including cleanup, release and GitHub App default-branch provenance consistent with the repository and commit);
the request's job ID; and `signing_manifest_sha256` equal to the manifest file. It then copies the archive
privately, requires the manifest's size and SHA-256, and extracts the copy refusing anything but root-owned
`0755` directories and `0755`/`0644` regular files below `App.xcarchive/`, traversal, duplicate or case-colliding
names, and any `0755` set other than the manifest's executables. It refuses an existing `embedded.mobileprovision`,
a bundle the admin policy does not list, and a profile that is not this bundle's unexpired App Store profile for the
team and configured certificate (no `ProvisionedDevices`/`ProvisionsAllDevices`, `beta-reports-active` true, exact
`application-identifier`, `get-task-allow` false). Each app and app extension is signed with the requested
entitlements the profile allows (`aps-environment` takes the profile's value; `$(AppIdentifierPrefix)` and
`$(TeamIdentifierPrefix)` resolve to `<team>.`) plus `application-identifier`, the team identifier,
`get-task-allow` false, `beta-reports-active` true (TestFlight; from the App Store profile, whatever the build
requested) and, if not requested, `keychain-access-groups` `[<team>.<bundle id>]`; frameworks and
dylibs are signed without entitlements. Signing is inside-out (dylibs, frameworks, app extensions and nested apps,
root app) with `codesign --force --sign <SHA-1> --keychain <kc> [--entitlements <plist>] --timestamp`, each node
verified with `codesign --verify --strict`. The ipa is a deterministic zip (`Payload/<App>.app`, byte-ordered
entries, 1980-01-01 timestamps, modes `0755`/`0644`), re-extracted and re-verified: every node verifies, every app
and app extension embeds its exact profile bytes and carries exactly the planned entitlements
(`codesign -d --entitlements :-`).

The signer receipt is an Ed25519 envelope in the job receipt's canonical form, signed by the key `signer-init`
generated; the controller pins it (`signer.key_id`/`public_key`) and checks the job, archive, manifest, job
receipt and ipa digests before storing `App.ipa` and `signer-receipt.json`. Capabilities publish the key.

```json
{"payload":{"archive":{"name":"App.xcarchive.tar","sha256":"850b…ca2c","size_bytes":13312},
 "build_name":"2.0.1","build_number":"17",
 "bundles":[{"bundle_id":"com.example.app","entitlements_sha256":"1a83…8223","path":"Products/Applications/Example.app","profile_sha256":"d44a…0a0c","profile_uuid":"8A464E05-BF03-7AF2-4322-00C8687455FC"},
  {"bundle_id":"com.example.lib","path":"Products/Applications/Example.app/Frameworks/Lib.framework"},
  {"bundle_id":"com.example.app.widget","entitlements_sha256":"dde2…93d0","path":"Products/Applications/Example.app/PlugIns/Widget.appex","profile_sha256":"3ffa…d071","profile_uuid":"690502AA-80A5-AE7D-0E87-DC99CFCED750"}],
 "commit":"cccc…cccc","dylibs":["Products/Applications/Example.app/Frameworks/libswiftCore.dylib"],
 "identity_sha1":"1B19192636BDFF18B441495C549D46DD3102084A",
 "ipa":{"name":"App.ipa","sha256":"b1b7…1ddf","size_bytes":6721},
 "job_id":"job-1","job_receipt_sha256":"3dc8…1338","repository":{"id":77,"name":"example-org/example-app"},
 "schema":1,"signed_at":"2026-11-06T12:00:00Z","signer":{"key_id":"macserve-signer-studio"},
 "signing_manifest_sha256":"d9ac…a00d","team_id":"ABCDE12345"},
 "signature":{"algorithm":"Ed25519","encoding":"base64","key_id":"macserve-signer-studio","value":"…"}}
```

`entitlements_sha256` is the SHA-256 of the exact entitlements plist passed to codesign. Uploading (part 3) verifies
this receipt with the published key before using the ipa.

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

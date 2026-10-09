# PR #11 — R1 corrections

Review input: `r1-pr11.md`, reviewing `eb7a0f68422b84152333b3af6a0f251915f93e50`. ShellCheck evidence: the supplied `shellcheck-pr11.txt`. Corrections are on `feat/deploy-kit`.

## Fixed

### P2 — ShellCheck CI failure

Replaced all 15 reported SC2015 chains with explicit conditionals: ten in `assets/create-users.sh`, five in `assets/install.sh`. Refusal conditions remain fail-closed. No ShellCheck suppression, severity reduction, skipped check, or CI workflow change was introduced. The supplied failure log was used as the baseline; the reported failure was not rerun merely to confirm it.

### P3 — Supplementary staff membership

`create-users.sh` now rejects GID 20 for both newly created service accounts, alongside GIDs 0, 80, and the other service account's primary GID. This check occurs before directory provisioning. Unexpected membership still leaves account creation in a refused partial state requiring reviewed recovery; no automatic account deletion or privilege removal was added. The production membership validator is exercised with both roles and each forbidden group.

### P3 — Case-insensitive JSON and StagePolicy field meaning

Qualification's strict JSON validation rejects duplicate keys under the same Unicode simple-fold equivalence used by Go's JSON field matching, recursively and before destination mutation. This covers ASCII case variants, escaped keys, long s, Kelvin sign, and nested reports/controller values.

`StagePolicy` already uses this validator through `policyConfig`; ambiguous controller input now fails before archiving or replacing installed files. The canonical `policy_sha256` field remains required. Reordering uniquely named fields preserves their typed controller meaning; only the intended policy digest changes. Regressions cover report success overrides, policy/other-field aliases, and unchanged unrelated controller semantics.

### P3 — Retryable partial collection

Each attempt uses fresh `collect-<random-id>-*` names for immutable report, snapshot, receipt, and snapshot-refusal artifacts. Receipt bytes are preserved before validation. Failed-attempt evidence remains in the protected session, while only the completing attempt's input hashes enter the candidate. Summary files may be replaced on retry; `candidate.json` remains the last publication step. An existing candidate blocks recollection, including when its categories failed: a new probe round needs a new session.

The session mutex now uses a persistent, owner-private, single-link regular file with a nonblocking advisory lock. Process exit releases the lock without deleting its inode. Concurrent writers and unsafe lock objects are refused. Old-version `.lock` directories are not automatically deleted or adopted. Retries retain challenge expiry, ownership checks, artifact limits, and live-binding checks.

Filesystem regressions exercise malformed-receipt failure after snapshots, corrected-input retry, preservation of original bytes, current-attempt hashes, completed-candidate refusal, process-exit lock release, contention, and unsafe lock objects.

### P3 — Root probe must not write `--out`

`qualify probe` rejects real or effective UID 0 before reading the challenge or accessing the output path. No root-owned refusal report is created. Non-root identity-refusal reporting remains unchanged. Boundary coverage supplies real-root/effective-root combinations without changing process privileges and checks new files, existing files, symlinks, invalid output paths, and a missing session.

The installation runbook and CLI help describe the updated root-refusal and collection-retry contracts.

## Verification

Passed locally:

- Existing private ShellCheck **0.11.0**, `--shell=bash assets/*.sh`; no system installation was performed.
- `/bin/bash -n` for `create-users.sh`, `install.sh`, and `qualify.sh`.
- Go **1.26.4**, `GOMAXPROCS=2`, `nice -n 10`, `-p 2`: targeted `assets`/`internal/qualification` regressions, `go vet ./...`, and `go test ./...`.
- `CGO_ENABLED=0`, `-trimpath` CLI builds for Darwin/arm64 and Linux/amd64. The CLI package tests and Darwin build were repeated after updating help text.
- Actual safe command smoke: account plan, UID-collision refusal, both roles' accepted unprivileged membership and rejected staff membership, installer missing-binary and wrong-digest refusals, and rebuilt `qualify --help`.

The first missing-binary smoke invocation omitted required `--env` and correctly returned usage status 2; the corrected invocation reached the binary refusal and passed. This was a smoke invocation error, not a product failure.

Limits: no `gh` use, remote CI rerun, push, actual root probe/collection, installation, account mutation, PF/launchd operation, owner-home probe, Apple tool, or GUI qualification. Root-ID ordering and collection persistence were verified through unprivileged production-helper fixtures, not a privileged native sitting. Linux was cross-built, not run. These checks do not claim operational qualification or resolve the deferred native-evidence findings below.

## Deferred P3

- **Job-report trust:** `owner_home_denial`, `unix_socket_boundary`, `approved_allow`, and `tool_profiles` still ultimately depend on the job's report rather than independent root verification. Hashing and strict decoding preserve interpretation and provenance, not truth. No stronger boundary claim is made.
- **IPv6 denial behavior:** the review's **[INFERENCE]** that macOS IPv6 denial rows may not time out remains unverified. Actual controlled native evidence is still required; timeout/denial semantics were not weakened.
- **Reboot predecessor bindings:** identical interface and root-rule digests remain required across the predecessor chain, despite the runbook's broader statement about recording changes. A changed binding can still block qualification. No compatibility exception was introduced.
- **Root/non-Darwin digest-mismatch test:** `TestBootstrapWrongDigestNeverExecutesBinary` still has the reviewed root/Linux failure. The supplied uid-65534 passing observation is accepted; no root rerun or unrelated test-policy change was made.
- **Full-SHA GitHub Actions pins:** retained exactly as reviewed. The review labels this P3 but identifies no defect to correct; CI/release pins and permissions were not relaxed.
- **Previously deferred PR #8 F2, F3, N2:** unchanged and outside this correction. PR #8 N1 (staff membership) is fixed above, not deferred.

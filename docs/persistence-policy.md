# Reviewed persistence policy — unreleased migration

This page was split out of the [README](../README.md); text is unchanged unless noted. It continues the worker description in [architecture.md](architecture.md#implemented-packages).

This policy change is not permission to deploy, grant security permissions, remove apps or start/reset a host.
Existing worker configurations must explicitly add a separate clean absolute `persistence_path`; deployment
material now uses `/Library/macserve/var/broker/reviewed-persistence.json`. There is no legacy-config fallback
and no generated allowlist. Old GUI baselines lack the reviewed digest and require a fresh reset/qualification.

With admission disabled and under separately approved root administration:

1. Run `macserve worker-persistence inspect --config /absolute/worker.json --out /root/private-candidate.json`.
   This is read-only native inspection plus creation of a new mode-0600 private candidate, **not acceptance**.
   Unresolved candidates retain private problems and exit nonzero; they cannot be accepted.
2. Privately review every registration, nested executable, relationship and integrity binding. Do not publish
   candidate contents. App/developer containers are explicit records, not ignored decoration. An unresolved
   embedded reference remains ineligible even if its container looks ordinary; attribution must precede any
   separate policy decision. Third-party daemon/login/autostart and unknown registration kinds remain ineligible.
3. Only after explicit review, run `macserve worker-persistence accept --config /absolute/worker.json
   --candidate /root/private-candidate.json --reviewed-sha256 REVIEWED_SHA256`. Acceptance holds the stopped
   broker's exclusive lock and requires an independently repeated live census/code match. It does not clear
   quarantine, reset processes, approve qualification or start services.
4. Perform the separately approved PID-baseline reset and fresh qualification. Manifest replacement invalidates
   the baseline binding and previous health/qualification; app, extension or OS updates are not auto-adopted.

Both `worker-persistence inspect` and `accept` have a fixed six-minute inspection deadline, with no
user override and below the ten-minute ceiling. The full native collector initially exceeded the
former 120-second limit; a complete warm collection measured 113.7 seconds. Six minutes is three
times that measured runtime rounded up, allowing cold-cache variation without removing a bound.
Expiry still fails closed: an incomplete inspection cannot authorize acceptance. Each unique parent
tree is measured once per pass; the mandatory post-signature tree and ACL rechecks remain intact.

Eligible third-party app/nested-code classifications are only a review schema, never trust by category. Every such executable
binding requires matching bundle/team signature identity, non-ad-hoc Apple-anchored signature verification and designated
requirement; a registration-only writer policy; and a canonical app-tree digest including nested bytes, names,
ownership, links and permissions. For the code tree **and every ancestor**, ownership must be root or configured
`owner_uid` (UID 501 in the reviewed deployment). Only root, that owner and the verified `wheel` (GID 0)
and `admin` (GID 80) groups may write through modes or ACLs, including unambiguous inherited grants.
`staff` (GID 20), job/controller groups and everyone are not allowed writers. Both service accounts'
actual primary, supplementary and nested memberships are checked: native Directory Services membership
queries supplement the group list, so membership in `wheel`/root, `staff` or `admin` refuses rather than
turning a service account into an allowed writer. Root/owner/job/controller identities must be distinct
and the named groups must resolve to their expected GIDs. Unavailable identities/memberships and unknown
ACL principals/rights fail closed; deny entries never cancel an unsafe grant or mode. This policy does **not** relax root-only broker/configuration,
manifest or owned-service protection.

Tree roots and all ancestors must be non-symlinks and are rechecked around inspection. Signed executable
containment uses filesystem directory identity and descriptor-confined access, not case-folded path text:
`Plugins` and `PlugIns` may identify the same directory only when the filesystem says they do. Existing internal
bundle links remain supported only when they resolve inside the protected tree. Strict, deep signature checking
uses the inline requirement `=anchor apple generic`. The full tree and ACL policy are checked again after
signature inspection. A failed initial tree measurement stays an unresolved private-candidate Problem, never
a cached digest or accepted authority. New, missing, changed, unprotected or incomplete state refuses. Owner/wheel/admin
write permission is **not automatic update approval**: every app/extension update that changes the bound tree
requires explicit re-review/acceptance, baseline reset and fresh qualification, even with the same signer/team.

Hot registration/claim, pre-job and post-job checks do **not** walk or hash registration descendants.
They freshly check the exact accepted BTM records/identities, zero legacy items, LaunchAgents/crontab,
group membership, and each registration root and ancestor's ownership, mode and ACL, alongside the
existing GUI process checks. They also require a protected durable full-scan attestation bound to the
accepted manifest, boot and relevant identities/version, stored as `persistence-attestation.json`
beside the protected accepted manifest. A short-lived `.lock` protects publication; a separate
`.scan.lock` serializes full scans across processes from initial observation through publication.
Lock acquisition polls nonblocking with a context deadline; health reads atomic records without acquiring
either lock. No FSEvents watcher or TTL cache substitutes for live checks.

Root maintenance performs one full scan every six hours in a background task, independently of its
eight-second health observation. A full scan has a fixed 480-second deadline, does not hold the worker
admission lock, and never overlaps another full attestation scan, even in another process. Scan-lock
contention refuses that invocation without changing authority. Missing attestation fails admission closed
and schedules an initial scan. A full-scan mismatch or collection error durably revokes only the revision
that scan checked; a stale scan cannot revoke a newer publication or review. Hot-path transient failures
refuse only that admission. Positive hot mismatches revoke; the reason precedence preserves an existing
`reset_required` marker over `mismatch`, then `authority_changed`, then `inspection_unavailable`. Revocation preserves the last
successful verification timestamp. Periodic success cannot silently heal revocation: preserve evidence,
review and accept the current registrations, reset the GUI baseline, then requalify. Acceptance writes
`reset_required`; only a successful explicit reset completes that recovery. Reset does not implicitly erase
an unrelated admission quarantine. Explicit inspection, acceptance, reset, and qualification retain
full verification; qualification `begin`, `collect`, `approve` and `reapprove` run it before the cheap
observation, under a 540-second outer command deadline.

The explicit full scan publishes the live binding whenever the stored record is not durably revoked: it
also rebinds a changed boot, UID or helper path. A release-carry sitting (`qualify begin --carry`) runs the
strict build rebind instead: the stored record must be valid and unrevoked and equal the live binding in
every field except the macserve `build`; only then does the same full scan run and publish the new build.
A version, manifest, boot, UID, GID or helper-path difference, or a missing or revoked record, refuses
before collection and leaves the record unchanged; a scan failure after acceptance revokes as usual. Maintenance launchd shutdown allows 600 seconds
for cancellation and protected revocation publication.
The periodic operation also has a 540-second outer deadline, leaving publication/revocation headroom
outside the worker's 480-second collector deadline.

The 480-second full-scan budget is three times an observed cold 157.806467208-second full registration
collection, rounded up to eight minutes. The corresponding cheap registration portion took
0.160902417 seconds. That native read-only replay covered all 16 accepted registrations (apps plus nested
plug-ins/extensions), with zero full-collector problems including final rechecks. It ran as the owner using
the accepted v016 census as a raw-input substitute and the installed helper for executable context.
These are registration-check measurements, **not** a full login-items/admission timing: root-only
legacy-item and job-home checks were not exercised, nor was a fresh root BTM census collected.

**Residual trusted-writer window:** root, the owner, and trusted admin/wheel writers can change protected
code between full scans without changing its registration-root metadata or BTM identity. Such descendant
changes are not detected by the hot path until the next full scan (normally within six hours, plus scan
time; an unavailable/stopped maintenance service can delay that scan). This is the approved boundary
against job/controller writers, not immediate detection of trusted-writer updates or hostile root.
Health reports the last successful full verification time, never relabels a health tick as a full scan,
and does not treat the six-hour schedule as a cached-success TTL.

The parser intentionally supports a bounded observed schema, not arbitrary future `dumpbtm` or ACL formats.
Native code verification and complete account qualification still need host evidence.
Since v0.1.18 the macOS 27 per-record `Last Use: <timestamp>` line (for example
`2026-10-29 13:16:14+04:00`, or `(null)`) is accepted on job-UID and owned root-daemon records as a volatile,
non-identity field: at most once per record, strictly validated, then discarded, so it never reaches the
census, manifest, digest or review export and a daemon run cannot invalidate accepted persistence. Every
other unknown record field still refuses.
The per-UID census **header UUID is part of the exact reviewed identity**, not a decorative field. Stability
across reboot/store migration is an operational assumption requiring host evidence. A changed header UUID
refuses admission and requires explicit re-review/acceptance followed by baseline reset and requalification;
macserve never strips or silently refreshes it.

The new pinned `github.com/ebitengine/purego v0.9.1` dependency is Darwin-only and binds only the deprecated
CoreServices session-list census plus CoreFoundation count/lifetime operations. It preserves the
`CGO_ENABLED=0` Linux-to-Darwin release build; there is no runtime compilation, extra installed native helper,
AppleEvents fallback or removal binding. Read-only native positive/empty snapshots establish operation on the
tested OS, not equivalence across all future System Events/OS implementations or global launch mechanisms.
The independent BTM/LaunchAgents/crontab/process checks remain mandatory; unavailable legacy APIs fail closed.

**Owned-service attribution (unreleased change):** the full root BTM dump may link a job-user developer
notification container to UID `-2` legacy-daemon records for macserve itself. Only the exact identifiers
`16.org.macserve.controller`, `16.org.macserve.worker`, and `16.org.macserve.maintenance` qualify for this
separate live check. The record URL must be `/Library/LaunchDaemons/<label>.plist`, and its executable path
must equal configured `helper_path`. The plist and helper, including their parents, must be root-owned,
non-symlink, not group/other-writable and have **no ACLs**, even deny-only ones. The XML plist's `Label` and
`ProgramArguments[0]` must match; any `Program` override must name the same executable. Open-file `fstat`
device/inode identity (`os.SameFile`) must match `helper_path` to `os.Executable()`.

Every embedded reference in an own-service container must resolve uniquely to a verified owned record,
with the matching parent relationship. Mixed, unknown, duplicate or unresolved references refuse. Only
after these checks is that container omitted from the third-party review census; the linked root records
are not persisted as approvals. Checks run again on each native census, including the post-inspection
snapshot. Thus later registration of the other owned labels does not auto-adopt third-party records or
invalidate the manifest solely for owned notification metadata. The job-UID header UUID remains bound.

This narrowly recognizes protected infrastructure, not any app name, developer name, team or signature.
Ad-hoc macserve code is permitted here because the check binds the protected helper to the checking
executable—not because an ad-hoc signature proves provenance. There is no new digest pin or claimed
installed-binary digest verification. The threat is job-UID-created persistence; root tampering, including
replacement of the executable path or protected configuration, is outside this boundary. `os.Executable`
plus `fstat` is not an attestation against a hostile root replacing a running image. All third-party manifest,
signature, process and other persistence controls remain mandatory. This does not authorize deployment.

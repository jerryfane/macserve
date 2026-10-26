# Issue43: public native artifact contract with receipt-bound PR CI

SOURCE-ONLY PROPOSED PR TEXT. No PR, upload, build, test or CI run has occurred.
Do not publish until exact pre-upload source review is complete and the separately
pending cooperative hosted supervision decision is accepted. PR publication
triggers CI; this document is not authorization to publish or execute.

## Scope

Adds ordinary same-repository pull-request CI for the public v0.1.16 native byte
contract, using only pinned public sources/dependencies and synthetic facts on a
fresh disposable hosted macOS runner. Optional manual dispatch remains subject
to default-branch registration; no default merge is required for first PR execution.
Existing pinned actions and read-only contents permission are retained.

No repository environments, secrets, variables, shared permission/security
changes or manual binary-hash approval service are required. The workflow records
runtime event identities rather than embedding its own commit or manifest hash.
It checks out both the exact source head and executing-workflow head and compares
the workflow bytes before building.

## Source-to-binary custody

One job serially verifies the pinned native archive and module inputs, builds the
native helper/oracle once, and saves a read-back/fsynced build receipt before root
work. The receipt carries source/workflow heads, manifest and source hashes,
archive/module hashes, toolchain executable hashes/versions, binary hashes and
command receipts. It explicitly does not claim independent runtime approval.

All Python and export logic remain unprivileged. A fixed system-tool bootstrap
installs the compiled helper in fresh protected root scratch and verifies the
frozen copy against the build receipt before execution. The narrow broker accepts
only bounded native requests and a final transcript/corpus ACK; it provides no
general path or command interface. Root never traverses/chowns runner-owned
output directories. Native scratch remains until unprivileged durable corpus
readback, followed by an explicit cleanup receipt.

Native production writers/verifier and real ACL/owner/artifact negatives remain
unchanged. Two synthetic profile cases produce four native histories and28
controls: four positives and24 refusals. No actual service/config/profile/ledger,
owner data, private source, installed-reset or live-host proof is included.

## Review and verification

`PUBLIC-SOURCE-ALLOWLIST.txt` and `PUBLIC-SOURCE-MANIFEST.json` identify the exact
public packet. Manifest self-hash is recorded outside the packet by the source
review; CI exports its measured value for independent comparison, not self-approval.
Five public artifacts are proposed: build provenance, corpus, run provenance,
command receipts and checksums. Independent post-run review must bind these to
the reviewed source and exact executing head and inspect real control outcomes.

The cooperative group monitor is a sampled budget, not an OS cap or guaranteed
immediate detached-child termination mechanism. Root broker deadlines and the
disposable hosted-VM job deadline are separately described in PUBLIC-PLAN.md.
Acceptance of that narrower policy remains PENDING; no waiver is assumed and it
must not be applied to a different multi-process-group harness.

Not verified: compilation, hosted sudo/group behavior, native controls, resource
limits, cleanup or actual workflow execution. This change is source-only. Existing
installed-service, full selected-artifact and independent runtime acceptance gates
are not reduced by this public corpus workflow.

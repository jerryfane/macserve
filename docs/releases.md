# Releases, the release manifest and the CI release key

Every `v*` tag runs `.github/workflows/release.yml`. Besides the binaries, `SHA256SUMS`, `macserve.rb` and (when
provable) `carry-proof.json`, every release publishes `release-manifest.json` and `release-manifest.json.sig`: a
manifest signed by the **CI release key**. The administrator's carry verb (`carry-install-controller`, in
macserve-admin) installs a controller-only release unattended only on the strength of that signature.

## What the CI release key trusts

The key states: *this workflow, running for this tag after its gates passed, built (or republished) exactly these
binaries.* Its trust is **merge + review + the CI key**, and nothing more:

- anyone who can get a commit onto `main` and push a `v*` tag (repository admins and maintainers, through branch
  protection and review) can get a manifest signed;
- anyone who holds `MACSERVE_RELEASE_SIGNING_KEY` (GitHub, the repository admins who can edit the
  `release-signing` environment, or a compromised runner of the sign job) can sign anything.

The Mac does not and cannot prove that a change was reviewed or merged; it proves only that the manifest was
signed by the pinned key. Under the K threat model ([architecture](architecture.md#two-binaries-and-class-k)) a
compromised key or a malicious merged controller change runs as the controller UID: the carry verb replaces only
`macserve-controller`, and only when the installed root binary, store schema and full installed inventory already
match the manifest. What controller-UID code can then reach is bounded by K's threat model, which reaches its
stated limit (never root, the owner's home or Apple signing) only with the keyholder and worker changes.

## Release jobs

1. **rebuild** (macOS): rebuilds both binaries with `checks/release-build.sh` on a second host and path, and runs
   the rebuilt `macserve-controller version --json` to report its `store_schema_version`.
2. **release** (Linux): builds both binaries, requires them byte-identical to the rebuild, selects the release
   kind, writes `SHA256SUMS`, attests both binaries, runs `checks/release-manifest create` and
   `checks/carry-proof`. It publishes nothing.
3. **sign** (Linux, environment `release-signing`): the only job given the key. It requires the tag commit to be
   on `main`, builds `checks/release-manifest` in a step that never sees the key, refuses a key whose public
   half differs from the committed `checks/release-manifest/release-signing.pub`, signs, and verifies the result.
4. **publish** (Linux): verifies the binaries' attestations and the signed manifest against them and
   `SHA256SUMS`, appends `release-manifest.json` and `release-manifest.json.sig` to `SHA256SUMS`, attests
   `SHA256SUMS`, the manifest, the signature and `carry-proof.json`, renders the formula and creates the release.

Any failed gate stops the run before `gh release create`; no unsigned release is published.

## `release-manifest.json`

Schema `macserve-release-manifest/1` (interface contract with macserve-admin):

```json
{
  "schema": "macserve-release-manifest/1",
  "tag": "v0.1.37",
  "commit": "<40 hex>",
  "kind": "full | controller-carry",
  "base_tag": "<full release whose root binary this keeps; equals tag when kind=full>",
  "binaries": {
    "macserve": {"sha256": "<sha256 of the unsigned macserve-darwin-arm64 asset>"},
    "macserve-controller": {"sha256": "<sha256 of the unsigned macserve-controller-darwin-arm64 asset>"}
  },
  "store_schema_version": 6,
  "created_at": "2026-11-07T12:00:00Z"
}
```

The bytes are canonical: exactly this key order, two-space indentation, `encoding/json` string escaping, one
trailing newline, lowercase hex, `created_at` in UTC with whole seconds. A verifier refuses any other encoding of
the same values, so one manifest has one byte sequence and one signature. `store_schema_version` is the SQLite
`user_version` the controller migrates to; CI requires the tag's source (`version --json` of its
`cmd/macserve-controller`) and the released controller binary (run on the macOS rebuild runner) to agree.

`release-manifest.json.sig` is standard padded base64 of the raw 64-byte Ed25519 signature over the exact bytes of
`release-manifest.json`, then a newline. Public keys are standard padded base64 of the raw 32 bytes, then a
newline (the newline is optional when reading). No PEM, no hex.

## Full and controller-carry releases

A tag is a **full** release unless it is an annotated tag whose message contains exactly one line

```
Macserve-Carry-Base: vX.Y.Z
```

naming an earlier full release. Such a tag is a **controller-carry** release:

```sh
git tag -a v0.1.37 -m "v0.1.37: controller fix

Macserve-Carry-Base: v0.1.36"
git push origin v0.1.37
```

(`go run ./checks/release-manifest carry-base -tag v0.1.37` prints the base the workflow will use.) For a carry,
the release job downloads the base release's `macserve-darwin-arm64` and `SHA256SUMS`, verifies both
attestations (base tag ref and commit, this repository's release workflow, GitHub-hosted runner) and the binary's
digest in the base `SHA256SUMS`, and **publishes those bytes** as this release's `macserve-darwin-arm64`. Only
`macserve-controller` comes from this tag's build. `release-manifest create` then refuses to produce a manifest
(and the run fails, publishing nothing) unless all of these hold:

- the base tag precedes the tag, names another commit, and is a full release (its own `release-manifest.json`,
  when it published one, is listed in its attested `SHA256SUMS`, has kind `full`, the base tag and commit, and the
  same root digest);
- the published root binary's digest equals the base `SHA256SUMS` entry;
- every path changed between the two commits is class K, C, G or T in the **base** tag's `BOUNDARY.json`, and
  `BOUNDARY.json` itself is unchanged (any B path, such as `cmd/macserve`, `go.mod`, LaunchDaemon assets or this
  workflow, refuses);
- the root binary's **source closure** is unchanged: `go list -deps -json ./cmd/macserve` under the release build
  settings (`GOOS=darwin GOARCH=arm64 GOARM64=v8.0 CGO_ENABLED=0`, `GOFLAGS`/`GOEXPERIMENT`/`GOENV` cleared) is run
  in both trees, extracted from the git object database, and must give the same set of standard-library
  packages, the same dependency module versions (and replacements), the same main-module packages and the same
  sha256 of every Go, assembly, embedded or other source file they compile, plus the same `go.mod` and `go.sum`
  digests (`go.mod` also pins the toolchain);
- `store_schema_version` of both trees is equal (no store migration in a carry), and equals the released
  controller binary's own report;
- the full boundary check (classification, C/G source rules, link graph) passes on the new tree.

`carry-proof.json` (qualification carry for `macserve upgrade`) is generated independently and usually refuses a
carry release, because it does not treat K paths as carryable. `macserve setup` and `macserve upgrade` refuse a
controller-carry release (its root binary reports the base tag, not the release tag); controller-carry releases
are for the administrator's carry verb only. The off-host rebuild of a carry tag reproduces its
`macserve-controller`; its `macserve` is reproduced by rebuilding the base tag.

## Verifying a manifest

```sh
go run ./checks/release-manifest verify \
  -pub checks/release-manifest/release-signing.pub \
  -manifest release-manifest.json -sig release-manifest.json.sig \
  [-tag vX.Y.Z] [-commit SHA] [-kind full|controller-carry] [-sums SHA256SUMS] \
  [-macserve macserve-darwin-arm64] [-controller macserve-controller-darwin-arm64]
```

Semantics, in order; the first failure exits 1 with its reason, success prints one `verified ...` line and exits
0, a usage error exits 2:

1. `-pub` is read (regular file, at most 4 KiB) and must decode to 32 bytes; `-manifest` must be at most 64 KiB;
   `-sig` must decode to 64 bytes.
2. The Ed25519 signature is checked over the exact manifest file bytes. Nothing in an unverified manifest is
   parsed.
3. The manifest is parsed strictly: known fields only, no trailing data, valid values (schema, `vX.Y.Z` tags, 40-hex
   commit, 64-hex digests, positive schema version, kind/base_tag consistency) and canonical bytes.
4. Each optional expectation: `-tag`, `-commit`, `-kind` equal the manifest's; `-sums` lists exactly one entry for
   each binary asset, equal to the manifest's digest; `-macserve` / `-controller` files hash to the manifest's
   digests.

The verifier checks the signature and the manifest only. It does not decide whether a carry may be installed: the
carry verb additionally compares the installed root binary's recorded release digest, the installed store's
`user_version` and the full installed inventory (see the carry contract).

The production public key is `checks/release-manifest/release-signing.pub`
(`Boflm04/NdP1a8+P1wzsYhHIW8BGDKNcQMJAshtYpQk=`, key id `0fc20662dd8148c4` = first 16 hex digits of sha256 over
the raw 32 bytes). The Mac pins its own copy at `/Library/macserve-admin/config/release-signing.pub` (root:wheel
`0644`), installed in a full sitting; the copy in this repository is what the sign job requires the secret to
match.

## One-time setup and key rotation

The key is generated off GitHub and stored only as the environment secret:

```sh
go run ./checks/release-manifest keygen -seed-out release-signing.seed -pub-out release-signing.pub
gh api -X PUT repos/jerryfane/macserve/environments/release-signing   # then restrict deployments to tags v*
gh secret set MACSERVE_RELEASE_SIGNING_KEY --env release-signing --repo jerryfane/macserve < release-signing.seed
shred -u release-signing.seed
```

`MACSERVE_RELEASE_SIGNING_KEY` is standard base64 of the **raw 32-byte Ed25519 seed** (the RFC 8032 private key),
no PEM; a 64-byte expanded private key is refused. The `release-signing` environment must allow deployments only
from tags matching `v*`.

To rotate (scheduled, or at once if the key or a sign-job runner may be exposed):

1. Generate a new key pair as above and set the new secret in `release-signing` (this overwrites the old one; tag
   no release in between).
2. Commit the new `checks/release-manifest/release-signing.pub` through a reviewed PR. Until it merges, the sign
   job refuses every tag (secret and pinned key differ), so no release can be signed by the wrong key.
3. Install the new public key on the Mac at `/Library/macserve-admin/config/release-signing.pub`. That file is
   root-owned protected config: changing it is a full-sitting (owner) step, never an agent carry.
4. Manifests signed by the old key stay verifiable with the old public key only. A carry verifies only the target
   release's manifest, so after rotation carries resume with the first release signed by the new key.

A compromised key is contained by the same rotation: the Mac stops accepting the old key when its pinned file
changes, and until then the carry verb still refuses anything that does not keep the installed root binary,
store schema and inventory.

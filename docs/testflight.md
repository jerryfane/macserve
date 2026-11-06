# Signed TestFlight: archive → sign → upload

macserve builds the release archive and signs it on the Mac; the agent uploads it to App Store Connect. No Apple
API key is on the Mac, in macserve or in the agent: the agent asks the local keyring relay for short-lived App
Store Connect JWTs and sends them only to App Store Connect.

| Step | Who | Call | Needs |
| --- | --- | --- | --- |
| 1. Archive | agent → macserve | `POST /v1/jobs` with `"kind": "ios_archive"` and `release` (see [configuration](configuration.md)) | scopes `jobs:submit` + `release:archive`; an org `ios_archive` template |
| 2. Sign | agent → macserve | `POST /v1/jobs/<id>/sign` until `200` (see [install](install.md#requesting-a-signature)) | scope `release:sign`; the job's own principal or `service:admin` |
| 3. Upload | agent → App Store Connect | `macserve testflight-upload` | scope `jobs:read`; a keyring role with the `appstoreconnect` service |

## `macserve testflight-upload`

```sh
macserve testflight-upload \
  --api http://127.0.0.1:7700/<role>/macserve-builds \
  --job <job id> --keyring-role <role> --app-id <numeric App Store Connect app ID> \
  --out evidence.json
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--api` | required | macserve API base that authenticates the agent (the keyring relay adds its token) |
| `--job` | required | the signed `ios_archive` job |
| `--keyring-role` | required | keyring role; JWTs come from `POST <keyring>/<role>/_keyring/sign/appstoreconnect` (empty body) → `{"token","expires_at"}` |
| `--app-id` | required | the App Store Connect app (Apple ID number in App Information) |
| `--keyring` | `http://127.0.0.1:7700` | keyring relay base |
| `--asc` | `https://api.appstoreconnect.apple.com` | App Store Connect API base |
| `--timeout` | `2h` | deadline for verification, upload and processing |
| `--out` | none | evidence JSON, created new (an existing file is refused before anything runs) |

It runs on Linux and macOS, needs no Xcode or Transporter, and never writes to macserve. Progress goes to stderr;
stdout gets a `key=value` summary. The exit status is `0` only when the build upload reached `COMPLETE`.

### What it verifies before App Store Connect is contacted

1. `GET /v1/capabilities` → the `signer` key (`key_id`, base64 Ed25519 `public_key`) the controller pins.
2. `GET /v1/jobs/<id>` → a `succeeded` `ios_archive` job and its requested `release`.
3. `GET /v1/jobs/<id>/signing` → `status: signed` with exactly one content-addressed (`id` = `sha256`) `App.ipa`
   and `signer-receipt.json`.
4. The signer receipt: its bytes match the listed SHA-256 and size; the Ed25519 envelope verifies under the
   published key; it names this job, this job's receipt (`GET /v1/jobs/<id>/receipt`, SHA-256), the job's
   repository and commit, the job's `build_name`/`build_number`, and the listed `App.ipa` digest and size.
5. `App.ipa` downloaded by its content ID: exactly the receipt's size (a longer body is cut off and refused) and
   SHA-256.
6. The ipa holds only `Payload/<root app>/`, and that app's `Info.plist` (XML or binary) has the receipt's root
   bundle ID as `CFBundleIdentifier` and its `build_name`/`build_number` as `CFBundleShortVersionString`/
   `CFBundleVersion`. The signed receipt is authoritative (the worker bound every bundle's versions into the signing
   manifest, which the receipt binds); the plist read is an independent check that needs no macOS tools.
7. `GET /v1/apps/<app id>` has that bundle ID.

Any mismatch stops the run with nothing sent to App Store Connect.

### Upload (App Store Connect Build Upload API)

| Request | Body / purpose |
| --- | --- |
| `GET /v1/apps/{id}/buildUploads?filter[cfBundleShortVersionString]=…&filter[cfBundleVersion]=…&filter[platform]=IOS` | find an upload to resume |
| `POST /v1/buildUploads` | `{"data":{"type":"buildUploads","attributes":{"cfBundleShortVersionString","cfBundleVersion","platform":"IOS"},"relationships":{"app":{"data":{"type":"apps","id"}}}}}` |
| `GET /v1/buildUploads/{id}/buildUploadFiles` | find a file reservation to resume |
| `POST /v1/buildUploadFiles` | `{"data":{"type":"buildUploadFiles","attributes":{"fileName":"App.ipa","fileSize","uti":"com.apple.ipa","assetType":"ASSET"},"relationships":{"buildUpload":{"data":{"type":"buildUploads","id"}}}}}` |
| each `uploadOperations[]` | its `method` to its pre-signed `url`, body exactly bytes `offset`…`offset+length-1`, exactly its `requestHeaders`, no JWT |
| `PATCH /v1/buildUploadFiles/{id}` | `{"data":{"type":"buildUploadFiles","id","attributes":{"uploaded":true,"sourceFileChecksums":{"file":{"hash","algorithm":"MD5"}}}}}` |
| `GET /v1/buildUploads/{id}` | poll every 15 s until `state.state` is `COMPLETE` or `FAILED` |

The operations must cover the ipa exactly (no gap, overlap or overrun) or nothing is sent. The commit checksum
is the whole file's MD5 (Apple's [upload guide](https://developer.apple.com/documentation/appstoreconnectapi/uploading-assets-to-app-store-connect)
specifies MD5 for `sourceFileChecksum`); if the reservation already names an algorithm (`MD5` or `SHA_256`) that one
is used, and a hash it already carries must equal this ipa's.

Retries: requests that got no response or a `5xx` are resent up to 5 times with doubling backoff from 1 s (at
most 30 s, or a longer `Retry-After` up to 60 s). Other `4xx` responses stop the run, except `401`, which fetches a
new JWT and resends once. Creations (`POST`) are never resent blindly: after a lost response, a `5xx` or a `409`
the tool lists again and resumes what exists. A JWT within 60 s of `expires_at` is replaced before the next
request, including between upload parts and while polling.

### Rerunning (idempotence)

Rerun the same command after any failure or interruption. An existing build upload for the same app, version,
build and `IOS` is resumed instead of creating a duplicate (`COMPLETE` first, then `PROCESSING`, then the newest
`AWAITING_UPLOAD`):

- `AWAITING_UPLOAD`: the existing ipa reservation is reused (its `fileSize` must equal this ipa's), every upload
  operation is sent again (parts are idempotent until commit) and the file is committed. A commit App Store
  Connect refuses is accepted only if the build upload already reports `PROCESSING` or `COMPLETE` and its file
  is bound (below).
- `PROCESSING` or `COMPLETE`, or a file already committed: nothing is uploaded or committed. The ipa file must be
  bound to this ipa: this ipa's size, and a `sourceFileChecksums.file` with a supported `algorithm` (`MD5` or
  `SHA_256`) and a `hash` equal to this ipa's. Apple may omit the checksum; an absent, empty or different checksum
  means the remote bytes cannot be shown to be this ipa, so the run fails with no `final_state` and the upload
  must be resolved in App Store Connect or a new build number archived. A bound upload is then polled.
- only `FAILED` uploads: the run fails with their errors. Delete the upload in App Store Connect or archive a new
  build number.

Reservations expire (Apple plans for about a week); an `AWAITING_UPLOAD` upload whose reservation lists no
operations must be deleted in App Store Connect before rerunning.

### Evidence

`--out` is written also when the run fails (with `error` and as far as the run got, including a
`build_upload_id` to resume):

```json
{
  "job_id": "job_4c0f…",
  "signer_receipt_sha256": "9b1c…e2",
  "ipa_sha256": "3f5a…71",
  "ipa_size": 48213376,
  "app_id": "6760713318",
  "bundle_id": "com.example.app",
  "build_name": "2.0.1",
  "build_number": "17",
  "build_upload_id": "b7e1c2d4-…",
  "resumed": false,
  "final_state": "COMPLETE",
  "started_at": "2026-11-06T12:00:00Z",
  "finished_at": "2026-11-06T12:09:41Z"
}
```

`state_errors` lists App Store Connect's `{code, description}` when it reports any. `COMPLETE` is the build
upload's terminal success state; the resulting build, its TestFlight processing and beta distribution are
read and managed through `/v1/builds`, which this command does not touch.

## Keyring role

The role named by `--keyring-role` needs the keyring's `appstoreconnect` service, backed by an App Store Connect
API key allowed to upload builds for the app. The agent only ever holds the signed JWT, never the key. When the
same relay also serves `--api`, the macserve token it adds for that role is the agent's own.

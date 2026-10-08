# macserve

**Use your own Mac as a private iOS build-and-test service.**

Submit an exact Git commit, pick a pinned Xcode toolchain, and get back logs, test results, screenshots and a
signed evidence receipt. Jobs run natively on your Mac under a dedicated non-admin account, one at a time, at low
priority, and you can pause them whenever you need the machine. GitHub integration is pull-based, so your CI never
needs network credentials for your private network. No VM required.

> Status: early development. Phase 1 (build and test, no signing) is being implemented.

## What it does (phase 1)

- Runs `build`, `unit_test` and `simulator_ui_test` jobs for a repository at an **exact 40-character commit SHA**.
- Uses controller-owned, versioned **profiles** (project/workspace, scheme, destination, allowed tests, artifacts);
  clients cannot inject shell commands, environment variables or paths.
- Pins the **Xcode version and build** and the **simulator runtime** per job.
- Returns status, paged logs, an `xcresult` summary (JSON/JUnit), artifacts, and a signed receipt
  (repo, SHA, tree, toolchain, runtime, exit status, test counts, log/artifact digests).
- **Pull model for GitHub**: a GitHub App polls allowlisted repositories and publishes results as check runs, which
  can be made required checks. No inbound access from GitHub to your Mac.
- Optional private HTTP API (bind to a private interface only, TLS, scoped bearer tokens) for local tooling.
- Plays nice with your daily use: **one job at a time**, background scheduling priority, memory budget, a persisted
  **pause / drain** switch, disk budget with per-job cleanup and simulator deletion.

## What it does not do (yet)

- **No code signing, archiving, App Store Connect or TestFlight in phase 1.** No signing credentials are ever given to
  build jobs.
- **Not a hostile-code sandbox.** Jobs run natively under a separate non-admin user with network restrictions, but they
  share the kernel and hardware with your session. Only run repositories you trust.
- No VM management, no device farm, no multi-host scheduling.

## Architecture

- `controller` (runs as a dedicated non-login service user): queue (SQLite), GitHub poller, API, receipt signer.
- `worker` (runs as a dedicated non-admin GUI user via a LaunchAgent): executes one job, reports over a Unix socket.
- Build user has no access to your home directory, your keychain, or service credentials.

## License

Apache-2.0

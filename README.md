# macserve

**Use your own Mac as a private iOS build-and-test service.**

Submit an exact Git commit, pick a pinned Xcode toolchain, and get back logs, test results, screenshots and a
signed evidence receipt. Jobs run natively on your Mac under a dedicated non-admin account, one at a time, at low
priority, and you can pause them whenever you need the machine. GitHub integration is pull-based, so your CI never
needs network credentials for your private network. No VM required.

> Status: early development. Only command-line wiring is implemented: `controller` and `worker` report that they
> are unavailable and exit nonzero. No listener, queue, job execution, account setup or system changes occur.
> The phase-1 capabilities and architecture below describe the planned service, not currently available behavior.

## Planned phase-1 capabilities

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

## Planned architecture

- `controller` (runs as a dedicated non-login service user): queue (SQLite), GitHub poller, API, receipt signer.
- `worker` (runs as a dedicated non-admin GUI user via a LaunchAgent): executes one job, reports over a Unix socket.
- Build user has no access to your home directory, your keychain, or service credentials.

## Development

Use the Go version declared in `go.mod`. The command-line package currently uses only the standard library.

```sh
go vet ./...
go test ./...
go run ./cmd/macserve --help
```

`macserve --help` and `macserve <command> --help` exit 0. Invoking `controller` or `worker` without help
exits 1 until those services are implemented; invalid or missing arguments exit 2. Help goes to stdout,
errors to stderr. These commands do not start services or require administrator privileges.

CI runs vet, tests and a CLI build on GitHub-hosted `ubuntu-latest` and `macos-latest`. Future macOS-only
implementation files must use Darwin build constraints so portable packages remain testable on Linux.
No simulator or app build is part of this initial CI workflow.

## License

Apache-2.0

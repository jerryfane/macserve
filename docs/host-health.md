# Installation assets and host health

This page was split out of the [README](../README.md); text is unchanged unless noted. The step-by-step runbook is the [installation guide](install.md).

[Quick path: four owner-approved deployment sittings](install.md#quick-path) starts with a reviewed
`v*` release, `deploy.env`, and `assets/install.sh` in plan mode. Tag CI publishes a CGO-disabled,
`-trimpath` Darwin arm64 binary and `SHA256SUMS` using only `GITHUB_TOKEN`; the deployed host needs no Go.
Explicit root apply stages disabled controller/worker/maintenance assets, empty profiles, generated keys
and a one-time API token. The installed `qualify.sh` collects actual account-specific probes and protected
candidate evidence; approval is a separate root command. Reboot stays pending until a sitting on a later
boot, and tool_profiles until root-run pinned recipes succeed. Nothing activates services or changes owner ACLs; macserve never writes PF.

Keep the owner's home at **0700**, or **0750 with an owner-private group—not staff—that excludes the job
account**. Audit ACL grants separately. Qualification requires an `owner_home_denial` probe from the actual
job GUI identity with its full groups: directory access and reading an approved nonsecret home canary must
be denied while owner read controls succeed. The installer never changes owner-home permissions.

`macserve maintenance --config PATH` publishes short-lived root-owned health after checking protected
qualification/evidence bindings, the job's `;ShadowHash;` authentication authority, exact GUI baseline identities, profile
digests, memory pressure and mutable storage including the entire job home. Since v0.1.17 only critical
kernel memory pressure blocks admission; warning admits (unknown levels and sysctl errors still fail
closed). A finding publishes invalid health; startup/shutdown invalidate it. A probe that failed without
evidence (for example its deadline) blocks admission; active work is cancelled only when the last valid health
expires (see [configuration](configuration.md)). Probe cadence is
measured from probe start, not completion.
`maintenance-observe` collects live inputs without approving the host or writing health. Both require
macOS root; neither modifies host policy, adopts processes or generates boundary-test evidence.

Job qualification and health identity inspection refuse a missing or unreadable authority with
`job user not listable at login window`. Account creation uses `JOB_REAL_NAME` (default `macserve build`)
and creates the job through `sysadminctl -password -` during interactive administrator apply, never with
`-admin` or a password value in argv. Any inherited job `staff` membership is removed and rechecked;
admin membership or a set `IsHidden` attribute refuses. See the installation guide.

`maintenance-observe --coexistence-only --config PATH` reads configured peer service PIDs and opaque main/peer
PF rule digests without needing a GUI baseline or completed qualification. PF read failures are recorded as
`unavailable`; stopped, unreadable or restarted configured services are not silently accepted. No PF rule
syntax, UID matching, translation policy, ownership receipt or loopback-filtering claim is inferred.
Normal build directory churn is tolerated by the approximate mutable-budget census, not treated as an
isolation failure. Root-protected qualification still requires real approved boundary/owner-home/GUI/reboot
probes; fixtures and local checks are not native host qualification.

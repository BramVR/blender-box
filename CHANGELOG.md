# Changelog

## Unreleased

- Stop reporting a successful Windows setup command as failed with cleanup unknown when Windows briefly omits an exited process from its Job member list; the list is read again and only a complete reading counts.
- Let delayed pairing-proof observers recover and collect the original expired request, and accept IPv6 SSH endpoints when resolving the pairing address.
- Prove pairing inside the `host-install` proof: preview SSH preparation, verify the offer digest, refuse a tampered offer, a forged offer and a wrong pinned host key, enroll twice with identical receipts, run the baseline Scenario through the paired target, revoke through the client, and require the revoked key to be refused while admin access and the pinned keys file survive; recovery from any pairing stage revokes host-locally and never replays enrollment.
- Add the `pair-and-run` job to the Windows onboarding proof workflow, which recovers and collects the baseline job's execution and passes only when every pairing outcome and the settlement pass; the installer grant scope is now `host-install-pair-run-remove`.
- Add host-local pairing commands `pair offer|enroll|revoke|status --state-root` and the `host pair-revoke` machine command: create-only offer, grant and tombstone records, one `restrict` line admitted into the keys file sshd resolves for the account, exact removal that preserves every other byte, byte-identical receipts on retry, and revocation fenced by host maintenance.
- Add `setup ssh` preview, apply and remove for Windows OpenSSH: start sshd and set it Automatic when needed, create one owned inbound firewall rule only when no enabled rule admits the port, refuse when public-key authentication is off, and restore only what it changed.
- Add the Windows pairing platform: elevated `sshd -T` resolution of the account's authorized keys file, descriptor checks sshd accepts, and a one-process keys-file replace that keeps the protected Administrators descriptor and verifies bytes and ACL after the write.
- Add `pair revoke NAME`, which asks the host to remove exactly this pairing's key over the paired connection and reports success only after the host confirms removal and a fresh paired connection is rejected; an unreachable host leaves every local file unchanged, and a retry after a lost confirmation repeats only the rejection check.
- Add local-only `pair forget NAME`, which refuses while accepted remote access is not confirmed revoked unless `--keep-remote-access` is passed, and warn that `targets forget` on a paired target does not revoke remote access.
- Classify SSH and SCP connection failures as `host-unreachable`, `tailscale-unreachable`, `host-key-mismatch` or `auth-rejected` with a next step, and report failed readiness checks from `doctor` and `run` as `interactive-desktop-unavailable`, `runtime-incompatible`, `account-mismatch` or `setup-incomplete` problems, including `host.problems` in doctor JSON.
- Print the enrollment request SHA-256 on stderr from `pair prepare` so the operator can pass it to host `pair enroll --trust-intent`.
- Add the [pairing guide](docs/pairing.md) for onboarding, connection troubleshooting and revocation.
- Settle a Windows setup execution whose worker ends at its deadline before reporting as a resumable `partial` result when the installation receipt shows no pending Scheduled Task change; it no longer fences the shared state root for manual review.
- Add local pairing preparation and trusted-receipt reconciliation, schema-3 targets with pinned SSH identity, shared SSH/SCP credential policy and unchanged legacy fingerprints; client credentials remain POSIX-only.
- Reserve pairing recovery state before credentials so oversized requests, concurrent preparation and interrupted publication do not leave undiscoverable private keys or change the original request on retry.
- Linux qualification `start` no longer replies `native-unavailable` when a fast case exits during observation; it settles the case when the unit is already empty and otherwise reports `released` for `status` to settle.
- Stop Linux qualification cases through the same owner identity as operational attempts; `descendant-stop` and `startup-withheld` no longer crash reading an operational-only receipt field during exact stop.
- Run the hosted `baseline` onboarding job through the persistent proof controller: one owned install, baseline Run, and removal execution per dispatch, with the controller-validated outcome and viewport published; `host-install` settles that same execution instead of consuming a second fixture.
- Add a bounded proof-controller `collect` operation that exports only root-bound baseline evidence, including passing or failed host-install executions without their private installer settlement, after exact settlement and retained viewport opt-in validation.
- Add bounded root-only proof-controller qualification cases and original-Run cleanup authority while keeping ordinary dispatch closed until all native evidence is approved.
- Retain Windows installation and original Run authority on the persistent proof controller across hosted job loss; require durable checkpoint acknowledgement before mutations and exact cleanup before settlement. Render disabled SSH commands as OpenSSH sentinels and restore SSH key terminal newlines stripped by secret storage so hosted proof can authenticate.

- Seal installed Windows Python packages before use so Blender imports cannot add bytecode that blocks repeated installation or exact removal; retain interrupted permission changes in installation ownership records. Batch read-only permission checks to stay within installer process limits.

- Wait for the entire owned Windows installer process tree to finish within its operation deadline, allowing children to exit naturally after their root while retaining exact cancellation and cleanup proof.

- Start Windows installer keepers through a temporary limited interactive Scheduled Task with durable launch receipts, a bounded deadline, and exact external task cleanup before releasing setup authority; preserve private worker Job cleanup across SSH disconnects.
- Add owned Windows runtime installation with pinned artifact manifests, previews that show selected identities and exact managed task changes, durable installation receipts, bounded execution status and recovery, generated targets, repeatable removal, and maintenance fencing; refuse legacy setup apply without ownership and prepare separately authorized host-install proof.
- Start trusted Windows installer PowerShell commands suspended with `CREATE_NO_WINDOW` to restore execution and output while generic commands remain detached and suspended; retain exact Job-member handles, including any console helper, and require complete membership and physical exit proof within one cleanup deadline before reporting tree cleanup.
- Preserve proof-controller Run authority across interruptions with fenced native attempts, one-use worker admission, and local enrollment previews; allow unprivileged identity checks without cgroup write access and wait for exact native stop settlement. Native qualification remains required.
- Require read-only Linux daemon package files and a private service file-creation mask so Blender startup preserves runtime integrity and cleanup permissions.
- Report only Linux-verified daemon capabilities in Linux proof outcomes.
- Accept systemd 255’s omitted empty service-hook and environment-file arrays during Linux setup verification while rejecting populated overrides.
- Recognize GNOME Xorg sessions when GDM leaves desktop metadata empty, using exact-session Xorg identity and display socket ownership.
- Accept official Blender 5.2.0 LTS version banners on Linux and report the normalized version as 5.2.0.
- Preserve verified Run request and Session identity in failed onboarding proof reports after recovery.
- Fix Windows named-target replacement while readers hold the previous profile open, preserving complete records and permission failures.
- Keep Linux daemon, Blender, and Scenario HOME-based caches under each private Run root, with prelaunch validation and exact settlement cleanup while preserving missing-home recovery.
- Keep Linux daemon and Blender temporary files under each private Run root, with prelaunch validation and exact settlement cleanup.
- Recover interrupted Linux setup final receipts only when prior pending hashes match both installed artifacts, and reject relative or noncanonical host paths before traversal.
- Add Linux targets, read-only readiness, explicit static-user-unit setup, and fenced Scenario execution with reviewed daemon provenance; preserve Windows wire compatibility and keep native Linux and hosted proof as outstanding acceptance requirements.
- Add platform-aware named targets with legacy Windows profile support, atomic user-local storage, and recovery bound to original Run authority; prepare named-target proof and block hosted execution until private recovery authority can be retained.
- Preserve owned command cleanup when onboarding proof receipt or process setup fails.
- Accept Blender's numeric PNG resolution metadata in onboarding proof and preserve verified cleanup when retained evidence fails validation.
- Add reusable Windows onboarding baseline proof with exact-candidate authorization, shared evidence and recovery assertions, and a separate protected live workflow.
- Add bounded schema-3 Blender UI clicks, key chords, and Unicode text with exact-Session delivery, capability checks, before/after window captures, and failure journals that never replay uncertain input.
- Add distinct Blender-window and opt-in Windows-desktop captures with local planning, host capability diagnosis, typed evidence provenance, exact-Session fencing, and no-replace publication.
- Fix `windows setup --apply` so every SSH command uses closed stdin, with bounded file staging and exact repeat-safe cleanup.
- Add fenced Windows Scenario execution with bounded SCP setup, payload verification, interactive exact-Session readiness, retry-safe cleanup and recovery, and hash-verified Evidence Bundles.
- Add the first public `windows check --target <file> --json` command for bounded, read-only Windows host inspection.

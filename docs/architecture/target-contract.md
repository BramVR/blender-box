---
summary: Named target selection, platform-specific configuration, and original-target Run recovery.
read_when:
  - Changing target documents, local profile storage, CLI selection, or recovery authority.
  - Adding a host platform or extending onboarding proof.
---

# Target contract

## Problem

A target name is a local convenience. Its contents can change while a Run still needs recovery. Resolving that name again must not let a newer profile redirect status or cleanup to another SSH alias, state root, or executable.

The original flat target document also mixed common selection with Windows identities and paths. Additional host platforms need their own configuration validation without replacing named selection or Run recovery.

## Usage

```sh
blender-box targets import studio --file /path/to/target.json --json
blender-box windows check --target-name studio --json
blender-box plan --target-name studio --payload payload.json --json
blender-box doctor --target-name studio --payload payload.json --json
blender-box run --target-name studio --payload payload.json --json
blender-box status --target-name studio --run bbx_... --json
blender-box stop --target /path/to/target.json --run bbx_... --json
```

`linux setup`, `linux check`, `windows setup`, `windows check`, `plan`, `doctor`, `run`, `status`, and `stop` each require exactly one nonempty `--target PATH` or `--target-name NAME`. Supplying both flags is an error even if one value is empty. There is no ambient default or interpretation of a missing file as a name.

## Decision

Normalize configuration before selecting a host. Keep a saved name, a validated target, and original Run authority separate.

Target schema version 2 requires `platform`, `ssh_alias`, and one platform-specific body. The `windows` body contains both Windows identities, the work root, task name, and executable paths. The `linux` body contains the supported distribution, UID, passwd home, work root, executable paths, static unit name, desktop settings, and reviewed daemon runtime. The two bodies cannot coexist. Version 1 accepts the original flat Windows shape and normalizes to the same target. Import and inspection emit version 2. Unknown versions, platforms, fields, duplicate JSON keys, and invalid platform bodies fail locally. Windows canonical JSON and fingerprints remain byte-for-byte compatible. Linux-specific changes participate in the same target fingerprint and original-authority comparison.

`internal/windowstarget` owns Windows configuration syntax and the existing path grammar. `internal/windows` retains readiness, SID, ACL, task, and daemon capability checks. Common target selection and storage know no Windows path or launch rules. `internal/linuxtarget` owns Linux syntax, and the Linux adapter and runtime own its concrete policy. See the [Linux host boundary](0006-linux-host.md). No empty macOS implementation is part of this decision.

Names use a portable lowercase grammar and select independently stored profiles. Import copies a validated document. Duplicate import requires explicit replacement. Forget deletes only the named local profile. Neither operation edits SSH configuration, revokes access, touches the host, or removes Run authority.

## Original Run authority

Before the first host inspection, the client publishes an immutable local record containing the complete original `LockClaim` and a fingerprint of the normalized target. The fingerprint covers platform, alias, identities, work root, task, and executable paths. It excludes the local name, source filename, JSON formatting, and source schema version.

Recovery validates the supplied configuration against that record before any adapter call. A different target fails even when its task name and Run ID match. A missing or corrupt record reports insufficient recovery authority. The client does not adopt a claim returned by whichever host the current profile happens to select.

After contact, every accepted receipt must match the complete original claim. The first valid nonempty Session identity is pinned separately. Later observations and cleanup require that exact identity. A prelaunch record cannot know an unpublished Session; the existing host and daemon fences still own startup reconciliation. Once a running controller knows that Session, a missing pin fails before another observation, evidence transfer, or cleanup. A fresh process holding only the original prelaunch claim cannot distinguish a never-published pin from a deleted historical pin; its first recovery still validates the complete original host claim before pinning the returned Session. Preserve both local records.

Session pins are immutable. Concurrent identical observations agree; conflicting observations fail. Pin publication failure cannot authorize blank-Session fallback cleanup. Deferred settlement and failed-Run JSON recovery use the same original authority checks as explicit status and stop. Capture and UI failure recovery preserve authority errors through the same path. Evidence transfer and publication revalidate the original claim and Session pin; lost authority cannot publish a successful bundle or trigger fallback cleanup.

A fully decoded receipt with the original claim can reveal a Session even when its remaining fields are invalid. The controller retains that identity to reject blank or conflicting fallback; the malformed receipt cannot publish a pin. Cleanup still requires an existing matching pin. Host observation and settlement errors cannot erase previously retained Session authority.

Equivalent profile contents under another name or in a version 1 file can recover the Run. Forgetting every original copy can make recovery unavailable. Runs created before these local records existed require the original client and original profile. There is no automatic adoption or bypass switch.

## Local storage boundary

The application uses `os.UserConfigDir()/blender-box`. An absolute `BLENDER_BOX_CONFIG_DIR` selects another operator-owned configuration root. Read-only operations do not create it. Profiles and Run records stay outside consuming repositories and public Evidence Bundles.

Publication writes complete bounded temporary files before making them visible. Profile creation and Run authority creation are exclusive. Explicit profile replacement publishes a complete new file atomically. Run claims and Session pins are never replaced. Interrupted writes must leave either complete prior data or no new record; an incomplete record never authorizes host contact.

POSIX publication flushes parent directories through the configuration hierarchy before it can authorize host contact. A failed directory flush is a storage failure, even if the newly created path is already visible to another process.

Recovery also flushes an authority record's directory entries before accepting it. A concurrent reader or a retry after an interrupted publisher must establish durability itself instead of treating visibility as successful persistence. Ordinary profile inspection does not perform these authority flushes.

Separate files avoid a shared mutable catalog or journal transaction. Explicit replacement and forget follow their filesystem operation order. A list is not a transactional snapshot of concurrent profile changes.

Managed records reject symlinks, reparse points, nonregular files, and excessive data. POSIX storage uses owner-only modes. Windows storage uses the per-user directory's inherited access controls. An override must remain private to the operator. The store does not provision or repair unrelated directory permissions, and it does not claim isolation from an actively hostile process running as that same user. Keep the small Run authority records for recovery; garbage collection is outside this change.

## SSH trust boundary

The fingerprint pins declared configuration, including the alias string. SSH continues to resolve and authenticate that alias through operator-managed configuration. Changes behind an unchanged alias, such as a hostname or trust-file edit, are outside profile-content matching. A target fingerprint is not physical-host identity.

Host-key enrollment and pairing remain separate work. The onboarding proof runner verifies its expected hostname and Windows identities before mutation, but that proof assertion does not replace product SSH trust or the Host Lock and exact Session fences.

## Alternatives considered

An immutable target snapshot per Run could recover after the last saved profile disappears. It would also create a second target store and a routing fallback that competes with explicit selection. Matching supplied configuration keeps one selection rule and retains only a fingerprint per Run.

A name plus revision would couple recovery to profile history and make file selection and renaming special cases. Content identity lets equivalent inputs use the same recovery path.

Adding the target fingerprint to every host message would spread a controller-side assertion through the protocol. The host cannot independently verify a local profile name or SSH alias. The original local claim comparison and existing host fences provide the required checks without that wire migration.

## Verification

Default tests exercise local stores and recording fake transports, including replacement before recovery, missing authority, concurrent publication, and first or changed Session identity. Unsupported platforms must fail before network access.

The required real proof is `Windows onboarding proof`, job `named-target`. It imports a real target, runs and recovers by name, verifies evidence and cleanup, and proves that a replacement cannot invoke transport for status or stop. The job extends the existing baseline runner and runs after `baseline` on the shared fixture. Adding its source and passing fake tests does not satisfy the required hosted result.

Hosted proof is blocked at preflight until private original authority can survive an ephemeral runner's loss. Retaining a public Run ID alone is insufficient. This change does not introduce a private storage backend or an authority export/adoption API.

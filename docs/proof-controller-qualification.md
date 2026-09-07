---
summary: Collect bounded qualification evidence through the installed root helper before admitting hosted proof.
read_when:
  - Qualifying an explicitly approved dedicated proof controller.
  - Recovering the original Windows Run after a qualification interruption.
---

# Qualify an installed proof controller

Audience: operators of an approved dedicated Linux controller and owned Windows fixture. Installation, account setup, keys, Windows execution, deliberate process loss, and reboot each require their agreed scope. The enrollment preview performs none of them.

Ordinary dispatch requires an achieved receipt covering all eleven qualification categories. Root qualification permits fixed proof cases before that evidence exists. It leaves ordinary dispatch closed and never writes `qualified:true`.

## Use the root entrypoint

The installed helper accepts `qualification` for Linux cases, `qualify-windows` for Windows cases, and `qualification-cleanup` for an original Windows Run whose recovery authority needs renewal. Both real and effective UID must be zero before protected reads. The control account's sudo rule and forced SSH command expose only `dispatch`.

Each command reads one strict JSON document from standard input, bounded to 16 KiB. Unknown fields, duplicate keys, unsupported cases, and mismatched hashes refuse. Qualification offers no arbitrary shell command, path, environment, or target selector.

Linux `start` requires `schema_version:1`, `operation:"start"`, `family:"linux-native-v1"`, a `q-` identifier followed by 32 lowercase hexadecimal characters, exact `policy_sha256` and `installation_sha256`, an integer `deadline_unix`, and a fixed `case`. The deadline must be within ten minutes. Later `status` and `stop` require the same `qualification_id` and accepted `intent_sha256`.

Windows commands require `schema_version:1`, `operation`, `authorization_id`, `authorization_sha256`, and `case`. Operations are `start`, `status`, `stop`, and `recover`. The authorization ID is `wq-` followed by 32 lowercase hexadecimal characters. Its reference selects the root-owned file under `/etc/blender-box-proof/qualification-authorizations`; the hash binds those exact file bytes.

An approved authorization pins the installed policy and artifacts, candidate and driver commits, fixture, operator manifest, target, client and host binary hashes, exactly one fixed case, launch and recovery deadlines, and attempt cap. The existing `cases` array must contain one entry. Use separate root-owned authorization files for different cases because their execution paths, manifests, and fixtures differ. Each authorization permits at most four attempts. Launch authority is bounded to two hours and original recovery authority to 24 hours when accepted. Do not replace these pins with placeholder values.

`QualificationAuthorization.parse` in `scripts/proof_controller_native.py` defines the complete Windows document. Its `WindowsExecution` identity derives from the authorization ID and case, so the original input manifest can be computed before authorization. That manifest covers the exact retained operator and SSH bytes, target, key, known-hosts file, normalized connection paths, candidate checkout, original config directory, and expected client hash. Changed authorization bytes cannot reuse an existing execution.

## Preserve authority across interruption

Qualification and operational work share one installed service and fixture lock. A version-2 selector distinguishes operational, Linux qualification, and Windows qualification intents. The supervisor repeats source, policy, origin, invocation, cgroup, and release checks before admitting a worker.

Windows qualification uses the existing Controller request, input snapshots, execution state, and recovery path. The root-owned immutable origin keeps it out of public dispatch, including after promotion. Retain the original accepted authorization and live product config. A runtime selector or a host reply cannot replace them.

Cleanup renewal binds directly to the original authorization and execution, original Run and Session, request hash and deadline, retained inputs, installed policy and artifacts. It permits recovery only. A renewal never depends on a predecessor renewal and cannot replay the Scenario. The `qualification-cleanup` command references an exact protected renewal file by ID and SHA-256. Its operations are `status`, `stop`, and `recover`.

Capacity refusal preserves existing records and cleanup authority. Expired launch authority cannot start new work. Root status remains available after expiry or promotion.

## Collect the fixed proof cases

Linux cases are `uid-confinement`, `storage-lock`, `startup-withheld`, `peer-rejection`, `descendant-stop`, `crash-before-release`, `crash-after-release`, `initiator-disconnect`, `reboot-observation`, and `network-local`. They run protected fixed code without reading Windows operator, key, or trust inputs. Review the actual observations for each category; a local network probe cannot establish the dedicated Windows trust boundary.

Windows cases are `windows-baseline`, `windows-named-target`, `windows-crash-recover`, and `windows-reboot-recover`. The first two must match the installed policy variant. Recovery cases use that same variant with the protected hold Scenario. The driver checks the built client before product commands and the expected host binary before setup transfer.

For an approved interruption, require the original local Run marker, immutable claim, Session pin, retained inputs, and matching public active status. At least 900 seconds must remain on the Run deadline. A completed Run never satisfies the active checkpoint. The fixed Scenario waits up to 1200 seconds and fails if its wait expires; its read timeout is 1230 seconds. Qualification uses a 25-minute Run and a 1595-second owned command budget.

Record exact local process ownership before deliberate loss. Stop only the recorded process tree. After reboot, prove the current service empty without querying or signaling previous-boot PIDs. Local termination and Windows cleanup are separate evidence.

Starting `windows-crash-recover` waits for the active checkpoint, then terminates the exact local controller task. The original Windows Run remains available for explicit recovery. Starting `windows-reboot-recover` retains the checkpoint and leaves the task active for the separately approved operator reboot. The helper does not reboot the host.

Linux crash cases terminate the recorded supervisor and observe service containment before fallback cleanup. If fallback cleanup is needed, the crash result remains failed. Disconnect and reboot cases keep their fixed worker waiting while the operator performs the approved interruption.

Recover through the Controller against the retained original live config. Fresh public `status`, exact `stop`, and `status` must agree on original Run authority and cleanup. Cleanup does not turn a failed Scenario into a pass.

## Review evidence before promotion

Bind each evidence category to the installed source and policy hashes. Linux results cannot establish the owned Windows fixture or original Windows recovery. Integrated disconnect and reboot cases need the actual controller and original active Windows Run.

Each Windows execution derives `qualification-evidence.json` and `native-readiness.json` from retained records. The projection binds the original authority, input snapshots, attempts, and original Run evidence. Missing interruption or cleanup facts leave the case partial. Recovery requires a retained root observation of completed cleanup before the original Run deadline. First observing completion after that deadline fails the case, even when renewed authority permits cleanup. Repeated status preserves identical projection bytes. A passing recovery case still leaves the original failed Scenario result unchanged.

An operator installs an achieved receipt only after reviewing all eleven categories. Required hosted baseline and named-target jobs follow that review and must actually pass. Local tests and fake commands do not satisfy native qualification or hosted acceptance.

Keep raw identities, credentials, journals, and detailed logs private. Publish only the defined proof projection. See [controller enrollment](proof-controller.md) for original-journal retention and [CI architecture](architecture/ci.md) for the test boundary.

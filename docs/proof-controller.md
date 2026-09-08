---
summary: Prepare exact enrollment artifacts for the persistent proof controller and distinguish local checks from native qualification.
read_when:
  - Preparing a persistent controller for hosted Windows proof or recovery.
---

# Prepare persistent controller enrollment

Use this guide to prepare a controller enrollment review. The tooling renders files and artifact hashes locally. It does not install resources or qualify a host. Runtime dispatch refuses without matching operator qualification.

## Inspect the resource proposal

Run the preview from the repository:

```sh
python3 scripts/proof_controller.py bootstrap
```

The JSON lists proposed resources and missing qualification. Its `installable` field remains `false`. This command performs no host inspection or network access.

To produce concrete enrollment files, prepare a private JSON specification with these exact fields:

- `schema_version` set to `1`.
- `control_uid`, `control_gid`, `runner_uid`, and `runner_gid` as positive integers for the dedicated accounts. Control and runner UIDs must differ.
- `candidate_sha` and `driver_sha` as full Git commit hashes.
- `expected_client_sha256` for the approved client binary.
- Optional `variant` set to `baseline` or `named-target`. Omission selects `baseline`. Each enrollment admits only its selected variant.
- `public_key` containing the existing controller dispatch public key as `ssh-ed25519 BASE64`, without a trailing comment.
- `tool_sha256` mapping `/usr/bin/python3`, `/usr/bin/git`, `/usr/bin/ssh`, `/usr/bin/scp`, `/usr/bin/systemctl`, and `/usr/local/go/bin/go` to their approved SHA-256 hashes.

Use measured, approved values. Placeholder UIDs or tool hashes describe a synthetic test, not a host enrollment. Keep private host configuration outside the repository.

Choose an output directory that does not exist:

```sh
python3 scripts/proof_controller.py bootstrap \
  --enrollment /path/to/private-enrollment.json \
  --output controller-enrollment
```

File output requires POSIX and a path without symlink components. Review the generated resource list, modes, owners, file contents, and hashes. The enrollment includes the fixed launchers, protected source and Scenario fixture, service, privilege rule, key restriction, policy, and unqualified receipt. A repeated render into the same directory fails.

The command creates no accounts or keys. It has no apply operation. Preserve the generated files as review material until installation and qualification have separate approval. Changing a qualification flag does not authorize changed policy or executable bytes.

## Review the ownership boundary

Check the fixed resources against the intended host:

- `/etc/blender-box-proof` holds root-owned policy, qualification, and operator inputs.
- `/usr/local/libexec/blender-box-proof` holds protected scripts and the matching baseline fixture. The fixed helper and worker launchers use the same prefix outside that directory.
- `/var/lib/blender-box-proof/control` holds root-owned request and process authority.
- `/var/lib/blender-box-proof/jobs` holds runner-owned job data and original recovery files.
- `/var/lib/blender-box-proof/candidate` selects the candidate checkout.
- `/run/blender-box-proof` holds the root supervisor rendezvous. The generated `/etc/tmpfiles.d/blender-box-proof.conf` recreates it with root ownership and mode `0700` at boot.

The control account can request the fixed privileged helper operation. The runner account executes candidate work and cannot choose privileged paths, commands, units, identities, or environment. Launchers check protected source ownership before imports. Root loads the protected driver and fixture. Candidate directories cannot supply its Python imports.

Verify the generated privilege rule allows only the fixed helper invocation. Do not replace it with a general shell, `systemctl`, `systemd-run`, or wildcard sudo grant. Review account and filesystem access, dedicated Windows trust, network reachability, fixture restoration, and candidate authorization before installation.

The installed dispatch public-key file remains root-owned and uses mode `0644` so OpenSSH can read it under the control account's UID. Private keys and operator inputs retain mode `0600`.

See [CI architecture](architecture/ci.md#persistent-controller-milestone) for the process and file ownership decisions.

## Preserve recovery authority

Retain the complete original target, expected host, authorization, and dedicated SSH connection and trust bytes. A copied SSH config that still refers to another account's mutable files is insufficient.

The accepted policy pins the client binary hash before launch. Original inputs publish before service start. Exact invocation authorization publishes before worker release. A result alone cannot establish local process termination.

Keep the original live `BLENDER_BOX_CONFIG_DIR` at the job's `baseline/private/config` directory. The product's immutable Run claim and separate Session pin remain authority. Do not substitute a backup or reconstruct authority from a host reply.

Recovery uses the retained target, client, and live config with fresh per-attempt command logs. It invokes public `status`, `stop`, and `status`, then checks full Run authority and all cleanup facts. Successful cleanup preserves a failed Scenario result as failure.

Keep unresolved jobs. This controller adds no deletion or historical ownership-rewriting policy.

## Dispatch a hosted baseline

Use `proof_controller_dispatch.py` from a hosted workflow whose checkout and installed controller policy are already approved. A fresh run accepts only GitHub attempt `1` and derives `gha_<github-run-id>_1`.

```sh
python3 scripts/proof_controller_dispatch.py run \
  --github-run-id "$GITHUB_RUN_ID" \
  --github-run-attempt "$GITHUB_RUN_ATTEMPT" \
  --candidate-sha "$APPROVED_CANDIDATE_SHA" \
  --policy-driver-sha "$INSTALLED_POLICY_DRIVER_SHA" \
  --expires-at "$FIXED_EXPIRY" \
  --ssh-config "$PRIVATE_CONTROLLER_CONFIG" \
  --controller "$CONTROLLER_ALIAS" \
  --state "$RUNNER_TEMP/proof-controller-private" \
  --output "$RUNNER_TEMP/proof-controller-public" \
  --budget-seconds 900
```

Both `--state` and `--output` must name absent absolute paths below a private directory. The SSH config must be a regular file owned by the current user with no group or other permission bits. The dispatcher uses `/usr/bin/ssh` with one fixed option set, no remote command, no forwarding, no agent, no password prompt, no multiplexing, and no local command.

Before SSH starts, the dispatcher stores and flushes the exact canonical start document in the private state directory. It also writes one canonical recovery metadata line to stdout. That line contains only `execution_id`, `request_sha256`, `candidate_sha`, and `policy_driver_sha`, plus its schema and kind. Preserve those four values with the hosted job record.

An uncertain start always leads to `status`. Only an exact `execution-not-found` error from that status permits one retry of the same start bytes. Any valid receipt closes the retry path. Active receipts are polled at a bounded cadence until settlement or the observation deadline. SIGINT or SIGTERM wakes that wait immediately. Start reconciliation leaves time reserved for `recover` against the original execution ID. If local SSH process cleanup cannot be proved, the dispatcher fails closed without another controller call.

To recover after the first runner is gone, use a new private state directory and the four published values:

```sh
python3 scripts/proof_controller_dispatch.py recover \
  --execution-id "$ORIGINAL_EXECUTION_ID" \
  --candidate-sha "$APPROVED_CANDIDATE_SHA" \
  --policy-driver-sha "$INSTALLED_POLICY_DRIVER_SHA" \
  --request-sha256 "$ORIGINAL_REQUEST_SHA256" \
  --ssh-config "$PRIVATE_CONTROLLER_CONFIG" \
  --controller "$CONTROLLER_ALIAS" \
  --state "$RUNNER_TEMP/proof-controller-recovery-private" \
  --output "$RUNNER_TEMP/proof-controller-recovery-public" \
  --budget-seconds 300
```

Recovery begins with `status`. It sends `recover` once for an unsettled execution, then observes the valid recovery receipt through paced `status` calls inside the reserved wall-clock budget. The dispatcher retains one final exchange and part of the remaining time for `collect`; it has no `start` transition. The four arguments pin the collected schema version 2 envelope to the original execution. Recovery does not need the first runner's state directory or the original expiry.

The dispatcher retains each bounded request, stdout, stderr, result digest, and owned process record in its private state directory. It drains stdout and stderr together. It retains the spawned leader identity until every exact process-group signal finishes, including when a child closes its output pipes and outlives the leader. Timeout, cancellation, output overflow, and normal leader exit cannot leave that child running. If cleanup cannot be proved, captured output and the failed exchange remain private and the dispatcher makes no later controller call.

The dispatcher validates the whole collection response before it creates the output directory. It checks the receipt, request pins, baseline report, settlement, recovery record, artifacts, hashes, base64 sizes, and PNG bytes. It writes an optional `viewport.png` first and `outcome.json` last. A failed baseline stays failed after successful recovery. If a settled failure has no attempt-one collection record, the dispatcher returns failure and keeps the controller receipt in private state.

A supervisor failure before worker release has a separate recovery path. It requires an exact, root-owned failure receipt after owned child cleanup, a completed start-command receipt, no release authorization or native receipt, and fresh proof that the unit has no queued job or remaining processes. Missing files alone never prove that a launch failed. The helper records this decision under the fixture lock, and later startup or release for that attempt must refuse it.

A proven failure of the first baseline attempt settles as failure because no Windows operation was admitted. A failed recovery attempt keeps the original Run, target, client, and journal; Windows cleanup remains unresolved until an explicit recovery succeeds. Unknown starts and uncertain cleanup stay fenced.

If the supervisor published a native receipt before the helper saved its Invocation, use `status` to reconcile that exact attempt. Adoption requires the original accepted request, intent, input binding, and matching process evidence. Conflicting authorization, results, pending work, or replacement identities refuse adoption. The helper saves the receipt's exact Invocation with admission closed before any stop. Repeated reconciliation checks the same evidence after a crash.

Adoption never releases the worker or replays the Scenario. `status` observes. `stop` can stop the exact adopted attempt. Once fresh evidence proves the original processes are gone and no worker release was authorized, a first attempt settles as failure. A recovery attempt retains the original Windows Run for explicit recovery. After a controller reboot, reconciliation proves service quiescence without reading or signaling old PIDs.

## Collect public baseline evidence

The native dispatch entry accepts a read-only collection command with exactly these fields:

```json
{"schema_version":1,"operation":"collect","execution_id":"gha_123_1"}
```

Collection succeeds only for a settled baseline execution whose controller receipt proves local termination and Windows cleanup. It revalidates the accepted request, immutable attempt-one result, final attempt identity, retained inputs, and the final native result. A recovered execution keeps the attempt-one report and its original pass or fail status; its schema version 2 `baseline-collect` envelope adds the final controller receipt plus the final recovery attempt number, exact record SHA-256, and validated cleanup map. The runner's `public/outcome.json` is never evidence authority.

The response has `schema_version`, `operation`, `execution_id`, and `files`. Each file has the exact `name`, byte `size`, SHA-256, and `content_base64`. The file allowlist is `outcome.json` plus optional `viewport.png`. The root-generated outcome is limited to 1 MiB. A viewport is limited to 16 MiB, and the complete canonical response is limited to 24 MiB before base64 materialization.

The retained original operator's `publish_viewport` value controls image release. When enabled, collection requires the immutable baseline report's one `screenshots/viewport.png` artifact and rechecks its type, size, remote and local hashes, offscreen capture method, dimensions, file ownership, symlink boundary, and PNG bytes. A missing, changed, planted, unapproved, or additional public file fails collection. Collection returns no private config, trust, key, journal, invocation, path, or command log.

## Run the local checks

Run the controller tests and full repository gate:

```sh
PYTHONPATH=tests/ci PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/ci -p 'test_proof_controller*.py' -v
./scripts/ci all
```

The tests use temporary files and fake native boundaries. They exercise command and protocol parsing, expected UID selection, publication and release ordering, stale identities, replacement races, recovery, and qualification refusal. They do not establish actual privilege dropping, systemd behavior, cgroup termination, or disk durability.

## Complete native and hosted qualification

After exact enrollment approval, verify the installed artifacts and distinct account permissions on the owned Linux host. Qualify startup, exact stop, supervisor exit, service emptiness, storage flushes and locks, initiator disconnect, controller restart, and controller reboot. A service restart cannot substitute for a reboot test.

The qualification receipt must bind the exact installed policy and artifact hashes. Preserve its real evidence. Bootstrap always renders an unqualified receipt and provides no command to manufacture qualification. The installed root helper supports bounded Linux and Windows qualification cases before ordinary dispatch opens. See [Qualify an installed proof controller](proof-controller-qualification.md) for authority, fixed cases, interruption, and original-Run cleanup.

Verify the selected policy variant before hosted proof. The native worker projects it into `ProofRequest.proof` while retaining hosted execution and the original target and config directory. The protected driver consumes one authenticated inherited socket authorization before candidate commands. The authorization binds the root supervisor, worker process, native receipt, request, and retained inputs.

Direct hosted calls still refuse with `hosted-recovery-retention-unavailable` before host activity. The native authorization admits only the Windows proof host. It does not authorize the Linux proof runner. An environment variable, flag, or caller-created Python object cannot replace native authority.

Required hosted `Windows onboarding proof / baseline` and `named-target` results remain outstanding until those jobs actually pass. Missing, skipped, fake-only, or merely local checks do not satisfy them.

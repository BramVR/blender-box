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
- Optional `variant` set to `baseline`, `named-target`, or `host-install`. Omission selects `baseline`. Each enrollment admits only its selected variant.
- For `host-install`, `installer_inputs` maps `operator.json`, `runtime-manifest.json`, `ssh-config`, `key`, and `known_hosts` to their exact original SHA-256 hashes. Other variants reject this field. The original operator must name `/etc/blender-box-proof/runtime-manifest.json` and the dedicated connection files under `/etc/blender-box-proof`.
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

The control account can request the fixed privileged helper operation. The runner account executes candidate work and cannot choose privileged paths, commands, units, identities, or environment. The root-owned attempt cgroup permits the runner to read and verify its identity. Only root can change membership, terminate the cgroup, or create child groups. Launchers check protected source ownership before imports. Root loads the protected driver and fixture. Candidate directories cannot supply its Python imports.

Verify the generated privilege rule allows only the fixed helper invocation. Do not replace it with a general shell, `systemctl`, `systemd-run`, or wildcard sudo grant. Review account and filesystem access, dedicated Windows trust, network reachability, fixture restoration, and candidate authorization before installation.

The installed dispatch public-key file remains root-owned and uses mode `0644` so OpenSSH can read it under the control account's UID. Private keys and operator inputs retain mode `0600`.

See [CI architecture](architecture/ci.md#persistent-controller-milestone) for the process and file ownership decisions.

## Preserve recovery authority

Retain the complete original target, expected host, authorization, and dedicated SSH connection and trust bytes. A copied SSH config that still refers to another account's mutable files is insufficient.

The accepted policy pins the client binary hash before launch. Original inputs publish before service start. Exact invocation authorization publishes before worker release. A result alone cannot establish local process termination. Exact stop waits within its deadline for both supervisor reaping and an empty settled service. A replacement service identity refuses settlement.

Keep the original live `BLENDER_BOX_CONFIG_DIR` at the job's `baseline/private/config` directory. The product's immutable Run claim and separate Session pin remain authority. Do not substitute a backup or reconstruct authority from a host reply.

Recovery uses the retained target, client, and live config with fresh per-attempt command logs. It invokes public `status`, `stop`, and `status`, then checks full Run authority and all cleanup facts. Successful cleanup preserves a failed Scenario result as failure.

Keep unresolved jobs. This controller adds no deletion or historical ownership-rewriting policy.

A supervisor failure before worker release has a separate recovery path. It requires an exact, root-owned failure receipt after owned child cleanup, a completed start-command receipt, no release authorization or native receipt, and fresh proof that the unit has no queued job or remaining processes. Missing files alone never prove that a launch failed. The helper records this decision under the fixture lock, and later startup or release for that attempt must refuse it.

A proven failure of the first baseline attempt settles as failure because no Windows operation was admitted. A failed recovery attempt keeps the original Run, target, client, and journal; Windows cleanup remains unresolved until an explicit recovery succeeds. Unknown starts and uncertain cleanup stay fenced.

If the supervisor published a native receipt before the helper saved its Invocation, use `status` to reconcile that exact attempt. Adoption requires the original accepted request, intent, input binding, and matching process evidence. Conflicting authorization, results, pending work, or replacement identities refuse adoption. The helper saves the receipt's exact Invocation with admission closed before any stop. Repeated reconciliation checks the same evidence after a crash.

Adoption never releases the worker or replays the Scenario. `status` observes. `stop` can stop the exact adopted attempt. Once fresh evidence proves the original processes are gone and no worker release was authorized, a first attempt settles as failure. A recovery attempt retains the original Windows Run for explicit recovery. After a controller reboot, reconciliation proves service quiescence without reading or signaling old PIDs.

## Retain host-install authority

Host installation has authority before a Run exists and after its cleanup. `proof_installation.py` owns that lifecycle. Its schema-2 anchor binds the immutable request, input digest, separate installation grant, installation ID, and original install and remove operation IDs. Baseline and named-target retain their schema-1 Run recovery records.

The controller snapshots the original installer operator, raw runtime manifest, connection, key, and host trust into both private stores before worker release. Only the execution copy's local manifest and SSH paths change. There is no fabricated pre-install target. The generated target becomes a retained input after installed status and exact publication verification.

The existing supervisor result socket carries bounded checkpoint and acknowledgment frames. Root validates each legal successor, checks referenced original bytes, publishes a numbered immutable revision, and fsyncs it before acknowledging its digest. The native Invocation and original request and input digests bind each revision. The worker cannot send install apply, exact installer stop, Run release, Run stop, or remove apply without the corresponding durable authority. Duplicate, stale, malformed, or mismatched proposals receive no acknowledgment. A lost acknowledgment closes the worker's mutation path.

The stages are `bound`, `install-released`, `install-observed`, `installed`, `target-bound`, `run-released`, `run-owned`, `run-clean`, `remove-released`, `remove-observed`, and `removed`. The normal proof's repeated successful install and remove calls have explicit pending, released, and verified substates. Their exact original execution pins cannot change. These checks retain the existing repeat acceptance requirements.

Recovery first proves exact local termination, reloads the root chain, and verifies original inputs. A released apply is potentially sent even if its acknowledgment or reply was lost. Recovery queries that original operation and never retries its uncertain apply. The product status contract supplies the retained plan and execution request digest. The first observed token, request digest, deadline, and process identities are committed before exact-token stop. Changed pins, missing operation records, and unresolved partial installation remain fenced.

A `run-released` record without the original marker and product journal remains unresolved. Marker absence cannot establish that no Run started. Run recovery uses the original client, target, live config, full claim, and Session pin. It re-proves `status`, `stop`, and `status` cleanup before removal. A changed original input refuses recovery. The proof never reconstructs Run authority from Windows output.

Windows cleanup requires either fresh untouched before-state under a bound record, or terminal owned removal, the retained tombstone, and unchanged declared unrelated files and tasks. A released Run also requires original Run cleanup. Linux process exit or reboot supplies no Windows cleanup fact. Interruption remains a failed proof even when a later recovery settles cleanup. Root revisions are private, bounded to 128 KiB each and 128 revisions per execution. Public receipts keep the same fixed fields.

Host-install admission uses a schema-2 qualification receipt with scope `host-install-native-admission-v1`. It binds the exact policy and proves native confinement, persistence, peer identity, cgroup stop, crash and reboot recovery, and network restrictions. `controller-journal-integrity` proves durable claim and Session-pin retention and tamper rejection; `fixture-preflight` proves the exact grant, host, bundle, and absent installation through read-only checks. These claims do not prove Windows lifecycle recovery. Older or differently scoped qualification cannot enable this variant. Enrollment still renders `qualified: false`.

Installer checkpoint acknowledgement, lost-reply recovery, real Run/removal, and installer reboot recovery are mandatory post-admission acceptance experiments. Record their actual evidence separately, bound to candidate, driver, policy, execution, fixture, and retained original authority. A normal successful hosted run does not prove the fault cases. Use separately authorized fixtures for destructive experiments; preserve their tombstones and recovery records. Prequalification must leave the final hosted fixture absent: running install/remove first would consume its immutable before-state. Admission authorizes the experiment; it does not report acceptance.

## Run the local checks

Run the controller tests and full repository gate:

```sh
PYTHONPATH=tests/ci PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/ci -p 'test_proof*.py' -v
./scripts/ci all
```

The tests use temporary files and fake native boundaries. They exercise command and protocol parsing, expected UID selection, publication and release ordering, stale identities, replacement races, recovery, and qualification refusal. They do not establish actual privilege dropping, systemd behavior, cgroup termination, or disk durability.

## Complete native and hosted qualification

After exact enrollment approval, verify the installed artifacts and distinct account permissions on the owned Linux host. Qualify startup, exact stop, supervisor exit, service emptiness, storage flushes and locks, initiator disconnect, controller restart, and controller reboot. A service restart cannot substitute for a reboot test.

The qualification receipt must bind the exact installed policy and artifact hashes. Preserve its real evidence. Bootstrap always renders an unqualified receipt and provides no command to manufacture qualification.

Verify the selected policy variant before hosted proof. The native worker projects it into `ProofRequest.proof` while retaining hosted execution and the original target and config directory. The protected driver consumes one authenticated inherited socket authorization before candidate commands. The authorization binds the root supervisor, worker process, native receipt, request, and retained inputs.

Direct hosted calls still refuse with `hosted-recovery-retention-unavailable` before host activity. The native authorization admits only the Windows proof host. It does not authorize the Linux proof runner. An environment variable, flag, or caller-created Python object cannot replace native authority.

Required hosted `Windows onboarding proof / baseline`, `named-target`, and `host-install` results remain outstanding until those jobs actually pass. The host-install job now dispatches through `proof_dispatch.py`; it does not bypass native qualification. Its dedicated dispatch key has access only to the fixed controller commands. The public start frame binds the exact original operator digest to `installer_inputs["operator.json"]`. Missing, skipped, fake-only, or merely local checks do not satisfy them.

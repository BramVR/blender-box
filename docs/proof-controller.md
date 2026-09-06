---
summary: Local preview and qualification boundary for a persistent Windows proof controller.
read_when:
  - Preparing a persistent controller for hosted Windows proof or recovery.
---

# Preview the persistent proof controller

This tooling prepares a local controller milestone for maintainers. It does not install a service, launch a proof, or qualify a hosted job. Production dispatch returns `native-adapter-unqualified` until the native process and storage boundary has an implementation and real proof.

Generate the resource preview:

```sh
python3 scripts/proof_controller.py bootstrap
```

The JSON lists proposed resources, file contents, and unresolved qualification facts. `status` remains `unqualified` and `installable` remains `false`. No host inspection or network access occurs.

To inspect the proposed files together, choose an output directory that does not exist:

```sh
python3 scripts/proof_controller.py bootstrap --output controller-preview
```

File output requires POSIX and a path without symlink components. Generated files have a `.proposal` suffix. They are local review material; do not commit or install them as a working controller. The command has no apply operation and creates no accounts, keys, privileged rules, or services.

## Dispatch contract

The future forced SSH command accepts one bounded JSON request on standard input. Its operations are `start`, `status`, `recover`, and `stop`. The request binds the fixed repository, exact candidate and trusted driver commits, proof variant, execution ID, and UTC expiry. Callers cannot select a shell command, service, signal, user, environment, or filesystem path.

An identical start request observes the accepted execution. Conflicting content under the same execution ID fails. Expired or closed executions cannot start another Scenario. A different execution cannot use the fixture while local termination or Windows cleanup remains unknown.

Start returns after the launch identity and authorization are durable. The supervised worker runs outside the dispatcher's fixture lock. Later status calls reconcile the same invocation and its result. A result alone cannot establish local process termination.

The local implementation tests the dispatcher with injected service and proof boundaries. The public command exposes no fake backend or local-execution bypass. `named-target` is reserved for integration with its qualified trusted driver. Parsing the variant does not establish support for it.

## Retained recovery data

The proposed native controller gives control records and runner files separate owners. The control owner stores the immutable request, original-input manifest, launch intent, and exact service invocation. The runner must not supply its own process authority. Files and their containing directories must be flushed before their publication permits later effects.

The local model uses the current UID for its temporary control and job trees. It does not implement the privileged file-access boundary between two accounts. That adapter and its access tests are required before deployment.

The retained original inputs include the complete target, expected host, authorization, and dedicated SSH connection and trust bytes. SSH configuration cannot depend on another account's agent, profile, key file, or mutable include. Copying only an SSH config file is insufficient when that file refers to keys and known-hosts files elsewhere.

The accepted policy also pins the expected client binary SHA-256 before launch. The worker checks the built client before public `run`, and recovery checks the retained client against that original hash. An interrupted worker cannot supply a newly observed hash as prior authority. Automatic artifact authorization remains part of native qualification.

The product's live `BLENDER_BOX_CONFIG_DIR` holds the original Run claim and any accepted Session pin. Recovery uses this same directory. A backup cannot replace the live authority directory, and a host reply cannot reconstruct lost authority. Current product builds without durable recovery journals cannot qualify restart recovery.

Each recovery attempt gets fresh command logs and uses the retained original target, client, and config directory. It invokes public `status`, `stop`, and `status`, then checks the complete exposed Run authority and all four cleanup facts. Successful cleanup does not turn a failed Scenario into a passing proof.

## Qualify the native boundary before installation

The preview proposes two dedicated accounts, private control/job/operator roots, a fixed helper, a static service, and a restricted forced SSH command. Account names and resource paths are proposed setup targets. They are not observations about an existing host.

Before any installation, establish these facts and approve the resulting exact resource diff:

- The owned Linux host, persistent filesystem, capacity, and distinct account UIDs. Preserve existing workloads and operator state.
- The fixed helper's ownership and allowed privileged operation. No generic shell, `systemctl`, `systemd-run`, or wildcard sudo grant.
- The service's boot ID, invocation identity, cgroup, PID, start time, and parent/spawn receipt. Persist launch intent before starting; authorize Windows contact only after exact identity is durable.
- An exact stop that rejects a replacement invocation and proves the recorded task has no processes left. A changed boot ID must never authorize signaling a recycled PID.
- The dedicated Windows key and pinned trust, controller dispatch key, protected GitHub credential release policy, and required network reachability.
- An automatic trusted-candidate authorization policy and dedicated Windows fixture restoration. Recurring human dispatch approval does not satisfy AFK operation.
- A retention policy that preserves unresolved executions. Capacity exhaustion must block new admission; this milestone deletes no execution data.

The proposed service containment needs native verification. Systemd's `KillMode=control-group` targets processes in the unit's cgroup, but that setting alone does not prove which invocation the controller owns. See the [systemd kill contract](https://raw.githubusercontent.com/systemd/systemd/main/man/systemd.kill.xml).

Bootstrap does not inspect or modify a host. A separately authorized read-only survey can supply facts for a private enrollment preview. Process, disk, reboot, SSH-disconnect, and GitHub-disconnect behavior still need native proof. A service restart cannot substitute for a controller reboot test.

## Verify the local milestone

Run the focused tests and repository gate:

```sh
PYTHONPATH=tests/ci PYTHONDONTWRITEBYTECODE=1 python3 -m unittest test_proof_controller -v
./scripts/ci all
```

The tests exercise real temporary files and dispatcher restarts with fake service and Windows boundaries. They cover publication ordering, replay/conflict/expiry, unresolved admission, stale invocation rejection, retained-input corruption, separate recovery logs, and public-output privacy. These tests establish local behavior only.

Keep the hosted `hosted-recovery-retention-unavailable` guard until storage, native task ownership, and original-target recovery qualify. The final integrated candidate still needs actual `Windows onboarding proof / baseline` and `named-target` workflow results. Missing, skipped, fake-only, or merely local proof does not satisfy those jobs.

---
summary: Prepare a pinned Windows runtime, inspect and install it, and remove only owned components.
read_when:
  - Installing or removing a Windows Blender Box host.
  - Preparing runtime artifacts or diagnosing partial setup.
---

# Install Blender Box on Windows

Use this guide as the operator of an owned Windows desktop. Setup installs the Blender Box host executable, an isolated daemon runtime, and one interactive Scheduled Task. It exports a target for remote Runs. It does not launch Blender during setup.

## Prerequisites

- An installed Blender executable and standard Windows amd64 CPython 3.11 through 3.14. Debug, free-threaded, build-tree, and existing virtual-environment interpreters are unsupported.
- The same Windows account for setup, SSH control, and the logged-in interactive desktop.
- An operator-selected state root with trusted physical ancestors. Reuse the host's shared Run authority root; a new directory must not bypass active work.
- A verified bootstrap executable outside the runtime that may later be removed.
- Three pinned runtime artifacts and their source provenance, available locally on Windows.

External prerequisite files are hashed with a 2 GiB bound. Runtime bundle artifacts have a separate 64 MiB limit each.

Before executing Python, setup audits its runtime tree and startup lookup paths for reparse points and write access by other accounts. Global `Lib/site-packages` contents are excluded because setup disables their import. Interpreter redirectors, build markers, missing standard-library landmarks, and unsafe lookup parents refuse setup. A per-user Python installation usually has the required ownership. Setup never repairs its permissions or creates missing protection directories. The audit has entry, depth, and time limits; exceeding them refuses the prerequisite.

Setup probes start in their executable directory. The daemon launcher starts Python in its private Scripts directory. Their `PATH` contains only the operating system's System32 directory; `SystemRoot` and `WINDIR` come from that location. This prevents missing bootstrap DLLs from loading through an inherited working directory or search path. Workloads must use explicit paths for external tools.

Setup does not install Blender or Python, pair the host, enroll SSH or Tailscale, change the firewall, or provision credentials. It does not download artifacts. Securely transfer and verify the bootstrap and bundle through your existing operator channel before invoking setup. Read-only setup does not upload files.

After installation, the separate [SSH preparation preview](windows-ssh-preparation.md) inspects existing OpenSSH state and describes an account-scoped proposal. It grants no apply authority and does not change SSH configuration.

## Build the runtime bundle

Build the host and native daemon launcher from the candidate checkout:

```sh
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o /tmp/blender-box.exe ./cmd/blender-box
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o /tmp/blender-box-broker.exe ./cmd/blender-box-broker
```

Supply a compatible `blendersessiond` wheel. The required capability probe is `capabilities --require blender-box-v1 --require-capability typed-call-error-reason`. Do not select a wheel by version alone. Record its source commit and any patch and build-recipe SHA-256 digests.

On Windows, create the manifest from the final local artifact paths. The variables below name operator-verified files and provenance; they are not values to copy from another installation.

```powershell
& $Bootstrap setup manifest --host-binary $HostBinary --broker-launcher $BrokerLauncher --daemon-wheel $DaemonWheel --source-commit $HostCommit --daemon-source-commit $DaemonCommit --patch-sha256 $DaemonPatchSHA256 --recipe-sha256 $DaemonRecipeSHA256 --out $Manifest --json
```

The manifest records sizes and SHA-256 hashes. Its inputs are bounded regular files, not URLs. Keep the manifest with its artifacts and verify all bytes after transfer. Rebuilding or changing an input needs a new manifest.

## Inspect and preview

Run commands on Windows through the verified bootstrap:

```powershell
& $Bootstrap setup inspect --platform windows --state-root $StateRoot --json
& $Bootstrap setup install --platform windows --state-root $StateRoot --runtime $Manifest --blender $Blender --python $Python --ssh-alias $SSHAlias --windows-user $WindowsUser --task-name $TaskName --target-out $TargetFile --json
```

Inspection reports selections, prerequisites, and conflicts. Select an exact Blender executable when discovery is ambiguous. Review the installation destination, account, task, runtime inventory, and retained components. Neither command applies changes without `--apply`.

Save the returned installation ID, operation ID, and plan SHA-256. Apply requires both identities from preview. Preserve them and the target publication destination on retries. A changed immutable selection requires resolving the conflict rather than overwriting the old installation.

## Install and export a target

```powershell
& $Bootstrap setup install --platform windows --state-root $StateRoot --runtime $Manifest --blender $Blender --python $Python --ssh-alias $SSHAlias --windows-user $WindowsUser --task-name $TaskName --installation $InstallationID --operation $InstallOperationID --expected-plan $PlanSHA256 --apply --target-out $TargetFile --json
```

Require `state: installed` and inspect the returned problems and target publication result. Installation probes the private daemon before declaring success. It creates only an owned runtime and an exactly marked, limited-rights interactive task. Existing unowned tasks or files are conflicts, even when their names or bytes match.

Copy the exported target to the developer machine through the trusted operator channel. Import it without editing its paths:

```sh
blender-box targets import studio --file /path/to/target.json --json
blender-box windows check --target-name studio --json
```

Require a passing read-only check before starting a Scenario. `--save-target NAME` saves through the existing target store on the machine running setup. A store or export failure is reported separately from installation; do not reinstall just to repair target publication. Existing output files and names are not overwritten implicitly.

Target exports and saved targets must stay outside the setup state root. Setup rejects destinations inside that root before installation so publication cannot add unowned files to an installation.

## Repeat and recover

Use the same runtime manifest, selections, installation ID, operation ID, and target publication destination to repeat install. The installer rereads its receipt and actual files. A running execution remains observable; a settled partial operation can resume only after exact process cleanup and fresh admission checks. Each resumed execution has a new internal token. Repeating an operation must not create another task or adopt unrelated resources.

If SSH or the waiting CLI loses its response, query the operation through a fresh connection:

```powershell
& $Bootstrap setup status --platform windows --state-root $StateRoot --installation $InstallationID --operation $InstallOperationID --json
```

The result includes execution state, process state, deadline, process-tree cleanup, task-mutation state, and `fence_state`. An admitted execution can briefly report `unknown` before its process identities appear; keep observing the same operation and token. A proven `not-started` attempt can be retried; missing worker identity alone is insufficient. To request cancellation, or release a fence still held by an already settled execution, use the exact execution token from that result:

```powershell
& $Bootstrap setup stop --platform windows --state-root $StateRoot --installation $InstallationID --operation $InstallOperationID --execution $ExecutionToken --apply --json
```

Cancellation requested does not mean cleanup completed. Query status again and retain the JSON receipts. A settled execution can still hold its fence if the keeper died between recording proof and releasing authority; exact stop reconciles that release. Stop affects that execution only; a later explicit apply may resume the logical operation after the previous execution settles.

Cancellation after admission but before the worker starts can leave process-tree cleanup known while task mutation remains unknown and the fence stays held. A physical cleanup receipt alone does not authorize release of that fence.

Status and exact stop validate the account and state root without rediscovering Blender or Python. They still require the authenticated account to match the logged-in desktop user, enabled UAC, and the existing root ownership checks.

An independent native keeper bounds installer execution even if SSH disconnects. An unknown outcome blocks new Runs and unrelated setup operations. Missing process IDs or an absent task do not establish cleanup. If the keeper dies before recording proof, or a Task Scheduler mutation remains unsettled, preserve the state for operator review.

If native startup fails without a returned process identity, retain the pending fence unless fresh Job accounting proves that no process was created. A later empty Job does not clear uncertain startup history.

Process cleanup requires exact retained process handles and complete Job membership evidence within one five-second cleanup deadline. A missed fast child, failed process query, or exceeded collection limit leaves cleanup unknown even when the root process has exited. Preserve the pending fence and receipts in that state; do not clear them because the task list looks empty. The [ownership decision](architecture/0007-windows-installation-ownership.md) records the bounded installer workload assumptions and required native proof.

Installation receipts live beneath `STATE_ROOT/installations/INSTALLATION_ID/`; execution records live beneath `STATE_ROOT/setup-operations/`. Do not delete receipts or pending setup authority to clear an error. A changed task, modified runtime file, interrupted operation, or active Run can prevent convergence.

Runtime and execution-record publication stages temporary bytes at the managed state root, outside their exact inventories. An interrupted writer can leave a temporary file there. Setup preserves that file without adopting or deleting it; it does not block a settled retry. Interruption before the first durable installation receipt or execution request remains ambiguous and requires operator review.

## Remove an installation

Finish all Runs first, using their original target and recorded Run/Session authority. Setup removal never stops Blender implicitly. Keep the external bootstrap available.

```powershell
& $Bootstrap setup remove --platform windows --state-root $StateRoot --installation $InstallationID --json
& $Bootstrap setup remove --platform windows --state-root $StateRoot --installation $InstallationID --operation $RemovalOperationID --expected-plan $RemovalPlanSHA256 --apply --json
```

Use the new removal operation ID returned by removal preview. Keep it for apply and every removal retry. Removal checks the receipt, exact task definition, file inventory, current hashes, and maintenance fences again. It removes the owned task before runtime files and does not need to execute Python or the daemon. It preserves modified files, unknown descendants, replacements, external Python, Blender, and operator settings. A partial result is not successful removal.

The state root, shared Run authority, lock files, receipts, and tombstones remain deliberately. Repeating removal verifies the same installation remains absent. It does not authorize deletion of a replacement at an old path.

## Legacy setup and proof

`windows setup --target ... --host-binary ...` retains its offline binary preview. `--apply` returns `legacy-setup-unowned` before SSH because that path cannot prove installation ownership. There is no automatic adoption of its files or task.

Use the separately authorized [host-install proof](windows-onboarding-proof.md) for native Windows acceptance. It needs a dedicated fixture, exact candidate and manifest, real Scenario evidence, recovery, repeated removal, and unchanged unrelated fixtures. Local tests and cross-builds do not establish native correctness. Hosted proof remains unavailable until private recovery records can survive loss of the hosted controller.

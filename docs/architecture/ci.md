---
summary: Local and hosted CI boundary, security checks, and live-proof separation.
read_when:
  - Changing CI, toolchains, release automation, or live Windows proof.
---

# CI architecture

## Problem

Blender Box needs useful pull-request checks for its Go client and Windows host entry point. The same checks must run from a developer checkout and on Linux, macOS, and Windows. Live Blender proof is a separate, host-sensitive gate and must never run for untrusted pull-request code.

## Usage

Run the full repository gate:

```sh
./scripts/ci all
```

Run one half while iterating:

```sh
./scripts/ci check
./scripts/ci test
```

The GitHub workflows call these same commands. A language implementation extends `scripts/ci`; callers do not learn another CI interface.

## Shape

`scripts/ci` owns repository checks and test selection. It detects the committed Go and Python project files, then runs the matching format, static-analysis, dependency, and test commands. `.github/workflows/ci.yml` supplies clean hosted runners, bounded execution, read-only permissions, stable job names, and cancellation. `.github/workflows/security.yml` scans changed content for verified and unknown secrets. Dependabot keeps pinned action revisions current.

The repository gate's public interface is three commands. Runner setup and language detection stay behind it. CI contract tests protect the parts GitHub cannot validate for us: triggers, permissions, timeouts, stable job names, supported operating systems, pinned actions, and the secret scan.

Real Windows Blender proof stays outside the ordinary CI and Security workflows. The separate `Windows onboarding proof` workflow calls the repository's baseline runner against an explicitly authorized owned host. The project-local `verify-blender-box` skill documents the same public CLI path. Proof records the candidate and driver revisions, binary hashes, Run and Session identities, evidence, and cleanup without publishing private host details.

Hosted proof currently refuses preflight until private original Run authority can survive loss of its ephemeral controller. Public artifact uploads retain neither the original claim nor the Session pin. A private durable retention mechanism and recovery procedure are prerequisites for enabling hosted execution.

## Synthesis decision

The repo-owned command design is the base. It keeps the caller's interface small and makes local proof match hosted proof. The alternative's explicit job names and runner limits were retained in thin workflow files.

## Tradeoffs accepted

- We accept a small Bash dependency in exchange for one gate that runs locally and in GitHub's Linux, macOS, and Windows environments.
- We accept separate Check and Test jobs on Linux in exchange for fast, specific failures.
- We accept hosted-runner coverage without Blender in exchange for safely running every pull request.

## Alternatives considered

A workflow-owned pipeline would put each language command directly in YAML. It is simple on day one but exposes runner details to every contributor and duplicates local commands. It also makes later Go and Python changes touch more GitHub-specific code.

A custom composite action would reuse steps across jobs, but it adds an action metadata interface without hiding more policy than `scripts/ci` already hides.

## Open questions and risks

- What exact files and command define a release candidate once the CLI has a stable artifact contract?
- Has the operator configured and verified the protected proof environment, restricted host access, and dedicated fixture restoration?
- Should macOS remain an every-commit gate once test duration becomes material, or become path-gated?

## Live-proof boundary

Hosted pull-request jobs never receive host credentials or network access to an owned Windows machine. The live workflow runs on a fresh GitHub-hosted controller. Its trusted main-branch driver validates an immutable candidate before the credential-bearing job. The protected environment must restrict access to main, and private SSH and Tailnet credentials stay out of repository-wide secrets. Runner labels on a shared self-hosted machine are not an authorization boundary.

`scripts/onboarding_proof.py` supplies one local and hosted execution path. It builds the candidate's client and Windows executable, verifies the expected physical host and Windows identity before mutation, checks readiness, executes the baseline Scenario, and validates the returned bundle. Fresh `status`, exact `stop`, and a second `status` invocation must agree on the complete exposed Run authority. The public CLI remains responsible for acquiring and releasing the Host Lock and settling its exact Session.

The baseline requires preparation, readiness, Scenario, evidence, recovery, and cleanup outcomes. Missing work fails the gate. Existing SSH connectivity does not count as product pairing. The `named-target` job extends the same runner with import, named selection, and replacement-refusal outcomes. Installation proof adds its own separately authorized dedicated fixture and install/removal outcomes. Jobs serialize access to the Windows host. Generic evidence and recovery assertions remain shared; baseline cube assertions remain separate. The first live target is Windows; adding a runner does not establish live coverage.

Legacy setup apply refuses unowned replacement. Baseline and named-target proof require an already installed exact candidate. The `host-install` authorization separately binds the candidate, manifest, installation identity, dedicated fixture, destination, before-state, and external bootstrap. A passing check or baseline Run grant cannot authorize installation or removal. Prepared and unpaired restoration still needs exact resource ownership and an authorized mechanism.

Raw configuration, check details, stdout, stderr, and recovery journals remain private. Public output contains a fixed projection of validated facts and an explicitly permitted viewport capture. A viewport proves scene appearance; it does not prove Blender window chrome or the Windows desktop. Failure and unknown cleanup remain visible, and a later successful recovery does not turn a failed Scenario into a passing proof.

The workflow file and local tests cannot prove GitHub environment settings, network policy, dedicated fixture restoration, or a live desktop. A missing, cancelled, skipped, fake-only, or merely local result does not satisfy a required hosted job. See [Windows onboarding proof](../windows-onboarding-proof.md) for configuration and the remaining enrollment boundary.

## Proof design decision

One standard-library Python runner keeps the local and hosted interfaces identical without adding a product command or changing Run architecture. Independent design comparison selected this shape over a new Go proof package with a fixture leasing protocol. The explicit required-outcome set and separate generic assertions came from that alternative. Fixture leasing was rejected because no concrete restoration mechanism exists to justify another protocol.

## Persistent controller milestone

Fresh GitHub-hosted execution was a workflow choice. It does not retain the original target and Run journal after the initiating job disappears. The next design uses a restricted dispatcher on one owned Linux controller with persistent private storage. GitHub supplies an immutable proof request; a separate runner identity executes reviewed candidate code. Controller admission remains closed until the exact local task is gone and Windows cleanup is known.

`scripts/proof_controller.py` provides the dispatcher and enrollment preview. The native helper, worker, and private file adapter connect that model to one fixed Linux service. Production dispatch requires qualification tied to the installed policy and artifact hashes. Rendering enrollment supplies no installation, credentials, or native qualification. The existing workflow and product journal remain unchanged. See [Prepare persistent controller enrollment](../proof-controller.md) for the preview and qualification requirements.

One immutable request, one atomic execution record, and one fixture lock keep this boundary small. Independent design comparison rejected an append-only event journal and public fake-backend switches. Complete original target and SSH trust retention, fresh recovery logs, and fixed public response fields remain part of the controller contract.

The root helper owns control records and mediates bounded access to runner-owned files. The control account can request the fixed helper operation. Candidate work runs under a separate runner UID. The root supervisor loads protected code, places the waiting worker in a unique attempt cgroup, and releases it only after exact invocation authorization is durable. The protected driver tree includes its matching Scenario fixture. Candidate directories never supply privileged Python imports.

Exact stop targets the recorded attempt cgroup through a checked directory handle. A static service name can refer to a replacement, so it cannot authorize a kill. Attempt-tree termination, supervisor exit, whole-service emptiness, and Windows cleanup remain distinct facts. Linux documents recursive termination and emptiness through [cgroup.kill and cgroup.events](https://raw.githubusercontent.com/torvalds/linux/v6.8/Documentation/admin-guide/cgroup-v2.rst). Local fake-boundary tests do not establish those kernel guarantees on the selected host.

An observed failure before release uses a typed root-owned proof instead of an invented Invocation. Exact supervisor cleanup, a completed start command, absent release authority, and fresh unit quiescence must all agree before admission can reopen. An unknown start remains fenced. Failure of a recovery attempt never proves cleanup of the original Windows Run.

After a helper crash before Invocation persistence, a matching native receipt supplies the original identity. Adoption binds the accepted request, intent, inputs, and current process evidence, then durably closes admission before stop. It never authorizes release or Scenario replay. Conflicting publication prefixes or replacement processes remain fenced. Reconciliation repeats these checks after an adoption-save crash. A never-authorized first attempt can settle as failure only after fresh proof of original process exit. A failed recovery attempt preserves the original Windows Run.

One immutable policy variant selects the baseline or named-target Windows driver. The root supervisor reloads qualified runtime and durable request authorization before sending the exact native receipt through the inherited socket. The worker checks the root peer and both process identities, binds the proof request and retained inputs, then consumes and closes the socket before candidate execution. This authority admits only the concrete Windows proof host. Direct hosted calls and Linux hosted proof retain their preflight refusal. Both Windows hosted jobs remain required after native process, storage, disconnect, reboot, and original-target recovery qualification.

## Linux proof

The separate `Linux Blender proof` workflow uses the `linux-blender-proof` job and the shared evidence, fencing, and public-projection assertions. The local runner targets the documented Ubuntu GNOME Xorg configuration. Its workflow retains the unconditional `hosted-recovery-retention-unavailable` preflight before operator loading or host activity.

Default Go tests exercise Linux orchestration through fake external boundaries. POSIX bootstrap tests and recursive Python import tests skip Windows while the Windows build and existing runtime tests preserve compatibility. These tests do not establish native Linux, Blender, or hosted acceptance. See [Linux Blender proof](../linux-proof.md).

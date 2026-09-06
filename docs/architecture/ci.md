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

The baseline requires preparation, readiness, Scenario, evidence, recovery, and cleanup outcomes. Missing work fails the gate. Existing SSH connectivity does not count as product pairing. The `named-target` job extends the same runner with import, named selection, and replacement-refusal outcomes. It runs after `baseline` so the two jobs do not share the Windows fixture concurrently. Generic evidence and recovery assertions remain reusable by later `host-install` and `pair-and-run` jobs; the baseline cube assertions remain separate. The first live target is Windows; adding this runner does not establish live coverage.

Setup authorization names the exact candidate, target digest, prior installed binary hash, and the existing `windows setup` scope, including task registration and ACL changes. A passing read-only check does not authorize replacing an installed executable. Baseline proof does not reset installations or operator state. Dedicated prepared and unpaired restoration needs its own exact resource ownership and authorized mechanism before dependent work can run without recurring maintainer steps.

Raw configuration, check details, stdout, stderr, and recovery journals remain private. Public output contains a fixed projection of validated facts and an explicitly permitted viewport capture. A viewport proves scene appearance; it does not prove Blender window chrome or the Windows desktop. Failure and unknown cleanup remain visible, and a later successful recovery does not turn a failed Scenario into a passing proof.

The workflow file and local tests cannot prove GitHub environment settings, network policy, dedicated fixture restoration, or a live desktop. A missing, cancelled, skipped, fake-only, or merely local result does not satisfy either required hosted job. See [Run the Windows onboarding baseline](../windows-onboarding-proof.md) for configuration and the remaining enrollment boundary.

## Proof design decision

One standard-library Python runner keeps the local and hosted interfaces identical without adding a product command or changing Run architecture. Independent design comparison selected this shape over a new Go proof package with a fixture leasing protocol. The explicit required-outcome set and separate generic assertions came from that alternative. Fixture leasing was rejected because no concrete restoration mechanism exists to justify another protocol.

## Linux proof

The separate `Linux Blender proof` workflow uses the `linux-blender-proof` job and the shared evidence, fencing, and public-projection assertions. The local runner targets the documented Ubuntu GNOME Xorg configuration. Its workflow retains the unconditional `hosted-recovery-retention-unavailable` preflight before operator loading or host activity.

Default Go tests exercise Linux orchestration through fake external boundaries. POSIX bootstrap tests and recursive Python import tests skip Windows while the Windows build and existing runtime tests preserve compatibility. These tests do not establish native Linux, Blender, or hosted acceptance. See [Linux Blender proof](../linux-proof.md).

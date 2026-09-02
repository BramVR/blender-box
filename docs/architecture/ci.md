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

Real Windows Blender proof does not belong in these workflows. The project-local `verify-blender-box` skill drives it only against an explicitly authorized owned host. Proof records the exact commit, Run ID, Session identity, evidence, and cleanup result without publishing private host details.

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
- Which protected GitHub environment should own credentials for opt-in live Windows proof?
- Should macOS remain an every-commit gate once test duration becomes material, or become path-gated?

## Live-proof boundary

Hosted pull-request jobs never receive host credentials or network access to an owned Windows machine. A maintainer runs the verification skill locally after checking the exact hostname and operator state. The live proof may apply only the declared Blender Box setup and must clean only the exact Run and Session it created.
